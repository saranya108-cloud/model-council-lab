"""Parent-side adapter process boundary.

Trust model (Human Chair decision): adapter implementations are trusted,
project-controlled harness code; model OUTPUT is untrusted. The child process
exists for timeout/process isolation and a clean invocation protocol — it is
NOT an OS sandbox against hostile project-controlled Python.

The parent serializes a request, spawns the child with a minimal environment
and a per-invocation neutral scratch directory (never the runs namespace), and
enforces the stage timeout by terminating the direct child. Only serialized
JSON crosses the boundary.

Failure taxonomy:
  - ModelFailure: structured failure returned by the adapter/provider layer;
    qualifies for the preregistered model retry policy.
  - ProtocolError: malformed worker stdout/protocol or invalid usage metrics;
    infrastructure failure, never consumes model retry budget.
  - InfrastructureError: worker crash / spawn failure; never retried as model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .live_contract import (
    LiveContractError,
    LiveInvocationRequest,
    NeutralProviderFailure,
    ProviderCallKind,
    ProviderCallOutcome,
    parse_neutral_error,
    parse_provider_call_outcome,
)
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from .sanitize import WORKER_CRASH_SUMMARY, suppressed_stream_meta
from .types import (
    AdapterIdentity,
    InfrastructureError,
    ModelFailure,
    ProtocolError,
    ResourceLimits,
    StageTimeout,
)

_SRC_ROOT = Path(__file__).resolve().parents[1]
_OPENAI_CHILD_ENV_KEY = "MCL_OPENAI_API_KEY"
_OPENAI_HOST_ENV_KEY = "OPENAI_API_KEY"
_WORKER_PROTOCOL_FD_ENV = "MCL_WORKER_PROTOCOL_FD"
_MAX_WORKER_PROTOCOL_BYTES = 8_000_000
_OPENAI_ENV_ASSIGNMENT_PREFIXES = (
    b"MCL_OPENAI_API_KEY=",
    b"OPENAI_API_KEY=",
)


class _WorkerExitUncertain(InfrastructureError):
    """The parent cannot attest that the worker lost its append capability."""


class _WorkerReaping:
    """Affirmative reaping evidence. Never inferred from an escaping exception."""

    _ATTESTABLE = frozenset({"unstarted", "reaped"})

    def __init__(self):
        self.status = "unstarted"

    def mark_uncertain(self):
        self.status = "uncertain"

    def mark_reaped(self):
        self.status = "reaped"

    def may_attest(self):
        return self.status in self._ATTESTABLE


def _run_openai_worker(args, *, input, deadline, protocol_fds, reaping, **kwargs):
    """Launch once, then transfer all communication ownership to the collector.

    protocol_fds holds only caller-owned descriptors. Popping transfers them;
    this also leaves pre-launch failures safe for the caller's finally block.
    No second wait/close/kill path runs after collector ownership transfer.
    """
    if type(input) is not bytes or not math.isfinite(deadline):
        raise ValueError("worker requires bytes and a finite absolute deadline")
    process = None
    protocol_r = protocol_fds.pop("read")
    protocol_w = protocol_fds.pop("write")
    transferred = False
    try:
        reaping.mark_uncertain()  # Before Popen, including partial launch failure.
        try:
            process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=False, bufsize=0, **kwargs,
            )
        except (KeyboardInterrupt, SystemExit):
            raise _WorkerExitUncertain("worker launch interrupted; exit unconfirmed") from None
        write_fd, protocol_w = protocol_w, None
        os.close(write_fd)
        # Arguments are validated above; from entry the collector owns every
        # process stream and the protocol reader, even if collection fails.
        transferred = True
        result = _collect_openai_worker(
            process, input=input, protocol_fd=protocol_r, deadline=deadline,
        )
        if result.reaped is True and result.cleanup_complete is True:
            reaping.mark_reaped()
        if result.interruption:
            # Reconstruct only the signal, never a caught exception or its data.
            if result.interruption == "keyboard_interrupt":
                raise KeyboardInterrupt()
            if result.interruption == "system_exit":
                raise SystemExit()
            raise BaseException("worker communication interrupted")
        if not reaping.may_attest():
            reason = result.abort_reason or "none"
            raise _WorkerExitUncertain(
                f"worker cleanup_uncertain (communication_reason={reason})"
            )
        if result.failure == "deadline":
            raise subprocess.TimeoutExpired(args, timeout=0)
        if result.failure == "protocol_limit":
            raise ProtocolError("worker communication failed: protocol_limit")
        if result.failure == "worker_exit":
            raise _openai_nonzero_worker_failure(result.returncode, result.stderr_observed)
        if result.failure is not None:
            raise InfrastructureError(f"worker communication failed: {result.failure}")
        return result
    finally:
        if not transferred:
            # Only setup/launch failures reach this cleanup. They cannot attest
            # collection completeness, even when the direct child is reaped.
            cleanup_deadline = time.monotonic() + _WORKER_CLEANUP_TIMEOUT_SECONDS
            if process is not None:
                try:
                    process.kill()
                except BaseException:
                    pass
                try:
                    process.wait(timeout=max(0.0, cleanup_deadline - time.monotonic()))
                except BaseException:
                    pass
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException:
                            pass
            _close_fd(protocol_r)
        _close_fd(protocol_w)
        kwargs.clear()
        process = None


# Accepted F6a communication policies; shared by production and contract tests.
# The protocol ceiling above is inherited; diagnostic ceilings are new,
# explicitly approved defensive policies, not application-response limits.
_MAX_WORKER_STDOUT_BYTES = 64 * 1024
_MAX_WORKER_STDERR_BYTES = 64 * 1024
_MAX_WORKER_DIAGNOSTIC_BYTES = 96 * 1024  # Independent aggregate policy.
# Implementation quanta, not accepted-output limits. One operation per ready
# descriptor per arbitration cycle; status/deadline checks also occur per turn.
_WORKER_IO_QUANTUM_BYTES = 64 * 1024
_WORKER_STATUS_POLL_SECONDS = 0.05
# Five seconds inherits the old wait duration, but sharing ONE allowance across
# all cleanup phases is new. It never extends the communication deadline.
_WORKER_CLEANUP_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class _WorkerCollection:
    """Owned collector facts, NOT lifecycle evidence or permission to retry.

    Observed counters freeze at the first abort. They do not report total
    producer output. High-water marks measure payload bytes, not allocator
    capacity or process RSS; conversion of protocol to bytes may also copy it.
    No diagnostic body or exception object is retained in this result.
    """

    protocol: bytes | None = field(repr=False)
    failure: str | None
    abort_reason: str | None
    returncode: int | None
    reaped: bool
    pipes_eof: bool
    cleanup_complete: bool
    interruption: str | None
    stdout_observed: int
    stderr_observed: int
    diagnostic_observed: int
    protocol_high_water: int
    read_high_water: int
    diagnostic_high_water: int = 0


def _collect_openai_worker(process, *, input: bytes, protocol_fd: int,
                           deadline: float, monotonic=time.monotonic) -> _WorkerCollection:
    """POSIX collector for an already-spawned, binary/unbuffered child.

    The caller establishes an absolute monotonic deadline BEFORE setup/spawn,
    closes its protocol WRITE descriptor after spawn, and passes exclusive
    ownership of stdin/stdout/stderr and protocol_fd here. Argument validation
    precedes ownership transfer. Never pass a descriptor used by another reader.

    This function does not spawn, dispatch, parse protocol, write evidence, or
    alter _WorkerReaping. The launch wrapper separately integrates these facts:
    direct reaping alone is insufficient when cleanup_complete is false.
    Interruptions are reported explicitly after cleanup, not silently accepted;
    the caller must preserve interrupt semantics when handling the result.
    OS calls and the injected monotonic clock must behave normally; there is no
    hard global bound against an unresponsive kernel or filesystem.
    """
    if type(input) is not bytes or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise ValueError("collector requires bytes and a finite absolute deadline")
    protocol = bytearray()
    accepted = None
    counts = {"stdout": 0, "stderr": 0}
    diagnostic_count = 0
    protocol_high_water = 0
    read_high_water = 0
    chunk = None
    offset = 0
    abort_reason = None
    interruption = None
    cleanup_deadline = None
    cleanup_error = False
    reaped = False
    returncode = None
    kill_attempted = False
    eof = set()
    endpoints = {}
    registered = set()
    selector = None

    def start_cleanup(now):
        nonlocal cleanup_deadline
        if cleanup_deadline is None:
            cleanup_deadline = now + _WORKER_CLEANUP_TIMEOUT_SECONDS

    def note_exception(exc):
        nonlocal interruption
        if isinstance(exc, KeyboardInterrupt):
            interruption = "keyboard_interrupt"
        elif isinstance(exc, SystemExit):
            interruption = "system_exit"
        elif not isinstance(exc, Exception):
            interruption = "base_exception"

    def close_endpoint(name):
        nonlocal cleanup_error
        endpoint = endpoints.pop(name, None)
        if endpoint is None:
            return
        fd, stream = endpoint
        if name in registered:
            registered.remove(name)
            try:
                selector.unregister(fd)
            except BaseException as exc:
                note_exception(exc)
                cleanup_error = True
        try:
            if stream is None:
                os.close(fd)
            else:
                stream.close()
        except BaseException as exc:
            note_exception(exc)
            cleanup_error = True

    def abort(reason, now):
        nonlocal abort_reason, kill_attempted
        if abort_reason is None:
            abort_reason = reason
        protocol.clear()
        start_cleanup(now)
        # Signal before closing/draining: cleanup operations must not postpone
        # cancellation. A failed kill may race with an independently reaped exit.
        if not reaped and not kill_attempted:
            kill_attempted = True
            try:
                process.kill()
            except BaseException as exc:
                note_exception(exc)
        close_endpoint("stdin")

    def observe_exit(now):
        nonlocal reaped, returncode
        if reaped:
            return
        try:
            returncode = process.wait(timeout=0)
        except subprocess.TimeoutExpired:
            return
        except BaseException as exc:
            note_exception(exc)
            abort("process_error", now)
            return
        reaped = True
        start_cleanup(now)
        close_endpoint("stdin")

    def arbitrate():
        now = monotonic()
        observe_exit(now)
        if abort_reason is None and now >= deadline:
            abort("deadline", now)
        if cleanup_error:
            abort("io_error", now)
        return now

    try:
        # Take ownership of every descriptor before operations that may fail.
        endpoints["protocol"] = (protocol_fd, None)
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(process, name)
            endpoints[name] = (stream.fileno(), stream)
        selector = selectors.DefaultSelector()
        for name in ("stdin", "stdout", "stderr", "protocol"):
            fd, _ = endpoints[name]
            os.set_blocking(fd, False)
            selector.register(fd, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)
            registered.add(name)
        if not input:
            close_endpoint("stdin")
        while True:
            now = arbitrate()
            if reaped and eof == {"stdout", "stderr", "protocol"}:
                break
            if cleanup_deadline is not None and now >= cleanup_deadline:
                break
            until = cleanup_deadline if abort_reason is not None else deadline
            if cleanup_deadline is not None:
                until = min(until, cleanup_deadline)
            ready = selector.select(min(_WORKER_STATUS_POLL_SECONDS, max(0.0, until - now)))
            for key, _ in ready:
                now = arbitrate()
                if cleanup_deadline is not None and now >= cleanup_deadline:
                    break
                name = key.data
                if name not in endpoints:
                    continue
                fd, _ = endpoints[name]
                try:
                    if name == "stdin":
                        written = os.write(fd, memoryview(input)[offset:offset + _WORKER_IO_QUANTUM_BYTES])
                        offset += written
                        if offset == len(input):
                            close_endpoint(name)
                        continue
                    size = _WORKER_IO_QUANTUM_BYTES
                    if abort_reason is None:
                        if name == "protocol":
                            remaining = _MAX_WORKER_PROTOCOL_BYTES - len(protocol)
                        else:
                            ceiling = _MAX_WORKER_STDOUT_BYTES if name == "stdout" else _MAX_WORKER_STDERR_BYTES
                            remaining = min(ceiling - counts[name], _MAX_WORKER_DIAGNOSTIC_BYTES - diagnostic_count)
                        size = min(size, remaining + 1)
                    chunk = os.read(fd, size)
                    read_high_water = max(read_high_water, len(chunk))
                    if not chunk:
                        eof.add(name)
                        # Stop polling EOF, but defer descriptor closes until
                        # communication (including its final copy) is latched.
                        selector.unregister(fd)
                        registered.remove(name)
                    elif abort_reason is None:
                        if name == "protocol":
                            if len(protocol) + len(chunk) > _MAX_WORKER_PROTOCOL_BYTES:
                                abort("protocol_limit", monotonic())
                            else:
                                protocol.extend(chunk)
                                protocol_high_water = max(protocol_high_water, len(protocol))
                        else:
                            counts[name] += len(chunk)
                            diagnostic_count += len(chunk)
                            if counts[name] > ceiling:
                                abort(name + "_limit", monotonic())
                            elif diagnostic_count > _MAX_WORKER_DIAGNOSTIC_BYTES:
                                abort("diagnostic_limit", monotonic())
                    chunk = None  # Diagnostics never survive the current operation.
                except (BlockingIOError, InterruptedError):
                    chunk = None
                    continue
                except BrokenPipeError:
                    chunk = None
                    if name == "stdin":
                        close_endpoint(name)
                    else:
                        raise
        # Finalize communication BEFORE final descriptor/selector cleanup.
        # The cleanup allowance already started at abort or observed exit;
        # it is independent of this one-time communication deadline decision.
        if (reaped and eof == {"stdout", "stderr", "protocol"}
                and abort_reason is None and not cleanup_error and not interruption
                and returncode == 0):
            accepted = bytes(protocol)
            if monotonic() >= deadline:
                accepted = None
                abort("deadline", monotonic())
        protocol.clear()
    except BaseException as exc:
        chunk = None
        note_exception(exc)
        abort("interrupted" if interruption else "io_error", monotonic())
        # The I/O mechanism itself failed; do not claim EOF or resume a broken
        # selector. Still attempt a confirmed wait within the SAME allowance.
        if not reaped:
            try:
                returncode = process.wait(timeout=max(0.0, cleanup_deadline - monotonic()))
                reaped = True
            except BaseException as wait_exc:
                note_exception(wait_exc)
    finally:
        chunk = None
        for name in tuple(endpoints):
            close_endpoint(name)
        if selector is not None:
            try:
                selector.close()
            except BaseException as exc:
                note_exception(exc)
                cleanup_error = True

    pipes_eof = eof == {"stdout", "stderr", "protocol"}
    cleanup_complete = reaped and pipes_eof and not cleanup_error
    if cleanup_deadline is not None and monotonic() > cleanup_deadline:
        cleanup_complete = False
    if not cleanup_complete:
        failure = "cleanup_uncertain"
    elif interruption:
        failure = "interrupted"
    elif abort_reason is not None:
        failure = abort_reason
    elif returncode != 0:
        failure = "worker_exit"
    else:
        failure = None
    # Cleanup failure/uncertainty can veto the latched result. Elapsed cleanup
    # time is never compared with the communication deadline here.
    if failure is not None:
        accepted = None
    return _WorkerCollection(
        protocol=accepted, failure=failure, abort_reason=abort_reason,
        returncode=returncode, reaped=reaped, pipes_eof=pipes_eof,
        cleanup_complete=cleanup_complete, interruption=interruption,
        stdout_observed=counts["stdout"], stderr_observed=counts["stderr"],
        diagnostic_observed=diagnostic_count, protocol_high_water=protocol_high_water,
        read_high_water=read_high_water,
    )


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _openai_env_assignment(item: object) -> bool:
    if isinstance(item, str):
        encoded = item.encode("utf-8", "surrogateescape")
    elif isinstance(item, (bytes, bytearray)):
        encoded = bytes(item)
    else:
        return False
    return encoded.startswith(_OPENAI_ENV_ASSIGNMENT_PREFIXES)


def _scrub_openai_env_containers(value: object, seen: set[int]) -> None:
    ident = id(value)
    if ident in seen:
        return
    seen.add(ident)
    if type(value) is dict:
        value.pop(_OPENAI_CHILD_ENV_KEY, None)
        value.pop(_OPENAI_HOST_ENV_KEY, None)
        for inner in list(value.values()):
            _scrub_openai_env_containers(inner, seen)
        return
    if type(value) is list:
        for index, item in enumerate(value):
            if _openai_env_assignment(item):
                value[index] = None
            else:
                _scrub_openai_env_containers(item, seen)


def _scrub_openai_subprocess_exception(exc: BaseException) -> None:
    """Drop captured buffers and credential-bearing spawn state before discard."""
    for attr in ("stdout", "stderr", "output"):
        if hasattr(exc, attr):
            setattr(exc, attr, None)
    seen: set[int] = set()
    tb = getattr(exc, "__traceback__", None)
    while tb is not None:
        for val in tb.tb_frame.f_locals.values():
            _scrub_openai_env_containers(val, seen)
        tb = tb.tb_next
    exc.__cause__ = None
    exc.__context__ = None
    exc.__traceback__ = None


def _openai_nonzero_worker_failure(exit_status: int, stderr_observed: int) -> InfrastructureError:
    """Report numeric observations only; no diagnostic body is retained."""
    return InfrastructureError(
        f"{WORKER_CRASH_SUMMARY} (exit {exit_status}; "
        f"stderr_bytes_observed={stderr_observed}; suppressed=True)"
    )


class SubprocessAdapter:
    def __init__(
        self,
        identity: AdapterIdentity,
        kind: str = "fake",
        options: dict | None = None,
        python_executable: str | None = None,
        provider_treatment_config: dict | None = None,
    ) -> None:
        self.identity = identity
        self.kind = kind
        # Deep-frozen so post-construction caller mutation cannot change what
        # the child executes or the recorded adapter configuration digest.
        from .security import deep_freeze, normalize_provider_treatment_config

        if options is None:
            raw_options = {}
        elif kind == "openai_responses":
            from .openai_adapter import materialize_openai_runtime_options

            raw_options = materialize_openai_runtime_options(options)
        else:
            raw_options = dict(options or {})
        self.options = deep_freeze(raw_options)
        # Treatment authority is supplied separately from adapter options and
        # is copied before freeze so later caller mutation cannot change it.
        self.provider_treatment_config = deep_freeze(
            normalize_provider_treatment_config(provider_treatment_config)
        )
        self.python_executable = python_executable or sys.executable
        self.last_scratch_dir: str | None = None
        self.last_attempt_timeout_seconds: float | None = None
        self.last_request: dict | None = None
        self.last_harness_observed_latency_seconds: float | None = None
        self.attempt_journal = None

    @property
    def scratch_dir(self) -> str | None:
        return self.last_scratch_dir

    def _child_options(self) -> dict:
        # Reuse the harness canonicalizer so heterogeneous frozen sets use
        # the same type-stable ordering as treatment/provenance hashing.
        from .security import canonical_json

        if self.kind == "openai_responses":
            from .openai_adapter import require_empty_openai_runtime_options

            require_empty_openai_runtime_options(self.options)
            return {}
        plain_options = json.loads(canonical_json(self.options))
        return {
            **plain_options,
            "model_id": self.identity.model_id,
            "identity": self.identity.to_dict(),
        }

    def persisted_provider_treatment_config(self) -> dict:
        from .security import canonical_json

        return json.loads(canonical_json(self.provider_treatment_config))

    @property
    def execution_profile(self) -> str:
        return execution_profile_for_kind(self.kind)

    def invoke(
        self,
        *,
        role_instruction: str,
        stage_inputs: dict[str, str],
        budget: ResourceLimits,
        seed: int,
        timeout_seconds: float | None = None,
    ) -> dict:
        profile = execution_profile_for_kind(self.kind)
        if profile != EXECUTION_PROFILE_PRE_LIVE_LEGACY:
            raise ProtocolError(
                f"adapter kind {self.kind!r} is registered for {profile}; "
                "legacy invoke() is not permitted"
            )
        declared_timeout = float(budget.stage_timeout_seconds)
        if timeout_seconds is None:
            attempt_timeout = declared_timeout
        else:
            attempt_timeout = float(timeout_seconds)
        # Runner owns the stage deadline. The executor may only enforce the
        # remaining time it was granted, and must never enlarge it past the
        # declared stage timeout.
        if attempt_timeout > declared_timeout:
            attempt_timeout = declared_timeout
        self.last_attempt_timeout_seconds = attempt_timeout
        request = {
            "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
            "execution_profile": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
            "adapter": {"kind": self.kind, "options": self._child_options()},
            "role_instruction": role_instruction,
            "stage_inputs": stage_inputs,
            "budget": budget.to_dict(),
            "seed": seed,
        }
        self.last_request = request
        payload = self._spawn_worker(request, attempt_timeout)
        return self._parse_legacy_payload(payload)

    def invoke_live(self, live_request: LiveInvocationRequest) -> ProviderCallOutcome:
        profile = execution_profile_for_kind(self.kind)
        if profile != EXECUTION_PROFILE_LIVE_CONTRACT_V1:
            raise ProtocolError(
                f"adapter kind {self.kind!r} is registered for {profile}; "
                "live-contract invoke_live() is not permitted"
            )
        if not isinstance(live_request, LiveInvocationRequest):
            raise ProtocolError("invoke_live requires a runner-built LiveInvocationRequest")
        attempt_timeout = float(live_request.attempt_timeout_seconds)
        self.last_attempt_timeout_seconds = attempt_timeout
        envelope = {
            "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
            "execution_profile": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
            "adapter": {"kind": self.kind, "options": self._child_options()},
            "provider_treatment_config": self.persisted_provider_treatment_config(),
            "live_invocation_request": live_request.to_dict(),
        }
        self.last_request = envelope
        if self.kind == "openai_responses":
            from .attempt_lifecycle import validate_prepared_binding, validate_worker_binding
            if self.attempt_journal is None:
                raise ProtocolError("OpenAI v15 requires runner-owned attempt lifecycle authorization")
            validate_prepared_binding(self.attempt_journal, live_request)
            self.attempt_journal.permit(attempt_timeout)
            writer = self.attempt_journal.open_writer()
            try:
                validate_worker_binding(writer, live_request)
                envelope["attempt_id"] = writer.attempt_id
                self._lifecycle_fd = writer.fd
                payload = self._spawn_worker(envelope, attempt_timeout)
            finally:
                self._lifecycle_fd = None
                os.close(writer.fd)
        else:
            payload = self._spawn_worker(envelope, attempt_timeout)
        return self._parse_live_payload(payload)

    def _spawn_worker(self, request: dict, attempt_timeout: float) -> dict:
        communication_deadline = (
            time.monotonic() + attempt_timeout if self.kind == "openai_responses" else None
        )
        if self.kind == "openai_responses" and self.attempt_journal is None:
            raise ProtocolError("OpenAI worker requires attempt lifecycle authorization")
        if attempt_timeout <= 0:
            raise StageTimeout(
                f"adapter process exceeded {attempt_timeout}s and was terminated"
            )
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_SRC_ROOT),
        }
        spawn_kwargs = {}
        if os.name == "posix":
            # New session/process group: guarantees we can terminate the direct
            # child cleanly. Descendant containment is NOT claimed; trusted
            # adapters must not intentionally spawn unmanaged descendants.
            spawn_kwargs["start_new_session"] = True
        openai_timeout = False
        openai_spawn_failure = None
        completed = None
        protocol_r = None
        protocol_w = None
        protocol_fds = {}
        worker_reaping = _WorkerReaping()
        try:
            if self.kind == "openai_responses":
                from .openai_adapter import (
                    CHILD_OPENAI_API_KEY_ENV,
                    HOST_OPENAI_API_KEY_ENV,
                    validate_openai_runtime_credential,
                )

                raw_credential = os.environ.get(HOST_OPENAI_API_KEY_ENV)
                try:
                    env[CHILD_OPENAI_API_KEY_ENV] = validate_openai_runtime_credential(
                        raw_credential
                    )
                finally:
                    raw_credential = None
                protocol_r, protocol_w = os.pipe()
                protocol_fds.update(read=protocol_r, write=protocol_w)
                os.set_inheritable(protocol_r, False)
                os.set_inheritable(protocol_w, True)
                env[_WORKER_PROTOCOL_FD_ENV] = str(protocol_w)
                from .attempt_lifecycle import LIFECYCLE_FD_ENV
                lifecycle_fd = getattr(self, "_lifecycle_fd", None)
                if type(lifecycle_fd) is not int:
                    raise ProtocolError("missing lifecycle descriptor")
                env[LIFECYCLE_FD_ENV] = str(lifecycle_fd)
                spawn_kwargs["pass_fds"] = (protocol_w, lifecycle_fd)

            with tempfile.TemporaryDirectory(prefix="mcl-scratch-") as scratch:
                self.last_scratch_dir = scratch
                started = time.monotonic()
                try:
                    command = [self.python_executable, "-B", "-m", "model_council.worker"]
                    if self.kind == "openai_responses":
                        completed = _run_openai_worker(
                            command, input=json.dumps(request).encode("utf-8"),
                            deadline=communication_deadline, protocol_fds=protocol_fds,
                            reaping=worker_reaping, cwd=scratch, env=dict(env),
                            **spawn_kwargs,
                        )
                    else:
                        completed = subprocess.run(
                            command, input=json.dumps(request), capture_output=True,
                            text=True, timeout=attempt_timeout, cwd=scratch,
                            env=dict(env), **spawn_kwargs,
                        )
                    if self.kind == "openai_responses":
                        if not worker_reaping.may_attest():
                            raise _WorkerExitUncertain("worker termination unconfirmed")
                        self.attempt_journal.close("returned" if completed.returncode == 0 else "infrastructure", worker_reaped=True)
                finally:
                    self.last_harness_observed_latency_seconds = time.monotonic() - started
        except subprocess.TimeoutExpired as exc:
            if self.kind == "openai_responses":
                _scrub_openai_subprocess_exception(exc)
                openai_timeout = True
                if worker_reaping.may_attest():
                    self.attempt_journal.close("timeout", worker_reaped=True)
                exc = None
            else:
                raise StageTimeout(
                    f"adapter process exceeded {attempt_timeout}s and was terminated"
                ) from exc
        except OSError as exc:
            if self.kind == "openai_responses":
                openai_spawn_failure = f"failed to spawn adapter process: {exc}"
                _scrub_openai_subprocess_exception(exc)
                completed = None
                exc = None
                if (not self.attempt_journal.persistence_failed
                        and worker_reaping.may_attest()
                        and not self.attempt_journal.path.with_name("closed.json").exists()):
                    self.attempt_journal.close("infrastructure", worker_reaped=True)
            else:
                raise InfrastructureError(
                    f"failed to spawn adapter process: {exc}"
                ) from exc
        except BaseException as exc:
            if self.kind == "openai_responses":
                if (worker_reaping.may_attest()
                        and not self.attempt_journal.persistence_failed
                        and not self.attempt_journal.path.with_name("closed.json").exists()):
                    self.attempt_journal.close(
                        "interrupted" if not isinstance(exc, Exception) else "infrastructure",
                        worker_reaped=True,
                    )
                _scrub_openai_subprocess_exception(exc)
            raise
        finally:
            env.pop(_OPENAI_CHILD_ENV_KEY, None)
            env.pop(_WORKER_PROTOCOL_FD_ENV, None)
            env.pop("MCL_ATTEMPT_LIFECYCLE_FD", None)
            for fd in protocol_fds.values():
                _close_fd(fd)
            protocol_fds.clear()
            protocol_r = protocol_w = None
            if openai_spawn_failure is not None:
                env.clear()
                env = None

        if openai_timeout:
            raise StageTimeout(
                f"adapter process exceeded {attempt_timeout}s and was terminated"
            )
        if openai_spawn_failure is not None:
            raise InfrastructureError(openai_spawn_failure)

        if self.kind != "openai_responses" and completed.returncode != 0:
            meta = suppressed_stream_meta(completed.stderr)
            raise InfrastructureError(
                f"{WORKER_CRASH_SUMMARY} (exit {completed.returncode}; "
                f"stderr_bytes={meta['bytes']}; stderr_sha256={meta['sha256']})"
            )
        openai_invalid_json = False
        stdout_text = None
        if self.kind == "openai_responses":
            protocol_bytes = completed.protocol
            completed = None
            if protocol_bytes is None:
                openai_invalid_json = True
            else:
                try:
                    stdout_text = protocol_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    stdout_text = None
                    openai_invalid_json = True
            protocol_bytes = None
        else:
            stdout_text = completed.stdout
        if openai_invalid_json:
            raise ProtocolError("worker stdout was not valid JSON")
        try:
            payload = json.loads(stdout_text)
        except json.JSONDecodeError as exc:
            if self.kind == "openai_responses":
                stdout_text = None
                completed = None
                try:
                    exc.doc = None
                except Exception:
                    pass
                _scrub_openai_subprocess_exception(exc)
                exc = None
                openai_invalid_json = True
            else:
                raise ProtocolError(f"worker stdout was not valid JSON: {exc}") from exc
        if openai_invalid_json:
            raise ProtocolError("worker stdout was not valid JSON")
        if self.kind == "openai_responses":
            stdout_text = None
            completed = None
        if not isinstance(payload, dict) or "ok" not in payload:
            raise ProtocolError("worker response missing required 'ok' field")
        if not payload["ok"]:
            error_class = payload.get("error_class")
            message = payload.get("message")
            if not isinstance(message, str):
                message = f"worker reported {error_class}"
            if error_class == "ProtocolError":
                raise ProtocolError(message)
            if error_class == "InfrastructureError":
                raise InfrastructureError(message)
            if error_class == "ModelFailure":
                raise ModelFailure(message)
            if error_class == "NeutralProviderFailure":
                try:
                    error = parse_neutral_error(payload.get("error"))
                except LiveContractError as exc:
                    raise ProtocolError(
                        f"NeutralProviderFailure payload was not a valid NeutralError: {exc}"
                    ) from exc
                raise NeutralProviderFailure(error)
            raise InfrastructureError(
                f"worker reported {error_class}: {message}"
            )
        return payload

    def _parse_legacy_payload(self, payload: dict) -> dict:
        if payload.get("execution_profile") not in (None, EXECUTION_PROFILE_PRE_LIVE_LEGACY):
            raise ProtocolError("legacy worker envelope carried a non-legacy execution profile")
        if "outcome" in payload:
            raise ProtocolError("legacy worker envelope must not include a live outcome")
        response = payload.get("response")
        if not isinstance(response, dict):
            raise ProtocolError("worker response missing structured 'response' object")
        self._validate_usage_fields(response)
        self._validate_identity_used(response)
        return response

    def _parse_live_payload(self, payload: dict) -> ProviderCallOutcome:
        if payload.get("execution_profile") != EXECUTION_PROFILE_LIVE_CONTRACT_V1:
            raise ProtocolError("live worker envelope missing live_contract_v1 execution profile")
        if "response" in payload:
            raise ProtocolError("live adapter returned a legacy response envelope")
        raw_outcome = payload.get("outcome")
        try:
            outcome = parse_provider_call_outcome(raw_outcome)
        except LiveContractError as exc:
            raise ProtocolError(f"live worker returned an invalid ProviderCallOutcome: {exc}") from exc
        if outcome.kind is not ProviderCallKind.SUCCESS:
            if outcome.error is None:
                raise ProtocolError("live error outcome is missing NeutralError evidence")
            raise NeutralProviderFailure(outcome.error, outcome=outcome)
        return outcome

    @staticmethod
    def _validate_usage_fields(response: dict) -> None:
        for field in ("tokens_in", "tokens_out", "tool_uses"):
            value = response.get(field)
            if value is None:
                raise ProtocolError(f"usage field '{field}' missing from worker response")
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProtocolError(
                    f"usage field '{field}' must be an integer, got {type(value).__name__}"
                )
            if value < 0:
                raise ProtocolError(f"usage field '{field}' must be non-negative")

    def _validate_identity_used(self, response: dict) -> None:
        used = response.get("identity_used")
        if not isinstance(used, dict):
            raise ProtocolError("worker response missing 'identity_used'")
        expected = self.identity.to_dict()
        for key in ("provider", "model_id", "model_version", "adapter_name", "adapter_version"):
            if not isinstance(used.get(key), str) or not used[key]:
                raise ProtocolError(f"identity_used['{key}'] must be a non-empty string")
        # The child reports what it actually resolved; equality with the
        # configured identity is enforced by the Runner against RunSpec.
        del expected
