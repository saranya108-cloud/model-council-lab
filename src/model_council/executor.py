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

import json
import os
import subprocess
import sys
import tempfile
import threading
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


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _read_protocol_fd(fd: int | None, *, limit: int) -> bytes | None:
    if fd is None:
        return None
    chunks = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                chunks = None
                return None
            chunks.append(chunk)
    except OSError:
        return None
    return b"".join(chunks)


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


def _openai_nonzero_worker_failure(completed: subprocess.CompletedProcess) -> InfrastructureError:
    """Build a sanitized crash error, then release secret-bearing subprocess buffers."""
    exit_status = completed.returncode
    stderr_text = completed.stderr
    stderr_bytes = (
        0
        if stderr_text is None
        else len(str(stderr_text).encode("utf-8", "replace"))
    )
    completed.stdout = None
    completed.stderr = None
    stderr_text = None
    completed = None
    return InfrastructureError(
        f"{WORKER_CRASH_SUMMARY} (exit {exit_status}; "
        f"stderr_bytes={stderr_bytes}; suppressed=True)"
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
        payload = self._spawn_worker(envelope, attempt_timeout)
        return self._parse_live_payload(payload)

    def _spawn_worker(self, request: dict, attempt_timeout: float) -> dict:
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
        protocol_holder = []
        protocol_reader = None
        protocol_reader_started = False
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
                os.set_inheritable(protocol_r, False)
                os.set_inheritable(protocol_w, True)
                env[_WORKER_PROTOCOL_FD_ENV] = str(protocol_w)
                spawn_kwargs["pass_fds"] = (protocol_w,)

                def _drain_protocol():
                    protocol_holder.append(
                        _read_protocol_fd(protocol_r, limit=_MAX_WORKER_PROTOCOL_BYTES)
                    )

                protocol_reader = threading.Thread(
                    target=_drain_protocol, daemon=True
                )
                protocol_reader.start()
                protocol_reader_started = True
            with tempfile.TemporaryDirectory(prefix="mcl-scratch-") as scratch:
                self.last_scratch_dir = scratch
                started = time.monotonic()
                try:
                    completed = subprocess.run(
                        [self.python_executable, "-B", "-m", "model_council.worker"],
                        input=json.dumps(request),
                        capture_output=True,
                        text=True,
                        timeout=attempt_timeout,
                        cwd=scratch,
                        env=dict(env),
                        **spawn_kwargs,
                    )
                finally:
                    self.last_harness_observed_latency_seconds = time.monotonic() - started
        except subprocess.TimeoutExpired as exc:
            if self.kind == "openai_responses":
                _scrub_openai_subprocess_exception(exc)
                openai_timeout = True
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
            else:
                raise InfrastructureError(
                    f"failed to spawn adapter process: {exc}"
                ) from exc
        finally:
            env.pop(_OPENAI_CHILD_ENV_KEY, None)
            env.pop(_WORKER_PROTOCOL_FD_ENV, None)
            _close_fd(protocol_w)
            protocol_w = None
            if protocol_reader_started:
                protocol_reader.join(timeout=1.0)
                if protocol_reader.is_alive():
                    _close_fd(protocol_r)
                    protocol_r = None
                    protocol_reader.join(timeout=1.0)
            else:
                _close_fd(protocol_r)
                protocol_r = None
            if openai_spawn_failure is not None:
                env.clear()
                env = None

        if openai_timeout:
            _close_fd(protocol_r)
            protocol_r = None
            raise StageTimeout(
                f"adapter process exceeded {attempt_timeout}s and was terminated"
            )
        if openai_spawn_failure is not None:
            _close_fd(protocol_r)
            protocol_r = None
            raise InfrastructureError(openai_spawn_failure)

        if completed.returncode != 0:
            _close_fd(protocol_r)
            protocol_r = None
            if self.kind == "openai_responses":
                error = _openai_nonzero_worker_failure(completed)
                completed = None
                raise error
            meta = suppressed_stream_meta(completed.stderr)
            raise InfrastructureError(
                f"{WORKER_CRASH_SUMMARY} (exit {completed.returncode}; "
                f"stderr_bytes={meta['bytes']}; stderr_sha256={meta['sha256']})"
            )
        openai_invalid_json = False
        stdout_text = None
        if self.kind == "openai_responses":
            protocol_bytes = protocol_holder[0] if protocol_holder else None
            protocol_holder = None
            _close_fd(protocol_r)
            protocol_r = None
            completed.stdout = None
            completed.stderr = None
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
