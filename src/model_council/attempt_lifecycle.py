"""F5 local attempt evidence. Trusted harness facts, never provider attestation.

The parent owns reservation, permission and closure. The worker receives only
an append descriptor for one journal. No recovery path issues new permission.
A valid prefix is useful evidence, but is never evidence of retry safety.
"""
from __future__ import annotations

import json
import fcntl
import math
import os
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .security import canonical_json, digest_json, safe_identifier
from .types import IntegrityViolation

LIFECYCLE_SCHEMA = "m1-attempt-lifecycle-v1"
LIFECYCLE_PROTOCOL = "m1-dev-harness-v15"
LIFECYCLE_FD_ENV = "MCL_ATTEMPT_LIFECYCLE_FD"
LIFECYCLE_ROOT = "attempt-lifecycle"
MAX_JOURNAL_BYTES = 16_000_000
MAX_FRAME_BYTES = 8_000_000
MAX_CLOSURE_BYTES = 4096
_DIGEST_FIELDS = {"authority_digest", "request_digest", "input_content_digest",
                  "request_parameter_digest", "identity_policy_digest", "treatment_digest"}
_BINDING_FIELDS = _DIGEST_FIELDS | {
    "run_id", "role", "attempt", "configured_identity", "wire_model",
    "resource_limits", "attempt_timeout_seconds", "execution_instance_id",
    "harness_protocol_version", "predecessor_attempt_id",
}
_NEXT = {
    None: {"attempt_prepared"},
    "attempt_prepared": {"dispatch_permitted"},
    "dispatch_permitted": {"sdk_call_boundary"},
    "sdk_call_boundary": {"sdk_return_observed", "sdk_exception_observed"},
    "sdk_return_observed": {"outcome_observed"},
    "sdk_exception_observed": {"outcome_observed"},
    "outcome_observed": set(),
}


def _require(value, message):
    if not value:
        raise IntegrityViolation("attempt lifecycle: " + message)


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def request_digest(request):
    # Deadline grants are enforcement, not request treatment. They are bounded
    # separately by the preparation record and existing invocation evidence.
    return digest_json({k: v for k, v in request.to_dict().items() if k != "attempt_timeout_seconds"})


def validate_prepared_binding(journal, request):
    snapshot = journal.inspect()
    _require(not snapshot["closed"] and len(snapshot["events"]) == 1, "attempt is not prepared")
    binding = snapshot["binding"]
    _require(binding["request_digest"] == request_digest(request)
             and binding["role"] == request.role
             and binding["configured_identity"] == request.configured_identity.to_dict()
             and binding["wire_model"] == request.configured_identity.model_id
             and binding["input_content_digest"] == request.input_content_digest
             and binding["request_parameter_digest"] == request.request_parameter_digest,
             "prepared request binding mismatch")


def validate_worker_binding(writer, request):
    events = writer.events()
    _require(events[0]["attempt_id"] == writer.attempt_id, "wrong attempt descriptor")
    _require(events[-1]["event"] == "dispatch_permitted", "missing or reused dispatch permission")
    binding = events[0]["data"]
    _require(binding["request_digest"] == request_digest(request)
             and binding["role"] == request.role
             and request.attempt_timeout_seconds == events[-1]["data"]["granted_timeout_seconds"], "request binding mismatch")


def summary(snapshot):
    return {key: snapshot[key] for key in (
        "schema", "attempt_id", "head_digest", "closure_digest", "closed", "retry_safety", "outcome_digest",
    )}


def journal_paths(run_dir):
    """Inventory the entire exclusive namespace, including empty/torn reserves."""
    root = run_dir / LIFECYCLE_ROOT
    if not root.exists() and not root.is_symlink():
        return []
    _require(root.is_dir() and not root.is_symlink(), "invalid lifecycle root")
    nodes = list(root.rglob("*"))
    _require(len(nodes) <= 12 and all(not p.is_symlink() for p in nodes), "invalid lifecycle namespace")
    paths = sorted(p for p in nodes if p.name == "journal.jsonl")
    expected = {p for path in paths for p in (path, path.with_name("closed.json"), path.parent, path.parent.parent)}
    _require(bool(paths) and set(nodes) == expected, "incomplete or unrecognized lifecycle namespace")
    return paths


def _read_fd(fd, limit):
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "journal must be an exclusive regular file")
    _require(0 < info.st_size <= limit, "invalid evidence size")
    data = os.pread(fd, limit + 1, 0)
    _require(len(data) == info.st_size, "evidence changed during read")
    return data


def _read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        return _read_fd(fd, limit)
    finally:
        os.close(fd)


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(root: Path) -> None:
    """Make existing authority durable before granting dispatch capability."""
    for path in sorted(root.rglob("*")):
        _require(not path.is_symlink(), "symlink in authority tree")
        if path.is_file():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
    for path in sorted((p for p in root.rglob("*") if p.is_dir()), reverse=True):
        sync_directory(path)
    sync_directory(root)
    sync_directory(root.parent)


def _write_all(fd: int, data: bytes) -> None:
    while data:
        count = os.write(fd, data)
        if count <= 0:
            raise OSError("lifecycle write made no progress")
        data = data[count:]
    os.fsync(fd)


def _validate_binding(binding):
    _require(type(binding) is dict and set(binding) == _BINDING_FIELDS, "invalid binding fields")
    for field in _DIGEST_FIELDS:
        _require(_digest(binding[field]), "invalid binding digest")
    safe_identifier(binding["run_id"], "run_id")
    safe_identifier(binding["role"], "role")
    _require(type(binding["attempt"]) is int and binding["attempt"] == 1, "retries are disabled")
    _require(type(binding["wire_model"]) is str and bool(binding["wire_model"]), "missing wire model")
    _require(type(binding["configured_identity"]) is dict, "invalid configured identity")
    _require(type(binding["resource_limits"]) is dict, "invalid budget")
    from .types import AdapterIdentity, ResourceLimits
    try:
        configured = binding["configured_identity"]
        identity = AdapterIdentity(**{k: v for k, v in configured.items() if k != "identity_key"})
        _require(identity.to_dict() == configured, "invalid configured identity fields")
        limits = ResourceLimits(**binding["resource_limits"])
        _require(limits.to_dict() == binding["resource_limits"], "invalid budget fields")
        _require(type(limits.max_stage_retries) is int and limits.max_stage_retries == 0, "retries are disabled")
    except (TypeError, ValueError) as exc:
        raise IntegrityViolation("attempt lifecycle: invalid identity or budget") from exc
    _require(binding["harness_protocol_version"] == LIFECYCLE_PROTOCOL, "invalid lifecycle protocol")
    _require(binding["predecessor_attempt_id"] is None, "retry predecessor forbidden")
    instance = binding["execution_instance_id"]
    _require(type(instance) is str and len(instance) == 32
             and all(c in "0123456789abcdef" for c in instance), "invalid execution instance")
    number = binding["attempt_timeout_seconds"]
    _require(type(number) in (int, float) and math.isfinite(number) and number > 0, "invalid timeout")


def _decode(data: bytes) -> list[dict]:
    _require(0 < len(data) <= MAX_JOURNAL_BYTES and data.endswith(b"\n"), "incomplete journal")
    try:
        frames = data.splitlines()
        _require(len(frames) <= 5 and all(len(line) <= MAX_FRAME_BYTES for line in frames), "frame bound exceeded")
        events = [json.loads(line) for line in frames]
        _require(all(canonical_json(event).encode() == line for event, line in zip(events, frames)), "noncanonical frame")
    except (ValueError, UnicodeError) as exc:
        raise IntegrityViolation("attempt lifecycle: malformed journal") from exc
    previous = None
    head = None
    attempt_id = None
    elapsed = -1
    for index, event in enumerate(events):
        _require(type(event) is dict and set(event) == {
            "schema", "attempt_id", "sequence", "previous_digest", "event", "data",
            "observed_at", "monotonic_ns", "digest",
        }, "invalid event fields")
        _require(event["schema"] == LIFECYCLE_SCHEMA, "unknown schema")
        _require(type(event["event"]) is str, "invalid event type")
        _require(type(event["sequence"]) is int and event["sequence"] == index, "invalid sequence")
        _require(event["previous_digest"] == head, "broken digest chain")
        body = {k: v for k, v in event.items() if k != "digest"}
        _require(event["digest"] == digest_json(body), "event digest mismatch")
        _require(event["event"] in _NEXT.get(previous, set()), "contradictory transition")
        try:
            parsed_time = datetime.fromisoformat(event["observed_at"])
            _require(parsed_time.tzinfo is not None, "timestamp lacks timezone")
        except (TypeError, ValueError) as exc:
            raise IntegrityViolation("attempt lifecycle: invalid timestamp") from exc
        tick = event["monotonic_ns"]
        _require(type(tick) is int and tick >= elapsed, "contradictory monotonic timing")
        elapsed = tick
        if index == 0:
            attempt_id = event["attempt_id"]
            _require(type(attempt_id) is str and len(attempt_id) == 32
                     and all(c in "0123456789abcdef" for c in attempt_id), "invalid attempt ID")
            _validate_binding(event["data"])
        _require(event["attempt_id"] == attempt_id, "attempt ID changed")
        payload = event["data"]
        _require(type(payload) is dict, "invalid event payload")
        if event["event"] == "dispatch_permitted":
            _require(set(payload) == {"granted_timeout_seconds"}, "invalid permission")
            grant = payload["granted_timeout_seconds"]
            _require(type(grant) in (int, float) and math.isfinite(grant)
                     and 0 < grant <= events[0]["data"]["attempt_timeout_seconds"], "invalid time grant")
        elif event["event"] == "sdk_call_boundary":
            _require(set(payload) == {"wire_request_digest"} and _digest(payload["wire_request_digest"]), "invalid wire digest")
        elif event["event"] == "outcome_observed":
            from .live_contract import parse_provider_call_outcome
            _require(set(payload) == {"outcome", "outcome_digest"}, "invalid outcome event")
            try:
                parse_provider_call_outcome(payload["outcome"])
            except Exception as exc:
                raise IntegrityViolation("attempt lifecycle: invalid normalized outcome") from exc
            _require(payload["outcome_digest"] == digest_json(payload["outcome"]), "outcome digest mismatch")
            _require(previous == "sdk_return_observed" or payload["outcome"]["kind"] != "success", "success after SDK exception")
        elif index and event["event"] != "sdk_call_boundary":
            _require(payload == {}, "unexpected event data")
        previous = event["event"]
        head = event["digest"]
    return events


class JournalWriter:
    """Single-writer append capability. The descriptor names no other artifact."""
    def __init__(self, fd: int, attempt_id: str):
        _require(type(fd) is int and fd >= 3 and stat.S_ISREG(os.fstat(fd).st_mode), "invalid journal descriptor")
        _require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_APPEND, "descriptor is not append-only")
        self.fd = fd
        self.attempt_id = attempt_id

    def events(self):
        return _decode(_read_fd(self.fd, MAX_JOURNAL_BYTES))

    def append(self, event: str, data: dict | None = None):
        events = self.events()
        _require(events[0]["attempt_id"] == self.attempt_id, "wrong attempt descriptor")
        last = events[-1]
        body = {
            "schema": LIFECYCLE_SCHEMA, "attempt_id": self.attempt_id,
            "sequence": len(events), "previous_digest": last["digest"],
            "event": event, "data": data or {},
            "observed_at": datetime.now(timezone.utc).isoformat(), "monotonic_ns": time.monotonic_ns(),
        }
        frame = {**body, "digest": digest_json(body)}
        encoded = (canonical_json(frame) + "\n").encode()
        existing = _read_fd(self.fd, MAX_JOURNAL_BYTES)
        _decode(existing + encoded)  # validate before writing, including size
        _write_all(self.fd, encoded)

    def outcome(self, outcome):
        payload = outcome.to_dict()
        self.append("outcome_observed", {"outcome": payload, "outcome_digest": digest_json(payload)})


class AttemptJournal:
    def __init__(self, path: Path):
        self.path = path
        self.permission_granted = False
        self._owner_pid = None
        self._file_identity = None
        self.persistence_failed = False
        self._prepared_digest = None
        self._closure_digest = None

    def _require_owner(self):
        _require(self._owner_pid == os.getpid(), "reconstructed attempt is inspection only")
        _require(not self.persistence_failed, "attempt persistence previously failed")
        info = self.path.lstat()
        _require((info.st_dev, info.st_ino) == self._file_identity, "attempt namespace replaced")

    @classmethod
    def create(cls, run_dir: Path, binding: dict):
        _validate_binding(binding)
        root = run_dir / LIFECYCLE_ROOT
        _require(not root.is_symlink(), "symlink lifecycle namespace")
        if (root / binding["role"]).exists():
            raise FileExistsError("attempt namespace already exists")
        existing_paths = journal_paths(run_dir) if root.exists() else []
        root.mkdir(exist_ok=True)
        attempt_id = uuid.uuid4().hex
        for existing in existing_paths:
            snapshot = AttemptJournal(existing).inspect(require_closed=True)
            _require(snapshot["attempt_id"] != attempt_id, "duplicate attempt ID")
        role_dir = root / binding["role"]
        role_dir.mkdir(exist_ok=False)
        parent = role_dir / "attempt-0001"
        parent.mkdir(exist_ok=False)
        path = parent / "journal.jsonl"
        body = {
            "schema": LIFECYCLE_SCHEMA, "attempt_id": attempt_id,
            "sequence": 0, "previous_digest": None, "event": "attempt_prepared",
            "data": json.loads(canonical_json(binding)),
            "observed_at": datetime.now(timezone.utc).isoformat(), "monotonic_ns": time.monotonic_ns(),
        }
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            _write_all(fd, (canonical_json({**body, "digest": digest_json(body)}) + "\n").encode())
        finally:
            os.close(fd)
        for directory in (parent, parent.parent, parent.parent.parent, run_dir):
            sync_directory(directory)
        journal = cls(path)
        journal._owner_pid = os.getpid()
        info = path.lstat()
        journal._file_identity = (info.st_dev, info.st_ino)
        journal._prepared_digest = digest_json(body)
        return journal

    def open_writer(self):
        self._require_owner()
        _require(not self.path.with_name("closed.json").exists(), "attempt is closed")
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        try:
            events = _decode(_read_fd(fd, MAX_JOURNAL_BYTES))
            _require(events[0]["digest"] == self._prepared_digest, "prepared authority changed")
            return JournalWriter(fd, events[0]["attempt_id"])
        except BaseException:
            os.close(fd)
            raise

    def permit(self, granted_timeout_seconds=None):
        writer = self.open_writer()
        try:
            if granted_timeout_seconds is None:
                granted_timeout_seconds = writer.events()[0]["data"]["attempt_timeout_seconds"]
            writer.append("dispatch_permitted", {"granted_timeout_seconds": granted_timeout_seconds})
            self.permission_granted = True
        except BaseException:
            self.persistence_failed = True
            raise
        finally:
            os.close(writer.fd)

    def close(self, reason: str, *, worker_reaped: bool):
        self._require_owner()
        events = _decode(_read_file(self.path, MAX_JOURNAL_BYTES))
        _require(events[0]["digest"] == self._prepared_digest, "prepared authority changed")
        _require(reason in {"not_started", "returned", "timeout", "infrastructure", "interrupted"}, "invalid closure")
        permitted = any(e["event"] == "dispatch_permitted" for e in events)
        _require((reason == "not_started") == (not permitted), "contradictory not-started closure")
        _require(worker_reaped is True, "worker quiescence not established")
        # A worker may have written a complete frame and failed its fsync.
        # Re-synchronize the validated disk prefix before authorizing closure.
        journal_fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(journal_fd)
        except BaseException:
            self.persistence_failed = True
            raise
        finally:
            os.close(journal_fd)
        payload = {"schema": LIFECYCLE_SCHEMA, "event": "closed_not_started" if not permitted else "attempt_closed",
                   "attempt_id": events[0]["attempt_id"],
                   "head_digest": events[-1]["digest"], "event_count": len(events),
                   "reason": reason, "worker_reaped": True,
                   "observed_at": datetime.now(timezone.utc).isoformat()}
        fd = os.open(self.path.with_name("closed.json"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            _write_all(fd, canonical_json(payload).encode())
            sync_directory(self.path.parent)
            self._closure_digest = digest_json(payload)
        except BaseException:
            self.persistence_failed = True
            raise
        finally:
            os.close(fd)

    def inspect(self, *, require_closed=False):
        _require(not self.persistence_failed, "attempt persistence previously failed")
        events = _decode(_read_file(self.path, MAX_JOURNAL_BYTES))
        if self._prepared_digest is not None:
            _require(events[0]["digest"] == self._prepared_digest, "prepared authority changed")
        closure_path = self.path.with_name("closed.json")
        closed = closure_path.exists()
        closure = None
        if closed:
            try:
                closure = json.loads(_read_file(closure_path, MAX_CLOSURE_BYTES))
            except (ValueError, UnicodeError) as exc:
                raise IntegrityViolation("attempt lifecycle: malformed closure") from exc
            _require(type(closure) is dict and set(closure) == {
                "schema", "event", "attempt_id", "head_digest", "event_count", "reason", "worker_reaped", "observed_at",
            }, "invalid closure fields")
            _require(closure["schema"] == LIFECYCLE_SCHEMA and closure["worker_reaped"] is True
                     and closure["attempt_id"] == events[0]["attempt_id"]
                     and closure["head_digest"] == events[-1]["digest"]
                     and type(closure["event_count"]) is int and closure["event_count"] == len(events), "closure binding mismatch")
            _require(closure["reason"] in {"not_started", "returned", "timeout", "infrastructure", "interrupted"}, "invalid closure reason")
            _require((closure["reason"] == "not_started") == (len(events) == 1), "contradictory closure")
            _require(closure["event"] == ("closed_not_started" if len(events) == 1 else "attempt_closed"), "invalid closure event")
            try:
                _require(datetime.fromisoformat(closure["observed_at"]).tzinfo is not None, "invalid closure timestamp")
            except (TypeError, ValueError) as exc:
                raise IntegrityViolation("attempt lifecycle: invalid closure timestamp") from exc
        if self._closure_digest is not None:
            _require(closed and digest_json(closure) == self._closure_digest, "committed closure changed")
        _require(not require_closed or closed, "attempt remains open")
        outcome = next((e["data"]["outcome"] for e in events if e["event"] == "outcome_observed"), None)
        safety = "indeterminate"
        if closed and closure["reason"] == "not_started":
            safety = "safe_not_dispatched"
        elif closed and outcome is not None and outcome["kind"] == "success":
            safety = "unsafe_response_observed"
        return {"schema": LIFECYCLE_SCHEMA, "attempt_id": events[0]["attempt_id"],
                "head_digest": events[-1]["digest"], "closure_digest": digest_json(closure) if closed else None,
                "binding": events[0]["data"], "events": events, "outcome": outcome,
                "outcome_digest": digest_json(outcome) if outcome is not None else None,
                "closure": closure,
                "closed": closed, "retry_safety": safety}
