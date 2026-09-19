"""Offline-testable control plane. All process/cgroup effects are injected ports.

No live host adapter or command-line execution entry point is supplied. A port
implementation must use bounded nonblocking IPC, pidfds when supported, and a
separate process watchdog; it must never execute the worker in this process.
"""

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from . import policy as p
from .observer import ObservationError, Sampler, Identity, METRICS, tripwires, validate_baseline


class ProtocolError(ValueError):
    pass


class HostPorts(Protocol):
    """Effect boundary requiring a separately authorized Acer integration.

    All methods return promptly. No method may wait on CUDA or a vendor query.
    configure_worker_cgroup must read back limits and exact single-PID membership.
    snapshot_identity must use /proc stat start ticks, namespace/executable inodes,
    cgroup inode and membership, plus independently observed target GPU identity.
    Signal operations must target a retained pidfd or revalidated start tuple.
    """

    def configure_worker_cgroup(self, identity, memory_max_bytes, swap_max_bytes): ...
    def snapshot_identity(self): ...
    def release(self): ...
    def request_cleanup(self): ...
    def terminate(self): ...
    def kill(self): ...
    def poll_exit(self): ...
    def reap(self): ...


def expected_worker_events(order):
    if order not in p.CREATE_ORDER:
        raise ProtocolError("unknown order")
    calls = (*p.MAPPING_ORDER, "cudaSetDevice", *p.CREATE_ORDER[order])
    items = [(kind, call) for call in calls for kind in ("CALL_START", "CALL_END")]
    items += [(kind, None) for kind in ("STARTUP_COMPLETE", "DWELL_COMPLETE", "CLEANUP_RELEASE")]
    items += [(kind, p.DESTROY_FOR[call]) for call in reversed(p.CREATE_ORDER[order])
              for kind in ("CALL_START", "CALL_END")]
    return items + [("CLEANUP_COMPLETE", None)]


def verify_libraries(manifest, mapped):
    """Manifest is independently acquired authority; mapped is process observation."""
    required = set(p.LIBRARY_FAMILIES)
    if set(manifest) != required or set(mapped) != required:
        raise ProtocolError("unadmitted/missing CUDA-family mapping")
    for name, expected in manifest.items():
        actual = mapped[name]
        # Each family must resolve to exactly one admitted file identity.
        if set(expected) != set(p.LIBRARY_ATTRIBUTES) or len(actual) != 1 or not strict_equal(actual[0], expected):
            raise ProtocolError("library mapping identity mismatch")


def strict_equal(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(strict_equal(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return a == b


def validate_identity_snapshot(identity, observed, received_ns):
    if type(observed) is not dict or set(observed) != {"identity", "observed_ns", "members"}:
        raise ObservationError("malformed identity snapshot")
    identity.match(observed["identity"])
    stamp = observed["observed_ns"]
    if (type(stamp) is not int or stamp < 0 or type(received_ns) is not int or
            not 0 <= received_ns - stamp <= p.IDENTITY_AGE_NS or
            not strict_equal(observed["members"], [identity.pid])):
        raise ObservationError("stale/changed identity or membership")


def validate_identity_gate(record, gate_ns):
    """The query receipt is the upper endpoint of observation freshness."""
    observed, received = record["observed_ns"], record["received_ns"]
    if (any(type(t) is not int or t < 0 for t in (observed, received, gate_ns)) or
            not 0 <= received - observed <= p.IDENTITY_AGE_NS or
            not 0 <= gate_ns - received <= p.IDENTITY_AGE_NS):
        raise ProtocolError("identity receipt stale or outside gate")


def bind_baseline(frames, samples, raw_records, gate_ns):
    """Bind supplied frames to accepted observations available at the live gate.

    Selection uses observation time (latest eligible sample at/before the frame),
    while receipt time proves that selection was available to the consumer.
    Equal observation times retain accepted journal order.
    """
    accepted = [r for r in raw_records if r["eligible"]]
    if not strict_equal([r["raw"] for r in accepted], samples):
        raise ProtocolError("accepted observations differ from raw journal")
    ordered = sorted(accepted, key=lambda r: r["raw"]["sample_end_monotonic_raw_ns"])
    latest, position = {}, 0
    for stamp, frame in frames:
        if type(stamp) is not int or not 0 <= stamp <= gate_ns:
            raise ProtocolError("baseline timestamp outside preparation gate")
        while position < len(ordered) and ordered[position]["raw"]["sample_end_monotonic_raw_ns"] <= stamp:
            record = ordered[position]
            latest[record["raw"]["stream"]] = record
            position += 1
        if set(latest) != set(p.STREAMS):
            raise ProtocolError("baseline observations unavailable")
        for record in latest.values():
            sample, receipt = record["raw"], record["received_ns"]
            end = sample["sample_end_monotonic_raw_ns"]
            if (sample["available"] is not True or sample["unavailable_reason"] is not None or
                    type(receipt) is not int or not end <= receipt <= gate_ns or
                    receipt - end > p.PRE_RELEASE_AGE_NS or
                    not 0 <= stamp - end <= p.PRE_RELEASE_AGE_NS):
                raise ProtocolError("baseline observation receipt unavailable, late or stale")
        if not strict_equal(frame, {k: r["raw"]["metrics"] for k, r in latest.items()}):
            raise ProtocolError("baseline not bound to raw observations")


def validate_successor_lifecycle(prior, boot_id, evidence, admitted_ns):
    """Only compare monotonic timestamps after establishing the same boot."""
    if prior["boot_id"] != boot_id or prior["verdict"] != "valid":
        raise ProtocolError("same-boot successor requires valid predecessor")
    events = prior["evidence"]["events"]
    stamps = {e["event_type"]: e["monotonic_raw_ns"] for e in events}
    if (not events or events[-1]["event_type"] != "ATTEMPT_COMPLETE" or
            "RESIDUAL_CLEAR" not in stamps or
            not stamps["RESIDUAL_CLEAR"] <= stamps["ATTEMPT_COMPLETE"]):
        raise ProtocolError("predecessor lacks residual clearance/completion")
    completed = stamps["ATTEMPT_COMPLETE"]
    points = [admitted_ns, evidence["sampler_started_ns"]]
    points.extend(frame[0] for frame in evidence["baseline_frames"])
    for journal in ("observation_raw", "identity_raw", "worker_raw", "mapping_records"):
        points.extend(r["received_ns"] for r in evidence.get(journal, []))
    points.extend(e["monotonic_raw_ns"] for e in evidence.get("events", []) if e["event_type"] == "RELEASE")
    if any(type(t) is not int or t < completed for t in points):
        raise ProtocolError("same-boot successor overlaps predecessor lifecycle")


def validate_proof(proof):
    if type(proof) is not dict or set(proof) != {*p.PRECONDITIONS, "library_stat_ns"}:
        raise ProtocolError("closed preparation proof required")
    if any(type(proof[k]) is not bool for k in p.PRECONDITIONS):
        raise ProtocolError("proof flags must be boolean")
    if type(proof["library_stat_ns"]) is not int or proof["library_stat_ns"] < 0:
        raise ProtocolError("library stat timestamp must be nonnegative integer")


class Controller:
    def __init__(self, run_id, trial_id, identity, order, ports, sampler, clock=p.raw_ns):
        self.run_id, self.trial_id, self.identity = run_id, trial_id, identity
        self.order, self.ports, self.sampler, self.clock = order, ports, sampler, clock
        self.expected = expected_worker_events(order)
        self.events, self.reasons = [], []
        self.state, self.position = "NEW", 0
        self.release_ns = self.active = self.mapping_start_ns = self.dwell_start_ns = None
        self.cleanup_deadline_ns = self.residual_deadline_ns = None
        self.cleanup_end_ns = None
        self.residual_times = []
        self.baseline = None
        self.last_ns = -1
        self.library_manifest = None
        p.token(run_id)
        p.token(trial_id)
        self.worker_raw, self.identity_raw, self.identity_records, self.mapping_records = [], [], [], []
        self.owned, self.destroy_attempts = [], []
        self.cleanup_started = False
        self.cleanup_complete = False
        self.campaign = None
        self.proof, self.limit_readback, self.frames = None, None, []

    def check_identity(self):
        try:
            observed = self.ports.snapshot_identity()
        except Exception as exc:
            self.identity_raw.append({"sequence": len(self.identity_raw) + 1,
                "received_ns": self.clock(), "raw": {"unavailable_reason": "QUERY_FAILED",
                "exception_type": type(exc).__name__}, "eligible": False, "rejection": "BACKEND_EXCEPTION"})
            raise ObservationError("identity query failed") from exc
        received = self.clock()
        try:
            raw = json.loads(json.dumps(observed, allow_nan=False))
        except (TypeError, ValueError):
            raw = {"unavailable_reason": "UNSERIALIZABLE", "raw_type": type(observed).__name__}
        entry = {"sequence": len(self.identity_raw) + 1, "received_ns": received,
                 "raw": raw, "eligible": False, "rejection": None}
        self.identity_raw.append(entry)
        try:
            validate_identity_snapshot(self.identity, observed, received)
        except Exception as exc:
            entry["rejection"] = type(exc).__name__ + ":" + str(exc)
            raise
        entry["eligible"] = True
        self.identity_records.append({**deepcopy(observed), "received_ns": received})
        return observed

    def event(self, kind, now=None, call=None, result=None, duration=None, reason=None):
        if self.state == "COMPLETED":
            raise ProtocolError("evidence already sealed")
        now = self.clock() if now is None else now
        if type(now) is not int or now < self.last_ns:
            raise ProtocolError("monotonic timestamp regression")
        self.last_ns = now
        item = {"schema_version": p.SCHEMA_VERSION, "run_id": self.run_id,
                "boot_id": self.identity.boot_id, "trial_id": self.trial_id,
                "sequence": len(self.events) + 1, "event_type": kind, "phase": self.state,
                "monotonic_raw_ns": now, "pid": self.identity.pid,
                "process_start_ticks": self.identity.process_start_ticks,
                "cgroup_path": self.identity.cgroup_path, "cgroup_inode": self.identity.cgroup_inode,
                "gpu_uuid": self.identity.gpu_uuid, "call_name": call,
                "raw_result": result, "duration_ns": duration, "failure_reason": reason}
        self.events.append(item)

    def prepare(self, frames, proof, library_manifest):
        if self.state != "NEW":
            raise ProtocolError("prepare once")
        if self.campaign is None or self.campaign.stopped or self.campaign.active is not self:
            raise ProtocolError("campaign slot must be owned before preparation")
        try:
            self._prepare(frames, proof, library_manifest)
        except Exception:
            self.abort("PREPARATION_GATE_FAILURE")
            raise

    def check_predecessor(self, frames):
        if self.slot["ordinal"] > 1:
            validate_successor_lifecycle(self.campaign.attempts[-1], self.identity.boot_id,
                {"sampler_started_ns": self.sampler.started_ns, "baseline_frames": frames,
                 "observation_raw": self.sampler.raw_records, "identity_raw": self.identity_raw,
                 "worker_raw": self.worker_raw, "mapping_records": self.mapping_records,
                 "events": self.events}, self.admitted_ns)

    def _prepare(self, frames, proof, library_manifest):
        now = self.clock()
        self.check_predecessor(frames)
        validate_proof(proof)
        self.proof = deepcopy(proof)
        self.frames = deepcopy(frames)
        bind_baseline(self.frames, self.sampler.records, self.sampler.raw_records, now)
        self.baseline = validate_baseline(self.frames)
        self.sampler.fresh(now)
        if not 0 <= now - frames[-1][0] <= p.PRE_RELEASE_AGE_NS:
            raise ProtocolError("stale baseline")
        required_true = p.PRECONDITIONS
        if any(proof.get(key) is not True for key in required_true):
            raise ProtocolError("precondition not independently established")
        if type(proof["library_stat_ns"]) is not int or not 0 <= now - proof["library_stat_ns"] <= p.LIBRARY_STAT_AGE_NS:
            raise ProtocolError("stale library stat")
        observed = self.check_identity()
        self.identity.match(observed["identity"])
        validate_identity_gate(self.identity_records[-1], self.clock())
        if observed["members"] != [self.identity.pid]:
            raise ProtocolError("worker cgroup membership mismatch")
        limits = self.ports.configure_worker_cgroup(
            self.identity, p.WORKER_MEMORY_MAX_BYTES, p.WORKER_SWAP_MAX_BYTES)
        if not strict_equal(limits, {"memory_max_bytes": p.WORKER_MEMORY_MAX_BYTES, "swap_max_bytes": 0,
                                    "members": [self.identity.pid]}):
            raise ProtocolError("cgroup limit readback mismatch")
        self.limit_readback = deepcopy(limits)
        verify_libraries(library_manifest, {k: [v] for k, v in library_manifest.items()})
        self.library_manifest = deepcopy(library_manifest)
        self.library_stat_ns = proof["library_stat_ns"]
        gate = self.clock()
        self.check_predecessor(self.frames)
        validate_identity_gate(self.identity_records[-1], gate)
        bind_baseline(self.frames, self.sampler.records, self.sampler.raw_records, gate)
        self.event("BOOT_BASELINE_VALID", gate)
        self.event("OBSERVER_ARMED")
        self.state = "READY"
        self.event("WORKER_READY")

    def release(self):
        if self.state != "READY":
            raise ProtocolError("worker not ready")
        try:
            if self.campaign is None or self.campaign.stopped or self.campaign.active is not self:
                raise ProtocolError("campaign release not admitted")
            self._release()
        except Exception:
            self.abort("RELEASE_GATE_FAILURE")
            raise

    def _release(self):
        self.check_predecessor(self.frames)
        now = self.clock()
        if not 0 <= now - self.custody["observed_ns"] <= p.IDENTITY_AGE_NS:
            raise ProtocolError("release custody expired")
        current = self.sampler.fresh(now)
        if not 0 <= now - self.library_stat_ns <= p.LIBRARY_STAT_AGE_NS:
            raise ProtocolError("library stat expired at release")
        observed = self.check_identity()
        self.identity.match(observed["identity"])
        now = self.clock()
        self.check_predecessor(self.frames)
        validate_identity_gate(self.identity_records[-1], now)
        if observed["members"] != [self.identity.pid]:
            raise ProtocolError("release membership changed")
        # Query latency must not age out the other release prerequisites.
        if not 0 <= now - self.custody["observed_ns"] <= p.IDENTITY_AGE_NS:
            raise ProtocolError("release custody expired")
        current = self.sampler.fresh(now)
        if not 0 <= now - self.library_stat_ns <= p.LIBRARY_STAT_AGE_NS:
            raise ProtocolError("library stat expired at release")
        if tripwires(current, self.baseline):
            raise ProtocolError("release reserve veto")
        self.state, self.release_ns = "RUNNING", now
        self.event("RELEASE", now)
        try:
            self.ports.release()
        except Exception:
            self.abort("RELEASE_FAILURE")
            raise

    def worker_event(self, record):
        entry = {"sequence": len(self.worker_raw) + 1, "received_ns": self.clock(),
                 "raw": deepcopy(record), "eligible": False, "rejection": None}
        self.worker_raw.append(entry)
        try:
            self._worker_event(record)
        except Exception as exc:
            entry["rejection"] = type(exc).__name__ + ":" + str(exc)
            self.abort("WORKER_RECORD_REJECTED")
            raise
        entry["eligible"] = True

    def _worker_event(self, record):
        if self.cleanup_complete:
            raise ProtocolError("worker record after cleanup completion")
        if self.state not in ("RUNNING", "COOPERATIVE", "TERM", "KILL"):
            raise ProtocolError("worker event outside running state")
        if set(record) != {"event_type", "call_name", "raw_result", "monotonic_raw_ns"}:
            raise ProtocolError("malformed worker record")
        kind, call = record["event_type"], record["call_name"]
        if kind != "CALL_END" and record["raw_result"] is not None:
            raise ProtocolError("non-result worker event has raw result")
        now = record["monotonic_raw_ns"]
        if (type(now) is not int or now < 0 or now < self.last_ns or
                not 0 <= self.clock() - now <= p.PRE_RELEASE_AGE_NS):
            self.abort("WORKER_TIME")
            raise ProtocolError("worker clock domain mismatch")
        failure = bool(self.reasons)
        if not failure and kind == "CLEANUP_RELEASE" and (self.position >= len(self.expected) or self.expected[self.position] != (kind, call)):
            self.abort("STARTUP_INTERRUPTED")
            failure = True
        if failure:
            # An already issued call may finish after cancellation. No new startup call.
            if self.active is not None and kind == "CALL_END" and call == self.active[0]:
                pass
            elif not self.cleanup_started and (kind, call) == ("CLEANUP_RELEASE", None):
                self.active = None  # An exception may prevent CALL_END; raw start remains.
            elif self.cleanup_started and self.active is None and self.owned and (kind, call) == ("CALL_START", p.DESTROY_FOR[self.owned[-1]]):
                pass
            elif self.cleanup_started and not self.owned and self.active is None and (kind, call) == ("CLEANUP_COMPLETE", None):
                pass
            else:
                raise ProtocolError("invalid failure cleanup suffix")
        elif self.position >= len(self.expected) or (kind, call) != self.expected[self.position]:
            self.abort("WORKER_ORDER")
            raise ProtocolError("unexpected worker event")
        duration = None
        if kind == "CALL_START":
            if call == "cudaSetDevice" and not getattr(self, "mapping_verified", False):
                raise ProtocolError("post-mapping proof missing before first call")
            if call == "cudaSetDevice" and not self.mapping_records[-1]["received_ns"] <= now <= self.mapping_records[-1]["observed_ns"] + p.IDENTITY_AGE_NS:
                raise ProtocolError("first call outside mapping proof freshness")
            self.active = (call, now)
            if call == p.MAPPING_ORDER[0]:
                self.mapping_start_ns = now
        elif kind == "CALL_END":
            if self.active is None or self.active[0] != call:
                self.abort("CALL_PAIR")
                raise ProtocolError("unpaired call")
            duration = now - self.active[1]
            self.active = None
            if type(record["raw_result"]) is not int:
                raise ProtocolError("noninteger raw result")
            if call in p.DESTROY_FOR and record["raw_result"] == 0:
                self.owned.append(call)
            if call in p.DESTROY_FOR.values():
                self.destroy_attempts.append(call)
                if self.owned and p.DESTROY_FOR[self.owned[-1]] == call:
                    self.owned.pop()
            if duration < 0 or duration > p.phase_timeout_ns(call):
                self.event(kind, now, call, record["raw_result"], duration)
                self.abort("PHASE_TIMEOUT")
                return
            if record["raw_result"] != 0 or type(record["raw_result"]) is not int:
                self.event(kind, now, call, record["raw_result"], duration)
                self.abort("CALL_FAILURE")
                return
            if call == p.MAPPING_ORDER[-1]:
                if now - self.mapping_start_ns > p.TIMEOUTS.mapping_total_ns:
                    self.abort("MAPPING_TIMEOUT")
                    return
                self.mapping_start_ns = None
        elif kind == "STARTUP_COMPLETE":
            self.dwell_start_ns = now
        elif kind == "DWELL_COMPLETE":
            if not p.DWELL_NS - p.DWELL_TOLERANCE_NS <= now - self.dwell_start_ns <= p.DWELL_NS + p.DWELL_TOLERANCE_NS:
                self.abort("DWELL_DURATION")
                return
            for stream in p.STREAMS:
                count = sum(s["stream"] == stream and self.dwell_start_ns <=
                            s["sample_end_monotonic_raw_ns"] <= now for s in self.sampler.records)
                if count < p.MIN_DWELL_SAMPLES:
                    self.abort("DWELL_COVERAGE")
                    return
            self.dwell_start_ns = None
        elif kind == "CLEANUP_RELEASE":
            self.cleanup_started = True
        elif kind == "CLEANUP_COMPLETE":
            if self.owned:
                raise ProtocolError("owned handles lack destruction results")
            self.cleanup_complete = True
            if not getattr(self, "terminal_mapping_verified", False):
                self.event(kind, now, call, record["raw_result"], duration)
                self.abort("TERMINAL_MAPPING_MISSING")
                return
            if not self.mapping_records[-1]["received_ns"] <= now <= self.mapping_records[-1]["observed_ns"] + p.IDENTITY_AGE_NS:
                raise ProtocolError("cleanup completion outside mapping proof freshness")
        self.event(kind, now, call, record["raw_result"], duration)
        if not failure:
            self.position += 1

    def abort(self, reason):
        if self.state == "COMPLETED":
            raise ProtocolError("completed attempt immutable")
        if self.campaign is not None:
            self.campaign.taint(reason)
        if reason not in self.reasons:
            self.reasons.append(reason)
        if self.state in ("COOPERATIVE", "TERM", "KILL", "RESIDUAL", "TAINTED", "DONE"):
            return
        self.state = "COOPERATIVE"
        now = self.clock()
        self.cleanup_deadline_ns = now + p.TIMEOUTS.cooperative_ns
        self.cleanup_end_ns = now + p.TIMEOUTS.cooperative_ns + p.TIMEOUTS.term_ns + p.TIMEOUTS.kill_ns
        self.event("ABORT", now, reason=reason)
        try:
            self.ports.request_cleanup()
        except Exception:
            self.reasons.append("COOPERATIVE_PORT_FAILURE")

    def tick(self):
        """Call at least every 100 ms; sample/watchdog breaches stop this boot."""
        now = self.clock()
        if self.state in ("NEW", "DONE", "COMPLETED", "TAINTED"):
            return
        try:
            self.sampler.tick(now)
            current = self.sampler.fresh(now, p.MAX_SAMPLE_GAP_NS)
            failures = tripwires(current, self.baseline, worker_alive=False)
            if failures:
                self.abort("/".join(failures))
            if self.state == "RUNNING" and current["worker_process"]["alive"]:
                self.check_identity()
                if current["worker_cgroup"]["pids"] != [self.identity.pid]:
                    raise ObservationError("membership changed")
                if self.dwell_start_ns is not None and not current["gpu_process"]["present"]:
                    raise ObservationError("GPU process binding missing during dwell")
        except Exception:
            self.abort("OBSERVER_FAILURE")
        if self.state == "RUNNING":
            if now - self.release_ns > p.TIMEOUTS.worker_ns:
                self.abort("WORKER_TIMEOUT")
            elif self.active and now - self.active[1] > p.phase_timeout_ns(self.active[0]):
                self.abort("PHASE_TIMEOUT")
            elif self.mapping_start_ns is not None and now - self.mapping_start_ns > p.TIMEOUTS.mapping_total_ns:
                self.abort("MAPPING_TIMEOUT")
            elif self.dwell_start_ns is not None and now - self.dwell_start_ns > p.DWELL_MAX_NS:
                self.abort("DWELL_TIMEOUT")
        if self.state in ("RUNNING", "COOPERATIVE", "TERM", "KILL"):
            try:
                status = self.ports.poll_exit()
                if status is not None:
                    if type(status) is not int:
                        raise ProtocolError("noninteger exit status")
                    if status != 0 or self.position != len(self.expected):
                        self.abort("WORKER_EXIT_FAILURE")
                    self.ports.reap()
                    self.event("PROCESS_REAPED")
                    self.state = "RESIDUAL"
                    self.residual_deadline_ns = (self.cleanup_end_ns if self.cleanup_end_ns is not None
                                                 else now + 15 * p.SECOND_NS)
                elif self.state == "RUNNING" and not self.sampler.latest.get("worker_process", {}).get("metrics", {}).get("alive", False):
                    self.abort("WORKER_LOST")
            except Exception:
                self.abort("PROCESS_PORT_FAILURE")
        if self.state in ("COOPERATIVE", "TERM", "KILL") and now >= self.cleanup_deadline_ns:
            if self.state == "KILL" or now >= self.cleanup_end_ns:
                self.state = "TAINTED"
                self.reasons.append("CLEANUP_TIMEOUT")
            else:
                self.state = "TERM" if self.state == "COOPERATIVE" else "KILL"
                self.cleanup_deadline_ns += (p.TIMEOUTS.term_ns if self.state == "TERM" else p.TIMEOUTS.kill_ns)
                self.event("ESCALATION")
                try:
                    (self.ports.terminate if self.state == "TERM" else self.ports.kill)()
                except Exception:
                    self.reasons.append("SIGNAL_PORT_FAILURE")
        if self.state == "RESIDUAL":
            if now >= self.residual_deadline_ns:
                self.state = "TAINTED"
                self.reasons.append("RESIDUAL_TIMEOUT")
                return
            try:
                current = self.sampler.fresh(now, p.PRE_RELEASE_AGE_NS)
                clear = (not current["worker_cgroup"]["populated"] and
                         current["worker_cgroup"]["pids"] == [] and
                         not current["worker_process"]["alive"] and
                         not current["gpu_process"]["present"] and
                         current["gpu_process"]["used_bytes"] == 0)
                stamp = min(s["sample_end_monotonic_raw_ns"] for s in self.sampler.latest.values())
                if not clear:
                    self.residual_times.clear()
                elif not self.residual_times or stamp > self.residual_times[-1]:
                    self.residual_times.append(stamp)
                if len(self.residual_times) >= p.RESIDUAL_CLEAR_SAMPLES and self.residual_times[-1] - self.residual_times[0] >= p.RESIDUAL_CLEAR_NS:
                    self.event("RESIDUAL_CLEAR")
                    self.state = "DONE"
            except ObservationError:
                self.residual_times.clear()

    def verify_mapping(self, mapped, observed_ns=None, *, terminal=False):
        try:
            now = self.clock()
            if type(terminal) is not bool or type(observed_ns) is not int or observed_ns < 0 or not 0 <= now - observed_ns <= p.IDENTITY_AGE_NS:
                raise ProtocolError("mapping observation timestamp missing/stale")
            if self.state not in ("RUNNING", "COOPERATIVE", "TERM", "KILL") or self.active is not None:
                raise ProtocolError("mapping outside live barrier")
            if terminal:
                if not self.cleanup_started or self.owned or getattr(self, "terminal_mapping_verified", False):
                    raise ProtocolError("premature/duplicate terminal mapping proof")
            elif self.position != 2 * len(p.MAPPING_ORDER) or self.reasons or getattr(self, "mapping_verified", False):
                raise ProtocolError("premature/duplicate post-mapping proof")
            lower = self.events[-1]["monotonic_raw_ns"]
            if observed_ns < lower:
                raise ProtocolError("mapping observation predates lifecycle checkpoint")
            self.check_identity()
            verify_libraries(self.library_manifest, mapped)
            received = self.clock()
            if not 0 <= received - observed_ns <= p.IDENTITY_AGE_NS:
                raise ProtocolError("mapping receipt stale")
        except Exception:
            self.abort("LIBRARY_IDENTITY")
            raise
        self.mapping_records.append({"stage": "terminal" if terminal else "post_mapping",
                                     "observed_ns": observed_ns, "received_ns": received, "mapped": deepcopy(mapped)})
        if terminal:
            self.terminal_mapping_verified = True
        else:
            self.mapping_verified = True
        return True

    def seal(self, manifest, trial, report):
        raise ProtocolError("per-attempt sealing removed; use complete_attempt then Campaign.seal")

    def complete_attempt(self):
        """Freeze an attempt, including failed evidence. Never seals a campaign."""
        if self.state not in ("DONE", "TAINTED"):
            raise ProtocolError("cannot seal a nonterminal trial")
        was_valid = self.valid
        self.event("ATTEMPT_COMPLETE")
        evidence = {"events": deepcopy(self.events), "samples": deepcopy(self.sampler.records),
            "worker_raw": deepcopy(self.worker_raw), "observation_raw": deepcopy(self.sampler.raw_records),
            "identity_raw": deepcopy(self.identity_raw),
            "identity_records": deepcopy(self.identity_records), "mapping_records": deepcopy(self.mapping_records),
            "proof": deepcopy(self.proof), "limit_readback": deepcopy(self.limit_readback),
            "baseline_frames": json.loads(json.dumps(self.frames)), "sampler_started_ns": self.sampler.started_ns,
            "observer_identity": asdict(self.sampler.observer_identity), "library_manifest": deepcopy(self.library_manifest)}
        trial = {"schema_version": p.SCHEMA_VERSION, "run_id": self.run_id, "trial_id": self.trial_id,
            "boot_id": self.identity.boot_id, "identity_binding": asdict(self.identity),
            "handle_order": self.order, "mapping_order": list(p.MAPPING_ORDER),
            "boot": self.slot["boot"], "ordinal": self.slot["ordinal"], "state": self.slot["state"],
            "custody": deepcopy(self.custody), "admitted_ns": self.admitted_ns, "evidence": evidence,
            "verdict": "valid" if was_valid else "aborted", "reason_codes": list(self.reasons),
            "replay_validation_error": None}
        trial.update(reconstruct(trial))
        try:
            validate_attempt(trial)
            if was_valid:
                self.check_predecessor(self.frames)
        except (ProtocolError, ObservationError, KeyError, TypeError, ValueError) as exc:
            # The failed cross-check remains evidence, never an accepted replay.
            reason = "REPLAY_VALIDATION_FAILURE"
            self.abort(reason)
            trial["verdict"] = "invalid"
            trial["reason_codes"] = list(self.reasons)
            trial["replay_validation_error"] = {"exception_type": type(exc).__name__, "message": str(exc)}
            was_valid = False
        self.state = "COMPLETED"
        self.completed_valid = was_valid
        self.campaign.finish(self, trial)
        return deepcopy(trial)

    @property
    def valid(self):
        return (self.state in ("DONE", "COMPLETED") and not self.reasons and
                self.position == len(self.expected) and getattr(self, "mapping_verified", False) and
                getattr(self, "terminal_mapping_verified", False))


@lru_cache(maxsize=1)
def _schema():
    return json.loads(Path(__file__).with_name("schema-v1.json").read_text())


def validate_record(kind, record, schema=None):
    """Strict stdlib validator for exactly the JSON Schema vocabulary in v1.

    Reject unsupported schema keywords; do not silently skip validation. The
    JSON file is also a Draft 2020-12 schema consumable by external validators.
    """
    if schema is None:
        schema = _schema()
    if kind not in ("manifest", "event", "sample", "trial", "campaign_seal"):
        raise ProtocolError("unknown evidence kind")

    def check(value, node, path):
        supported = {"$ref", "type", "const", "enum", "minimum", "minLength", "pattern",
                     "required", "properties", "additionalProperties", "items", "minItems",
                     "oneOf", "description"}
        if set(node) - supported:
            raise ProtocolError("unsupported schema vocabulary")
        if "$ref" in node:
            name = node["$ref"].removeprefix("#/$defs/")
            if name == node["$ref"] or name not in schema["$defs"]:
                raise ProtocolError("external/unknown schema reference")
            check(value, schema["$defs"][name], path)
        if "oneOf" in node:
            matches = 0
            for alternative in node["oneOf"]:
                try:
                    check(value, alternative, path)
                    matches += 1
                except ProtocolError:
                    pass
            if matches != 1:
                raise ProtocolError(path + ": oneOf")
        types = {"object": lambda v: type(v) is dict, "array": lambda v: type(v) is list,
                 "string": lambda v: type(v) is str, "integer": lambda v: type(v) is int,
                 "boolean": lambda v: type(v) is bool, "null": lambda v: v is None}
        if "type" in node and not types[node["type"]](value):
            raise ProtocolError(path + ": type")
        if "const" in node and not strict_equal(value, node["const"]):
            raise ProtocolError(path + ": const")
        if "enum" in node and not any(strict_equal(value, option) for option in node["enum"]):
            raise ProtocolError(path + ": enum")
        if "minimum" in node and value < node["minimum"]:
            raise ProtocolError(path + ": minimum")
        if "minLength" in node and len(value) < node["minLength"]:
            raise ProtocolError(path + ": minLength")
        if "pattern" in node:
            import re
            if re.search(node["pattern"], value) is None or (node["pattern"].endswith("$") and re.fullmatch(node["pattern"], value) is None):
                raise ProtocolError(path + ": pattern")
        if type(value) is dict:
            if set(node.get("required", ())) - set(value):
                raise ProtocolError(path + ": required")
            properties = node.get("properties", {})
            for key, item in value.items():
                definition = properties.get(key, node.get("additionalProperties", True))
                if definition is False:
                    raise ProtocolError(path + ": extra field " + key)
                if type(definition) is dict:
                    check(item, definition, path + "." + key)
        if type(value) is list:
            if len(value) < node.get("minItems", 0):
                raise ProtocolError(path + ": minItems")
            for item in value:
                check(item, node.get("items", {}), path + "[]")

    check(record, schema["$defs"][kind], kind)
    if kind == "manifest" and not any(strict_equal(record["matrix"], list(p.trial_matrix(v))) for v in (False, True)):
        raise ProtocolError("matrix differs from frozen 4/12 or 6/18 design")
    if kind == "manifest" and len(record["matrix"]) == 18 and not record["expansion_authorization_reference"]:
        raise ProtocolError("expanded matrix lacks separate authorization")


COUNTERS = ("low", "high", "max", "oom", "oom_kill")
SUMMARY_METRICS = (
    *("worker_cgroup." + k for k in ("memory_current_bytes", "memory_peak_bytes",
       "memory_swap_current_bytes", "memory_max_bytes", "swap_max_bytes")),
    *("worker_cgroup." + group + "." + k for group in ("memory_events", "memory_events_local") for k in COUNTERS),
    *("gpu_device." + k for k in ("total_bytes", "free_bytes", "used_bytes")),
    "gpu_process.used_bytes",
    *("machine_reserve." + k for k in METRICS["machine_reserve"]),
    "observer_cgroup.memory_current_bytes", "observer_cgroup.query_latency_ns")
UNAVAILABLE = {"available": False, "reason": "NOT_OBSERVED"}


def measurement(value):
    return deepcopy(UNAVAILABLE) if value is None else {"available": True, "value": value}


def metric(bundle, key):
    value = bundle
    for part in key.split("."):
        if type(value) is not dict or part not in value:
            return None
        value = value[part]
    return value if type(value) is int else None


def sample_frames(samples):
    latest, frames = {}, []
    for sample in sorted(samples, key=lambda s: (s["sample_end_monotonic_raw_ns"], s["stream"])):
        latest[sample["stream"]] = sample
        now = sample["sample_end_monotonic_raw_ns"]
        if set(latest) == set(p.STREAMS) and all(0 <= now - s["sample_end_monotonic_raw_ns"] <= p.MAX_SAMPLE_GAP_NS for s in latest.values()):
            frames.append((now, {k: s["metrics"] for k, s in latest.items()}))
    return frames


def reconstruct(trial):
    """Compute every summary from retained raw evidence, including explicit gaps."""
    ev = trial["evidence"]
    events, samples = ev["events"], ev["samples"]
    calls = [e for e in events if e["event_type"] == "CALL_END"]
    starts = {}
    durations = {}
    for event in events:
        key = event["call_name"]
        if event["event_type"] == "CALL_START":
            starts[key] = event["monotonic_raw_ns"]
        elif event["event_type"] == "CALL_END" and key in starts:
            durations[key] = event["monotonic_raw_ns"] - starts.pop(key)
    stamps = {e["event_type"]: e["monotonic_raw_ns"] for e in events}
    if "STARTUP_COMPLETE" in stamps and "DWELL_COMPLETE" in stamps:
        durations["dwell"] = stamps["DWELL_COMPLETE"] - stamps["STARTUP_COMPLETE"]
    first_mapping = next((e["monotonic_raw_ns"] for e in events if e["event_type"] == "CALL_START"), None)
    startup = stamps["STARTUP_COMPLETE"] - first_mapping if first_mapping is not None and "STARTUP_COMPLETE" in stamps else None
    baseline = ev["baseline_frames"][-1][1] if ev["baseline_frames"] else {}
    frames = sample_frames(samples)
    active = [m for t, m in frames if stamps.get("RELEASE", 1 << 100) <= t <= stamps.get("PROCESS_REAPED", stamps.get("ATTEMPT_COMPLETE", 0))]
    peaks, deltas, bases, minima = {}, {}, {}, {}
    for key in SUMMARY_METRICS:
        base = metric(baseline, key)
        values = [metric(m, key) for m in active]
        values = [v for v in values if v is not None]
        peak = max(values) if values else None
        bases[key], peaks[key] = measurement(base), measurement(peak)
        deltas[key] = measurement(peak - base if peak is not None and base is not None else None)
        minima[key] = measurement(min(values) if values else None)
    failures = set()
    for _, frame in frames:
        if baseline:
            failures.update(tripwires(frame, baseline, worker_alive=False))
    tripwire_results = {k: ("FAIL" if k in failures else "PASS" if active else "UNKNOWN") for k in p.TRIPWIRES}
    proof = ev["proof"] or {}
    preconditions = {k: ({"available": True, "passed": proof[k]} if type(proof.get(k)) is bool else deepcopy(UNAVAILABLE)) for k in p.PRECONDITIONS}
    create_successes = [e["call_name"] for e in calls if e["call_name"] in p.DESTROY_FOR and e["raw_result"] == 0]
    destroys = [(e["call_name"], e["raw_result"]) for e in calls if e["call_name"] in p.DESTROY_FOR.values()]
    cleanup = ("PASS" if "CLEANUP_COMPLETE" in stamps and destroys == [(p.DESTROY_FOR[c], 0) for c in reversed(create_successes)]
               else "FAIL" if any(result != 0 for _, result in destroys) else "UNKNOWN")
    return {"call_results": [{"call_name": e["call_name"], "raw_result": e["raw_result"]} for e in calls],
            "startup_duration_ns": measurement(startup),
            "phase_durations_ns": {k: measurement(durations.get(k)) for k in p.PHASES},
            "baseline_metrics": bases, "peak_metrics": peaks, "delta_metrics": deltas, "minimum_metrics": minima,
            "maximum_sample_gap_ns": measurement(max((s["previous_gap_ns"] for s in samples), default=None)),
            "preconditions": preconditions, "tripwire_results": tripwire_results,
            "cleanup_result": cleanup, "residual_result": "PASS" if "RESIDUAL_CLEAR" in stamps else "UNKNOWN",
            "events_first_sequence": events[0]["sequence"] if events else 0,
            "events_last_sequence": events[-1]["sequence"] if events else 0,
            "samples_first_sequence": min((s["sequence"] for s in samples), default=0),
            "samples_last_sequence": max((s["sequence"] for s in samples), default=0)}


def validate_attempt(trial):
    validate_record("trial", trial)
    if trial["replay_validation_error"] is not None:
        raise ProtocolError("retained replay validation failure: " + trial["replay_validation_error"]["message"])
    for key, value in reconstruct(trial).items():
        if not strict_equal(trial[key], value):
            raise ProtocolError("summary differs from raw evidence: " + key)
    ev, ident = trial["evidence"], trial["identity_binding"]
    events, samples = ev["events"], ev["samples"]
    if not events or events[-1]["event_type"] != "ATTEMPT_COMPLETE":
        raise ProtocolError("attempt lacks completion record")
    if [e["sequence"] for e in events] != list(range(1, len(events) + 1)):
        raise ProtocolError("event sequence discontinuity")
    if any(a["monotonic_raw_ns"] > b["monotonic_raw_ns"] for a, b in zip(events, events[1:])):
        raise ProtocolError("event clock regression")
    for event in events:
        validate_record("event", event)
        if any(event[k] != trial[k] for k in ("run_id", "trial_id", "boot_id")) or any(not strict_equal(event[k], ident[k]) for k in
                ("pid", "process_start_ticks", "cgroup_path", "cgroup_inode", "gpu_uuid")):
            raise ProtocolError("event attribution")
    completed = events[-1]["monotonic_raw_ns"]
    for journal in (ev["worker_raw"], ev["observation_raw"], ev["identity_raw"]):
        if [r["sequence"] for r in journal] != list(range(1, len(journal) + 1)):
            raise ProtocolError("raw journal sequence")
        receipts = [r["received_ns"] for r in journal]
        if any(t > completed for t in receipts) or any(a > b for a, b in zip(receipts, receipts[1:])):
            raise ProtocolError("raw receipt chronology")
        if any((r["eligible"] and r["rejection"] is not None) or (not r["eligible"] and not r["rejection"]) for r in journal):
            raise ProtocolError("raw eligibility/rejection contradiction")
    snapshots = []
    for record in ev["identity_raw"]:
        if record["eligible"]:
            try:
                validate_identity_snapshot(Identity(**ident), record["raw"], record["received_ns"])
            except ObservationError as exc:
                raise ProtocolError("invalid eligible identity observation") from exc
            snapshots.append({**record["raw"], "received_ns": record["received_ns"]})
    if not strict_equal(snapshots, ev["identity_records"]):
        raise ProtocolError("identity snapshots differ from raw journal")
    worker_kinds = {"CALL_START", "CALL_END", "STARTUP_COMPLETE", "DWELL_COMPLETE", "CLEANUP_RELEASE", "CLEANUP_COMPLETE"}
    retained = [{"event_type": e["event_type"], "call_name": e["call_name"], "raw_result": e["raw_result"],
                 "monotonic_raw_ns": e["monotonic_raw_ns"]} for e in events if e["event_type"] in worker_kinds]
    raw_worker = [r["raw"] for r in ev["worker_raw"] if r["eligible"]]
    # A failed duration/dwell record may be raw-only, but no canonical record may be invented.
    remaining = list(raw_worker)
    for record in retained:
        index = next((i for i, raw in enumerate(remaining) if strict_equal(raw, record)), None)
        if index is None:
            raise ProtocolError("canonical worker event absent from raw journal")
        remaining = remaining[index + 1:]
    raw_samples = [r["raw"] for r in ev["observation_raw"] if r["eligible"]]
    if not strict_equal(raw_samples, samples):
        raise ProtocolError("accepted observations differ from raw journal")
    for sample in samples:
        validate_record("sample", sample)
        if not strict_equal(sample["worker_identity"], ident) or any(sample[k] != trial[k] for k in ("run_id", "trial_id", "boot_id")):
            raise ProtocolError("sample attribution")
    for record in ev["worker_raw"]:
        if not record["eligible"]:
            continue
        raw = record["raw"]
        if type(raw) is not dict or set(raw) != {"event_type", "call_name", "raw_result", "monotonic_raw_ns"}:
            raise ProtocolError("malformed eligible worker record")
        stamp = raw["monotonic_raw_ns"]
        if type(stamp) is not int or stamp < 0 or not 0 <= record["received_ns"] - stamp <= p.PRE_RELEASE_AGE_NS:
            raise ProtocolError("worker receipt timing impossible or stale")
    replay = Sampler(None, Identity(**ident), Identity(**ev["observer_identity"]), trial["run_id"], trial["trial_id"], lambda: ev["sampler_started_ns"])
    for record in ev["observation_raw"]:
        try:
            replay.accept(record["raw"], record["received_ns"])
        except (ObservationError, KeyError, TypeError, ValueError):
            if record["eligible"]:
                raise ProtocolError("invalid eligible observer evidence")
        else:
            if not record["eligible"]:
                raise ProtocolError("observer eligibility differs from replay")
    if trial["verdict"] != "valid":
        if not trial["reason_codes"]:
            raise ProtocolError("unsuccessful attempt without reason")
        return
    if trial["reason_codes"] or any(not r["eligible"] for r in ev["worker_raw"] + ev["observation_raw"] + ev["identity_raw"]):
        raise ProtocolError("valid attempt with rejected evidence")
    if not strict_equal(retained, raw_worker):
        raise ProtocolError("valid worker raw/canonical correspondence")
    if any(e["raw_result"] is not None for e in events if e["event_type"] != "CALL_END"):
        raise ProtocolError("non-result event has raw result")
    if [e["event_type"] for e in events if e["event_type"] in p.BARRIERS] != list(p.BARRIERS[:-1]):
        raise ProtocolError("valid attempt missing barriers")
    if any(e["event_type"] in ("ABORT", "ESCALATION", "EVIDENCE_SEALED") for e in events):
        raise ProtocolError("failure/seal inside valid attempt")
    if [(e["event_type"], e["call_name"]) for e in events if e["event_type"] in worker_kinds] != expected_worker_events(trial["handle_order"]):
        raise ProtocolError("worker protocol order")
    if any(e["raw_result"] != 0 for e in events if e["event_type"] == "CALL_END"):
        raise ProtocolError("valid attempt with vendor failure")
    if any(v != {"available": True, "passed": True} for v in trial["preconditions"].values()):
        raise ProtocolError("missing/failed preconditions")
    for key in ("phase_durations_ns", "baseline_metrics", "peak_metrics", "delta_metrics", "minimum_metrics"):
        if any(not value["available"] for value in trial[key].values()):
            raise ProtocolError("missing summary measurement")
    if not trial["startup_duration_ns"]["available"] or not trial["maximum_sample_gap_ns"]["available"]:
        raise ProtocolError("missing duration/gap")
    if trial["cleanup_result"] != "PASS" or trial["residual_result"] != "PASS" or any(v != "PASS" for v in trial["tripwire_results"].values()):
        raise ProtocolError("failed safety/cleanup result")
    if not strict_equal(ev["limit_readback"], {"memory_max_bytes": p.WORKER_MEMORY_MAX_BYTES, "swap_max_bytes": 0, "members": [ident["pid"]]}):
        raise ProtocolError("missing effective limit readback")
    verify_libraries(ev["library_manifest"], {k: [v] for k, v in ev["library_manifest"].items()})
    preparation_stamp = next(e["monotonic_raw_ns"] for e in events if e["event_type"] == "BOOT_BASELINE_VALID")
    bind_baseline(ev["baseline_frames"], samples, ev["observation_raw"], preparation_stamp)
    baseline = validate_baseline(ev["baseline_frames"])
    release_stamp = next(e["monotonic_raw_ns"] for e in events if e["event_type"] == "RELEASE")
    validate_proof(ev["proof"])
    if (not 0 <= release_stamp - trial["custody"]["observed_ns"] <= p.IDENTITY_AGE_NS or
            not trial["custody"]["observed_ns"] <= trial["admitted_ns"] <= release_stamp):
        raise ProtocolError("custody stale at release")
    stamps = {e["event_type"]: e["monotonic_raw_ns"] for e in events}
    # Evidence must have reached the controller before the gate that uses it.
    dwell_receipt = next(r["received_ns"] for r in ev["worker_raw"] if r["raw"]["event_type"] == "DWELL_COMPLETE")
    for stream in p.STREAMS:
        received = [r for r in ev["observation_raw"] if r["raw"]["stream"] == stream]
        for barrier in ("RELEASE", "RESIDUAL_CLEAR"):
            point = stamps[barrier]
            if not any(r["received_ns"] <= point and 0 <= point - r["raw"]["sample_end_monotonic_raw_ns"] <= p.PRE_RELEASE_AGE_NS for r in received):
                raise ProtocolError("sample receipt unavailable at " + barrier.lower())
        if sum(r["received_ns"] <= dwell_receipt and stamps["STARTUP_COMPLETE"] <= r["raw"]["sample_end_monotonic_raw_ns"] <= stamps["DWELL_COMPLETE"] for r in received) < p.MIN_DWELL_SAMPLES:
            raise ProtocolError("dwell samples received too late")
    if not trial["admitted_ns"] <= stamps["WORKER_READY"]:
        raise ProtocolError("preparation predates admission")
    if any(r["received_ns"] < trial["admitted_ns"] for r in ev["identity_raw"]):
        raise ProtocolError("identity observation predates admission")
    if any(r["received_ns"] < stamps["RELEASE"] or r["received_ns"] > stamps["PROCESS_REAPED"] for r in ev["worker_raw"]):
        raise ProtocolError("worker receipt outside live lifecycle")
    if not 0 <= stamps["RELEASE"] - ev["baseline_frames"][-1][0] <= p.PRE_RELEASE_AGE_NS:
        raise ProtocolError("baseline stale at release")
    if not 0 <= stamps["RELEASE"] - ev["proof"]["library_stat_ns"] <= p.LIBRARY_STAT_AGE_NS:
        raise ProtocolError("library stat stale")
    calls = [e for e in events if e["event_type"] == "CALL_END"]
    for event in calls:
        duration = trial["phase_durations_ns"][event["call_name"]]["value"]
        if event["duration_ns"] != duration or not 0 <= duration <= p.phase_timeout_ns(event["call_name"]):
            raise ProtocolError("phase duration mismatch/timeout")
    mapping_start = next(e["monotonic_raw_ns"] for e in events if e["event_type"] == "CALL_START")
    mapping_end = next(e["monotonic_raw_ns"] for e in calls if e["call_name"] == p.MAPPING_ORDER[-1])
    first_call = next(e["monotonic_raw_ns"] for e in events if e["event_type"] == "CALL_START" and e["call_name"] == "cudaSetDevice")
    if mapping_end - mapping_start > p.TIMEOUTS.mapping_total_ns or stamps["PROCESS_REAPED"] - stamps["RELEASE"] > p.TIMEOUTS.worker_ns:
        raise ProtocolError("mapping/worker timeout")
    if not p.DWELL_NS - p.DWELL_TOLERANCE_NS <= trial["phase_durations_ns"]["dwell"]["value"] <= p.DWELL_NS + p.DWELL_TOLERANCE_NS:
        raise ProtocolError("dwell duration")
    if [r["stage"] for r in ev["mapping_records"]] != ["post_mapping", "terminal"]:
        raise ProtocolError("mapping checkpoint evidence")
    last_destroy = max(e["monotonic_raw_ns"] for e in calls if e["call_name"] in p.DESTROY_FOR.values())
    for record, low, high in zip(ev["mapping_records"], (mapping_end, last_destroy), (first_call, stamps["CLEANUP_COMPLETE"])):
        if not low <= record["observed_ns"] <= record["received_ns"] <= high or high - record["observed_ns"] > p.IDENTITY_AGE_NS:
            raise ProtocolError("mapping checkpoint misplaced/stale")
        verify_libraries(ev["library_manifest"], record["mapped"])
    for point in (stamps["BOOT_BASELINE_VALID"], stamps["WORKER_READY"], stamps["RELEASE"]):
        candidates = [r for r in ev["identity_records"] if r["received_ns"] <= point]
        if not candidates:
            raise ProtocolError("missing fresh identity checkpoint")
        validate_identity_gate(candidates[-1], point)
    for point in (r["received_ns"] for r in ev["mapping_records"]):
        if not any(r["received_ns"] <= point and 0 <= point - r["observed_ns"] <= p.IDENTITY_AGE_NS for r in ev["identity_records"]):
            raise ProtocolError("missing fresh identity checkpoint")
    for stream in p.STREAMS:
        records = [s for s in samples if s["stream"] == stream]
        times = [s["sample_end_monotonic_raw_ns"] for s in records]
        if not any(0 <= stamps["RELEASE"] - t <= p.PRE_RELEASE_AGE_NS for t in times):
            raise ProtocolError("release sample freshness")
        if sum(stamps["STARTUP_COMPLETE"] <= t <= stamps["DWELL_COMPLETE"] for t in times) < p.MIN_DWELL_SAMPLES:
            raise ProtocolError("dwell sample coverage")
        if stream == "gpu_process" and any(not s["metrics"]["present"] for s in records
                if stamps["STARTUP_COMPLETE"] <= s["sample_end_monotonic_raw_ns"] <= stamps["DWELL_COMPLETE"]):
            raise ProtocolError("GPU worker attribution absent during dwell")
        if not any(0 <= stamps["RESIDUAL_CLEAR"] - t <= p.PRE_RELEASE_AGE_NS for t in times):
            raise ProtocolError("residual sample freshness")
    for stamp, frame in sample_frames(samples):
        if stamps["RELEASE"] <= stamp < stamps["CLEANUP_COMPLETE"]:
            if not frame["worker_process"]["alive"] or frame["worker_cgroup"]["pids"] != [ident["pid"]]:
                raise ProtocolError("live worker attribution lost")
            if not any(r["received_ns"] <= stamp and 0 <= stamp - r["observed_ns"] <= p.IDENTITY_AGE_NS for r in ev["identity_records"]):
                raise ProtocolError("mid-trial identity freshness")
    clear_times = []
    for stamp, frame in sample_frames(samples):
        if not stamps["PROCESS_REAPED"] <= stamp <= stamps["RESIDUAL_CLEAR"]:
            continue
        clear = (not frame["worker_cgroup"]["populated"] and frame["worker_cgroup"]["pids"] == [] and
                 not frame["worker_process"]["alive"] and not frame["gpu_process"]["present"] and frame["gpu_process"]["used_bytes"] == 0)
        if not clear:
            clear_times.clear()
        elif not clear_times or stamp > clear_times[-1]:
            clear_times.append(stamp)
    if len(clear_times) < p.RESIDUAL_CLEAR_SAMPLES or clear_times[-1] - clear_times[0] < p.RESIDUAL_CLEAR_NS or stamps["RESIDUAL_CLEAR"] - stamps["PROCESS_REAPED"] >= 15 * p.SECOND_NS:
        raise ProtocolError("insufficient residual proof")


class Campaign:
    """Single campaign, ordered boots; any abort is a sticky campaign stop.

    Custody is supplied independently. This class performs no host operations.
    An 18-worker campaign requires a separate explicit authorization reference.
    """
    def __init__(self, run_id, *, expanded=False, expansion_authorization=None):
        p.token(run_id)
        if type(expanded) is not bool:
            raise ProtocolError("expansion requires separate authority")
        if expanded or expansion_authorization is not None:
            try:
                p.token(expansion_authorization)
            except ValueError as exc:
                raise ProtocolError("expansion requires a safe authorization reference") from exc
        self.run_id, self.matrix = run_id, p.trial_matrix(expanded)
        self.expansion_authorization = expansion_authorization
        self.active, self.attempts, self.stopped = None, [], False
        self.sealed = False
        self.stop_reasons, self.boot_ids, self.identities = [], {}, set()

    def taint(self, reason):
        self.stopped = True
        if reason not in self.stop_reasons:
            self.stop_reasons.append(reason)

    def admit(self, controller, custody):
        if self.stopped or self.active is not None or len(self.attempts) >= len(self.matrix):
            raise ProtocolError("campaign stopped/busy/complete")
        if controller.state != "NEW" or controller.campaign is not None:
            raise ProtocolError("controller must be unprepared and not already admitted")
        slot = self.matrix[len(self.attempts)]
        required = {"boot", "ordinal", "state", "boot_id", "observed_ns", "no_prior_experiment", "previous_trial_id"}
        if set(custody) != required or any(not strict_equal(custody[k], slot[k]) for k in ("boot", "ordinal", "state")):
            raise ProtocolError("matrix/custody mismatch")
        if controller.run_id != self.run_id or controller.order != slot["handle_order"] or custody["boot_id"] != controller.identity.boot_id:
            raise ProtocolError("campaign identity/order")
        if type(custody["observed_ns"]) is not int or not 0 <= controller.clock() - custody["observed_ns"] <= p.IDENTITY_AGE_NS:
            raise ProtocolError("custody freshness")
        if slot["ordinal"] == 1:
            if custody["boot_id"] in self.boot_ids.values() or custody["no_prior_experiment"] is not True or custody["previous_trial_id"] is not None:
                raise ProtocolError("cold boot custody")
            self.boot_ids[slot["boot"]] = custody["boot_id"]
        elif (self.boot_ids.get(slot["boot"]) != custody["boot_id"] or custody["no_prior_experiment"] is not False or
              custody["previous_trial_id"] != self.attempts[-1]["trial_id"] or self.attempts[-1]["verdict"] != "valid"):
            raise ProtocolError("warm predecessor custody")
        if slot["ordinal"] > 1:
            validate_successor_lifecycle(self.attempts[-1], controller.identity.boot_id,
                {"sampler_started_ns": controller.sampler.started_ns, "baseline_frames": controller.frames,
                 "observation_raw": controller.sampler.raw_records, "identity_raw": controller.identity_raw,
                 "worker_raw": controller.worker_raw, "mapping_records": controller.mapping_records},
                controller.clock())
        key = (controller.identity.boot_id, controller.identity.pid, controller.identity.process_start_ticks)
        if key in self.identities or any(t["trial_id"] == controller.trial_id or
                (t["boot_id"] == controller.identity.boot_id and
                 (t["identity_binding"]["pid"] == controller.identity.pid or t["identity_binding"]["cgroup_path"] == controller.identity.cgroup_path))
                for t in self.attempts):
            raise ProtocolError("worker/cgroup reuse")
        self.identities.add(key)
        controller.campaign, controller.slot, controller.custody = self, dict(slot), deepcopy(custody)
        controller.admitted_ns = controller.clock()
        self.active = controller

    def finish(self, controller, trial):
        if self.active is not controller:
            raise ProtocolError("unadmitted attempt")
        self.attempts.append(deepcopy(trial))
        self.active = None
        if trial["verdict"] != "valid":
            self.taint("UNSUCCESSFUL_ATTEMPT")

    def seal(self, manifest, report=None):
        if self.sealed or self.active is not None or self.stopped or len(self.attempts) != len(self.matrix):
            raise ProtocolError("campaign incomplete/tainted; attempt evidence retained")
        if not strict_equal(manifest["matrix"], list(self.matrix)):
            raise ProtocolError("manifest matrix mismatch")
        if len(self.matrix) == 18 and manifest["expansion_authorization_reference"] != self.expansion_authorization:
            raise ProtocolError("expansion authority mismatch")
        events = [e for t in self.attempts for e in t["evidence"]["events"]]
        samples = [s for t in self.attempts for s in t["evidence"]["samples"]]
        bundle = evidence_bundle(manifest, events, samples, self.attempts,
                                 report)
        self.sealed = True
        return bundle


def comparison_rows(trials, memory_metric="worker_cgroup.memory_current_bytes"):
    def value(measurement):
        return measurement["value"] if measurement["available"] else None
    rows = []
    for trial in trials:
        m = trial["peak_metrics"]
        baseline = value(trial["baseline_metrics"]["gpu_device.used_bytes"])
        frames = sample_frames(trial["evidence"]["samples"])
        disagreements = [f["gpu_device"]["used_bytes"] - baseline - f["gpu_process"]["used_bytes"]
                         for _, f in frames] if baseline is not None else []
        rows.append({"boot": trial["boot"], "state": trial["state"], "order": trial["handle_order"],
            "duration_ns": value(trial["startup_duration_ns"]),
            "memory_bytes": value(m[memory_metric]),
            "baseline_bytes": baseline,
            "gpu_bytes": value(m["gpu_process.used_bytes"]),
            # Unattributed growth is evaluated per synchronized frame, never by summing ledgers.
            "ledger_disagreement_bytes": max(0, max(disagreements)) if disagreements else None,
            "outcome": trial["verdict"], "cleanup": trial["cleanup_result"]})
    return rows


def render_report(manifest, trials):
    """Deterministic, source-backed report. Caller prose cannot replace required data."""
    assessment, checked = assess_campaign(manifest, trials)
    return _render_report(manifest, trials, assessment, checked)


def _render_report(manifest, trials, assessment, checked):
    report = {"scope": "startup characterization only; no GGUF accessed; Tranche B remains CLOSED",
        "canonical_head": manifest["canonical_head"], "source_hashes": manifest["source_artifact_hashes"],
        "authorization": manifest["authorization_reference"], "host": manifest["host_identity"],
        "software": manifest["software_identity"], "libraries": manifest["library_manifest"],
        "matrix": manifest["matrix"], "thresholds": manifest["thresholds"], "timeouts": manifest["timeout_policy"],
        "attempts": [{k: v for k, v in t.items() if k != "evidence"} for t in trials],
        "acceptance": assessment["acceptance"], "validation_errors": assessment["errors"],
        "review": {key: p.evaluate_expansion(comparison_rows(checked, key)) for key in
                   ("worker_cgroup.memory_current_bytes", "worker_cgroup.memory_peak_bytes",
                    "gpu_process.used_bytes", "gpu_device.used_bytes", "observer_cgroup.memory_current_bytes")},
        "limitations": ["Sampled GPU observation is not preventative enforcement.",
            "Host and GPU ledgers may overlap; do not sum them.",
            "100 ms target sampling cannot establish unsampled instantaneous peaks.",
            "Observer cost is included in the retained observer cgroup metrics.",
            "In-memory bytes are not canonical filesystem publication or deployment authority."]}
    return "# Startup characterization evidence\n\n" + json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"


def check_campaign_order(manifest, trials):
    """Cross-attempt custody checks, after individual attempts have been validated."""
    if len(trials) != len(manifest["matrix"]):
        raise ProtocolError("campaign matrix incomplete")
    if len({t["trial_id"] for t in trials}) != len(trials):
        raise ProtocolError("duplicate trial")
    boots, processes, cgroups = {}, set(), set()
    for index, (trial, slot) in enumerate(zip(trials, manifest["matrix"])):
        if trial["verdict"] != "valid" or trial["run_id"] != manifest["run_id"] or any(not strict_equal(trial[k], slot[k]) for k in slot):
            raise ProtocolError("failed/misordered campaign attempt")
        if not strict_equal(trial["evidence"]["library_manifest"], manifest["library_manifest"]):
            raise ProtocolError("library authority differs across attempts")
        custody = trial["custody"]
        if any(not strict_equal(custody[k], trial[k]) for k in ("boot", "ordinal", "state", "boot_id")):
            raise ProtocolError("custody/trial mismatch")
        if slot["ordinal"] == 1:
            if trial["boot_id"] in boots.values() or custody["no_prior_experiment"] is not True or custody["previous_trial_id"] is not None:
                raise ProtocolError("cold boot reuse/custody")
            boots[slot["boot"]] = trial["boot_id"]
        elif boots.get(slot["boot"]) != trial["boot_id"] or custody["no_prior_experiment"] is not False or custody["previous_trial_id"] != trials[index - 1]["trial_id"]:
            raise ProtocolError("warm custody")
        if slot["ordinal"] > 1:
            validate_successor_lifecycle(trials[index - 1], trial["boot_id"],
                                         trial["evidence"], trial["admitted_ns"])
            release = next(e["monotonic_raw_ns"] for e in trial["evidence"]["events"] if e["event_type"] == "RELEASE")
            if trial["admitted_ns"] > release:
                raise ProtocolError("same-boot successor release predates admission")
        process = (trial["boot_id"], trial["identity_binding"]["pid"])
        cgroup = (trial["boot_id"], trial["identity_binding"]["cgroup_path"])
        if process in processes or cgroup in cgroups:
            raise ProtocolError("reused worker/cgroup")
        processes.add(process)
        cgroups.add(cgroup)


def assess_campaign(manifest, trials):
    validate_record("manifest", manifest)
    checked, errors = [], []
    for trial in trials:
        try:
            validate_attempt(trial)
        except (ProtocolError, ObservationError, KeyError, TypeError, ValueError) as exc:
            errors.append({"trial_id": trial.get("trial_id"), "reason": type(exc).__name__ + ":" + str(exc)})
        else:
            checked.append(trial)
    crosschecked = bool(trials) and len(checked) == len(trials)
    complete = False
    if crosschecked:
        try:
            check_campaign_order(manifest, trials)
        except (ProtocolError, KeyError, TypeError, ValueError) as exc:
            errors.append({"trial_id": None, "reason": type(exc).__name__ + ":" + str(exc)})
        else:
            complete = True
    flags = {"matrix_complete": complete,
             "all_attempts_valid": crosschecked and all(t["verdict"] == "valid" for t in trials),
             "raw_evidence_crosschecked": crosschecked}
    return {"acceptance": flags, "errors": errors}, checked


def evidence_bundle(manifest, events, samples, trials, report=None):
    """Final campaign only. Incomplete/failed attempts remain available individually."""
    assessment, checked = assess_campaign(manifest, trials)
    if not all(assessment["acceptance"].values()):
        raise ProtocolError("campaign incomplete/invalid: " + json.dumps(assessment["errors"]))
    if not strict_equal(events, [e for t in trials for e in t["evidence"]["events"]]) or not strict_equal(samples, [s for t in trials for s in t["evidence"]["samples"]]):
        raise ProtocolError("bundle journal mismatch")
    expected_report = _render_report(manifest, trials, assessment, checked)
    if report is not None and report != expected_report:
        raise ProtocolError("report not the complete source-backed report")
    report = expected_report
    def encode(value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    seal = {"schema_version": p.SCHEMA_VERSION, "run_id": manifest["run_id"], "event_type": "EVIDENCE_SEALED",
            "trial_ids": [t["trial_id"] for t in trials],
            "attempt_sha256": {t["trial_id"]: hashlib.sha256(encode(t)).hexdigest() for t in trials}}
    validate_record("campaign_seal", seal)
    files = {"manifest.json": encode(manifest),
             "events.jsonl": b"".join(encode(v) for v in events) + encode(seal),
             "samples.jsonl": b"".join(encode(v) for v in samples),
             "report.md": report.encode("utf-8")}
    for trial in trials:
        p.token(trial["trial_id"])
        files["trials/" + trial["trial_id"] + ".json"] = encode(trial)
    files["sha256sums.txt"] = "".join(hashlib.sha256(data).hexdigest() + "  " + path + "\n"
                                    for path, data in sorted(files.items())).encode("ascii")
    return files
