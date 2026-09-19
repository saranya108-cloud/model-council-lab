"""Persistent, injected sampling. No NVML import, shell query or host writes."""

from dataclasses import asdict, dataclass
from copy import deepcopy
from typing import Protocol

from . import policy as p


class ObservationError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    boot_id: str
    pid: int
    process_start_ticks: int
    pid_namespace_inode: int
    executable_path: str
    executable_inode: int
    cgroup_path: str
    cgroup_inode: int
    gpu_uuid: str

    def __post_init__(self):
        for value in (self.pid, self.process_start_ticks, self.pid_namespace_inode,
                      self.executable_inode, self.cgroup_inode):
            if type(value) is not int or value <= 0:
                raise ObservationError("invalid identity integer")
        p.token(self.boot_id)
        if self.gpu_uuid != p.GPU_UUID:
            raise ObservationError("boot/GPU identity mismatch")
        if not self.cgroup_path.startswith("/") or not self.executable_path.startswith("/"):
            raise ObservationError("absolute identity path required")
        if ".." in self.cgroup_path.split("/") or self.cgroup_path == "/":
            raise ObservationError("invalid dedicated cgroup")

    def match(self, observed):
        if type(observed) is not dict or any(type(observed.get(k)) is not type(v) or observed.get(k) != v for k, v in asdict(self).items()) or set(observed) != set(asdict(self)):
            raise ObservationError("identity mismatch")


class SampleBackend(Protocol):
    """A persistent external observer; poll must be nonblocking.

    Return a completed sample or None. The adapter owns subprocess/query
    containment; blocking vendor queries must never block the controller loop.
    """

    def poll(self, stream: str, now_ns: int): ...


METRICS = {
    "worker_cgroup": ("memory_current_bytes", "memory_peak_bytes", "memory_swap_current_bytes",
                      "memory_max_bytes", "swap_max_bytes", "cgroup_events", "membership_exact",
                      "memory_events", "memory_events_local", "populated", "pids"),
    "worker_process": ("alive",),
    "gpu_device": ("total_bytes", "free_bytes", "used_bytes"),
    "gpu_process": ("present", "used_bytes"),
    "machine_reserve": ("mem_total_bytes", "mem_available_bytes", "swap_in_pages",
                        "swap_out_pages", "psi_full_total_us", "oom_kill_count"),
    "observer_cgroup": ("memory_current_bytes", "query_latency_ns"),
}


class Sampler:
    def __init__(self, backend, identity, observer_identity, run_id, trial_id, clock=p.raw_ns):
        self.backend, self.identity = backend, identity
        self.observer_identity = observer_identity
        if observer_identity.boot_id != identity.boot_id:
            raise ObservationError("observer boot mismatch")
        a, b = observer_identity.cgroup_path, identity.cgroup_path
        if a == b or a.startswith(b + "/") or b.startswith(a + "/"):
            raise ObservationError("observer and worker cgroups must be separate siblings")
        if observer_identity.pid == identity.pid:
            raise ObservationError("observer is worker")
        self.run_id, self.trial_id, self.clock = run_id, trial_id, clock
        p.token(run_id)
        p.token(trial_id)
        self.latest, self.records, self.due = {}, [], {}
        self.raw_records = []
        self.sequence_state = {}
        self.started_ns = clock()

    def accept(self, sample, now_ns):
        entry = {"sequence": len(self.raw_records) + 1, "received_ns": now_ns,
                 "raw": deepcopy(sample), "eligible": False, "rejection": None}
        self.raw_records.append(entry)
        try:
            self._accept(sample, now_ns)
        except Exception as exc:
            entry["rejection"] = type(exc).__name__ + ":" + str(exc)
            if type(sample) is dict:
                self.latest.pop(sample.get("stream"), None)
            raise
        entry["eligible"] = True

    def _accept(self, sample, now_ns):
        required = {"schema_version", "run_id", "trial_id", "boot_id", "observer_pid", "observer_start_ticks",
                    "observer_cgroup", "worker_identity", "stream", "sequence", "previous_gap_ns",
                    "sample_start_monotonic_raw_ns", "sample_end_monotonic_raw_ns", "available", "unavailable_reason", "metrics"}
        if type(sample) is not dict or set(sample) != required:
            raise ObservationError("malformed sample")
        stream = sample["stream"]
        if stream not in p.STREAMS:
            raise ObservationError("unknown stream")
        for key, expected in (("schema_version", p.SCHEMA_VERSION), ("run_id", self.run_id),
                              ("trial_id", self.trial_id), ("boot_id", self.identity.boot_id),
                              ("observer_pid", self.observer_identity.pid),
                              ("observer_start_ticks", self.observer_identity.process_start_ticks),
                              ("observer_cgroup", self.observer_identity.cgroup_path)):
            if type(sample.get(key)) is not type(expected) or sample.get(key) != expected:
                raise ObservationError("sample attribution mismatch")
        self.identity.match(sample["worker_identity"])
        start, end = sample["sample_start_monotonic_raw_ns"], sample["sample_end_monotonic_raw_ns"]
        if any(type(v) is not int or v < 0 for v in (start, end, now_ns)) or not start <= end <= now_ns:
            raise ObservationError("sample time invalid")
        previous_sequence, previous_end = self.sequence_state.get(stream, (0, self.started_ns))
        gap = end - previous_end
        sequence = previous_sequence + 1
        if gap < 0 or gap > p.MAX_SAMPLE_GAP_NS or end - start > p.MAX_SAMPLE_GAP_NS:
            raise ObservationError("sample gap/query duration")
        if type(sample["sequence"]) is not int or type(sample["previous_gap_ns"]) is not int or sample["sequence"] != sequence or sample["previous_gap_ns"] != gap:
            raise ObservationError("sample sequence/gap mismatch")
        self.sequence_state[stream] = (sequence, end)
        if sample["available"] is not True or sample["unavailable_reason"] is not None:
            raise ObservationError("required sample unavailable")
        metrics = sample["metrics"]
        if set(metrics) != set(METRICS[stream]):
            raise ObservationError("missing or extra metrics")
        for name, value in metrics.items():
            if name in ("alive", "present", "populated", "membership_exact"):
                valid = type(value) is bool
            elif name == "pids":
                valid = isinstance(value, list) and all(type(v) is int and v > 0 for v in value)
            elif name == "cgroup_events":
                valid = type(value) is dict and set(value) == {"populated", "frozen"} and all(type(v) is int and v in (0, 1) for v in value.values())
            elif name in ("memory_events", "memory_events_local"):
                valid = isinstance(value, dict) and {"low", "high", "max", "oom", "oom_kill"} <= set(value)
                valid = valid and all(type(v) is int and v >= 0 for v in value.values())
            else:
                valid = type(value) is int and value >= 0
            if not valid:
                raise ObservationError("invalid metric type")
        if stream == "worker_cgroup":
            if (metrics["memory_peak_bytes"] < metrics["memory_current_bytes"] or
                    metrics["memory_max_bytes"] != p.WORKER_MEMORY_MAX_BYTES or metrics["swap_max_bytes"] != 0 or
                    metrics["cgroup_events"]["populated"] != int(metrics["populated"]) or
                    not metrics["membership_exact"] or metrics["pids"] != ([self.identity.pid] if metrics["populated"] else [])):
                raise ObservationError("host accounting/limit/membership contradiction")
        if stream == "gpu_process" and not metrics["present"] and metrics["used_bytes"] != 0:
            raise ObservationError("empty GPU query with nonzero bytes")
        if stream == "observer_cgroup" and metrics["query_latency_ns"] > p.MAX_SAMPLE_GAP_NS:
            raise ObservationError("observer query latency")
        if now_ns - end > p.MAX_SAMPLE_GAP_NS:
            raise ObservationError("stale received observation")
        self.latest[stream] = deepcopy(sample)
        self.records.append(deepcopy(sample))

    def tick(self, now_ns=None):
        now = self.clock() if now_ns is None else now_ns
        for stream in p.STREAMS:
            if now >= self.due.get(stream, self.started_ns):
                try:
                    sample = self.backend.poll(stream, now)
                except Exception as exc:
                    self.raw_records.append({"sequence": len(self.raw_records) + 1,
                        "received_ns": now, "raw": {"stream": stream, "available": False,
                        "unavailable_reason": "QUERY_FAILED", "exception_type": type(exc).__name__},
                        "eligible": False, "rejection": "BACKEND_EXCEPTION"})
                    self.latest.pop(stream, None)
                    raise ObservationError("backend exception: " + stream) from exc
                if sample is not None:
                    self.accept(sample, now)
                    self.due[stream] = now + p.SAMPLE_PERIOD_NS
            last = self.latest.get(stream, {}).get("sample_end_monotonic_raw_ns", self.started_ns)
            if now < last or now - last > p.MAX_SAMPLE_GAP_NS:
                raise ObservationError("observer heartbeat lost")

    def fresh(self, now_ns, max_age_ns=p.PRE_RELEASE_AGE_NS):
        if set(self.latest) != set(p.STREAMS):
            raise ObservationError("incomplete observer streams")
        for sample in self.latest.values():
            age = now_ns - sample["sample_end_monotonic_raw_ns"]
            if not 0 <= age <= max_age_ns:
                raise ObservationError("stale observation")
        return {stream: item["metrics"] for stream, item in self.latest.items()}


def tripwires(current, baseline, *, worker_alive=True):
    """Independent ledgers. Never sum cgroup and GPU attribution."""
    failures = []
    worker, gpu = current["worker_cgroup"], current["gpu_process"]
    machine, device = current["machine_reserve"], current["gpu_device"]
    old_machine, old_worker = baseline["machine_reserve"], baseline["worker_cgroup"]
    if worker["memory_current_bytes"] - old_worker["memory_current_bytes"] >= p.WORKER_DELTA_MAX_BYTES:
        failures.append("WORKER_DELTA")
    if (worker["memory_current_bytes"] >= p.WORKER_MEMORY_MAX_BYTES or worker["memory_swap_current_bytes"] or
            worker["memory_max_bytes"] != p.WORKER_MEMORY_MAX_BYTES or worker["swap_max_bytes"] != 0):
        failures.append("WORKER_LIMIT_OR_SWAP")
    for counter in ("memory_events", "memory_events_local"):
        if any(worker[counter].get(key, 0) > old_worker[counter].get(key, 0)
               for key in ("high", "max", "oom", "oom_kill", "oom_group_kill")):
            failures.append("WORKER_MEMORY_EVENT")
    if gpu["used_bytes"] >= p.GPU_PROCESS_MAX_BYTES:
        failures.append("GPU_PROCESS")
    if device["used_bytes"] - baseline["gpu_device"]["used_bytes"] - gpu["used_bytes"] > p.UNATTRIBUTED_MAX_BYTES:
        failures.append("UNATTRIBUTED_DEVICE")
    if current["observer_cgroup"]["memory_current_bytes"] >= p.OBSERVER_MAX_BYTES:
        failures.append("OBSERVER_MEMORY")
    if machine["mem_available_bytes"] < p.host_reserve_bytes(machine["mem_total_bytes"]):
        failures.append("HOST_RESERVE")
    if device["free_bytes"] < p.device_reserve_bytes(device["total_bytes"]):
        failures.append("DEVICE_RESERVE")
    if any(machine[k] != old_machine[k] for k in
           ("swap_in_pages", "swap_out_pages", "psi_full_total_us", "oom_kill_count")):
        failures.append("MACHINE_PRESSURE")
    if worker_alive and not current["worker_process"]["alive"]:
        failures.append("WORKER_LOST")
    return tuple(failures)


def validate_baseline(frames):
    """frames: timestamp + complete validated six-stream metric bundles."""
    if any(type(stamp) is not int or stamp < 0 for stamp, _ in frames):
        raise ObservationError("baseline timestamp must be nonnegative integer ns")
    if len(frames) < 2 or frames[-1][0] - frames[0][0] < p.BASELINE_NS:
        raise ObservationError("baseline shorter than 60 seconds")
    for (a, _), (b, _) in zip(frames, frames[1:]):
        if not 0 < b - a <= p.MAX_SAMPLE_GAP_NS:
            raise ObservationError("baseline sample gap")
    baseline = frames[0][1]
    for _, metrics in frames:
        if tripwires(metrics, baseline):
            raise ObservationError("baseline safety veto")
    used = [metrics["gpu_device"]["used_bytes"] for _, metrics in frames]
    if max(used) - min(used) > p.BASELINE_GPU_DRIFT_BYTES:
        raise ObservationError("baseline GPU drift")
    return frames[-1][1]
