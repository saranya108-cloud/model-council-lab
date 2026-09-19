"""Offline only: no subprocesses, signals, cgroups, files or vendor libraries."""

import copy
from dataclasses import asdict, replace
import os
import json
import unittest
from unittest.mock import Mock

from tools.decision_0009.startup_characterization import policy as p
from tools.decision_0009.startup_characterization.controller import (
    Controller, Campaign, ProtocolError, expected_worker_events, verify_libraries, validate_attempt, validate_record, render_report,
)
from tools.decision_0009.startup_characterization.observer import (
    Identity, ObservationError, Sampler, tripwires, validate_baseline,
)
from tools.decision_0009.startup_characterization.worker import CtypesBackend, run as worker_run


def libraries():
    return {n: {"path": "/approved/" + n, "device": 1, "inode": i, "size_bytes": 1024,
                "mtime_ns": 1, "elf_build_id": "build1", "soname": n + ".so",
                "package_version": "1", "sha256": "a" * 64}
            for i, n in enumerate(p.LIBRARY_FAMILIES, 1)}


def run(order, vendor, emit, wait, cancelled=lambda: False, clock=p.raw_ns):
    controller = getattr(emit, "__self__", None)
    def gate(terminal=False):
        if isinstance(controller, Controller):
            return controller.verify_mapping({n: [v] for n, v in libraries().items()}, clock(), terminal=terminal)
        return True
    return worker_run(order, vendor, emit, wait, cancelled, clock, gate, lambda: gate(True))


class Clock:
    def __init__(self, now=0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, ns):
        self.now += ns


def identity():
    return Identity("boot-1", 123, 345, 67, "/usr/bin/python3", 789, "/workers/trial1", 234, p.GPU_UUID)


def metrics():
    counters = {"low": 0, "high": 0, "max": 0, "oom": 0, "oom_kill": 0}
    return {"worker_cgroup": {"memory_current_bytes": 32 * p.MIB, "memory_swap_current_bytes": 0,
                               "memory_peak_bytes": 32 * p.MIB, "memory_max_bytes": p.WORKER_MEMORY_MAX_BYTES,
                               "swap_max_bytes": 0, "cgroup_events": {"populated": 1, "frozen": 0}, "membership_exact": True,
                               "memory_events": counters.copy(), "memory_events_local": counters.copy(),
                               "populated": True, "pids": [123]},
            "worker_process": {"alive": True},
            "gpu_device": {"total_bytes": 120 * p.GIB, "free_bytes": 100 * p.GIB, "used_bytes": 20 * p.GIB},
            "gpu_process": {"present": True, "used_bytes": 170 * p.MIB},
            "machine_reserve": {"mem_total_bytes": 128 * p.GIB, "mem_available_bytes": 100 * p.GIB,
                                "swap_in_pages": 0, "swap_out_pages": 0, "psi_full_total_us": 0, "oom_kill_count": 0},
            "observer_cgroup": {"memory_current_bytes": 40 * p.MIB, "query_latency_ns": 1_000_000}}


class Samples:
    def __init__(self, clock, ident=None, run_id="run1", trial_id="trial1"):
        self.clock = clock
        self.started_ns = clock()
        self.ident, self.run_id, self.trial_id = ident or identity(), run_id, trial_id
        self.values = metrics()
        self.values["worker_cgroup"]["pids"] = [self.ident.pid]
        self.sequence, self.previous = {}, {}
        self.enabled = True

    def poll(self, stream, now):
        if not self.enabled:
            return None
        seq = self.sequence.get(stream, 0) + 1
        gap = now - self.previous.get(stream, self.started_ns)
        self.sequence[stream], self.previous[stream] = seq, now
        return {"schema_version": p.SCHEMA_VERSION, "run_id": self.run_id, "boot_id": self.ident.boot_id,
                "trial_id": self.trial_id, "stream": stream, "sequence": seq,
                "sample_start_monotonic_raw_ns": now, "sample_end_monotonic_raw_ns": now,
                "previous_gap_ns": gap, "observer_pid": 124, "observer_start_ticks": 346,
                "observer_cgroup": "/observers/run1", "worker_identity": asdict(identity()),
                "metrics": copy.deepcopy(self.values[stream]), "available": True, "unavailable_reason": None,
                "worker_identity": asdict(self.ident)}


class Ports:
    def __init__(self, clock):
        self.clock, self.actions, self.exit_status = clock, [], None
        self.observed = identity()

    def configure_worker_cgroup(self, ident, memory_max_bytes, swap_max_bytes):
        self.actions.append("configure")
        return {"memory_max_bytes": memory_max_bytes, "swap_max_bytes": swap_max_bytes, "members": [ident.pid]}

    def snapshot_identity(self):
        return {"identity": asdict(self.observed), "observed_ns": self.clock(), "members": [self.observed.pid]}

    def release(self):
        self.actions.append("release")

    def request_cleanup(self):
        self.actions.append("cooperative")

    def terminate(self):
        self.actions.append("TERM")

    def kill(self):
        self.actions.append("KILL")

    def poll_exit(self):
        return self.exit_status

    def reap(self):
        self.actions.append("reap")


class Vendor:
    def __init__(self, fail=None, exception=None):
        self.calls, self.maps, self.live = [], [], []
        self.fail, self.exception = fail, exception

    def map_library(self, name):
        self.maps.append(name)
        if self.exception == name:
            raise RuntimeError("fake mapping failure")

    def call(self, name, handle=None):
        self.calls.append(name)
        if name == self.exception:
            raise RuntimeError("fake vendor failure")
        if name == self.fail:
            return 7, None
        if name in ("cublasCreate_v2", "cublasLtCreate"):
            self.live.append(name)
            return 0, name
        if name in ("cublasDestroy_v2", "cublasLtDestroy"):
            self.live.remove(handle)
        return 0, None


class WorkerTests(unittest.TestCase):
    def test_orders_and_coexistence(self):
        for order, expected in (
            ("BL", ["cudaSetDevice", "cublasCreate_v2", "cublasLtCreate", "cublasLtDestroy", "cublasDestroy_v2"]),
            ("LB", ["cudaSetDevice", "cublasLtCreate", "cublasCreate_v2", "cublasDestroy_v2", "cublasLtDestroy"]),
        ):
            with self.subTest(order=order):
                vendor, clock, events = Vendor(), Clock(), []
                def dwell(ns):
                    self.assertEqual(set(vendor.live), {"cublasCreate_v2", "cublasLtCreate"})
                    self.assertEqual(ns, 2_000_000_000)
                    clock.advance(ns)
                result = run(order, vendor, events.append, dwell, clock=clock)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(vendor.calls, expected)
                self.assertEqual(vendor.maps, ["libcudart", "libcublasLt", "libcublas"])
                self.assertEqual(vendor.live, [])
                self.assertEqual([(e["event_type"], e["call_name"]) for e in events], expected_worker_events(order))

    def test_failure_cleanup(self):
        for order, failing, cleanup in (
            ("BL", "cublasLtCreate", ["cublasDestroy_v2"]),
            ("LB", "cublasCreate_v2", ["cublasLtDestroy"]),
            ("BL", "cudaSetDevice", []),
        ):
            vendor = Vendor(fail=failing)
            result = run(order, vendor, lambda e: None, lambda ns: None, clock=Clock())
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual([c for c in vendor.calls if "Destroy" in c], cleanup)
            self.assertIn({"call_name": failing, "raw_result": 7}, result["call_results"])
            self.assertFalse(vendor.live)

    def test_sink_failure_cannot_skip_owned_handle_cleanup(self):
        vendor = Vendor()
        def sink(event):
            if event["event_type"] == "CALL_END" and event["call_name"] == "cublasCreate_v2":
                raise OSError("fake evidence failure")
        result = run("BL", vendor, sink, lambda ns: None, clock=Clock())
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(vendor.calls[-1], "cublasDestroy_v2")
        self.assertFalse(vendor.live)

    def test_cleanup_sink_failure_and_destroy_failure_still_attempt_other_handle(self):
        vendor = Vendor(fail="cublasLtDestroy")
        def sink(event):
            if event["event_type"] == "CLEANUP_RELEASE":
                raise OSError()
        result = run("BL", vendor, sink, lambda ns: None, clock=Clock())
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(vendor.calls[-2:], ["cublasLtDestroy", "cublasDestroy_v2"])

    def test_loader_flags_and_closed_symbol_surface(self):
        resolved, loaded = [], []
        class Library:
            def __getattr__(self, name):
                resolved.append(name)
                return Mock(return_value=0)
        def loader(path, *, mode):
            loaded.append((path, mode))
            return Library()
        backend = CtypesBackend({n: "/approved/" + n + ".so" for n in p.MAPPING_ORDER}, loader=loader)
        for name in p.MAPPING_ORDER:
            backend.map_library(name)
        self.assertEqual(set(resolved), {"cudaSetDevice", "cublasCreate_v2", "cublasDestroy_v2", "cublasLtCreate", "cublasLtDestroy"})
        self.assertEqual([path for path, _ in loaded], ["/approved/" + n + ".so" for n in p.MAPPING_ORDER])
        self.assertTrue(all(flags == os.RTLD_NOW | os.RTLD_LOCAL for _, flags in loaded))
        for forbidden in ("cudaFree", "cudaMemGetInfo", "cudaDeviceReset", "cuInit", "cudaMalloc", "cublasGetVersion_v2"):
            with self.assertRaises(Exception):
                backend.call(forbidden)
        with self.assertRaises(ValueError):
            CtypesBackend({n: n + ".so" for n in p.MAPPING_ORDER}, loader=loader)

    def test_cancel_and_mapping_exception(self):
        for vendor, cancel in ((Vendor(), lambda: True), (Vendor(exception="libcublasLt"), lambda: False)):
            result = run("BL", vendor, lambda e: None, lambda ns: None, cancel, Clock())
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(vendor.calls, [])


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.backend = Samples(self.clock)
        self.sampler = Sampler(self.backend, identity(), replace(identity(), pid=124, process_start_ticks=346,
                               cgroup_path="/observers/run1"), "run1", "trial1", self.clock)
        self.sampler.tick()

    def test_gap_and_staleness(self):
        self.clock.advance(150_000_001)
        with self.assertRaises(ObservationError):
            self.sampler.fresh(self.clock())
        self.clock.advance(100_000_000)
        with self.assertRaises(ObservationError):
            self.sampler.tick()

    def test_missing_observer_and_identity(self):
        self.backend.enabled = False
        self.clock.advance(250_000_001)
        with self.assertRaises(ObservationError):
            self.sampler.tick()
        with self.assertRaises(ObservationError):
            identity().match(asdict(replace(identity(), process_start_ticks=346)))
        with self.assertRaises(ObservationError):
            Sampler(self.backend, identity(), identity(), "run1", "trial1", self.clock)

    def test_bad_sample_rejected(self):
        for field, value in (("observer_pid", 999), ("available", False), ("sequence", 100),
                              ("sample_end_monotonic_raw_ns", -1)):
            backend = Samples(self.clock)
            sample = backend.poll("gpu_process", 0)
            sample[field] = value
            with self.assertRaises(ObservationError):
                self.sampler.accept(sample, 0)

    def test_independent_tripwires(self):
        baseline = metrics()
        for stream, field, value, reason in (
            ("worker_cgroup", "memory_current_bytes", 32 * p.MIB + p.GIB, "WORKER_DELTA"),
            ("gpu_process", "used_bytes", p.GIB, "GPU_PROCESS"),
            ("observer_cgroup", "memory_current_bytes", 512 * p.MIB, "OBSERVER_MEMORY"),
            ("machine_reserve", "mem_available_bytes", 16 * p.GIB - 1, "HOST_RESERVE"),
            ("gpu_device", "free_bytes", 8 * p.GIB - 1, "DEVICE_RESERVE"),
            ("machine_reserve", "psi_full_total_us", 1, "MACHINE_PRESSURE"),
        ):
            current = copy.deepcopy(baseline)
            current[stream][field] = value
            self.assertIn(reason, tripwires(current, baseline))
        self.assertEqual(tripwires(baseline, baseline), ())

    def test_empty_gpu_query_is_eligible(self):
        self.backend.values["gpu_process"].update(present=False, used_bytes=0)
        self.clock.advance(p.SAMPLE_PERIOD_NS)
        self.sampler.tick()
        self.assertFalse(self.sampler.fresh(self.clock())["gpu_process"]["present"])
        self.assertTrue(self.sampler.raw_records[-1]["eligible"])

    def test_failed_and_stale_unavailable_observations_retained(self):
        for stale in (False, True):
            sample = self.backend.poll("gpu_process", self.clock())
            sample.update(available=False, metrics=None, unavailable_reason="QUERY_FAILED")
            now = self.clock() + (p.SECOND_NS if stale else 0)
            with self.assertRaises(ObservationError):
                self.sampler.accept(sample, now)
            self.assertEqual(self.sampler.raw_records[-1]["raw"], sample)
            self.assertFalse(self.sampler.raw_records[-1]["eligible"])
            self.assertNotIn("gpu_process", self.sampler.latest)

    def test_backend_exception_preserves_attribution(self):
        def broken(stream, now):
            raise RuntimeError("fake backend")
        self.backend.poll = broken
        self.clock.advance(p.SAMPLE_PERIOD_NS)
        with self.assertRaises(ObservationError):
            self.sampler.tick()
        entry = self.sampler.raw_records[-1]
        self.assertEqual(entry["raw"]["exception_type"], "RuntimeError")
        self.assertEqual(entry["raw"]["stream"], "worker_cgroup")
        self.assertFalse(entry["eligible"])

    def test_failed_query_sequence_can_resume_for_cleanup(self):
        self.clock.advance(p.SAMPLE_PERIOD_NS)
        sample = self.backend.poll("gpu_process", self.clock())
        sample.update(available=False, metrics=None, unavailable_reason="QUERY_FAILED")
        with self.assertRaises(ObservationError):
            self.sampler.accept(sample, self.clock())
        self.clock.advance(p.SAMPLE_PERIOD_NS)
        self.backend.values["gpu_process"].update(present=False, used_bytes=0)
        self.sampler.tick()
        self.assertFalse(self.sampler.fresh(self.clock())["gpu_process"]["present"])
        self.assertTrue(any(not r["eligible"] for r in self.sampler.raw_records))

    def test_required_host_metrics_cannot_be_omitted(self):
        for field in ("memory_peak_bytes", "memory_max_bytes", "swap_max_bytes", "cgroup_events", "membership_exact"):
            self.setUp()
            sample = self.backend.poll("worker_cgroup", 0)
            sample["sequence"] = 2
            del sample["metrics"][field]
            with self.subTest(field=field), self.assertRaises(ObservationError):
                self.sampler.accept(sample, 0)
            self.assertFalse(self.sampler.raw_records[-1]["eligible"])

    def test_boolean_sequence_is_not_integer(self):
        sample = self.backend.poll("gpu_process", 0)
        sample["sequence"] = True
        with self.assertRaises(ObservationError):
            self.sampler.accept(sample, 0)

    def test_boolean_baseline_timestamp_is_not_integer(self):
        frames = [(n * p.SAMPLE_PERIOD_NS, metrics()) for n in range(601)]
        frames[0] = (False, metrics())
        with self.assertRaises(ObservationError):
            validate_baseline(frames)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.samples = Samples(self.clock)
        self.sampler = Sampler(self.samples, identity(), replace(identity(), pid=124, process_start_ticks=346,
                               cgroup_path="/observers/run1"), "run1", "trial1", self.clock)
        frames = []
        for _ in range(601):
            self.sampler.tick()
            frames.append((self.clock(), copy.deepcopy(self.samples.values)))
            if len(frames) != 601:
                self.clock.advance(100_000_000)
        self.ports = Ports(self.clock)
        self.controller = Controller("run1", "trial1", identity(), "BL", self.ports, self.sampler, self.clock)
        proof = dict.fromkeys(("cold_or_warm_proven", "persistence_unchanged", "desktop_stable", "no_unexpected_compute",
                               "target_libraries_absent", "pidfd_or_start_guard", "source_hashes_verified",
                               "environment_clean", "library_stats_match"), True)
        proof["library_stat_ns"] = self.clock()
        self.manifest = libraries()
        self.campaign = Campaign("run1")
        self.campaign.admit(self.controller, {"boot": 1, "ordinal": 1, "state": "boot-cold", "boot_id": "boot-1",
            "observed_ns": self.clock(), "no_prior_experiment": True, "previous_trial_id": None})
        self.controller.prepare(frames, proof, self.manifest)

    def advance(self, ns):
        for _ in range(ns // 100_000_000):
            self.clock.advance(100_000_000)
            self.controller.tick()

    def finish_worker(self, fail=None):
        self.controller.release()
        result = run("BL", Vendor(fail=fail), self.controller.worker_event, self.advance, clock=self.clock)
        self.ports.exit_status = result["exit_code"]
        self.samples.values["worker_cgroup"].update(populated=False, pids=[])
        self.samples.values["worker_cgroup"]["cgroup_events"]["populated"] = 0
        self.samples.values["worker_process"]["alive"] = False
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(2_200_000_000)
        return self.controller.complete_attempt()

    def test_complete_attempt_is_not_campaign_seal(self):
        trial = self.finish_worker()
        self.assertEqual(trial["verdict"], "valid")
        self.assertEqual(trial["evidence"]["events"][-1]["event_type"], "ATTEMPT_COMPLETE")
        with self.assertRaises(ProtocolError):
            self.campaign.seal({})

    def test_failed_second_create_keeps_cleanup_and_aborted_verdict(self):
        trial = self.finish_worker("cublasLtCreate")
        self.assertEqual(trial["verdict"], "aborted")
        self.assertEqual(trial["cleanup_result"], "PASS")
        calls = trial["call_results"]
        self.assertEqual(calls[-2:], [{"call_name": "cublasLtCreate", "raw_result": 7},
                                     {"call_name": "cublasDestroy_v2", "raw_result": 0}])
        kinds = [e["event_type"] for e in trial["evidence"]["events"]]
        self.assertIn("CLEANUP_RELEASE", kinds)
        self.assertIn("CLEANUP_COMPLETE", kinds)
        self.assertIn("PROCESS_REAPED", kinds)
        self.assertIn("RESIDUAL_CLEAR", kinds)
        self.assertTrue(self.campaign.stopped)

    def test_destroy_failure_preserves_remaining_destroy_result(self):
        trial = self.finish_worker("cublasLtDestroy")
        self.assertEqual(trial["verdict"], "aborted")
        self.assertEqual(trial["cleanup_result"], "FAIL")
        self.assertEqual(trial["call_results"][-2:], [{"call_name": "cublasLtDestroy", "raw_result": 7},
                                                     {"call_name": "cublasDestroy_v2", "raw_result": 0}])

    def test_unavailable_sample_survives_completed_attempt_serialization(self):
        sample = self.samples.poll("gpu_process", self.clock())
        sample.update(available=False, metrics=None, unavailable_reason="QUERY_FAILED")
        with self.assertRaises(ObservationError):
            self.sampler.accept(sample, self.clock())
        self.controller.abort("OBSERVER_FAILURE")
        self.ports.exit_status = 1
        self.samples.values["worker_cgroup"].update(populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
        self.samples.values["worker_process"]["alive"] = False
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(15_000_000_000)
        trial = json.loads(json.dumps(self.controller.complete_attempt()))
        self.assertEqual(trial["verdict"], "aborted")
        self.assertTrue(any(r["raw"] == sample and not r["eligible"] for r in trial["evidence"]["observation_raw"]))

    def test_success_exit_has_separate_residual_window(self):
        self.controller.release()
        result = run("BL", Vendor(), self.controller.worker_event, self.advance, clock=self.clock)
        self.assertEqual(result["exit_code"], 0)
        self.ports.exit_status = 0
        self.samples.values["worker_cgroup"].update(populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
        self.samples.values["worker_process"]["alive"] = False
        self.advance(10_000_000_000)
        self.assertEqual(self.controller.state, "RESIDUAL")
        self.assertIsNone(self.controller.cleanup_end_ns)
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(2_200_000_000)
        self.assertTrue(self.controller.valid)

    def test_release_mismatch_is_sticky_and_stops_campaign(self):
        self.ports.observed = replace(identity(), process_start_ticks=999)
        with self.assertRaises(ObservationError):
            self.controller.release()
        self.ports.observed = identity()
        with self.assertRaises(ProtocolError):
            self.controller.release()
        self.assertNotIn("release", self.ports.actions)
        self.assertTrue(self.campaign.stopped)
        with self.assertRaises(ProtocolError):
            self.campaign.admit(self.controller, self.controller.custody)

    def test_midtrial_identity_change_stops_campaign(self):
        self.controller.release()
        self.ports.observed = replace(identity(), executable_inode=999)
        self.advance(100_000_000)
        self.assertEqual(self.controller.state, "COOPERATIVE")
        self.assertTrue(self.campaign.stopped)

    def test_mapping_identity_complete_and_exact(self):
        for field, value in (("inode", 999), ("sha256", "b" * 64), ("elf_build_id", "different"),
                             ("package_version", "2"), ("mtime_ns", 999), ("size_bytes", 2), ("soname", "other")):
            mapped = {n: [copy.deepcopy(v)] for n, v in self.manifest.items()}
            mapped["libcublas"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                verify_libraries(self.manifest, mapped)
        extra = dict(self.manifest, extra=self.manifest["libcuda"])
        with self.assertRaises(ProtocolError):
            verify_libraries(extra, {n: [v] for n, v in extra.items()})

    def test_premature_mapping_verification_aborts(self):
        self.controller.release()
        with self.assertRaises(ProtocolError):
            self.controller.verify_mapping({n: [v] for n, v in self.manifest.items()}, self.clock())
        self.assertTrue(self.campaign.stopped)

    def test_rejected_cleanup_record_retained(self):
        self.controller.release()
        self.controller.abort("INJECTED")
        record = {"event_type": "CALL_START", "call_name": "cublasCreate_v2", "raw_result": None, "monotonic_raw_ns": self.clock()}
        with self.assertRaises(ProtocolError):
            self.controller.worker_event(record)
        self.assertEqual(self.controller.worker_raw[-1]["raw"], record)
        self.assertFalse(self.controller.worker_raw[-1]["eligible"])

    def test_summary_tampering_and_missing_readback_rejected(self):
        trial = self.finish_worker()
        for field in ("preconditions", "phase_durations_ns", "baseline_metrics", "peak_metrics", "delta_metrics", "tripwire_results", "call_results"):
            bad = copy.deepcopy(trial)
            bad[field] = [] if field == "call_results" else {}
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                validate_attempt(bad)
        bad = copy.deepcopy(trial)
        bad["evidence"]["limit_readback"] = None
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)
        bad = copy.deepcopy(trial)
        bad["startup_duration_ns"]["value"] += 1
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)

    def test_success_barriers_and_residuals(self):
        self.controller.release()
        result = run("BL", Vendor(), self.controller.worker_event, self.advance, clock=self.clock)
        self.assertEqual(result["exit_code"], 0)
        self.ports.exit_status = 0
        self.samples.values["worker_cgroup"].update(populated=False, pids=[])
        self.samples.values["worker_cgroup"]["cgroup_events"]["populated"] = 0
        self.samples.values["worker_process"]["alive"] = False
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(2_200_000_000)
        self.assertTrue(self.controller.valid, self.controller.reasons)
        kinds = [e["event_type"] for e in self.controller.events if e["event_type"] in p.BARRIERS]
        self.assertEqual(kinds, list(p.BARRIERS[:-1]))
        stamps = [e["monotonic_raw_ns"] for e in self.controller.events]
        self.assertEqual(stamps, sorted(stamps))

    def test_release_identity_mismatch(self):
        self.ports.observed = replace(identity(), process_start_ticks=999)
        with self.assertRaises(ObservationError):
            self.controller.release()
        self.assertNotIn("release", self.ports.actions)

    def test_clock_regression_and_order(self):
        self.controller.release()
        with self.assertRaises(ProtocolError):
            self.controller.event("CALL_START", self.clock() - 1)
        with self.assertRaises(ProtocolError):
            self.controller.worker_event({"event_type": "STARTUP_COMPLETE", "call_name": None,
                                          "monotonic_raw_ns": self.clock(), "raw_result": None})
        self.assertEqual(self.controller.state, "COOPERATIVE")

    def test_timeout_escalation_and_no_success(self):
        self.controller.release()
        self.controller.worker_event({"event_type": "CALL_START", "call_name": "libcudart",
                                      "monotonic_raw_ns": self.clock(), "raw_result": None})
        self.advance(5_100_000_000)
        self.assertEqual(self.controller.state, "COOPERATIVE")
        self.advance(15_000_000_000)
        self.assertEqual(self.controller.state, "TAINTED")
        self.assertEqual(self.ports.actions[-3:], ["cooperative", "TERM", "KILL"])
        self.assertFalse(self.controller.valid)
        with self.assertRaises(ProtocolError):
            self.controller.release()

    def test_observer_failure_starts_cleanup(self):
        self.controller.release()
        self.samples.enabled = False
        self.advance(300_000_000)
        self.assertEqual(self.controller.state, "COOPERATIVE")
        self.assertIn("OBSERVER_FAILURE", self.controller.reasons)

    def test_abort_reaping_does_not_restart_cleanup_deadline(self):
        self.controller.release()
        self.controller.abort("INJECTED_FAILURE")
        deadline = self.controller.cleanup_end_ns
        self.advance(14_000_000_000)
        self.ports.exit_status = 1
        self.samples.values["worker_cgroup"].update(populated=False, pids=[])
        self.samples.values["worker_cgroup"]["cgroup_events"]["populated"] = 0
        self.samples.values["worker_process"]["alive"] = False
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(100_000_000)
        self.assertEqual(self.controller.residual_deadline_ns, deadline)
        self.advance(900_000_000)
        self.assertEqual(self.controller.state, "TAINTED")
        self.assertIn("RESIDUAL_TIMEOUT", self.controller.reasons)

    def test_residual_requires_distinct_clear_samples(self):
        self.controller.release()
        self.controller.abort("INJECTED_FAILURE")
        self.ports.exit_status = 1
        self.samples.values["worker_cgroup"].update(populated=False, pids=[])
        self.samples.values["worker_cgroup"]["cgroup_events"]["populated"] = 0
        self.samples.values["worker_process"]["alive"] = False
        self.samples.values["gpu_process"].update(present=False, used_bytes=0)
        self.advance(100_000_000)
        for _ in range(30):
            self.controller.tick()
        self.assertEqual(len(self.controller.residual_times), 1)
        self.assertFalse(self.controller.valid)

    def test_seal_nonterminal_rejected(self):
        with self.assertRaises(ProtocolError):
            self.controller.seal({}, {}, "report")

    def test_duplicate_or_unadmitted_mapping(self):
        mapped = {n: [v] for n, v in self.manifest.items()}
        mapped["libcublasLt"].append(dict(self.manifest["libcublasLt"], inode=999))
        with self.assertRaises(ProtocolError):
            verify_libraries(self.manifest, mapped)


class PolicyTests(unittest.TestCase):
    @staticmethod
    def row(**changes):
        row = dict(boot=1, state="boot-cold", order="BL", duration_ns=1_000_000_000,
                   memory_bytes=p.GIB, baseline_bytes=20 * p.GIB, gpu_bytes=170 * p.MIB,
                   ledger_disagreement_bytes=0, outcome="valid", cleanup="PASS")
        row.update(changes)
        return row

    def test_caution_boundary_is_not_execution_authority(self):
        for value, expected in ((512 * p.MIB - 1, False), (512 * p.MIB, True), (512 * p.MIB + 1, True)):
            result = p.evaluate_expansion([self.row(gpu_bytes=value)])
            self.assertEqual(result["caution"], expected)
            self.assertFalse(result["expansion_authorized"])
            self.assertFalse(result["production_admission_authorized"])

    def test_spread_strict_boundary(self):
        for high, expected in ((225, False), (226, True)):
            rows = [self.row(duration_ns=v) for v in (175, 200, high)]
            self.assertEqual("WITHIN_STATE_ORDER_SPREAD" in p.evaluate_expansion(rows)["reasons"], expected)

    def test_median_difference_requires_relative_and_absolute(self):
        for dimension, label in (("order", "BL_LB_DIFFERENCE"), ("state", "COLD_WARM_DIFFERENCE")):
            for base, delta, expected in ((100_000_000, 25_000_000, False),
                                          (100_000_000, 25_000_001, True),
                                          (200_000_000, 40_000_000, False),
                                          (200_000_000, 40_000_001, True),
                                          (1_000_000_000, 30_000_000, False)):
                second = {dimension: "LB" if dimension == "order" else "same-boot-warm"}
                rows = [self.row(duration_ns=base), self.row(duration_ns=base + delta, **second)]
                self.assertEqual(label in p.evaluate_expansion(rows)["reasons"], expected)

    def test_memory_median_difference_boundary(self):
        for delta, expected in ((32 * p.MIB, False), (32 * p.MIB + 1, True)):
            rows = [self.row(memory_bytes=100 * p.MIB), self.row(order="LB", memory_bytes=100 * p.MIB + delta)]
            self.assertEqual("BL_LB_DIFFERENCE" in p.evaluate_expansion(rows)["reasons"], expected)

    def test_crossboot_larger_absolute_or_relative_boundary(self):
        for baseline, limit in ((p.GIB, 512 * p.MIB), (20 * p.GIB, p.GIB)):
            for delta, expected in ((limit - 1, False), (limit, False), (limit + 1, True)):
                rows = [self.row(baseline_bytes=baseline), self.row(boot=2, baseline_bytes=baseline + delta)]
                self.assertEqual("CROSS_BOOT_BASELINE" in p.evaluate_expansion(rows)["reasons"], expected)

    def test_disagreement_and_failure_difference(self):
        for value, expected in ((256 * p.MIB, False), (256 * p.MIB + 1, True)):
            self.assertEqual("LEDGER_DISAGREEMENT" in p.evaluate_expansion([self.row(ledger_disagreement_bytes=value)])["reasons"], expected)
        rows = [self.row(), self.row(order="LB", outcome="aborted", cleanup="FAIL")]
        self.assertIn("ORDER_FAILURE_CLEANUP_DIFFERENCE", p.evaluate_expansion(rows)["reasons"])

    def test_frozen_policy(self):
        self.assertEqual(p.WORKER_MEMORY_MAX_BYTES, 2_147_483_648)
        self.assertEqual(p.WORKER_SWAP_MAX_BYTES, 0)
        self.assertEqual(p.WORKER_DELTA_MAX_BYTES, 1_073_741_824)
        self.assertEqual(p.GPU_PROCESS_MAX_BYTES, 1_073_741_824)
        self.assertEqual(p.GPU_CAUTION_BYTES, 536_870_912)
        self.assertEqual(p.OBSERVER_MAX_BYTES, 536_870_912)
        self.assertEqual(p.BASELINE_GPU_DRIFT_BYTES, 268_435_456)
        self.assertEqual((p.SAMPLE_PERIOD_NS, p.MAX_SAMPLE_GAP_NS, p.PRE_RELEASE_AGE_NS),
                         (100_000_000, 250_000_000, 150_000_000))
        self.assertEqual(p.host_reserve_bytes(128 * p.GIB), 16 * p.GIB)
        self.assertEqual(p.host_reserve_bytes(256 * p.GIB), 32 * p.GIB)
        self.assertEqual(p.device_reserve_bytes(256 * p.GIB), 16 * p.GIB)
        self.assertEqual(list(asdict(p.TIMEOUTS).values()),
                         [5_000_000_000, 10_000_000_000, 10_000_000_000, 10_000_000_000,
                          5_000_000_000, 45_000_000_000, 5_000_000_000, 5_000_000_000, 5_000_000_000])

    def test_matrix(self):
        initial = p.trial_matrix()
        self.assertEqual(len(initial), 12)
        self.assertEqual([t["handle_order"] for t in initial],
                         ["BL", "LB", "BL", "LB", "BL", "LB", "BL", "BL", "LB", "LB", "LB", "BL"])
        self.assertEqual(sum(t["state"] == "boot-cold" for t in initial), 4)
        self.assertEqual(len(p.trial_matrix(expanded=True)), 18)

    def test_expansion_authority_rejects_nonreferences_at_construction(self):
        for value in (None, "", " ", "\t", True, False, 1, 0, 1.5, {}, [],
                      {"reference": "chair"}, ["chair"], "a/b", "x\n", "x\x00"):
            with self.subTest(value=repr(value)), self.assertRaises((ProtocolError, ValueError)):
                Campaign("run1", expanded=True, expansion_authorization=value)
        for value in (1, 0, None, "true", {}, []):
            with self.subTest(expanded=value), self.assertRaises((ProtocolError, ValueError)):
                Campaign("run1", expanded=value, expansion_authorization="chair-approved-expansion")
        self.assertEqual(len(Campaign("run1", expanded=True, expansion_authorization="chair-approved-expansion").matrix), 18)

    def test_unavailable_measurements_preserve_outcome_comparison(self):
        rows = [self.row(duration_ns=None, memory_bytes=None, baseline_bytes=None, gpu_bytes=None,
                         ledger_disagreement_bytes=None, outcome="aborted", cleanup="FAIL"),
                self.row(order="LB")]
        result = p.evaluate_expansion(rows)
        self.assertIn("ORDER_FAILURE_CLEANUP_DIFFERENCE", result["reasons"])
        self.assertFalse(result["expansion_authorized"])
        self.assertTrue(result["missing_measurements"])


class CorrectionLifecycleTests(unittest.TestCase):
    def prepared(self):
        case = ControllerTests()
        case.setUp()
        return case

    def unreleased(self):
        case = self.prepared()
        old = case.controller
        case.controller = Controller("run1", "trial1", identity(), "BL", case.ports, case.sampler, case.clock)
        case.campaign = Campaign("run1")
        case.campaign.admit(case.controller, old.custody)
        return case, old.frames, old.proof

    def clear_worker(self, case):
        case.ports.exit_status = 1
        case.samples.values["worker_cgroup"].update(populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
        case.samples.values["worker_process"]["alive"] = False
        case.samples.values["gpu_process"].update(present=False, used_bytes=0)
        case.advance(2_200_000_000)
        return case.controller.complete_attempt()

    def mapped(self):
        case = self.prepared()
        case.controller.release()
        for name in p.MAPPING_ORDER:
            case.controller.worker_event(dict(event_type="CALL_START", call_name=name, raw_result=None, monotonic_raw_ns=case.clock()))
            case.clock.advance(10_000_000)
            case.controller.worker_event(dict(event_type="CALL_END", call_name=name, raw_result=0, monotonic_raw_ns=case.clock()))
        return case

    def test_inflated_baseline_cannot_weaken_live_growth_tripwire(self):
        case, frames, proof = self.unreleased()
        honest = copy.deepcopy(frames[-1][1])
        current = copy.deepcopy(honest)
        current["gpu_process"].update(present=False, used_bytes=0)
        current["gpu_device"]["used_bytes"] += 500 * p.MIB
        for _, frame in frames:
            frame["gpu_device"]["used_bytes"] += 300 * p.MIB
            frame["gpu_device"]["free_bytes"] -= 300 * p.MIB
        self.assertIn("UNATTRIBUTED_DEVICE", tripwires(current, honest))
        self.assertNotIn("UNATTRIBUTED_DEVICE", tripwires(current, frames[-1][1]))
        before = list(case.ports.actions)
        with self.assertRaises((ProtocolError, ObservationError)):
            case.controller.prepare(frames, proof, libraries())
        self.assertNotEqual(case.controller.state, "READY")
        self.assertEqual(case.ports.actions, before + ["cooperative"])
        self.assertTrue(case.campaign.stopped)

    def test_baseline_requires_latest_fresh_received_raw_sample(self):
        for defect in ("mismatch", "future", "stale", "late_receipt", "unavailable", "older_sample"):
            with self.subTest(defect=defect):
                case, frames, proof = self.unreleased()
                if defect == "mismatch":
                    frames[0][1]["observer_cgroup"]["memory_current_bytes"] += 1
                elif defect == "future":
                    frames[-1] = (case.clock() + 1, frames[-1][1])
                elif defect == "stale":
                    # A middle frame has no sample in the preceding 150 ms.
                    for journal in (case.sampler.records, case.sampler.raw_records):
                        journal[:] = [r for r in journal if
                            (r.get("raw", r))["sample_end_monotonic_raw_ns"] not in
                            (100_000_000, 200_000_000)]
                elif defect == "late_receipt":
                    case.sampler.raw_records[0]["received_ns"] = case.clock() + 1
                elif defect == "unavailable":
                    case.sampler.records.pop(0)
                    case.sampler.raw_records[0].update(eligible=False, rejection="unavailable")
                else:
                    case.sampler.records[6]["metrics"]["memory_current_bytes"] += 1
                    case.sampler.raw_records[6]["raw"]["metrics"]["memory_current_bytes"] += 1
                with self.assertRaises((ProtocolError, ObservationError)):
                    case.controller.prepare(frames, proof, libraries())
                self.assertTrue(case.campaign.stopped)

    def test_replay_failure_finalizes_invalid_retains_error_and_stops_campaign(self):
        from test_startup_characterization_schema import fixture, SCHEMA
        case = self.prepared()
        c = case.controller
        c.release()
        result = run("BL", Vendor(), c.worker_event, case.advance, clock=case.clock)
        self.assertEqual(result["exit_code"], 0)
        case.ports.exit_status = 0
        case.samples.values["worker_cgroup"].update(populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
        case.samples.values["worker_process"]["alive"] = False
        case.samples.values["gpu_process"].update(present=False, used_bytes=0)
        case.advance(2_200_000_000)
        self.assertEqual(c.state, "DONE")
        # Corrupt retained evidence after successful live gates, not the validator.
        c.identity_raw[0]["raw"]["identity"]["process_start_ticks"] += 1
        retained = copy.deepcopy(c.identity_raw)
        trial = json.loads(json.dumps(c.complete_attempt()))
        self.assertEqual(trial["verdict"], "invalid")
        validate_record("trial", trial)
        self.assertIn("REPLAY_VALIDATION_FAILURE", trial["reason_codes"])
        self.assertIn("identity", trial["replay_validation_error"]["message"])
        self.assertEqual(trial["evidence"]["identity_raw"], retained)
        self.assertEqual(c.state, "COMPLETED")
        self.assertFalse(c.valid)
        self.assertFalse(c.completed_valid)
        self.assertIsNone(case.campaign.active)
        self.assertTrue(case.campaign.stopped)
        self.assertEqual(case.campaign.attempts, [trial])
        with self.assertRaises(ProtocolError):
            case.campaign.admit(None, {})
        with self.assertRaises(ProtocolError):
            c.complete_attempt()
        with self.assertRaises(ProtocolError):
            validate_attempt(trial)
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest.update(run_id="run1", library_manifest=libraries())
        report = json.loads(render_report(manifest, [trial]).split("\n\n", 1)[1])
        self.assertFalse(any(report["acceptance"].values()))
        self.assertTrue(report["validation_errors"])
        self.assertEqual(report["attempts"][0]["replay_validation_error"], trial["replay_validation_error"])

    def test_identity_query_advancing_clock_passes_preparation_and_release(self):
        case, frames, proof = self.unreleased()
        query = case.ports.snapshot_identity
        remaining = [2]
        def advancing_query():
            if not remaining[0]:
                return query()
            remaining[0] -= 1
            case.clock.advance(10_000_000)
            observed = query()
            case.clock.advance(10_000_000)
            return observed
        case.ports.snapshot_identity = advancing_query
        case.controller.prepare(frames, proof, libraries())
        trial = case.finish_worker()
        self.assertEqual(trial["verdict"], "valid")
        validate_attempt(trial)
        release = next(e["monotonic_raw_ns"] for e in trial["evidence"]["events"] if e["event_type"] == "RELEASE")
        self.assertLessEqual(trial["evidence"]["identity_records"][1]["received_ns"], release)

    def test_identity_receipt_cannot_age_out_before_preparation_consumes_it(self):
        case, frames, proof = self.unreleased()
        configure = case.ports.configure_worker_cgroup
        def delayed_configure(*args):
            case.clock.advance(p.IDENTITY_AGE_NS + 1)
            return configure(*args)
        case.ports.configure_worker_cgroup = delayed_configure
        with self.assertRaises(ProtocolError):
            case.controller.prepare(frames, proof, libraries())
        self.assertTrue(case.campaign.stopped)
        self.assertNotIn("release", case.ports.actions)

    def test_identity_query_latency_cannot_expire_release_custody(self):
        case = self.prepared()
        query = case.ports.snapshot_identity
        def late_query():
            case.clock.advance(p.IDENTITY_AGE_NS + 1)
            return query()
        case.ports.snapshot_identity = late_query
        with self.assertRaises(ProtocolError):
            case.controller.release()
        self.assertNotIn("release", case.ports.actions)
        self.assertTrue(case.campaign.stopped)

    def test_identity_future_and_stale_receipts_fail_both_gates(self):
        for gate in ("prepare", "release"):
            for defect in ("future", "stale"):
                with self.subTest(gate=gate, defect=defect):
                    case, frames, proof = self.unreleased()
                    if gate == "release":
                        case.controller.prepare(frames, proof, libraries())
                    query = case.ports.snapshot_identity
                    def bad_query():
                        observed = query()
                        if defect == "future":
                            observed["observed_ns"] += 1
                        else:
                            case.clock.advance(p.IDENTITY_AGE_NS + 1)
                        return observed
                    case.ports.snapshot_identity = bad_query
                    with self.assertRaises((ProtocolError, ObservationError)):
                        if gate == "prepare":
                            case.controller.prepare(frames, proof, libraries())
                        else:
                            case.controller.release()
                    self.assertNotIn("release", case.ports.actions)
                    self.assertTrue(case.campaign.stopped)

    def test_mapping_observation_lower_boundary_and_staleness(self):
        for offset in (-1, 0):
            case = self.mapped()
            c = case.controller
            mapped = {n: [v] for n, v in libraries().items()}
            if offset < 0:
                with self.assertRaises(ProtocolError):
                    c.verify_mapping(mapped, case.clock() + offset)
                with self.assertRaises(ProtocolError):
                    c.worker_event(dict(event_type="CALL_START", call_name="cudaSetDevice", raw_result=None, monotonic_raw_ns=case.clock()))
                self.assertTrue(case.campaign.stopped)
            else:
                self.assertTrue(c.verify_mapping(mapped, case.clock()))
                self.assertEqual(c.mapping_records[-1]["received_ns"], case.clock())
        case = self.mapped()
        observed = case.clock()
        case.clock.advance(p.IDENTITY_AGE_NS + 1)
        with self.assertRaises(ProtocolError):
            case.controller.verify_mapping({n: [v] for n, v in libraries().items()}, observed)

    def test_terminal_mapping_must_follow_destruction(self):
        for offset in (-1, 0):
            case = self.prepared()
            c = case.controller
            c.release()
            mapped = {n: [v] for n, v in libraries().items()}
            result = worker_run("BL", Vendor(), c.worker_event, case.advance, clock=case.clock,
                mapping_gate=lambda: c.verify_mapping(mapped, case.clock()),
                terminal_gate=lambda: c.verify_mapping(mapped, case.clock() + offset, terminal=True))
            self.assertEqual(result["exit_code"], 1 if offset < 0 else 0)
            self.assertEqual(case.campaign.stopped, offset < 0)

    def test_prepare_identity_failure_is_sticky_across_retry_and_replacement(self):
        case, frames, proof = self.unreleased()
        c = case.controller
        case.ports.observed = replace(identity(), process_start_ticks=999)
        with self.assertRaises(ObservationError):
            c.prepare(frames, proof, libraries())
        self.assertTrue(case.campaign.stopped)
        case.ports.observed = identity()
        with self.assertRaises(ProtocolError):
            c.prepare(frames, proof, libraries())
        with self.assertRaises(ProtocolError):
            c.release()
        replacement = Controller("run1", "trial2", identity(), "BL", case.ports, case.sampler, case.clock)
        with self.assertRaises(ProtocolError):
            case.campaign.admit(replacement, c.custody)
        trial = self.clear_worker(case)
        self.assertEqual(trial["verdict"], "aborted")
        with self.assertRaises(ProtocolError):
            case.campaign.admit(replacement, dict(c.custody, ordinal=2, state="same-boot-warm", previous_trial_id="trial1"))
        self.assertNotIn("release", case.ports.actions)

    def test_unowned_controller_cannot_prepare(self):
        case = self.prepared()
        old = case.controller
        new = Controller("run1", "trial2", identity(), "BL", case.ports, case.sampler, case.clock)
        before = list(case.ports.actions)
        with self.assertRaises(ProtocolError):
            new.prepare(old.frames, old.proof, libraries())
        self.assertEqual(case.ports.actions, before)

    def test_malformed_preparation_identity_and_query_exception_finalize(self):
        for raw in (None, "wrong-type", {"identity": {}}, "exception"):
            case, frames, proof = self.unreleased()
            def query():
                if raw == "exception":
                    raise RuntimeError("offline identity query")
                return raw
            case.ports.snapshot_identity = query
            with self.assertRaises((ProtocolError, ObservationError)):
                case.controller.prepare(frames, proof, libraries())
            self.assertTrue(case.campaign.stopped)
            trial = json.loads(json.dumps(self.clear_worker(case)))
            validate_attempt(trial)
            journal = trial["evidence"]["identity_raw"]
            self.assertFalse(journal[0]["eligible"])
            self.assertTrue(journal[0]["rejection"])
            self.assertEqual(trial["evidence"]["identity_records"], [])
            if raw == "exception":
                self.assertEqual(journal[0]["raw"]["exception_type"], "RuntimeError")
            else:
                self.assertEqual(journal[0]["raw"], raw)

    def test_valid_identity_snapshots_are_separate_and_replay_bound(self):
        case = self.prepared()
        trial = case.finish_worker()
        self.assertTrue(trial["evidence"]["identity_records"])
        self.assertTrue(all(r["eligible"] for r in trial["evidence"]["identity_raw"]))
        bad = copy.deepcopy(trial)
        bad["evidence"]["identity_raw"][0]["raw"]["identity"]["process_start_ticks"] += 1
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)

    def test_malformed_running_identity_still_finalizes_raw_evidence(self):
        case = self.prepared()
        case.controller.release()
        case.ports.snapshot_identity = lambda: None
        case.advance(p.SAMPLE_PERIOD_NS)
        self.assertTrue(case.campaign.stopped)
        trial = json.loads(json.dumps(self.clear_worker(case)))
        self.assertEqual(trial["verdict"], "aborted")
        self.assertTrue(any(r["raw"] is None and not r["eligible"] for r in trial["evidence"]["identity_raw"]))
        validate_attempt(trial)

    def test_failed_attempts_and_empty_campaign_remain_reportable(self):
        # Import lazily to avoid the schema fixture module's import cycle.
        from test_startup_characterization_schema import fixture, SCHEMA
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest.update(run_id="run1", library_manifest=libraries())
        trials = []
        for failure in ("second_create", "timeout", "identity", "observer"):
            case = self.prepared()
            if failure == "second_create":
                trial = case.finish_worker("cublasLtCreate")
            else:
                if failure == "identity":
                    case.ports.observed = replace(identity(), process_start_ticks=999)
                    with self.assertRaises(ObservationError):
                        case.controller.release()
                else:
                    case.controller.release()
                    if failure == "timeout":
                        case.controller.worker_event(dict(event_type="CALL_START", call_name="libcudart", raw_result=None, monotonic_raw_ns=case.clock()))
                        case.advance(5_100_000_000)
                    else:
                        case.samples.enabled = False
                        case.advance(300_000_000)
                        case.samples.enabled = True
                trial = self.clear_worker(case) if failure != "observer" else self.finish_timeout(case)
            trials.append(trial)
            report = json.loads(render_report(manifest, [trial]).split("\n\n", 1)[1])
            self.assertFalse(report["acceptance"]["matrix_complete"])
            self.assertFalse(report["acceptance"]["all_attempts_valid"])
            self.assertTrue(report["acceptance"]["raw_evidence_crosschecked"])
            self.assertFalse(report["attempts"][0]["startup_duration_ns"]["available"])
        invalid = copy.deepcopy(trials[0])
        invalid["verdict"] = "invalid"
        report = json.loads(render_report(manifest, [invalid]).split("\n\n", 1)[1])
        self.assertFalse(report["acceptance"]["all_attempts_valid"])
        empty = json.loads(render_report(manifest, []).split("\n\n", 1)[1])
        self.assertFalse(any(empty["acceptance"].values()))

    def finish_timeout(self, case):
        case.advance(15 * p.SECOND_NS)
        return case.controller.complete_attempt()


if __name__ == "__main__":
    unittest.main()
