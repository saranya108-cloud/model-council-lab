import dataclasses
import unittest

from tools.decision_0009.acer_adapter.evidence import (
    AttributionUnavailable, enforce_f5_mapping, normalize_gpu_attribution,
)
from acer_adapter_fakes import GPU_UUID, identity


def query(entries=(), complete=True, gpu_uuid=GPU_UUID,
          api_families=("nvml-compute", "nvml-graphics"), error=None,
          pid_namespace="pidns-1", namespace_pid=1,
          cgroup_path="/workers/token-1", domain_members=(123,)):
    return {"entries": tuple(entries), "complete": complete, "gpu_uuid": gpu_uuid,
            "api_families": api_families, "api_identity": "offline-nvml-fixture",
            "api_version": "fixture-v1", "error": error,
            "pre_observed_ns": 9, "start_ns": 10, "end_ns": 20,
            "post_observed_ns": 21, "received_ns": 22,
            "pid_namespace": pid_namespace, "namespace_pid": namespace_pid,
            "cgroup_path": cgroup_path, "domain_members": domain_members}


class AttributionTests(unittest.TestCase):
    def test_exact_worker_entry_is_attributed(self):
        process = identity()
        result = normalize_gpu_attribution(process, query(({
            "host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
            "context_id": "ctx-1", "used_bytes": 4096,
        },)), process)
        self.assertTrue(result.available)
        self.assertEqual(result.used_bytes, 4096)

    def test_pid_reuse_namespace_ambiguity_and_wrong_gpu_are_unavailable(self):
        process = identity()
        cases = (
            (dataclasses.replace(process, process_start_ticks=999), process),
            (dataclasses.replace(process, pid_namespace="other"), process),
            (process, dataclasses.replace(process, gpu_uuid="GPU-wrong")),
        )
        for pre, post in cases:
            with self.subTest(pre=pre, post=post), self.assertRaises(AttributionUnavailable):
                normalize_gpu_attribution(pre, query(), post)

    def test_unavailable_partial_sentinel_and_conflicting_accounting_never_become_zero(self):
        process = identity()
        cases = (
            query(complete=False),
            query(error="permission"),
            query(({"host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
                    "context_id": "ctx", "used_bytes": None},)),
            query(({"host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
                    "context_id": "ctx", "used_bytes": 1},
                   {"host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
                    "context_id": "ctx", "used_bytes": 2})),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(AttributionUnavailable):
                normalize_gpu_attribution(process, candidate, process)

    def test_exact_duplicates_may_collapse_but_ambiguous_contexts_do_not_sum(self):
        process = identity()
        entry = {"host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
                 "context_id": "ctx", "used_bytes": 10}
        self.assertEqual(normalize_gpu_attribution(process, query((entry, dict(entry))), process).used_bytes, 10)
        other = dict(entry, context_id="ctx-2")
        with self.assertRaises(AttributionUnavailable):
            normalize_gpu_attribution(process, query((entry, other)), process)

    def test_f5_missing_libcuda_extra_family_or_expected_as_observed_fails_closed(self):
        exact = {name: "observed-" + name for name in ("libcudart", "libcublasLt", "libcublas", "libcuda")}
        enforce_f5_mapping(exact, exact)
        for observed in ({k: v for k, v in exact.items() if k != "libcuda"},
                         {**exact, "extra": "x"},
                         {**exact, "libcuda": None}):
            with self.subTest(observed=observed), self.assertRaises(AttributionUnavailable):
                enforce_f5_mapping(exact, observed)

    def test_helpers_and_incomplete_api_coverage_are_unavailable(self):
        process = identity()
        worker = {"host_pid": 123, "start_ticks": 456, "gpu_uuid": GPU_UUID,
                  "context_id": "ctx", "used_bytes": 0}
        helper = {"host_pid": 124, "start_ticks": 457, "gpu_uuid": GPU_UUID,
                  "context_id": "helper", "used_bytes": 1}
        for candidate in (query((worker,), api_families=("nvml-compute",)),
                          query((worker, helper))):
            with self.subTest(candidate=candidate), self.assertRaises(AttributionUnavailable):
                normalize_gpu_attribution(process, candidate, process)
        helper_identity = dataclasses.replace(process, cgroup_members=(123, 124))
        with self.assertRaises(AttributionUnavailable):
            normalize_gpu_attribution(
                helper_identity, query((worker,), domain_members=(123, 124)), helper_identity)
        with self.assertRaises(AttributionUnavailable):
            normalize_gpu_attribution(process, query((worker,), namespace_pid=2), process)
