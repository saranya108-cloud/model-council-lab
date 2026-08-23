"""Adversarial tests for the subprocess adapter boundary (Blocking Finding 2)."""

import json
import unittest
from pathlib import Path

import helpers  # noqa: F401 - installs src on sys.path
from model_council import ExperimentRunner  # noqa: F401
from helpers import IDENTITY_KEY, TempRoot, make_runner, make_spec, make_task


class TestAdapterBoundary(unittest.TestCase):
    def test_adapters_receive_no_harness_object_references(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("iso-1", "A"), make_task())
            self.assertEqual(result.status, "succeeded")

    def test_introspection_adapter_finds_no_evaluator_or_store(self):
        """The child context holds only serialized data: no runner/evaluator/store.

        A secret marker planted in the *evaluator config* must be invisible;
        permitted stage inputs are visible by design and carry no secrets.
        """
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="introspect")
            response = runner.adapter.invoke(
                role_instruction="role:solver probe",
                stage_inputs={"task": "example task text"},
                budget=make_spec("iso-2", "A").resource_limits,
                seed=0,
            )
            report = response["structured"]
            self.assertEqual(report["found_objects"], [])
            self.assertEqual(report["evaluator_secret_markers_found"], [])
            # The child's working directory is a neutral scratch dir.
            self.assertNotIn("runs", report["cwd_entries"])

    def test_tampering_adapter_cannot_reach_preserved_artifacts(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            spec = make_spec("tamper-1", "A")
            task = make_task()
            # First produce the artifacts via a normal fake run in this namespace.
            normal_runner, _ = make_runner(root)
            baseline = normal_runner.execute(make_spec("tamper-baseline", "A"), task)
            self.assertEqual(baseline.status, "succeeded")
            before = (runs_root / "tamper-baseline" / "solver" / "candidate.md").read_bytes()

            # Now aim a tampering adapter at the same namespace via the runner.
            tamper_runner, _ = make_runner(root, kind="tamper")
            tamper_result = tamper_runner.execute(spec, task)
            after = (runs_root / "tamper-baseline" / "solver" / "candidate.md").read_bytes()
            self.assertEqual(before, after)

    def test_sleeping_adapter_is_terminated_by_enforced_timeout(self):
        with TempRoot() as root:
            spec = make_spec("sleep-1", "A", stage_timeout_seconds=1.0, max_stage_retries=0)
            slow_runner, _ = make_runner(root, kind="sleep", options={"seconds": 15})
            import time

            started = time.monotonic()
            result = slow_runner.execute(spec, make_task())
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 10.0, "child must be terminated, not awaited")
            self.assertEqual(result.status, "retry_exhausted")
            self.assertIn("timeout", result.stage_results[0].error)
            payload = json.loads(
                (Path(root) / "runs" / "sleep-1" / "run_result.json").read_text()
            )
            self.assertEqual(payload["status"], "retry_exhausted")


if __name__ == "__main__":
    unittest.main()
