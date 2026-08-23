import json
import unittest
from pathlib import Path

from helpers import (
    IDENTITY_KEY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
)


class TestConditionA(unittest.TestCase):
    def test_single_stage_single_invocation_passes_evaluation(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("run-a-1", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(result.stage_results), 1)
            self.assertEqual(result.stage_results[0].role, "solver")
            self.assertEqual(
                result.stage_results[0].verified_identity["identity_key"], IDENTITY_KEY
            )
            self.assertIsNotNone(result.final_candidate_ref)
            self.assertTrue(result.evaluation.passed)
            self.assertEqual(result.retries_used, 0)
            self.assertIn("not call-matched", result.workflow_note)

    def test_candidate_artifact_preserved_and_readable(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("run-a-2", "A"), make_task())
            candidate = (runs_root / "run-a-2" / result.final_candidate_ref).read_text()
            self.assertIn("PROPOSED_FIX", candidate)

    def test_determinism_same_spec_same_output(self):
        outputs = []
        for i in range(2):
            with TempRoot() as root:
                runner, _ = make_runner(root)
                spec = make_spec(f"run-a-det-{i}", "A", seed=42)
                result = runner.execute(spec, make_task())
                self.assertTrue(result.evaluation.passed)
                run_dir = Path(root) / "runs" / f"run-a-det-{i}"
                outputs.append((run_dir / result.final_candidate_ref).read_text())
        self.assertEqual(outputs[0], outputs[1])

    def test_run_result_terminal_record_written(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("run-a-3", "A"), make_task())
            payload = json.loads((Path(root) / "runs" / "run-a-3" / "run_result.json").read_text())
            self.assertEqual(payload["status"], "succeeded")
            output_names = [ref.split("/")[-1] for ref in payload["stages"][0]["output_refs"]]
            self.assertIn("candidate.md", output_names)
            self.assertIn("evidence.md", output_names)


if __name__ == "__main__":
    unittest.main()
