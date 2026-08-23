import json
import unittest
from pathlib import Path

from helpers import IDENTITY_KEY, TempRoot, make_runner, make_spec, make_task


class TestConditionC(unittest.TestCase):
    def setUp(self):
        self._tmp = TempRoot()
        self.root = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.runner, self.runs_root = make_runner(self.root)

    def test_council_order_and_homogeneous_verified_identity(self):
        result = self.runner.execute(make_spec("run-c-1", "C"), make_task())
        roles = [s.role for s in result.stage_results]
        self.assertEqual(roles, ["solver", "verifier", "reviser"])
        identities = {s.verified_identity["identity_key"] for s in result.stage_results}
        self.assertEqual(identities, {IDENTITY_KEY})
        self.assertIn("homogeneous role-separated council", result.workflow_note)

    def test_verifier_context_isolation_via_preserved_artifacts(self):
        result = self.runner.execute(make_spec("run-c-2", "C"), make_task())
        run_dir = Path(self.root) / "runs" / "run-c-2"
        findings = (run_dir / "verifier" / "findings.md").read_text()
        # The verifier saw the candidate (digest echoed) but no hidden info.
        self.assertIn("prior candidate present: true", findings)
        self.assertNotIn("hidden test", findings.lower())
        # Verifier produced its own artifact; it never wrote a candidate.
        self.assertFalse((run_dir / "verifier" / "candidate.md").exists())

    def test_solver_candidate_preserved_byte_identical_after_revision(self):
        result = self.runner.execute(make_spec("run-c-3", "C"), make_task())
        run_dir = Path(self.root) / "runs" / "run-c-3"
        candidate_bytes = (run_dir / "solver" / "candidate.md").read_bytes()
        final_text = (run_dir / result.final_candidate_ref).read_text()
        digest_line = [
            ln for ln in candidate_bytes.decode().splitlines() if "PROPOSED_FIX" in ln
        ][0]
        digest = digest_line.split("[")[1].split("]")[0]
        self.assertIn(digest, final_text)
        # The final candidate embeds the preserved solver work product.
        self.assertIn("# Candidate (solver)", final_text)
        self.assertNotEqual(candidate_bytes.decode(), final_text)

    def test_evidence_artifact_separate_from_candidate(self):
        self.runner.execute(make_spec("run-c-4", "C"), make_task())
        run_dir = Path(self.root) / "runs" / "run-c-4"
        evidence = (run_dir / "solver" / "evidence.md").read_text()
        candidate = (run_dir / "solver" / "candidate.md").read_text()
        findings = (run_dir / "verifier" / "findings.md").read_text()
        self.assertIn("# Evidence", evidence)
        self.assertIn("# Candidate", candidate)
        self.assertIn("SUFFICIENCY", findings)

    def test_reviser_dispositions_cover_all_findings(self):
        runner, _ = make_runner(self.root, options={"verifier_extra_finding": True})
        result = runner.execute(make_spec("run-c-5", "C"), make_task())
        self.assertEqual(result.status, "succeeded")
        payload = json.loads(
            (Path(self.root) / "runs" / "run-c-5" / "run_result.json").read_text()
        )
        self.assertTrue(payload["evaluation"]["passed"])

    def test_integrity_verified_at_completion(self):
        result = self.runner.execute(make_spec("run-c-6", "C"), make_task())
        self.assertTrue(result.metadata["integrity"]["integrity_verified"])
        payload = json.loads(
            (Path(self.root) / "runs" / "run-c-6" / "integrity_check.json").read_text()
        )
        self.assertEqual(set(payload["stages"]), {"solver", "verifier", "reviser"})


if __name__ == "__main__":
    unittest.main()
