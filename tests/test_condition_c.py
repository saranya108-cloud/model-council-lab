import json
import unittest
from pathlib import Path

from helpers import IDENTITY_KEY, TempRoot, make_runner, make_spec, make_task
from model_council.types import Finding, canonical_findings_text
from test_invocation_evidence import _invocation_dir

DEFAULT_V1 = Finding(
    finding_id="V1",
    description="confirm fix addresses reported behavior",
    material=True,
)
DEFAULT_V2 = Finding(
    finding_id="V2",
    description="second material finding",
    material=True,
)


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
        self.assertEqual(result.status, "succeeded")
        run_dir = Path(self.root) / "runs" / "run-c-2"
        findings = (run_dir / "verifier" / "findings.md").read_text()
        self.assertEqual(findings, canonical_findings_text((DEFAULT_V1,)))
        self.assertNotIn("hidden test", findings.lower())
        self.assertFalse((run_dir / "verifier" / "candidate.md").exists())
        raw = (_invocation_dir(run_dir, "verifier", 1) / "raw-output.txt").read_text()
        self.assertIn("prior candidate present: true", raw)
        self.assertNotIn("hidden test", raw.lower())

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
        self.assertEqual(findings, canonical_findings_text((DEFAULT_V1,)))
        raw = (_invocation_dir(run_dir, "verifier", 1) / "raw-output.txt").read_text()
        self.assertIn("SUFFICIENCY", raw)

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

    def test_zero_findings_remains_condition_c_and_accepts_empty_dispositions(self):
        runner, _ = make_runner(self.root, options={"empty_verifier_findings": True})
        result = runner.execute(make_spec("run-c-empty", "C"), make_task())
        self.assertEqual(result.status, "succeeded")
        self.assertEqual(
            [stage.role for stage in result.stage_results],
            ["solver", "verifier", "reviser"],
        )
        for stage in result.stage_results:
            self.assertEqual(stage.status.value, "succeeded")
        run_dir = Path(self.root) / "runs" / "run-c-empty"
        self.assertEqual(
            (run_dir / "verifier" / "findings.md").read_text(),
            canonical_findings_text(()),
        )
        reviser_inputs = runner.adapter.last_request["stage_inputs"]
        self.assertEqual(reviser_inputs["verifier_findings"], canonical_findings_text(()))
        self.assertIn("homogeneous role-separated council", result.workflow_note)

    def test_canonical_findings_handoff_matches_validated_structured_payload(self):
        result = self.runner.execute(make_spec("run-c-canonical", "C"), make_task())
        self.assertEqual(result.status, "succeeded")
        expected = canonical_findings_text((DEFAULT_V1,))
        run_dir = Path(self.root) / "runs" / "run-c-canonical"
        sealed = (run_dir / "verifier" / "findings.md").read_text()
        self.assertEqual(sealed, expected)
        payload = json.loads(sealed)
        self.assertEqual(
            payload,
            {
                "findings": [
                    {
                        "finding_id": "V1",
                        "description": "confirm fix addresses reported behavior",
                        "material": True,
                    }
                ]
            },
        )
        reviser_inputs = self.runner.adapter.last_request["stage_inputs"]
        self.assertEqual(reviser_inputs["verifier_findings"], expected)
        self.assertEqual(payload["findings"][0]["finding_id"], DEFAULT_V1.finding_id)
        self.assertEqual(payload["findings"][0]["description"], DEFAULT_V1.description)

    def test_divergent_verifier_prose_cannot_alter_accepted_findings(self):
        runner, _ = make_runner(self.root, options={"divergent_findings_prose": True})
        result = runner.execute(make_spec("run-c-divergent", "C"), make_task())
        self.assertEqual(result.status, "succeeded")
        expected = canonical_findings_text((DEFAULT_V1,))
        run_dir = Path(self.root) / "runs" / "run-c-divergent"
        sealed = (run_dir / "verifier" / "findings.md").read_text()
        self.assertEqual(sealed, expected)
        self.assertNotIn("V9", sealed)
        reviser_inputs = runner.adapter.last_request["stage_inputs"]
        self.assertEqual(reviser_inputs["verifier_findings"], expected)
        self.assertNotIn("V9", reviser_inputs["verifier_findings"])
        raw = (_invocation_dir(run_dir, "verifier", 1) / "raw-output.txt").read_text()
        self.assertIn("V9", raw)
        self.assertIn("extra finding present only in free-text artifact", raw)

    def test_extra_finding_ids_and_descriptions_remain_canonical(self):
        runner, _ = make_runner(self.root, options={"verifier_extra_finding": True})
        result = runner.execute(make_spec("run-c-ids", "C"), make_task())
        self.assertEqual(result.status, "succeeded")
        expected = canonical_findings_text((DEFAULT_V1, DEFAULT_V2))
        run_dir = Path(self.root) / "runs" / "run-c-ids"
        self.assertEqual((run_dir / "verifier" / "findings.md").read_text(), expected)
        self.assertEqual(
            runner.adapter.last_request["stage_inputs"]["verifier_findings"],
            expected,
        )
        payload = json.loads(expected)
        self.assertEqual(
            [(item["finding_id"], item["description"]) for item in payload["findings"]],
            [
                ("V1", "confirm fix addresses reported behavior"),
                ("V2", "second material finding"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
