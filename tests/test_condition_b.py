import json
import unittest
from pathlib import Path

from helpers import IDENTITY_KEY, TempRoot, make_runner, make_spec, make_task


class TestConditionB(unittest.TestCase):
    def setUp(self):
        self._tmp = TempRoot()
        self.root = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.runner, self.runs_root = make_runner(self.root)

    def test_three_stages_in_order_same_verified_identity(self):
        result = self.runner.execute(make_spec("run-b-1", "B"), make_task())
        roles = [s.role for s in result.stage_results]
        self.assertEqual(roles, ["draft", "self_review", "reviser"])
        for stage in result.stage_results:
            self.assertEqual(stage.status.value, "succeeded")
            self.assertEqual(stage.verified_identity["identity_key"], IDENTITY_KEY)
        self.assertIn("serial self-refinement", result.workflow_note)
        self.assertIn("not independent best-of-N", result.workflow_note)

    def test_stage_inputs_follow_refinement_chain(self):
        self.runner.execute(make_spec("run-b-2", "B"), make_task())
        run_dir = Path(self.root) / "runs" / "run-b-2"
        # Chain visibility is proven via preserved artifacts: the reviser's
        # final candidate embeds the draft content (solver/draft text).
        draft_text = (run_dir / "draft" / "draft.md").read_text()
        final_text = (run_dir / "reviser" / "final_candidate.md").read_text()
        digest_line = [ln for ln in draft_text.splitlines() if "PROPOSED_FIX" in ln][0]
        digest = digest_line.split("[")[1].split("]")[0]
        self.assertIn(digest, final_text)
        self.assertIn("# Dispositions", final_text)

    def test_each_stage_preserved_separately_and_evaluated_once_at_end(self):
        result = self.runner.execute(make_spec("run-b-3", "B"), make_task())
        run_dir = Path(self.root) / "runs" / "run-b-3"
        for role in ("draft", "self_review", "reviser"):
            self.assertTrue((run_dir / role).is_dir())
            self.assertTrue(any((run_dir / role).iterdir()))
        self.assertTrue((run_dir / "evaluation.json").exists())
        self.assertTrue(result.evaluation.passed)

    def test_audit_trail_output_refs_populated(self):
        result = self.runner.execute(make_spec("run-b-4", "B"), make_task())
        by_role = {s.role: s for s in result.stage_results}
        self.assertEqual(by_role["draft"].output_refs, ("draft/draft.md",))
        self.assertEqual(by_role["self_review"].output_refs, ("self_review/self_review.md",))
        self.assertEqual(
            by_role["reviser"].output_refs, ("reviser/final_candidate.md",)
        )


if __name__ == "__main__":
    unittest.main()
