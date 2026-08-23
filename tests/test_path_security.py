import unittest
from pathlib import Path

from model_council import Condition, GovernanceViolation, RunSpec, ResourceLimits, safe_identifier
from model_council.artifacts import ArtifactStore, ALLOWED_EVENTS, EVENT_EVALUATION
from helpers import FAKE_IDENTITY, TempRoot, make_task


def make_spec(run_id, condition="A"):
    return RunSpec(
        run_id=run_id,
        task_id="dev-001",
        condition=Condition(condition),
        model_identifier=FAKE_IDENTITY.key(),
        prompt_version="p",
        resource_limits=ResourceLimits(),
    )


class UnsafeRunIdTests(unittest.TestCase):
    UNSAFE = [
        "../escape",
        "../../escape",
        "/tmp/escape",
        "runs/../escape",
        "a/b",
        "a\\b",
        ".",
        "..",
        "",
        " ",
        ".hidden",
        "run\nid",
        "run\x00id",
    ]

    def test_store_rejects_traversal_and_separator_run_ids(self):
        with TempRoot() as root:
            runs_root = Path(root) / "runs"
            for run_id in self.UNSAFE:
                with self.assertRaises(GovernanceViolation, msg=run_id):
                    ArtifactStore(runs_root, make_spec(run_id))

    def test_no_directory_created_by_unsafe_ids(self):
        with TempRoot() as root:
            runs_root = Path(root) / "runs"
            for run_id in self.UNSAFE:
                try:
                    ArtifactStore(runs_root, make_spec(run_id))
                except GovernanceViolation:
                    pass
            # Nothing escaped the (not yet created) namespace or polluted root.
            self.assertFalse((Path(root) / "escape").exists())
            self.assertFalse((Path(root) / "tmp").exists())

    def test_safe_identifiers_still_accepted(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("run-2026_08.a-b"))
            self.assertTrue(store.run_dir.is_dir())

    def test_safe_identifier_policy_unit(self):
        for value in ("ok", "Run_1.2-3"):
            self.assertEqual(safe_identifier(value), value)
        for value in ("../x", "/abs", "a/b", ".", "..", "", None, 5):
            with self.assertRaises(GovernanceViolation):
                safe_identifier(value)


class EventPathTests(unittest.TestCase):
    def test_event_names_are_internal_constants_only(self):
        self.assertEqual(ALLOWED_EVENTS, frozenset({
            "evaluation.json",
            "run_result.json",
            "governance_violation.json",
            "integrity_check.json",
        }))

    def test_event_filename_traversal_rejected(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("evt-1"))
            for bad in ("../../evil.json", "sub/dir/x.json", "x/../../y.json"):
                with self.assertRaises(GovernanceViolation):
                    store.record_event(bad, {"payload": True})
            ref = store.record_event(EVENT_EVALUATION, {"outcome": {"passed": True}})
            self.assertEqual(ref, EVENT_EVALUATION)

    def test_artifact_ref_read_containment(self):
        with TempRoot() as root:
            store_a = ArtifactStore(Path(root) / "runs2", make_spec("ref-2", "A"))
            store_a.write("solver", "candidate", "content")
            self.assertEqual(store_a.read("solver/candidate.md"), "content")
            for bad in (
                "../../run_spec.json",
                "/etc/passwd",
                "solver/../../../outside.md",
                "solver/candidate.md/../../seals/x.json",
            ):
                with self.assertRaises(GovernanceViolation):
                    store_a.read(bad)

    def test_artifact_name_validation(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("name-1", "A"))
            for bad in ("../candidate", "sub/name", ".", ".."):
                with self.assertRaises(GovernanceViolation):
                    store.write("solver", bad, "content")


if __name__ == "__main__":
    unittest.main()
