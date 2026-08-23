import json
import unittest
from pathlib import Path

from model_council import Condition, GovernanceViolation, ResourceLimits, RunSpec
from model_council.artifacts import ArtifactStore, EVENT_EVALUATION
from helpers import IDENTITY_KEY, TempRoot


def make_spec(run_id, condition="A", retries=2):
    return RunSpec(
        run_id=run_id,
        task_id="dev-001",
        condition=Condition(condition),
        model_identifier=IDENTITY_KEY,
        prompt_version="p",
        resource_limits=ResourceLimits(max_stage_retries=retries),
    )


class TestArtifactStore(unittest.TestCase):
    def setUp(self):
        self._tmp = TempRoot()
        self.root = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)

    def test_run_directory_structure_created_with_stage_dirs(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-1", "C"))
        self.assertTrue((store.run_dir / "run_spec.json").exists())
        for role in ("solver", "verifier", "reviser"):
            self.assertTrue((store.run_dir / role).is_dir())

    def test_run_spec_frozen_and_matches_spec_hash(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-2"))
        payload = json.loads((store.run_dir / "run_spec.json").read_text())
        self.assertEqual(payload["spec_hash"], make_spec("art-2").spec_hash)
        self.assertIn('"task_id":"dev-001"', payload["canonical"])

    def test_write_read_roundtrip_and_refs_are_relative(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-3"))
        ref = store.write("solver", "candidate", "hello")
        self.assertFalse(Path(ref).is_absolute())
        self.assertEqual(store.read(ref), "hello")

    def test_duplicate_write_rejected(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-4", "C"))
        store.write("verifier", "findings", "first")
        with self.assertRaises(GovernanceViolation):
            store.write("verifier", "findings", "second")

    def test_role_outside_condition_rejected(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-5", "A"))
        with self.assertRaises(GovernanceViolation):
            store.write("verifier", "findings", "not in condition A")

    def test_event_files_are_write_once_and_constants_only(self):
        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-6"))
        store.record_event(EVENT_EVALUATION, {"outcome": {"passed": True}})
        with self.assertRaises(GovernanceViolation):
            store.record_event(EVENT_EVALUATION, {"outcome": {"passed": False}})

    def test_manifest_records_sha256_for_every_write(self):
        import hashlib

        store = ArtifactStore(Path(self.root) / "runs", make_spec("art-7", "A"))
        ref = store.write("solver", "candidate", "payload bytes")
        manifest_path = Path(self.root) / "runs" / "art-7" / "manifest.jsonl"
        entry = json.loads(manifest_path.read_text().splitlines()[0])
        self.assertEqual(entry["role"], "solver")
        self.assertEqual(entry["sha256"], hashlib.sha256(b"payload bytes").hexdigest())


if __name__ == "__main__":
    unittest.main()
