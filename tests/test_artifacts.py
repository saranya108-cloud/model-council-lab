import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import Condition, GovernanceViolation, IntegrityViolation, ResourceLimits, RunSpec
from model_council.artifacts import (
    CONSTRUCTOR_STAGING_PREFIX,
    EVENT_EVALUATION,
    EVENT_RUN_RESULT,
    ArtifactStore,
)
from model_council.security import sha256_text
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


def _constructor_staging_dirs(runs_root: Path) -> list[Path]:
    if not runs_root.is_dir():
        return []
    return sorted(
        path
        for path in runs_root.iterdir()
        if path.name.startswith(CONSTRUCTOR_STAGING_PREFIX)
    )


def _tree_snapshot(root: Path) -> dict[str, str]:
    snapshot = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            snapshot[rel] = f"symlink:{path.readlink()}"
        elif path.is_dir():
            snapshot[rel] = "dir"
        elif path.is_file():
            snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


class TestConstructorPublication(unittest.TestCase):
    def setUp(self):
        self._tmp = TempRoot()
        self.root = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.runs_root = Path(self.root) / "runs"

    def _assert_no_canonical_residue(self, run_id: str) -> None:
        canonical = self.runs_root / run_id
        self.assertFalse(canonical.exists(), f"canonical run directory remained: {canonical}")
        self.assertFalse((canonical / EVENT_RUN_RESULT).exists())
        self.assertEqual(_constructor_staging_dirs(self.runs_root), [])

    def _assert_retry_succeeds(self, run_id: str) -> ArtifactStore:
        store = ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self.assertEqual(store.run_dir, (self.runs_root / run_id).resolve())
        self.assertEqual(store.spec_path, store.run_dir / "run_spec.json")
        self.assertTrue(store.spec_path.is_file())
        self.assertTrue((store.run_dir / "solver").is_dir())
        self.assertEqual(_constructor_staging_dirs(self.runs_root), [])
        return store

    def test_role_directory_failure_does_not_publish_canonical(self):
        run_id = "l1-role-mkdir"
        original = Path.mkdir

        def wrapped(self, *args, **kwargs):
            if self.name == "solver":
                raise OSError("injected role-directory failure")
            return original(self, *args, **kwargs)

        with patch.object(Path, "mkdir", wrapped):
            with self.assertRaises(OSError):
                ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self._assert_no_canonical_residue(run_id)
        self._assert_retry_succeeds(run_id)

    def test_run_spec_write_failure_does_not_publish_canonical(self):
        run_id = "l1-spec-write"
        original = Path.write_text

        def wrapped(self, *args, **kwargs):
            if self.name == "run_spec.json":
                raise OSError("injected run_spec.json write failure")
            return original(self, *args, **kwargs)

        with patch.object(Path, "write_text", wrapped):
            with self.assertRaises(OSError):
                ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self._assert_no_canonical_residue(run_id)
        self._assert_retry_succeeds(run_id)

    def test_run_spec_chmod_failure_does_not_publish_canonical(self):
        run_id = "l1-spec-chmod"
        original = Path.chmod

        def wrapped(self, mode, *args, **kwargs):
            if self.name == "run_spec.json":
                raise OSError("injected run_spec.json chmod failure")
            return original(self, mode, *args, **kwargs)

        with patch.object(Path, "chmod", wrapped):
            with self.assertRaises(OSError):
                ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self._assert_no_canonical_residue(run_id)
        self._assert_retry_succeeds(run_id)

    def test_preexisting_canonical_run_directory_is_never_modified(self):
        run_id = "l1-preexisting"
        store = ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        marker = store.run_dir / "keep-me.txt"
        marker.write_text("original-canonical-contents", encoding="utf-8")
        before = _tree_snapshot(store.run_dir)
        with self.assertRaises(GovernanceViolation) as raised:
            ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self.assertIn("already exists", str(raised.exception))
        self.assertEqual(_tree_snapshot(store.run_dir), before)
        self.assertEqual(marker.read_text(encoding="utf-8"), "original-canonical-contents")
        self.assertEqual(_constructor_staging_dirs(self.runs_root), [])

    def test_published_paths_point_at_canonical_run_directory(self):
        store = ArtifactStore(self.runs_root, make_spec("l1-published", "C"))
        self.assertEqual(store.run_dir.name, "l1-published")
        self.assertTrue(store.run_dir.is_relative_to(self.runs_root.resolve()))
        self.assertEqual(store.spec_path, store.run_dir / "run_spec.json")
        self.assertFalse(store.spec_path.as_posix().startswith(CONSTRUCTOR_STAGING_PREFIX))
        self.assertEqual(_constructor_staging_dirs(self.runs_root), [])

    def test_keyboard_interrupt_immediately_after_rename_does_not_pin_run_id(self):
        """Sol L1 remainder: rename syscall completed, published flag never set."""
        run_id = "l1-post-rename-ki"
        neighbor = ArtifactStore(self.runs_root, make_spec("l1-post-rename-neighbor", "A"))
        marker = neighbor.run_dir / "keep-me.txt"
        marker.write_text("unrelated-canonical-contents", encoding="utf-8")
        before = _tree_snapshot(neighbor.run_dir)
        original = Path.rename

        def wrapped(path_self, target):
            result = original(path_self, target)
            if Path(target).name == run_id:
                raise KeyboardInterrupt
            return result

        with patch.object(Path, "rename", wrapped):
            with self.assertRaises(KeyboardInterrupt):
                ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        self._assert_no_canonical_residue(run_id)
        self.assertEqual(_tree_snapshot(neighbor.run_dir), before)
        self.assertEqual(marker.read_text(encoding="utf-8"), "unrelated-canonical-contents")
        self._assert_retry_succeeds(run_id)


def _recompute_seal_digest(seal: dict) -> None:
    body = {
        "artifacts": seal.get("artifacts"),
        "invocations": seal.get("invocations") if "invocations" in seal else [],
        "expected_attempts": seal.get("expected_attempts", 0),
    }
    seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))


class TestMalformedSealShapes(unittest.TestCase):
    def setUp(self):
        self._tmp = TempRoot()
        self.root = self._tmp.__enter__()
        self.addCleanup(self._tmp.__exit__, None, None, None)
        self.runs_root = Path(self.root) / "runs"

    def _sealed_solver(self, run_id: str) -> ArtifactStore:
        store = ArtifactStore(self.runs_root, make_spec(run_id, "A"))
        store.write("solver", "candidate", "candidate-body")
        store.write("solver", "evidence", "evidence-body")
        store.seal_stage("solver")
        return store

    def _mutate_seal(self, store: ArtifactStore, mutator) -> None:
        path = store.run_dir / "seals" / "solver.json"
        seal = json.loads(path.read_text(encoding="utf-8"))
        mutator(seal)
        _recompute_seal_digest(seal)
        path.write_text(json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")

    def test_valid_seal_positive_control_verifies(self):
        store = self._sealed_solver("seal-shape-valid")
        store.verify_sealed_stage("solver")

    def test_invocations_explicit_null_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-inv-explicit-null")
        path = store.run_dir / "seals" / "solver.json"
        seal = json.loads(path.read_text(encoding="utf-8"))
        seal["invocations"] = None
        body = {
            "artifacts": seal.get("artifacts"),
            "invocations": [],
            "expected_attempts": seal.get("expected_attempts", 0),
        }
        seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
        path.write_text(json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_empty_invocations_list_remains_valid(self):
        store = self._sealed_solver("seal-shape-inv-empty-list")
        path = store.run_dir / "seals" / "solver.json"
        seal = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(seal["invocations"], [])
        self._mutate_seal(store, lambda value: value.update({"invocations": []}))
        store.verify_sealed_stage("solver")

    def test_omitted_invocations_field_remains_valid(self):
        store = self._sealed_solver("seal-shape-inv-omitted")

        def mutate(seal):
            seal.pop("invocations", None)

        self._mutate_seal(store, mutate)
        store.verify_sealed_stage("solver")

    def test_invocations_list_of_int_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-inv-int")
        self._mutate_seal(store, lambda seal: seal.update({"invocations": [1]}))
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_invocation_entry_as_string_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-inv-str")
        self._mutate_seal(store, lambda seal: seal.update({"invocations": ["not-an-object"]}))
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_invocation_entry_as_null_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-inv-null")
        self._mutate_seal(store, lambda seal: seal.update({"invocations": [None]}))
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_artifact_entry_wrong_container_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-art-list")
        self._mutate_seal(store, lambda seal: seal.update({"artifacts": [["candidate"]]}))
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_nested_artifact_digest_wrong_type_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-digest-type")

        def mutate(seal):
            seal["artifacts"][0]["sha256"] = 123

        self._mutate_seal(store, mutate)
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")

    def test_nested_invocation_digest_wrong_type_is_integrity_violation(self):
        store = self._sealed_solver("seal-shape-inv-digest")
        self._mutate_seal(
            store,
            lambda seal: seal.update(
                {
                    "invocations": [
                        {
                            "kind": "invocation_metadata",
                            "attempt": 1,
                            "ref": "invocations/solver/attempt-0001/invocation.json",
                            "sha256": 123,
                            "bytes": 1,
                        }
                    ]
                }
            ),
        )
        with self.assertRaises(IntegrityViolation):
            store.verify_sealed_stage("solver")


if __name__ == "__main__":
    unittest.main()
