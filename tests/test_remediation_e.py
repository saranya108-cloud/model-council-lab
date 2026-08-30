"""Deterministic closure tests for Remediation E trust-anchor and raw classification."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from helpers import TempRoot, make_runner, make_spec, make_task
from model_council import ArtifactStore, IntegrityViolation
from model_council.artifacts import RUN_AUTHORITY, RUN_AUTHORITY_SCHEMA
from model_council.invocation import KIND_UNTRUSTED_RAW_OUTPUT, classify_stored_raw_evidence
from model_council.protocol import HARNESS_PROTOCOL_VERSION
from test_invocation_evidence import _invocation_dir, _sample_record


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rewrite_frozen(path: Path, **updates) -> None:
    payload = json.loads(path.read_text())
    payload.update(updates)
    path.chmod(0o644)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    path.chmod(0o444)


def _rewrite_raw_meta(run_dir: Path, **updates) -> None:
    lines = []
    for line in (run_dir / "manifest.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry.get("kind") == KIND_UNTRUSTED_RAW_OUTPUT:
            entry.update(updates)
        lines.append(json.dumps(entry, sort_keys=True))
    (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")


def _record_raw(root, run_id, payload, limit):
    store = ArtifactStore(
        Path(root) / "runs",
        make_spec(run_id),
        max_raw_evidence_bytes=limit,
    )
    store.record_invocation("solver", 1, _sample_record(run_id), payload)
    report = store.verify_invocation_evidence()
    assert report["invocation_evidence_verified"]
    stored = (_invocation_dir(Path(root) / "runs" / run_id, "solver", 1) / "raw-output.txt").read_bytes()
    assert len(stored) <= limit
    return store, stored


class TestBidirectionalRawClassification(unittest.TestCase):
    def test_full_truncated_relabeled_false_fails(self):
        with TempRoot() as root:
            store, stored = _record_raw(root, "e-raw-full-false", "X" * 400, 100)
            self.assertEqual(classify_stored_raw_evidence(stored)["form"], "full")
            _rewrite_raw_meta(
                Path(root) / "runs" / "e-raw-full-false",
                truncated=False,
                observed_bytes=len(stored),
            )
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_minimal_truncated_relabeled_false_fails(self):
        with TempRoot() as root:
            store, stored = _record_raw(root, "e-raw-min-false", "X" * 80, 16)
            self.assertEqual(classify_stored_raw_evidence(stored)["form"], "minimal")
            _rewrite_raw_meta(
                Path(root) / "runs" / "e-raw-min-false",
                truncated=False,
                observed_bytes=len(stored),
            )
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_clipped_truncated_relabeled_false_fails(self):
        with TempRoot() as root:
            store, stored = _record_raw(root, "e-raw-clip-false", "X" * 40, 1)
            self.assertEqual(classify_stored_raw_evidence(stored)["form"], "clipped_minimal")
            _rewrite_raw_meta(
                Path(root) / "runs" / "e-raw-clip-false",
                truncated=False,
                observed_bytes=len(stored),
            )
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_inconsistent_observed_stored_sizes_fail(self):
        with TempRoot() as root:
            store, stored = _record_raw(root, "e-raw-obs-trunc", "X" * 400, 100)
            _rewrite_raw_meta(
                Path(root) / "runs" / "e-raw-obs-trunc",
                observed_bytes=len(stored) - 1,
            )
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()
        with TempRoot() as root:
            store, stored = _record_raw(root, "e-raw-obs-full", "short", 100)
            self.assertFalse(classify_stored_raw_evidence(stored)["truncated"])
            _rewrite_raw_meta(
                Path(root) / "runs" / "e-raw-obs-full",
                observed_bytes=len(stored) + 5,
            )
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_legitimate_bounds_and_unicode_still_verify(self):
        cases = (
            ("e-raw-ok-100", "X" * 400, 100, "full"),
            ("e-raw-ok-16", "X" * 80, 16, "minimal"),
            ("e-raw-ok-1", "X" * 40, 1, "clipped_minimal"),
            ("e-raw-ok-uni", "😀" * 80, 100, None),
        )
        for run_id, payload, limit, form in cases:
            with self.subTest(run_id=run_id):
                with TempRoot() as root:
                    store, stored = _record_raw(root, run_id, payload, limit)
                    view = classify_stored_raw_evidence(stored)
                    if form is not None:
                        self.assertEqual(view["form"], form)
                    store.verify_invocation_evidence()


class TestRunAuthority(unittest.TestCase):
    def _success(self, root, run_id):
        runner, runs_root = make_runner(root)
        result = runner.execute(make_spec(run_id, "A"), make_task())
        self.assertEqual(result.status, "succeeded")
        return runs_root, runs_root / run_id

    def test_authority_record_is_written_and_bound(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-ok")
            self.assertEqual(HARNESS_PROTOCOL_VERSION, "m1-dev-harness-v13")
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            self.assertEqual(authority["schema"], RUN_AUTHORITY_SCHEMA)
            self.assertEqual(authority["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertEqual(authority["run_id"], "e-auth-ok")
            self.assertEqual(authority["run_spec_sha256"], _sha256_path(run_dir / "run_spec.json"))
            self.assertEqual(authority["task_sha256"], _sha256_path(run_dir / "task.json"))
            self.assertEqual(
                authority["execution_binding_sha256"],
                _sha256_path(run_dir / "execution_binding.json"),
            )
            self.assertEqual(
                authority["evaluator_binding_sha256"],
                _sha256_path(run_dir / "evaluator_binding.json"),
            )
            self.assertEqual(
                authority["source_provenance_sha256"],
                _sha256_path(run_dir / "source_provenance.json"),
            )
            self.assertEqual(
                authority["treatment_declaration_sha256"],
                _sha256_path(run_dir / "treatment_declaration.json"),
            )
            report = ArtifactStore.verify_terminal_run(runs_root, "e-auth-ok")
            self.assertTrue(report["terminal_verified"])

    def test_missing_authority_record_fails_terminal_verify(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-missing")
            (run_dir / RUN_AUTHORITY).chmod(0o644)
            (run_dir / RUN_AUTHORITY).unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "e-auth-missing")

    def test_partial_authority_file_mutations_fail(self):
        files = (
            ("run_spec.json", {"spec_hash": "0" * 64}),
            ("task.json", {"task_content_hash": "0" * 64}),
            ("execution_binding.json", {"adapter_kind": "tamper"}),
            ("evaluator_binding.json", {"evaluator_version": "forged-eval"}),
            ("source_provenance.json", {"source_revision": "0" * 40}),
            ("treatment_declaration.json", {"treatment_hash": "0" * 64}),
        )
        for filename, updates in files:
            with self.subTest(filename=filename):
                with TempRoot() as root:
                    runs_root, run_dir = self._success(root, "e-auth-partial")
                    _rewrite_frozen(run_dir / filename, **updates)
                    with self.assertRaises(IntegrityViolation):
                        ArtifactStore.verify_terminal_run(runs_root, "e-auth-partial")

    def test_declaration_plus_terminal_without_authority_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-term")
            path = run_dir / "treatment_declaration.json"
            stored = json.loads(path.read_text())
            stored["declaration"]["adapter_kind"] = "tamper"
            stored["treatment_hash"] = "0" * 64
            path.chmod(0o644)
            path.write_text(json.dumps(stored, indent=2, sort_keys=True))
            path.chmod(0o444)
            result_path = run_dir / "run_result.json"
            result = json.loads(result_path.read_text())
            result["treatment_hash"] = "0" * 64
            result_path.write_text(json.dumps(result, indent=2, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "e-auth-term")

    def test_binding_declaration_terminal_without_authority_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-bind")
            _rewrite_frozen(run_dir / "execution_binding.json", adapter_kind="tamper")
            path = run_dir / "treatment_declaration.json"
            stored = json.loads(path.read_text())
            stored["declaration"]["adapter_kind"] = "tamper"
            stored["treatment_hash"] = "1" * 64
            path.chmod(0o644)
            path.write_text(json.dumps(stored, indent=2, sort_keys=True))
            path.chmod(0o444)
            result_path = run_dir / "run_result.json"
            result = json.loads(result_path.read_text())
            result["treatment_hash"] = "1" * 64
            result_path.write_text(json.dumps(result, indent=2, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "e-auth-bind")

    def test_entire_trust_anchor_rewrite_is_internally_consistent(self):
        """Expected under the trusted-ArtifactStore model: rewriting the
        authority record together with the bound file and terminal copy can
        produce an internally valid run. This is not claimed as a defense."""
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-all")
            provenance = json.loads((run_dir / "source_provenance.json").read_text())
            provenance["working_tree_dirty"] = not provenance.get("working_tree_dirty")
            provenance["uncommitted_implementation"] = provenance["working_tree_dirty"]
            _rewrite_frozen(run_dir / "source_provenance.json", **provenance)
            result_path = run_dir / "run_result.json"
            result = json.loads(result_path.read_text())
            result["source_provenance"] = json.loads((run_dir / "source_provenance.json").read_text())
            result_path.write_text(json.dumps(result, indent=2, sort_keys=True))
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            authority["source_provenance_sha256"] = _sha256_path(run_dir / "source_provenance.json")
            _rewrite_frozen(run_dir / RUN_AUTHORITY, **authority)
            report = ArtifactStore.verify_terminal_run(runs_root, "e-auth-all")
            self.assertTrue(report["terminal_verified"])

    def test_partial_evidence_does_not_require_authority(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "e-auth-partial-ev")
            (run_dir / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "e-auth-partial-ev")
            self.assertEqual(report["verification_scope"], "partial_evidence")
            self.assertFalse(report["terminal_verified"])


if __name__ == "__main__":
    unittest.main()
