"""Deterministic closure tests for remaining SOL findings (Remediation D)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import TempRoot, make_runner, make_spec, make_task
from model_council import ArtifactStore, IntegrityViolation
from model_council.invocation import (
    KIND_UNTRUSTED_RAW_OUTPUT,
    bound_raw_evidence,
    classify_stored_raw_evidence,
)
from model_council.runner import ExperimentRunner
from model_council.security import digest_json
from test_invocation_evidence import _invocation_dir, _sample_record
from test_remediation_c import _no_promoted_success, _rewrite_json
from test_runner_invariants import ControllableClock


class TestPostCommitDeadlineAbort(unittest.TestCase):
    def test_clock_jump_after_commit_returns_aborts_success(self):
        clock = ControllableClock(1_000.0)
        original = ExperimentRunner._commit_stage_transaction

        def wrapped(runner, **kwargs):
            refs = original(runner, **kwargs)
            clock.advance(10.0)
            return refs

        with TempRoot() as root:
            runner, runs_root = make_runner(root, monotonic=clock)
            with patch.object(ExperimentRunner, "_commit_stage_transaction", wrapped):
                result = runner.execute(
                    make_spec(
                        "d-dl-post-commit",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertNotEqual(result.status, "succeeded")
            self.assertIsNone(result.evaluation)
            _no_promoted_success(runs_root / "d-dl-post-commit")
            self.assertFalse((runs_root / "d-dl-post-commit" / "evaluation.json").exists())

    def test_in_deadline_success_still_evaluates(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("d-dl-ok", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertIsNotNone(result.evaluation)
            ArtifactStore.verify_terminal_run(runs_root, "d-dl-ok")


class TestTinyRawTruncationVerification(unittest.TestCase):
    def _record_and_verify(self, root, run_id, payload, limit):
        store = ArtifactStore(
            Path(root) / "runs",
            make_spec(run_id),
            max_raw_evidence_bytes=limit,
        )
        store.record_invocation("solver", 1, _sample_record(run_id), payload)
        report = store.verify_invocation_evidence()
        self.assertTrue(report["invocation_evidence_verified"])
        raw_path = _invocation_dir(Path(root) / "runs" / run_id, "solver", 1) / "raw-output.txt"
        stored = raw_path.read_bytes()
        self.assertLessEqual(len(stored), limit)
        return store, stored

    def test_limit_100_full_marker_verifies(self):
        with TempRoot() as root:
            payload = "X" * 400
            _, stored = self._record_and_verify(root, "d-raw-100", payload, 100)
            view = classify_stored_raw_evidence(stored)
            self.assertTrue(view["truncated"])
            self.assertEqual(view["form"], "full")

    def test_limit_16_minimal_marker_verifies(self):
        with TempRoot() as root:
            payload = "X" * 80
            _, stored = self._record_and_verify(root, "d-raw-16", payload, 16)
            view = classify_stored_raw_evidence(stored)
            self.assertTrue(view["truncated"])
            self.assertEqual(view["form"], "minimal")

    def test_limit_1_clipped_marker_verifies(self):
        with TempRoot() as root:
            payload = "X" * 40
            _, stored = self._record_and_verify(root, "d-raw-1", payload, 1)
            self.assertEqual(stored, b"[")
            view = classify_stored_raw_evidence(stored)
            self.assertEqual(view["form"], "clipped_minimal")
            bounded = bound_raw_evidence(payload, limit=1)
            self.assertEqual(bounded["stored_bytes"], 1)

    def test_multibyte_unicode_payload_verifies(self):
        with TempRoot() as root:
            payload = "😀" * 80
            _, stored = self._record_and_verify(root, "d-raw-emoji", payload, 100)
            self.assertLessEqual(len(stored), 100)
            view = classify_stored_raw_evidence(stored)
            self.assertTrue(view["truncated"])

    def test_untruncated_raw_still_verifies(self):
        with TempRoot() as root:
            payload = "short"
            _, stored = self._record_and_verify(root, "d-raw-ok", payload, 100)
            self.assertEqual(stored, b"short")
            self.assertFalse(classify_stored_raw_evidence(stored)["truncated"])

    def test_forged_tiny_marker_fails(self):
        with TempRoot() as root:
            store, _ = self._record_and_verify(root, "d-raw-forge", "X" * 80, 16)
            run_dir = Path(root) / "runs" / "d-raw-forge"
            raw_path = _invocation_dir(run_dir, "solver", 1) / "raw-output.txt"
            forged = b"NOT_A_CANONICAL!"
            raw_path.write_bytes(forged)
            digest = __import__("hashlib").sha256(forged).hexdigest()
            lines = []
            for line in (run_dir / "manifest.jsonl").read_text().splitlines():
                entry = json.loads(line)
                if entry.get("kind") == KIND_UNTRUSTED_RAW_OUTPUT:
                    entry["sha256"] = digest
                    entry["bytes"] = len(forged)
                    entry["stored_bytes"] = len(forged)
                    entry["truncated"] = True
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_missing_truncation_metadata_fails(self):
        with TempRoot() as root:
            store, _ = self._record_and_verify(root, "d-raw-meta", "X" * 80, 16)
            run_dir = Path(root) / "runs" / "d-raw-meta"
            lines = []
            for line in (run_dir / "manifest.jsonl").read_text().splitlines():
                entry = json.loads(line)
                if entry.get("kind") == KIND_UNTRUSTED_RAW_OUTPUT:
                    entry.pop("truncated", None)
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()

    def test_stored_bytes_mismatch_fails(self):
        with TempRoot() as root:
            store, stored = self._record_and_verify(root, "d-raw-bytes", "X" * 80, 16)
            run_dir = Path(root) / "runs" / "d-raw-bytes"
            lines = []
            for line in (run_dir / "manifest.jsonl").read_text().splitlines():
                entry = json.loads(line)
                if entry.get("kind") == KIND_UNTRUSTED_RAW_OUTPUT:
                    entry["stored_bytes"] = len(stored) + 3
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                store.verify_invocation_evidence()


class TestTerminalAuthority(unittest.TestCase):
    def _success(self, root, run_id, condition="A"):
        runner, runs_root = make_runner(root)
        result = runner.execute(make_spec(run_id, condition), make_task())
        self.assertEqual(result.status, "succeeded")
        return runs_root, runs_root / run_id

    def _rewrite_declaration(self, run_dir, **field_updates):
        path = run_dir / "treatment_declaration.json"
        stored = json.loads(path.read_text())
        stored["declaration"].update(field_updates)
        stored["treatment_hash"] = digest_json(stored["declaration"])
        path.chmod(0o644)
        path.write_text(json.dumps(stored, indent=2, sort_keys=True))
        path.chmod(0o444)
        return stored["treatment_hash"]

    def test_terminal_treatment_hash_only_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-hash-only")
            _rewrite_json(run_dir / "run_result.json", treatment_hash="0" * 64)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-hash-only")

    def test_condition_and_model_forgeries_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-cond")
            _rewrite_json(run_dir / "run_result.json", condition="C")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-cond")
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-model")
            _rewrite_json(run_dir / "run_result.json", model_identifier="forged:model:v9:x:y")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-model")

    def test_adapter_kind_and_config_in_declaration_plus_hash_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-adapter")
            new_hash = self._rewrite_declaration(
                run_dir,
                adapter_kind="tamper",
                adapter_config_digest="0" * 64,
            )
            _rewrite_json(run_dir / "run_result.json", treatment_hash=new_hash)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-adapter")

    def test_evaluator_version_and_config_in_declaration_plus_hash_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-evalbind")
            new_hash = self._rewrite_declaration(
                run_dir,
                evaluator_version="forged-eval",
                evaluator_config_digest="1" * 64,
            )
            _rewrite_json(run_dir / "run_result.json", treatment_hash=new_hash)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-evalbind")

    def test_task_content_hash_in_declaration_plus_hash_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-taskhash")
            new_hash = self._rewrite_declaration(run_dir, task_content_hash="2" * 64)
            _rewrite_json(run_dir / "run_result.json", treatment_hash=new_hash)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-taskhash")

    def test_context_policy_version_in_declaration_plus_hash_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-ctx")
            new_hash = self._rewrite_declaration(run_dir, context_policy_version="ctx-forged")
            _rewrite_json(run_dir / "run_result.json", treatment_hash=new_hash)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-ctx")

    def test_source_provenance_replaced_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-src")
            _rewrite_json(
                run_dir / "run_result.json",
                source_provenance={
                    "source_revision": "0" * 40,
                    "working_tree_dirty": False,
                    "git_available": True,
                    "uncommitted_implementation": False,
                },
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-src")

    def test_per_stage_status_forged_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-stage")
            payload = json.loads((run_dir / "run_result.json").read_text())
            payload["stages"][0]["status"] = "failed"
            (run_dir / "run_result.json").write_text(json.dumps(payload, indent=2, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-stage")

    def test_terminal_evaluation_copy_forged_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-evalcopy")
            payload = json.loads((run_dir / "run_result.json").read_text())
            forged = dict(payload["evaluation"])
            forged["passed"] = not forged["passed"]
            forged["reasons"] = ["forged"]
            _rewrite_json(run_dir / "run_result.json", evaluation=forged)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-evalcopy")

    def test_succeeded_relabeled_failed_budget_fails(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-budget")
            _rewrite_json(run_dir / "run_result.json", status="failed_budget")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-budget")

    def test_failed_forged_to_succeeded_without_topology_fails(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"fail_if_seed_lt": 10**9})
            result = runner.execute(
                make_spec("d-forge-ok", "A", max_stage_retries=0), make_task()
            )
            self.assertEqual(result.status, "retry_exhausted")
            _rewrite_json(
                runs_root / "d-forge-ok" / "run_result.json",
                status="succeeded",
                evaluation={"passed": True},
                final_candidate_ref="solver/candidate.md",
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-forge-ok")

    def test_missing_seal_candidate_evaluation_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-noseal")
            (run_dir / "seals" / "solver.json").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-noseal")
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-nocand")
            _rewrite_json(run_dir / "run_result.json", final_candidate_ref=None)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-nocand")
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-noeval")
            _rewrite_json(run_dir / "run_result.json", evaluation=None)
            (run_dir / "evaluation.json").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-noeval")

    def test_spec_and_protocol_mismatch_fail(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-spec")
            _rewrite_json(run_dir / "run_result.json", spec_hash="0" * 64)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-spec")
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-proto")
            _rewrite_json(run_dir / "run_result.json", harness_protocol_version="forged-protocol")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-proto")

    def test_partial_evidence_still_allows_missing_terminal(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "d-partial")
            (run_dir / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "d-partial")
            self.assertEqual(report["verification_scope"], "partial_evidence")
            self.assertFalse(report["terminal_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "d-partial")


class TestRemediationDRegressions(unittest.TestCase):
    def test_seal_binding_and_profile_still_hold(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("d-reg-ok", "A"), make_task())
            report = ArtifactStore.verify_terminal_run(runs_root, "d-reg-ok")
            self.assertTrue(report["terminal_verified"])
            manifest = (runs_root / "d-reg-ok" / "manifest.jsonl").read_text()
            self.assertNotIn("record_digest", manifest)


if __name__ == "__main__":
    unittest.main()
