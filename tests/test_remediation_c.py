"""Deterministic closure tests for remaining SOL findings (Remediation C)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    ArtifactStore,
    IntegrityViolation,
    LiveContractError,
    parse_provider_call_outcome,
)
from model_council.invocation import (
    KIND_INVOCATION_METADATA,
    MINIMAL_TRUNCATION_MARKER,
    bound_raw_evidence,
)
from model_council.live_contract import (
    MAX_STAGE_OUTPUT_ARTIFACTS,
    MAX_STAGE_OUTPUT_ENVELOPE_BYTES,
    MAX_STAGE_OUTPUT_STRING_BYTES,
)
from model_council.protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
)
from model_council.security import sha256_text
from model_council.types import ProtocolError

from helpers import (
    IDENTITY_KEY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
)
from test_live_contract import make_outcome, make_request
from test_runner_invariants import ControllableClock


def _rewrite_json(path: Path, **updates) -> dict:
    payload = json.loads(path.read_text())
    payload.update(updates)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return payload


def _no_promoted_success(run_dir: Path, role="solver") -> None:
    assert not (run_dir / role / "candidate.md").exists()
    assert not (run_dir / role / "evidence.md").exists()
    assert not (run_dir / "seals" / f"{role}.json").exists()
    assert not (run_dir / "evaluation.json").exists()
    staging = run_dir / ".uncommitted"
    assert not staging.exists() or not any(staging.rglob("*"))


class TestDeadlineSafeFinalization(unittest.TestCase):
    def test_expiry_during_artifact_write_leaves_no_promoted_artifacts(self):
        clock = ControllableClock(1_000.0)
        original = ArtifactStore.write_staged

        def wrapped(store, *args, **kwargs):
            clock.advance(10.0)
            return original(store, *args, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root, monotonic=clock)
            with patch.object(ArtifactStore, "write_staged", wrapped):
                result = runner.execute(
                    make_spec(
                        "c-dl-write",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertNotEqual(result.status, "succeeded")
            self.assertIsNone(result.evaluation)
            run_dir = runs_root / "c-dl-write"
            _no_promoted_success(run_dir)
            self.assertEqual(result.status, "retry_exhausted")

    def test_expiry_inside_seal_does_not_succeed_or_evaluate(self):
        clock = ControllableClock(1_000.0)
        original = ArtifactStore.seal_stage

        def wrapped(store, role, expected_attempts=None, before_persist=None):
            def hooked():
                clock.advance(10.0)
                if before_persist is not None:
                    before_persist()

            return original(
                store,
                role,
                expected_attempts=expected_attempts,
                before_persist=hooked,
            )

        with TempRoot() as root:
            runner, runs_root = make_runner(root, monotonic=clock)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                result = runner.execute(
                    make_spec(
                        "c-dl-seal",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertNotEqual(result.status, "succeeded")
            self.assertIsNone(result.evaluation)
            run_dir = runs_root / "c-dl-seal"
            _no_promoted_success(run_dir)
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertIsNone(payload["evaluation"])

    def test_expiry_after_seal_construction_before_success_fails(self):
        clock = ControllableClock(1_000.0)
        original = ArtifactStore.seal_stage

        def wrapped(store, *args, **kwargs):
            seal = original(store, *args, **kwargs)
            clock.advance(10.0)
            return seal

        with TempRoot() as root:
            runner, runs_root = make_runner(root, monotonic=clock)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                result = runner.execute(
                    make_spec(
                        "c-dl-final",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertNotEqual(result.status, "succeeded")
            self.assertIsNone(result.evaluation)
            _no_promoted_success(runs_root / "c-dl-final")

    def test_in_deadline_success_is_unchanged(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("c-dl-ok", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertIsNotNone(result.evaluation)
            run_dir = runs_root / "c-dl-ok"
            self.assertTrue((run_dir / "solver" / "candidate.md").is_file())
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            self.assertTrue((run_dir / "evaluation.json").is_file())
            report = ArtifactStore.verify_terminal_run(runs_root, "c-dl-ok")
            self.assertTrue(report["terminal_verified"])


class TestTerminalRecordCoherence(unittest.TestCase):
    def _success(self, root, run_id):
        runner, runs_root = make_runner(root)
        result = runner.execute(make_spec(run_id, "A"), make_task())
        self.assertEqual(result.status, "succeeded")
        return runs_root, runs_root / run_id

    def test_forged_treatment_hash_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-hash")
            _rewrite_json(run_dir / "run_result.json", treatment_hash="0" * 64)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-hash")

    def test_condition_a_changed_to_c_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-cond")
            _rewrite_json(run_dir / "run_result.json", condition="C")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-cond")

    def test_replaced_model_identity_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-model")
            _rewrite_json(
                run_dir / "run_result.json",
                model_identifier="forged-provider:forged-model:v9",
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-model")
            self.assertNotEqual(IDENTITY_KEY, "forged-provider:forged-model:v9")

    def test_succeeded_relabeled_failed_budget_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-budget")
            _rewrite_json(run_dir / "run_result.json", status="failed_budget")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-budget")

    def test_success_seal_removed_while_status_succeeded_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-noseal")
            (run_dir / "seals" / "solver.json").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-noseal")

    def test_evaluation_removed_from_succeeded_run_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-noeval")
            _rewrite_json(run_dir / "run_result.json", evaluation=None)
            (run_dir / "evaluation.json").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-noeval")

    def test_final_candidate_removed_from_succeeded_run_is_rejected(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-nocand")
            _rewrite_json(run_dir / "run_result.json", final_candidate_ref=None)
            (run_dir / "solver" / "candidate.md").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-nocand")

    def test_failed_run_forged_to_succeeded_without_topology_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"fail_if_seed_lt": 10**9})
            result = runner.execute(
                make_spec("c-term-forge-ok", "A", max_stage_retries=0),
                make_task(),
            )
            self.assertEqual(result.status, "retry_exhausted")
            _rewrite_json(
                runs_root / "c-term-forge-ok" / "run_result.json",
                status="succeeded",
                evaluation={"passed": True},
                final_candidate_ref="solver/candidate.md",
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-forge-ok")

    def test_partial_evidence_verification_still_allows_missing_terminal(self):
        with TempRoot() as root:
            runs_root, run_dir = self._success(root, "c-term-partial")
            (run_dir / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "c-term-partial")
            self.assertEqual(report["verification_scope"], "partial_evidence")
            self.assertFalse(report["terminal_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-term-partial")

    def test_authentic_failed_evaluation_still_terminal_verifies(self):
        class ExplodingEvaluator:
            version = "exploding-v1"
            config_digest = "digest"

            @staticmethod
            def evaluate(candidate):
                raise RuntimeError("hidden test harness crashed")

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.evaluator = ExplodingEvaluator()
            result = runner.execute(make_spec("c-term-evalfail", "A"), make_task())
            self.assertEqual(result.status, "failed_evaluation")
            report = ArtifactStore.verify_terminal_run(runs_root, "c-term-evalfail")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")


class TestStageOutputBounds(unittest.TestCase):
    def test_two_million_character_text_is_rejected(self):
        payload = make_outcome().to_dict()
        payload["stage_output"]["text"] = "a" * 2_000_000
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_two_million_character_artifact_is_rejected(self):
        payload = make_outcome().to_dict()
        payload["stage_output"]["artifacts"]["candidate"] = "b" * 2_000_000
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_many_valid_artifacts_exceeding_envelope_are_rejected(self):
        payload = make_outcome().to_dict()
        chunk = "x" * 80_000
        artifacts = {f"art{index:02d}": chunk for index in range(20)}
        payload["stage_output"]["artifacts"] = artifacts
        self.assertLessEqual(len(artifacts), MAX_STAGE_OUTPUT_ARTIFACTS)
        self.assertLessEqual(len(chunk.encode("utf-8")), MAX_STAGE_OUTPUT_STRING_BYTES)
        encoded = json.dumps(
            {"text": payload["stage_output"]["text"], "artifacts": artifacts, "structured": None},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertGreater(encoded.__len__(), MAX_STAGE_OUTPUT_ENVELOPE_BYTES)
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_emoji_stage_output_uses_utf8_byte_count(self):
        payload = make_outcome().to_dict()
        over = "😀" * 250_001
        self.assertGreater(len(over.encode("utf-8")), MAX_STAGE_OUTPUT_STRING_BYTES)
        self.assertLess(len(over), MAX_STAGE_OUTPUT_STRING_BYTES)
        payload["stage_output"]["text"] = over
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_normal_bounded_stage_output_is_accepted(self):
        outcome = parse_provider_call_outcome(make_outcome().to_dict())
        self.assertEqual(outcome.stage_output["text"], "candidate text")
        emoji = make_outcome().to_dict()
        emoji["stage_output"]["text"] = "ok 😀"
        parsed = parse_provider_call_outcome(emoji)
        self.assertIn("😀", parsed.stage_output["text"])


class TestExactRawRetainedBytes(unittest.TestCase):
    def test_stored_raw_file_is_at_most_n_bytes(self):
        from test_invocation_evidence import _invocation_dir, _sample_record

        payload = "X" * 400
        limit = 100
        bounded = bound_raw_evidence(payload, limit=limit)
        self.assertTrue(bounded["truncated"])
        self.assertLessEqual(len(bounded["stored_text"].encode("utf-8")), limit)
        self.assertEqual(len(bounded["stored_text"].encode("utf-8")), bounded["stored_bytes"])
        self.assertTrue(bounded["stored_text"].startswith("[m1-raw-evidence: truncated"))
        with TempRoot() as root:
            store = ArtifactStore(
                Path(root) / "runs",
                make_spec("c-raw-100"),
                max_raw_evidence_bytes=limit,
            )
            store.record_invocation("solver", 1, _sample_record("c-raw-100"), payload)
            raw_path = _invocation_dir(Path(root) / "runs" / "c-raw-100", "solver", 1) / "raw-output.txt"
            stored = raw_path.read_bytes()
            self.assertLessEqual(len(stored), limit)
            self.assertEqual(len(stored), bounded["stored_bytes"])

    def test_tiny_limit_uses_minimal_marker_and_exact_ceiling(self):
        payload = "X" * 80
        bounded = bound_raw_evidence(payload, limit=16)
        self.assertTrue(bounded["truncated"])
        self.assertLessEqual(bounded["stored_bytes"], 16)
        self.assertTrue(bounded["stored_text"].startswith(MINIMAL_TRUNCATION_MARKER.strip()))
        self.assertEqual(len(bounded["stored_text"].encode("utf-8")), bounded["stored_bytes"])


class TestRecordDigestRemoved(unittest.TestCase):
    def test_false_record_digest_cannot_verify(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("c-digest", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "c-digest"
            manifest = (run_dir / "manifest.jsonl").read_text().splitlines()
            for line in manifest:
                entry = json.loads(line)
                self.assertNotIn("record_digest", entry)
            seal_path = run_dir / "seals" / "solver.json"
            seal = json.loads(seal_path.read_text())
            for entry in seal["invocations"]:
                self.assertNotIn("record_digest", entry)
            fake = "0" * 64
            for entry in seal["invocations"]:
                if entry["kind"] == KIND_INVOCATION_METADATA:
                    entry["record_digest"] = fake
            body = {
                "artifacts": seal["artifacts"],
                "invocations": seal["invocations"],
                "expected_attempts": seal["expected_attempts"],
            }
            seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
            seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True))
            lines = []
            for line in manifest:
                entry = json.loads(line)
                if entry.get("kind") == KIND_INVOCATION_METADATA:
                    entry["record_digest"] = fake
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "c-digest")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-digest")


class TestPreviouslyClosedFindings(unittest.TestCase):
    def test_trusted_profile_and_live_cannot_use_legacy(self):
        self.assertEqual(HARNESS_PROTOCOL_VERSION, "m1-dev-harness-v11")
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="live_stub", options={"return_legacy_response": True})
            result = runner.execute(make_spec("c-reg-legacy", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="fake")
            with self.assertRaises(ProtocolError):
                runner.adapter.invoke_live(make_request())
        self.assertEqual(EXECUTION_PROFILE_PRE_LIVE_LEGACY, "pre_live_legacy")
        self.assertEqual(EXECUTION_PROFILE_LIVE_CONTRACT_V1, "live_contract_v1")

    def test_partial_versus_terminal_and_projected_input(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("c-reg-ok", "A"), make_task())
            (runs_root / "c-reg-ok" / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "c-reg-ok")
            self.assertFalse(report["terminal_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "c-reg-ok")


if __name__ == "__main__":
    unittest.main()
