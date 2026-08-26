"""Checkpoint 5: invocation evidence is untrusted, write-once, and integrity-protected."""

from __future__ import annotations

import hashlib
import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    ArtifactStore,
    GovernanceViolation,
    IntegrityViolation,
)
from model_council.invocation import (
    INVOCATION_SCHEMA,
    KIND_INVOCATION_METADATA,
    KIND_MODEL_ARTIFACT,
    KIND_UNTRUSTED_RAW_OUTPUT,
    MAX_RAW_EVIDENCE_BYTES,
    bound_raw_evidence,
    build_invocation_record,
    raw_text_from_untrusted_response,
    serialize_invocation_record,
    treatment_digest_for_attempt,
)
from model_council.protocol import EXECUTION_PROFILE_PRE_LIVE_LEGACY
from model_council.roles import ROLE_INSTRUCTIONS
from model_council.security import digest_json
from model_council.types import ResourceLimits
from helpers import (
    FAKE_IDENTITY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
    transient_failure_options,
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _invocation_dir(run_dir: Path, role: str, attempt: int) -> Path:
    return run_dir / "invocations" / role / f"attempt-{attempt:04d}"


def _load_record(run_dir: Path, role: str, attempt: int) -> dict:
    return json.loads((_invocation_dir(run_dir, role, attempt) / "invocation.json").read_text())


def _sample_record(run_id, role="solver", attempt=1, timeout=30.0, remaining=12.5, **kwargs):
    input_digest, treatment = treatment_digest_for_attempt(
        condition="A",
        role=role,
        role_instruction=ROLE_INSTRUCTIONS[role],
        stage_inputs={"task": "example defect"},
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        seed=7,
        resource_limits=ResourceLimits(),
        execution_profile=EXECUTION_PROFILE_PRE_LIVE_LEGACY,
        adapter_kind="fake",
        adapter_config_digest=digest_json({}),
    )
    fields = dict(
        run_id=run_id,
        condition="A",
        role=role,
        attempt=attempt,
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        stage_timeout_seconds=timeout,
        attempt_timeout_seconds=remaining,
        input_content_digest=input_digest,
        treatment_digest=treatment,
        tokens_in=8,
        tokens_out=4,
        cumulative_tokens_in=8,
        retry_decision="promote",
        retry_rationale="stage_succeeded",
        contract_verdict="passed",
        identity_verdict="passed",
        failure_class=None,
        execution_profile=EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    )
    fields.update(kwargs)
    return build_invocation_record(**fields)


class TestInvocationPathsAndWriteOnce(unittest.TestCase):
    def test_paths_are_harness_owned_and_write_once(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("inv-path"))
            store.record_invocation("solver", 1, _sample_record("inv-path", attempt=1), "raw-one")
            store.record_invocation("solver", 2, _sample_record("inv-path", attempt=2, remaining=4.0), "raw-two")
            run_dir = Path(root) / "runs" / "inv-path"
            first = _invocation_dir(run_dir, "solver", 1)
            second = _invocation_dir(run_dir, "solver", 2)
            self.assertTrue((first / "invocation.json").is_file())
            self.assertTrue((first / "raw-output.txt").is_file())
            self.assertTrue((second / "invocation.json").is_file())
            self.assertEqual((first / "raw-output.txt").read_text(), "raw-one")
            self.assertEqual((second / "raw-output.txt").read_text(), "raw-two")
            with self.assertRaises(GovernanceViolation):
                store.record_invocation(
                    "solver", 1, _sample_record("inv-path", attempt=1), "overwrite"
                )
            self.assertEqual((first / "raw-output.txt").read_text(), "raw-one")

    def test_provider_path_escape_cannot_select_evidence_location(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("inv-escape"))
            with self.assertRaises(GovernanceViolation):
                store.record_invocation(
                    "../../escape",
                    1,
                    _sample_record("inv-escape"),
                    "should-not-land",
                )
            self.assertFalse((Path(root) / "escape").exists())
            self.assertFalse((Path(root) / "runs" / "escape").exists())


class TestRawBoundsAndPromotion(unittest.TestCase):
    def test_truncated_raw_evidence_is_labeled_and_bounded(self):
        payload = "X" * 80
        bounded = bound_raw_evidence(payload, limit=16)
        self.assertTrue(bounded["truncated"])
        self.assertIn("truncated", bounded["label"])
        self.assertEqual(bounded["stored_bytes"], len(bounded["stored_text"].encode("utf-8")))
        self.assertLessEqual(bounded["stored_bytes"], 16)
        self.assertEqual(bounded["observed_bytes"], 80)
        self.assertEqual(
            bounded["sha256_complete"],
            hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(MAX_RAW_EVIDENCE_BYTES, 1_000_000)
        with TempRoot() as root:
            store = ArtifactStore(
                Path(root) / "runs",
                make_spec("inv-trunc"),
                max_raw_evidence_bytes=16,
            )
            store.record_invocation("solver", 1, _sample_record("inv-trunc"), payload)
            raw_path = _invocation_dir(Path(root) / "runs" / "inv-trunc", "solver", 1) / "raw-output.txt"
            stored = raw_path.read_bytes()
            self.assertLessEqual(len(stored), 16)
            self.assertEqual(len(stored), bounded["stored_bytes"])
            record = _load_record(Path(root) / "runs" / "inv-trunc", "solver", 1)
            self.assertTrue(record["raw_output"]["truncated"])
            self.assertEqual(record["raw_output"]["observed_bytes"], 80)
            self.assertEqual(record["raw_output"]["stored_bytes"], len(stored))

    def test_rejected_raw_output_is_evidence_not_stage_or_evaluator_input(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"malformed_verifier": "findings_scalar"})
            seen_inputs = []
            original = runner.adapter.invoke

            def wrapped(**kwargs):
                seen_inputs.append(dict(kwargs["stage_inputs"]))
                return original(**kwargs)

            evaluated = []

            def capture(candidate):
                evaluated.append(candidate)
                return runner.evaluator.__class__.evaluate(runner.evaluator, candidate)

            with patch.object(runner.adapter, "invoke", side_effect=wrapped):
                runner.evaluator.evaluate = capture
                result = runner.execute(make_spec("inv-reject", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            run_dir = runs_root / "inv-reject"
            raw = (_invocation_dir(run_dir, "verifier", 1) / "raw-output.txt").read_text()
            self.assertTrue(raw)
            self.assertFalse((run_dir / "verifier" / "findings.md").exists())
            self.assertFalse((run_dir / "seals" / "verifier.json").exists())
            self.assertFalse((run_dir / "reviser" / "final_candidate.md").exists())
            self.assertEqual(evaluated, [])
            for payload in seen_inputs:
                blob = json.dumps(payload)
                self.assertNotIn("invocations/", blob)
                self.assertNotIn("retry_decision", blob)
                self.assertNotIn("provider_request_id", blob)

    def test_successful_promotion_does_not_feed_invocation_metadata_to_evaluator(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            seen_inputs = []
            original = runner.adapter.invoke

            def wrapped(**kwargs):
                seen_inputs.append((kwargs.get("role_instruction", ""), dict(kwargs["stage_inputs"])))
                return original(**kwargs)

            evaluated = []
            real_evaluate = runner.evaluator.evaluate

            def capture(candidate):
                evaluated.append(candidate)
                return real_evaluate(candidate)

            runner.evaluator.evaluate = capture
            with patch.object(runner.adapter, "invoke", side_effect=wrapped):
                result = runner.execute(make_spec("inv-eval", "C"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(evaluated), 1)
            record = _load_record(runs_root / "inv-eval", "solver", 1)
            self.assertEqual(record["schema"], INVOCATION_SCHEMA)
            self.assertNotIn(record["treatment_digest"], evaluated[0])
            self.assertNotIn("retry_decision", evaluated[0])
            self.assertNotIn("provider_request_id", evaluated[0])
            self.assertNotIn("invocations/", evaluated[0])
            for _instruction, payload in seen_inputs:
                blob = json.dumps(payload)
                self.assertNotIn("invocations/", blob)
                self.assertNotIn("retry_decision", blob)
                self.assertNotIn(record["treatment_digest"], blob)


class TestSecretExclusion(unittest.TestCase):
    def test_secret_canaries_are_rejected_before_persistence(self):
        canaries = (
            {"Authorization": "Bearer sk-test"},
            {"api_key": "sk-live"},
            {"Cookie": "sid=abc"},
            {"HTTP_AUTHORIZATION": "secret-env"},
            {"X-Api-Key": "hdr"},
            {"proxy_credentials": "user:pass"},
            {"traceback": "stack"},
        )
        for extra in canaries:
            with self.subTest(extra=list(extra)):
                with self.assertRaises(GovernanceViolation):
                    _sample_record("inv-secret", identity_used=extra)


class TestTreatmentVersusEnforcement(unittest.TestCase):
    def test_retry_attempts_share_treatment_digest_not_record_hash(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options=transient_failure_options(root))
            result = runner.execute(make_spec("inv-retry", "A", max_stage_retries=1), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "inv-retry"
            first = _load_record(run_dir, "solver", 1)
            second = _load_record(run_dir, "solver", 2)
            self.assertEqual(first["treatment_digest"], second["treatment_digest"])
            self.assertEqual(first["attempt"], 1)
            self.assertEqual(second["attempt"], 2)
            self.assertNotEqual(first["attempt_timeout_seconds"], second["attempt_timeout_seconds"])
            self.assertNotEqual(
                _sha256_file(_invocation_dir(run_dir, "solver", 1) / "invocation.json"),
                _sha256_file(_invocation_dir(run_dir, "solver", 2) / "invocation.json"),
            )
            self.assertEqual(first["retry_decision"], "retry")
            self.assertEqual(second["retry_decision"], "promote")
            self.assertEqual(second["promoted_artifact_refs"], ["solver/candidate.md", "solver/evidence.md"])
            self.assertEqual(first["promoted_artifact_refs"], [])
            seal = json.loads((run_dir / "seals" / "solver.json").read_text())
            self.assertEqual(seal["expected_attempts"], 2)
            ArtifactStore.verify_completed(runs_root, "inv-retry")


class TestIntegrityAdversary(unittest.TestCase):
    def _success_a(self, root, run_id, **options):
        runner, runs_root = make_runner(root, options=options or None)
        result = runner.execute(make_spec(run_id, "A"), make_task())
        self.assertEqual(result.status, "succeeded")
        return runs_root

    def test_invocation_metadata_tampering_detected(self):
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-meta")
            path = _invocation_dir(runs_root / "adv-meta", "solver", 1) / "invocation.json"
            record = json.loads(path.read_text())
            record["usage_estimated"]["tokens_out"] = record["usage_estimated"]["tokens_out"] + 1
            path.write_text(json.dumps(record))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-meta")

    def test_raw_output_tampering_and_deletion_detected(self):
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-raw")
            raw = _invocation_dir(runs_root / "adv-raw", "solver", 1) / "raw-output.txt"
            raw.write_bytes(raw.read_bytes() + b"x")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-raw")
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-raw-del")
            raw = _invocation_dir(runs_root / "adv-raw-del", "solver", 1) / "raw-output.txt"
            raw.unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-raw-del")

    def test_invocation_deletion_detected(self):
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-inv-del")
            shutil.rmtree(_invocation_dir(runs_root / "adv-inv-del", "solver", 1))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-inv-del")

    def test_extra_invocation_record_rejected(self):
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-extra")
            run_dir = runs_root / "adv-extra"
            src = _invocation_dir(run_dir, "solver", 1)
            dest = _invocation_dir(run_dir, "solver", 2)
            shutil.copytree(src, dest)
            extra = json.loads((dest / "invocation.json").read_text())
            extra["attempt"] = 2
            (dest / "invocation.json").write_text(json.dumps(extra))
            manifest = run_dir / "manifest.jsonl"
            entry = {
                "kind": KIND_INVOCATION_METADATA,
                "role": "solver",
                "attempt": 2,
                "ref": "invocations/solver/attempt-0002/invocation.json",
                "sha256": _sha256_file(dest / "invocation.json"),
                "bytes": (dest / "invocation.json").stat().st_size,
            }
            manifest.write_text(manifest.read_text() + json.dumps(entry) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-extra")

    def test_cross_stage_substitution_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("adv-cross-stage", "C"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "adv-cross-stage"
            solver = _invocation_dir(run_dir, "solver", 1) / "invocation.json"
            verifier = _invocation_dir(run_dir, "verifier", 1) / "invocation.json"
            verifier.write_bytes(solver.read_bytes())
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-cross-stage")

    def test_cross_run_substitution_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("adv-run-a", "A"), make_task())
            runner.execute(make_spec("adv-run-b", "A"), make_task())
            src = _invocation_dir(runs_root / "adv-run-a", "solver", 1) / "invocation.json"
            dest = _invocation_dir(runs_root / "adv-run-b", "solver", 1) / "invocation.json"
            dest.write_bytes(src.read_bytes())
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-run-b")

    def test_deleting_failed_first_attempt_of_successful_retry_fails_verification(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options=transient_failure_options(root))
            result = runner.execute(make_spec("adv-retry-del", "A", max_stage_retries=1), make_task())
            self.assertEqual(result.status, "succeeded")
            shutil.rmtree(_invocation_dir(runs_root / "adv-retry-del", "solver", 1))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "adv-retry-del")

    def test_failed_stage_evidence_tamper_detected_without_success_seal(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"fail_if_seed_lt": 10**9})
            result = runner.execute(make_spec("adv-fail", "A", max_stage_retries=1), make_task())
            self.assertEqual(result.status, "retry_exhausted")
            run_dir = runs_root / "adv-fail"
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            report = ArtifactStore.verify_run_integrity(runs_root, "adv-fail")
            self.assertTrue(report["invocation_evidence_verified"])
            self.assertFalse(report["completed_topology_verified"])
            path = _invocation_dir(run_dir, "solver", 1) / "invocation.json"
            record = json.loads(path.read_text())
            record["retry_decision"] = "promote"
            path.write_text(json.dumps(record))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_run_integrity(runs_root, "adv-fail")
            terminal = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(terminal["status"], "retry_exhausted")

    def test_manifest_kinds_do_not_weaken_role_artifact_topology(self):
        with TempRoot() as root:
            runs_root = self._success_a(root, "adv-kinds")
            manifest = [
                json.loads(line)
                for line in (runs_root / "adv-kinds" / "manifest.jsonl").read_text().splitlines()
                if line.strip()
            ]
            kinds = {entry["kind"] for entry in manifest}
            self.assertIn(KIND_MODEL_ARTIFACT, kinds)
            self.assertIn(KIND_INVOCATION_METADATA, kinds)
            self.assertIn(KIND_UNTRUSTED_RAW_OUTPUT, kinds)
            model_names = {
                (e["role"], e["name"])
                for e in manifest
                if e["kind"] == KIND_MODEL_ARTIFACT
            }
            self.assertEqual(model_names, {("solver", "candidate"), ("solver", "evidence")})
            ArtifactStore.verify_completed(runs_root, "adv-kinds")


class TestCompatibilitySeam(unittest.TestCase):
    def test_fake_adapter_records_pre_live_compatibility_envelope(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("inv-compat", "A"), make_task())
            record = _load_record(runs_root / "inv-compat", "solver", 1)
            self.assertEqual(record["adapter_evidence"]["compatibility"], "pre_live_fake_adapter")
            self.assertIsNone(record["adapter_evidence"]["provider_call_outcome"])
            self.assertEqual(record["adapter_evidence"]["adapter_internal_retry_count"], 0)
            raw = raw_text_from_untrusted_response({"text": "hello", "artifacts": {"candidate": "x"}})
            self.assertIn("hello", raw)
            serialized = serialize_invocation_record(record)
            self.assertNotIn("Authorization", serialized)
            self.assertNotIn("api_key", serialized)


if __name__ == "__main__":
    unittest.main()
