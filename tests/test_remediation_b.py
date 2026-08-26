"""Deterministic regressions for remaining SOL findings (Remediation B)."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    ArtifactStore,
    HARNESS_PROTOCOL_VERSION,
    IntegrityViolation,
    LiveContractError,
    parse_provider_call_outcome,
)
from model_council.invocation import (
    KIND_INVOCATION_METADATA,
    bound_raw_evidence,
    treatment_digest_for_attempt,
)
from model_council.live_contract import MAX_STRUCTURED_STRING_BYTES
from model_council.protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
)
from model_council.roles import ROLE_INSTRUCTIONS
from model_council.security import digest_json, sha256_text
from model_council.types import ProtocolError, ResourceLimits

from helpers import (
    FAKE_IDENTITY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
)
from test_live_contract import make_outcome, make_request
from test_runner_invariants import ControllableClock, JumpAfterFirstRead


CANARY = "CANARY_SECRET_sk-live-not-for-persistence"
AUTH_CANARY = "Authorization: Bearer sk-canary-token"
CAUSE_CANARY = "nested-cause-api_key=supersecret"


class ExpireAfterReads:
    """Keep returning the start instant for N reads, then jump past the deadline."""

    def __init__(self, start=1_000.0, keep_reads=5, jump=10.0):
        self.start = float(start)
        self.keep_reads = int(keep_reads)
        self.jump = float(jump)
        self.reads = 0

    def __call__(self):
        self.reads += 1
        if self.reads <= self.keep_reads:
            return self.start
        return self.start + self.jump


def _load_invocation(run_dir: Path, role="solver", attempt=1) -> dict:
    path = run_dir / "invocations" / role / f"attempt-{attempt:04d}" / "invocation.json"
    return json.loads(path.read_text())


def _durable_text(run_dir: Path) -> str:
    parts = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name == "raw-output.txt":
            continue
        parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _treatment(**overrides):
    kwargs = dict(
        condition="A",
        role="solver",
        role_instruction=ROLE_INSTRUCTIONS["solver"],
        stage_inputs={"task": "example defect"},
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        seed=7,
        resource_limits=ResourceLimits(),
        execution_profile=EXECUTION_PROFILE_PRE_LIVE_LEGACY,
        adapter_kind="fake",
        adapter_config_digest=digest_json({}),
    )
    kwargs.update(overrides)
    return treatment_digest_for_attempt(**kwargs)[1]


class TestAuthoritativeDeadline(unittest.TestCase):
    def test_post_return_clock_jump_does_not_promote(self):
        clock = ControllableClock(5_000.0)
        with TempRoot() as root:
            runner, runs_root = make_runner(root, monotonic=clock)
            original = runner.adapter.invoke

            def invoke(**kwargs):
                result = original(**kwargs)
                clock.advance(10.0)
                return result

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "dl-post-return",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertNotEqual(result.status, "succeeded")
            self.assertIn("timeout", (result.stage_results[0].error or "").lower())
            self.assertFalse((runs_root / "dl-post-return" / "seals" / "solver.json").exists())
            self.assertFalse((runs_root / "dl-post-return" / "solver" / "candidate.md").exists())

    def test_expiry_during_preparation_makes_zero_calls(self):
        clock = JumpAfterFirstRead(start=4_000.0, jump=5.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            calls = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                calls.append(1)
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("dl-prep", "A", stage_timeout_seconds=1.0, max_stage_retries=0),
                    make_task(),
                )
            self.assertEqual(calls, [])
            self.assertEqual(result.status, "retry_exhausted")

    def test_expiry_before_promotion_and_before_seal(self):
        for keep_reads, run_id in ((5, "dl-promote"), (6, "dl-seal")):
            with self.subTest(run_id=run_id, keep_reads=keep_reads):
                clock = ExpireAfterReads(keep_reads=keep_reads, jump=10.0)
                with TempRoot() as root:
                    runner, runs_root = make_runner(root, monotonic=clock)
                    result = runner.execute(
                        make_spec(run_id, "A", stage_timeout_seconds=1.0, max_stage_retries=0),
                        make_task(),
                    )
                    self.assertNotEqual(result.status, "succeeded")
                    self.assertFalse((runs_root / run_id / "seals" / "solver.json").exists())


class TestCredentialSanitization(unittest.TestCase):
    def test_exception_canaries_do_not_persist(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root,
                options={
                    "raise_message": AUTH_CANARY,
                    "raise_cause": CAUSE_CANARY,
                    "Authorization": "Bearer nested-option-secret",
                    "api_key": CANARY,
                },
            )
            result = runner.execute(make_spec("san-exc", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            blob = _durable_text(runs_root / "san-exc")
            self.assertNotIn(AUTH_CANARY, blob)
            self.assertNotIn(CAUSE_CANARY, blob)
            self.assertNotIn(CANARY, blob)
            self.assertNotIn("nested-option-secret", blob)
            self.assertNotIn("Traceback", blob)
            self.assertNotIn("Bearer", blob)
            payload = json.loads((runs_root / "san-exc" / "run_result.json").read_text())
            self.assertNotIn(AUTH_CANARY, payload["error"])

    def test_stderr_canary_is_not_copied_into_terminal_evidence(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, kind="crash_worker", options={"stderr_canary": CANARY}
            )
            result = runner.execute(make_spec("san-stderr", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            blob = _durable_text(runs_root / "san-stderr")
            self.assertNotIn(CANARY, blob)
            payload = json.loads((runs_root / "san-stderr" / "run_result.json").read_text())
            self.assertIn("stderr_bytes", payload["error"])
            self.assertIn("stderr_sha256", payload["error"])
            self.assertNotIn(CANARY, payload["error"])


class TestSealInvocationBinding(unittest.TestCase):
    def _success(self, root, run_id):
        runner, runs_root = make_runner(root)
        result = runner.execute(make_spec(run_id, "A"), make_task())
        self.assertEqual(result.status, "succeeded")
        return runs_root / run_id

    def test_false_seal_sha_and_bytes_fail_after_digest_recompute(self):
        with TempRoot() as root:
            run_dir = self._success(root, "seal-false-meta")
            seal_path = run_dir / "seals" / "solver.json"
            seal = json.loads(seal_path.read_text())
            target = next(
                e for e in seal["invocations"] if e["kind"] == KIND_INVOCATION_METADATA
            )
            target["sha256"] = "0" * 64
            target["bytes"] = 1
            body = {
                "artifacts": seal["artifacts"],
                "invocations": seal["invocations"],
                "expected_attempts": seal["expected_attempts"],
            }
            seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
            seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(run_dir.parent, "seal-false-meta")

    def test_changed_file_and_manifest_against_original_seal_fail(self):
        with TempRoot() as root:
            run_dir = self._success(root, "seal-file-man")
            inv = run_dir / "invocations" / "solver" / "attempt-0001" / "invocation.json"
            record = json.loads(inv.read_text())
            record["usage_estimated"]["tokens_out"] = record["usage_estimated"]["tokens_out"] + 9
            payload = json.dumps(record, sort_keys=True)
            inv.write_text(payload)
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            lines = []
            for line in (run_dir / "manifest.jsonl").read_text().splitlines():
                entry = json.loads(line)
                if entry.get("kind") == KIND_INVOCATION_METADATA:
                    entry["sha256"] = digest
                    entry["bytes"] = len(payload.encode("utf-8"))
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(run_dir.parent, "seal-file-man")

    def test_changed_seal_and_manifest_without_file_fail(self):
        with TempRoot() as root:
            run_dir = self._success(root, "seal-man-only")
            fake = "1" * 64
            seal_path = run_dir / "seals" / "solver.json"
            seal = json.loads(seal_path.read_text())
            for entry in seal["invocations"]:
                if entry["kind"] == KIND_INVOCATION_METADATA:
                    entry["sha256"] = fake
            body = {
                "artifacts": seal["artifacts"],
                "invocations": seal["invocations"],
                "expected_attempts": seal["expected_attempts"],
            }
            seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
            seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True))
            lines = []
            for line in (run_dir / "manifest.jsonl").read_text().splitlines():
                entry = json.loads(line)
                if entry.get("kind") == KIND_INVOCATION_METADATA:
                    entry["sha256"] = fake
                lines.append(json.dumps(entry, sort_keys=True))
            (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(run_dir.parent, "seal-man-only")


class TestTreatmentDigestCompleteness(unittest.TestCase):
    def test_declared_resources_and_identity_change_digest(self):
        base = _treatment()
        self.assertNotEqual(base, _treatment(resource_limits=ResourceLimits(max_input_tokens_per_stage=128)))
        self.assertNotEqual(base, _treatment(resource_limits=ResourceLimits(max_output_tokens_per_stage=32)))
        self.assertNotEqual(base, _treatment(resource_limits=ResourceLimits(stage_timeout_seconds=12.0)))
        self.assertNotEqual(base, _treatment(resource_limits=ResourceLimits(max_stage_retries=0)))
        self.assertNotEqual(base, _treatment(seed=99))
        self.assertNotEqual(base, _treatment(condition="C", role="verifier", role_instruction=ROLE_INSTRUCTIONS["verifier"], stage_inputs={"task": "example defect", "solver_candidate": "c", "solver_evidence": "e"}))
        other = FAKE_IDENTITY.__class__(
            provider="other",
            model_id="other-model",
            model_version="v9",
            adapter_name="fake",
            adapter_version="v0",
        )
        self.assertNotEqual(
            base,
            _treatment(requested_identity=other, configured_identity=other),
        )
        self.assertNotEqual(
            base,
            _treatment(execution_profile=EXECUTION_PROFILE_LIVE_CONTRACT_V1, adapter_kind="live_stub"),
        )

    def test_enforcement_state_does_not_change_digest(self):
        first = _treatment()
        second = _treatment()
        self.assertEqual(first, second)
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("td-retry", "A", max_stage_retries=1, stage_timeout_seconds=30.0), make_task())
            # Single-success path still has stable digest if we retry via clock? Use two records
            # from a transient failure instead.
        from helpers import transient_failure_options

        with TempRoot() as root:
            runner, runs_root = make_runner(root, options=transient_failure_options(root))
            runner.execute(make_spec("td-retry2", "A", max_stage_retries=1), make_task())
            first_rec = _load_invocation(runs_root / "td-retry2", attempt=1)
            second_rec = _load_invocation(runs_root / "td-retry2", attempt=2)
            self.assertEqual(first_rec["treatment_digest"], second_rec["treatment_digest"])
            self.assertNotEqual(first_rec["attempt"], second_rec["attempt"])
            self.assertNotEqual(first_rec["attempt_timeout_seconds"], second_rec["attempt_timeout_seconds"])


class TestProjectedVersusConsumed(unittest.TestCase):
    def test_protocol_failure_after_invoke_consumes_input(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="crash_worker")
            result = runner.execute(make_spec("acct-crash", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            record = _load_invocation(runs_root / "acct-crash")
            self.assertTrue(record["invocation_began"])
            self.assertGreater(record["consumed_tokens_in"], 0)
            self.assertEqual(record["consumed_tokens_in"], record["projected_tokens_in"])


class TestEvidenceBoundsAndLatency(unittest.TestCase):
    def test_utf8_emoji_uses_byte_ceiling(self):
        payload = "😀" * 400
        bounded = bound_raw_evidence(payload, limit=100)
        self.assertTrue(bounded["truncated"])
        self.assertLessEqual(bounded["stored_bytes"], 100)
        self.assertGreater(bounded["observed_bytes"], 100)
        self.assertTrue(bounded["sha256_complete"])

    def test_giant_structured_field_is_rejected(self):
        payload = make_outcome().to_dict()
        payload["structured_output"] = {
            "untrusted": True,
            "value": {"blob": "x" * (MAX_STRUCTURED_STRING_BYTES + 8)},
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_adapter_cannot_forge_harness_observed_latency(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="live_stub")
            result = runner.execute(make_spec("lat-own", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            record = _load_invocation(runs_root / "lat-own")
            self.assertIsNotNone(record["harness_observed_latency_seconds"])
            self.assertGreaterEqual(record["harness_observed_latency_seconds"], 0)
            outcome = record["adapter_evidence"]["provider_call_outcome"]
            self.assertNotIn("harness_observed_latency_seconds", outcome["timing"])
            self.assertLess(record["harness_observed_latency_seconds"], 999.0)
            forged = make_outcome().to_dict()
            forged["timing"]["harness_observed_latency_seconds"] = 999.0
            with self.assertRaises(LiveContractError):
                parse_provider_call_outcome(forged)


class TestTerminalVerification(unittest.TestCase):
    def test_deleted_terminal_record_is_not_terminal_verified(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("term-del", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            (runs_root / "term-del" / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "term-del")
            self.assertEqual(report["verification_scope"], "partial_evidence")
            self.assertFalse(report["terminal_verified"])
            self.assertIsNone(report["terminal_status"])
            self.assertFalse(report["completed_topology_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "term-del")

    def test_failed_run_terminal_verification_requires_record(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"fail_if_seed_lt": 10**9})
            result = runner.execute(make_spec("term-fail", "A", max_stage_retries=0), make_task())
            self.assertEqual(result.status, "retry_exhausted")
            report = ArtifactStore.verify_terminal_run(runs_root, "term-fail")
            self.assertEqual(report["verification_scope"], "terminal_run")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "retry_exhausted")
            payload = json.loads((runs_root / "term-fail" / "run_result.json").read_text())
            self.assertEqual(payload["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)


class TestRemediationAStillHolds(unittest.TestCase):
    def test_live_cannot_use_legacy_route_and_profiles_stay_registry_owned(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="live_stub", options={"return_legacy_response": True})
            result = runner.execute(make_spec("b-live-legacy", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="fake")
            with self.assertRaises(ProtocolError):
                runner.adapter.invoke_live(make_request())


if __name__ == "__main__":
    unittest.main()
