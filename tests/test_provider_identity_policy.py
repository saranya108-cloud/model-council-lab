"""F2 provider identity governance regressions; entirely offline."""

from __future__ import annotations

import json
import hashlib
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from helpers import FAKE_IDENTITY, TempRoot, make_runner, make_spec, make_task
from model_council import AdapterIdentity, ArtifactStore
from model_council.adapters import fake_generate, live_stub_generate
from model_council.invocation import treatment_digest_for_attempt
from model_council.live_contract import (
    NeutralProviderFailure,
    ProviderCallKind,
    UnavailableReason,
    parse_provider_call_outcome,
)
from model_council.protocol import (
    HARNESS_PROTOCOL_VERSION,
    HISTORICAL_HARNESS_PROTOCOL_VERSION,
)
from model_council.roles import ROLE_INSTRUCTIONS
from model_council.security import digest_json
from model_council.types import IntegrityViolation, ResourceLimits
from test_provider_treatment_config import (
    _rewrite_invocation_field,
    _rewrite_invocation_treatment_digest,
    _stage_inputs_from_trusted_records,
)


OPENAI_IDENTITY = AdapterIdentity(
    provider="openai",
    model_id="gpt-5.6-sol",
    model_version="configured-label-v1",
    adapter_name="openai_responses",
    adapter_version="v0",
)


def _spec(run_id: str, condition: str = "A", **limits):
    return replace(
        make_spec(run_id, condition, **limits),
        model_identifier=OPENAI_IDENTITY.key(),
    )


def _outcome(request, observed_model=OPENAI_IDENTITY.model_id, *, malformed=False):
    payload = live_stub_generate({}, {}, request).to_dict()
    if observed_model is None:
        payload["provider_resolved_identity"] = {
            "value": None,
            "unavailable_reason": UnavailableReason.NOT_EXPOSED.value,
        }
    elif malformed:
        payload["provider_resolved_identity"] = {
            "value": {"provider": "openai"},
            "unavailable_reason": None,
        }
    else:
        payload["provider_resolved_identity"] = {
            "value": {"model_id": observed_model},
            "unavailable_reason": None,
        }
    return parse_provider_call_outcome(payload)


def _replace_json(path: Path, payload: dict) -> None:
    path.chmod(0o644)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    path.chmod(0o444)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expected_attempt_digest_without_identity_policy(run_dir: Path, role: str) -> str:
    canonical = json.loads(json.loads((run_dir / "run_spec.json").read_text())["canonical"])
    binding = json.loads((run_dir / "execution_binding.json").read_text())
    return treatment_digest_for_attempt(
        condition=canonical["condition"],
        role=role,
        role_instruction=ROLE_INSTRUCTIONS[role],
        stage_inputs=_stage_inputs_from_trusted_records(
            run_dir, canonical["condition"], role
        ),
        requested_identity=OPENAI_IDENTITY,
        configured_identity=OPENAI_IDENTITY,
        seed=canonical["seed"],
        resource_limits=ResourceLimits(**canonical["resource_limits"]),
        execution_profile=binding["execution_profile"],
        adapter_kind=binding["adapter_kind"],
        adapter_config_digest=binding["adapter_config_digest"],
        live_contract_version=binding["live_contract_version"],
        harness_protocol_version=binding["harness_protocol_version"],
        provider_treatment_config=binding["provider_treatment_config"],
    )[1]


def _run_with_observations(root: str, run_id: str, condition: str, observations):
    runner, runs_root = make_runner(
        root,
        kind="openai_responses",
        identity=OPENAI_IDENTITY,
    )
    observed_by_role = dict(observations)
    called = []
    evaluated = []

    def invoke(request):
        called.append(request.role)
        value = observed_by_role[request.role]
        if value == "<malformed>":
            return _outcome(request, malformed=True)
        return _outcome(request, value)

    real_evaluate = runner.evaluator.evaluate

    def evaluate(candidate):
        evaluated.append(candidate)
        return real_evaluate(candidate)

    runner.evaluator.evaluate = evaluate
    with patch.object(runner.adapter, "invoke_live", side_effect=invoke):
        result = runner.execute(_spec(run_id, condition), make_task())
    return result, runs_root, called, evaluated


class TestProviderIdentityPromotionGate(unittest.TestCase):
    def test_exact_provider_observation_succeeds_under_frozen_policy(self):
        with TempRoot() as root:
            result, runs_root, called, evaluated = _run_with_observations(
                root, "f2-exact", "A", {"solver": OPENAI_IDENTITY.model_id}
            )
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(called, ["solver"])
            self.assertEqual(len(evaluated), 1)
            run_dir = runs_root / "f2-exact"
            binding = json.loads((run_dir / "execution_binding.json").read_text())
            self.assertEqual(
                binding["provider_identity_policy"],
                {
                    "schema": "m1-provider-identity-policy-v1",
                    "match": "exact",
                    "provider_observed_identity_required": True,
                    "requested_model": OPENAI_IDENTITY.model_id,
                    "configured_model": OPENAI_IDENTITY.model_id,
                    "wire_model": OPENAI_IDENTITY.model_id,
                },
            )
            report = ArtifactStore.verify_terminal_run(runs_root, "f2-exact")
            self.assertTrue(report["provider_identity_policy_verified"])

    def test_mismatch_fails_before_promotion_and_evaluation(self):
        with TempRoot() as root:
            result, runs_root, called, evaluated = _run_with_observations(
                root, "f2-mismatch", "A", {"solver": "gpt-different"}
            )
            self.assertEqual(result.status, "failed_governance")
            self.assertEqual(called, ["solver"])
            self.assertEqual(evaluated, [])
            run_dir = runs_root / "f2-mismatch"
            self.assertFalse((run_dir / "solver" / "candidate.md").exists())
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            self.assertFalse((run_dir / "evaluation.json").exists())
            record = json.loads(
                (run_dir / "invocations/solver/attempt-0001/invocation.json").read_text()
            )
            self.assertEqual(record["identity_verdict"], "failed")
            self.assertEqual(record["failure_class"], "governance")
            self.assertEqual(record["retry_decision"], "stop")
            self.assertEqual(
                record["adapter_evidence"]["provider_call_outcome"]
                ["provider_resolved_identity"]["value"]["model_id"],
                "gpt-different",
            )
            self.assertEqual(record["configured_identity"]["model_id"], "gpt-5.6-sol")
            self.assertEqual(record["requested_identity"]["model_id"], "gpt-5.6-sol")
            report = ArtifactStore.verify_terminal_run(runs_root, "f2-mismatch")
            self.assertTrue(report["provider_identity_policy_verified"])

    def test_missing_and_malformed_observations_fail_governance(self):
        cases = (("missing", None), ("malformed", "<malformed>"))
        for label, observation in cases:
            with self.subTest(label=label), TempRoot() as root:
                result, runs_root, called, evaluated = _run_with_observations(
                    root, f"f2-{label}", "A", {"solver": observation}
                )
                self.assertEqual(result.status, "failed_governance")
                self.assertEqual(called, ["solver"])
                self.assertEqual(evaluated, [])
                run_dir = runs_root / f"f2-{label}"
                self.assertFalse((run_dir / "solver" / "candidate.md").exists())
                self.assertFalse((run_dir / "evaluation.json").exists())
                record = json.loads(
                    (run_dir / "invocations/solver/attempt-0001/invocation.json").read_text()
                )
                self.assertEqual(record["identity_verdict"], "failed")
                ArtifactStore.verify_terminal_run(runs_root, f"f2-{label}")

    def test_same_family_prefix_and_unapproved_snapshot_are_not_aliases(self):
        observations = (
            "gpt-5.6-sol-2026-09-05",
            "gpt-5.6",
            "prefix-gpt-5.6-sol",
        )
        for index, observation in enumerate(observations):
            with self.subTest(observation=observation), TempRoot() as root:
                result, runs_root, _called, _evaluated = _run_with_observations(
                    root, f"f2-no-alias-{index}", "A", {"solver": observation}
                )
                self.assertEqual(result.status, "failed_governance")
                self.assertFalse(
                    (runs_root / f"f2-no-alias-{index}" / "solver/candidate.md").exists()
                )

    def test_provider_output_cannot_rewrite_configured_authority(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, kind="openai_responses", identity=OPENAI_IDENTITY
            )

            def invoke(request):
                payload = _outcome(request).to_dict()
                payload["configured_identity"]["model_id"] = "provider-rewrite"
                payload["configured_identity"]["identity_key"] = (
                    "openai:provider-rewrite:configured-label-v1:openai_responses:v0"
                )
                payload["provider_resolved_identity"]["value"]["model_id"] = (
                    "provider-rewrite"
                )
                return parse_provider_call_outcome(payload)

            with patch.object(runner.adapter, "invoke_live", side_effect=invoke):
                result = runner.execute(_spec("f2-authority"), make_task())
            self.assertEqual(result.status, "failed_governance")
            record = json.loads(
                (
                    runs_root
                    / "f2-authority/invocations/solver/attempt-0001/invocation.json"
                ).read_text()
            )
            self.assertEqual(record["configured_identity"]["model_id"], "gpt-5.6-sol")
            self.assertEqual(record["requested_identity"]["model_id"], "gpt-5.6-sol")
            self.assertEqual(
                record["adapter_evidence"]["provider_call_outcome"]
                ["configured_identity"]["model_id"],
                "provider-rewrite",
            )

    def test_runtime_metadata_cannot_broaden_exact_policy(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, kind="openai_responses", identity=OPENAI_IDENTITY
            )

            def invoke(request):
                payload = _outcome(request, "gpt-5.6-sol-snapshot").to_dict()
                payload["provider_metadata"] = {
                    "untrusted": True,
                    "value": {
                        "accepted_observed_model": "gpt-5.6-sol-snapshot",
                        "alias_of": OPENAI_IDENTITY.model_id,
                    },
                    "unavailable_reason": None,
                }
                return parse_provider_call_outcome(payload)

            with patch.object(runner.adapter, "invoke_live", side_effect=invoke):
                result = runner.execute(_spec("f2-runtime-alias"), make_task())
            self.assertEqual(result.status, "failed_governance")
            self.assertFalse(
                (runs_root / "f2-runtime-alias/solver/candidate.md").exists()
            )


class TestProviderIdentityCrossStage(unittest.TestCase):
    def test_condition_b_drift_stops_before_reviser_and_evaluation(self):
        with TempRoot() as root:
            result, runs_root, called, evaluated = _run_with_observations(
                root,
                "f2-drift-b",
                "B",
                {
                    "draft": OPENAI_IDENTITY.model_id,
                    "self_review": "gpt-5.6-sol-snapshot",
                    "reviser": OPENAI_IDENTITY.model_id,
                },
            )
            self.assertEqual(result.status, "failed_governance")
            self.assertEqual(called, ["draft", "self_review"])
            self.assertEqual(evaluated, [])
            run_dir = runs_root / "f2-drift-b"
            self.assertTrue((run_dir / "draft/draft.md").exists())
            self.assertFalse((run_dir / "self_review/self_review.md").exists())
            self.assertFalse((run_dir / "reviser/final_candidate.md").exists())
            self.assertFalse((run_dir / "evaluation.json").exists())

    def test_condition_c_drift_stops_before_reviser_and_evaluation(self):
        with TempRoot() as root:
            result, runs_root, called, evaluated = _run_with_observations(
                root,
                "f2-drift-c",
                "C",
                {
                    "solver": OPENAI_IDENTITY.model_id,
                    "verifier": "gpt-5.6-sol-snapshot",
                    "reviser": OPENAI_IDENTITY.model_id,
                },
            )
            self.assertEqual(result.status, "failed_governance")
            self.assertEqual(called, ["solver", "verifier"])
            self.assertEqual(evaluated, [])
            run_dir = runs_root / "f2-drift-c"
            self.assertTrue((run_dir / "solver/candidate.md").exists())
            self.assertFalse((run_dir / "verifier/findings.md").exists())
            self.assertFalse((run_dir / "reviser/final_candidate.md").exists())
            self.assertFalse((run_dir / "evaluation.json").exists())

    def test_provider_error_without_identity_keeps_provider_classification(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root,
                kind="openai_responses",
                identity=OPENAI_IDENTITY,
            )

            def fail(request):
                outcome = live_stub_generate(
                    {"neutral_error_category": "rate_limit"}, {}, request
                )
                self.assertIsNot(outcome.kind, ProviderCallKind.SUCCESS)
                raise NeutralProviderFailure(outcome.error, outcome=outcome)

            with patch.object(runner.adapter, "invoke_live", side_effect=fail):
                result = runner.execute(
                    _spec("f2-provider-error", "A", max_stage_retries=0),
                    make_task(),
                )
            self.assertEqual(result.status, "retry_exhausted")
            record = json.loads(
                (
                    runs_root
                    / "f2-provider-error/invocations/solver/attempt-0001/invocation.json"
                ).read_text()
            )
            self.assertEqual(record["failure_class"], "provider")
            self.assertEqual(record["identity_verdict"], "not_evaluated")
            self.assertIsNone(
                record["adapter_evidence"]["provider_call_outcome"]
                ["provider_resolved_identity"]["value"]
            )


class TestProviderIdentityTerminalVerification(unittest.TestCase):
    def _successful_run(self, root: str, run_id: str):
        result, runs_root, _called, _evaluated = _run_with_observations(
            root, run_id, "A", {"solver": OPENAI_IDENTITY.model_id}
        )
        self.assertEqual(result.status, "succeeded")
        return runs_root, runs_root / run_id

    def test_policy_tampering_fails_even_when_local_hashes_are_rewritten(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-policy-tamper")
            binding_path = run_dir / "execution_binding.json"
            binding = json.loads(binding_path.read_text())
            binding["provider_identity_policy"]["wire_model"] = "gpt-forged"
            _replace_json(binding_path, binding)

            declaration_path = run_dir / "treatment_declaration.json"
            stored = json.loads(declaration_path.read_text())
            stored["declaration"]["provider_identity_policy"] = binding[
                "provider_identity_policy"
            ]
            stored["treatment_hash"] = digest_json(stored["declaration"])
            _replace_json(declaration_path, stored)

            terminal_path = run_dir / "run_result.json"
            terminal = json.loads(terminal_path.read_text())
            terminal["treatment_hash"] = stored["treatment_hash"]
            terminal_path.write_text(json.dumps(terminal, indent=2, sort_keys=True))

            authority_path = run_dir / "run_authority.json"
            authority = json.loads(authority_path.read_text())
            authority["execution_binding_sha256"] = _sha256(binding_path)
            authority["treatment_declaration_sha256"] = _sha256(declaration_path)
            _replace_json(authority_path, authority)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "f2-policy-tamper")

    def test_provider_observation_tampering_fails_semantic_recomputation(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-observation-tamper")
            record_path = (
                run_dir / "invocations/solver/attempt-0001/invocation.json"
            )
            record = json.loads(record_path.read_text())
            evidence = record["adapter_evidence"]
            evidence["provider_call_outcome"]["provider_resolved_identity"][
                "value"
            ]["model_id"] = "gpt-forged"
            _rewrite_invocation_field(
                run_dir, "solver", 1, "adapter_evidence", evidence
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(
                    runs_root, "f2-observation-tamper"
                )

    def test_stored_identity_verdict_is_not_trusted(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-verdict-tamper")
            _rewrite_invocation_field(
                run_dir, "solver", 1, "identity_verdict", "failed"
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "f2-verdict-tamper")

    def test_new_f2_record_uses_v14_discriminator_through_bound_evidence(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-v14")
            binding = json.loads((run_dir / "execution_binding.json").read_text())
            declaration = json.loads(
                (run_dir / "treatment_declaration.json").read_text()
            )["declaration"]
            authority = json.loads((run_dir / "run_authority.json").read_text())
            terminal = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(HARNESS_PROTOCOL_VERSION, "m1-dev-harness-v14")
            self.assertEqual(binding["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertEqual(declaration["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertEqual(authority["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertEqual(terminal["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertIn("provider_identity_policy", binding)
            self.assertIn("provider_identity_policy_version", binding)
            self.assertTrue(
                ArtifactStore.verify_terminal_run(runs_root, "f2-v14")
                ["provider_identity_policy_verified"]
            )

    def test_successful_live_record_cannot_omit_provider_outcome(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-outcome-removed")
            record_path = (
                run_dir / "invocations/solver/attempt-0001/invocation.json"
            )
            record = json.loads(record_path.read_text())
            evidence = record["adapter_evidence"]
            evidence["provider_call_outcome"] = None
            _rewrite_invocation_field(run_dir, "solver", 1, "adapter_evidence", evidence)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "f2-outcome-removed")

    def test_current_openai_policy_cannot_be_downgraded_to_historical(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-policy-downgrade")

            binding_path = run_dir / "execution_binding.json"
            binding = json.loads(binding_path.read_text())
            binding.pop("provider_identity_policy")
            binding.pop("provider_identity_policy_version")
            _replace_json(binding_path, binding)

            old_digest = _expected_attempt_digest_without_identity_policy(
                run_dir, "solver"
            )
            _rewrite_invocation_treatment_digest(run_dir, "solver", 1, old_digest)

            declaration_path = run_dir / "treatment_declaration.json"
            stored = json.loads(declaration_path.read_text())
            stored["declaration"].pop("provider_identity_policy")
            stored["declaration"].pop("provider_identity_policy_version")
            stored["treatment_hash"] = digest_json(stored["declaration"])
            _replace_json(declaration_path, stored)

            terminal_path = run_dir / "run_result.json"
            terminal = json.loads(terminal_path.read_text())
            terminal["treatment_hash"] = stored["treatment_hash"]
            terminal_path.write_text(json.dumps(terminal, indent=2, sort_keys=True))

            authority_path = run_dir / "run_authority.json"
            authority = json.loads(authority_path.read_text())
            authority["execution_binding_sha256"] = _sha256(binding_path)
            authority["treatment_declaration_sha256"] = _sha256(declaration_path)
            _replace_json(authority_path, authority)

            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "f2-policy-downgrade")

    def test_v14_discriminator_cannot_be_downgraded_while_authority_remains_v14(self):
        with TempRoot() as root:
            runs_root, run_dir = self._successful_run(root, "f2-version-downgrade")

            binding_path = run_dir / "execution_binding.json"
            binding = json.loads(binding_path.read_text())
            binding["harness_protocol_version"] = HISTORICAL_HARNESS_PROTOCOL_VERSION
            binding.pop("provider_identity_policy")
            binding.pop("provider_identity_policy_version")
            _replace_json(binding_path, binding)

            old_digest = _expected_attempt_digest_without_identity_policy(
                run_dir, "solver"
            )
            _rewrite_invocation_treatment_digest(run_dir, "solver", 1, old_digest)

            declaration_path = run_dir / "treatment_declaration.json"
            stored = json.loads(declaration_path.read_text())
            stored["declaration"]["harness_protocol_version"] = (
                HISTORICAL_HARNESS_PROTOCOL_VERSION
            )
            stored["declaration"].pop("provider_identity_policy")
            stored["declaration"].pop("provider_identity_policy_version")
            stored["treatment_hash"] = digest_json(stored["declaration"])
            _replace_json(declaration_path, stored)

            terminal_path = run_dir / "run_result.json"
            terminal = json.loads(terminal_path.read_text())
            terminal["harness_protocol_version"] = HISTORICAL_HARNESS_PROTOCOL_VERSION
            terminal["treatment_hash"] = stored["treatment_hash"]
            terminal_path.write_text(json.dumps(terminal, indent=2, sort_keys=True))

            authority_path = run_dir / "run_authority.json"
            authority = json.loads(authority_path.read_text())
            authority["execution_binding_sha256"] = _sha256(binding_path)
            authority["treatment_declaration_sha256"] = _sha256(declaration_path)
            _replace_json(authority_path, authority)

            with self.assertRaisesRegex(
                IntegrityViolation,
                "run authority harness protocol version mismatch",
            ):
                ArtifactStore.verify_terminal_run(runs_root, "f2-version-downgrade")

    def test_v13_record_remains_verifiable_without_current_policy_claim(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)

            def invoke(**kwargs):
                response = fake_generate(
                    {"model_id": FAKE_IDENTITY.model_id},
                    kwargs["role_instruction"],
                    kwargs["stage_inputs"],
                    kwargs["budget"].to_dict(),
                    kwargs["seed"],
                )
                response["identity_used"] = {
                    "provider": FAKE_IDENTITY.provider,
                    "model_id": FAKE_IDENTITY.model_id,
                    "model_version": FAKE_IDENTITY.model_version,
                    "adapter_name": FAKE_IDENTITY.adapter_name,
                    "adapter_version": FAKE_IDENTITY.adapter_version,
                }
                return response

            real_treatment_digest = treatment_digest_for_attempt

            def v13_treatment_digest(**kwargs):
                kwargs["harness_protocol_version"] = (
                    HISTORICAL_HARNESS_PROTOCOL_VERSION
                )
                return real_treatment_digest(**kwargs)

            with (
                patch(
                    "model_council.runner.HARNESS_PROTOCOL_VERSION",
                    HISTORICAL_HARNESS_PROTOCOL_VERSION,
                ),
                patch(
                    "model_council.artifacts.HARNESS_PROTOCOL_VERSION",
                    HISTORICAL_HARNESS_PROTOCOL_VERSION,
                ),
                patch(
                    "model_council.runner.treatment_digest_for_attempt",
                    side_effect=v13_treatment_digest,
                ),
                patch.object(runner.adapter, "invoke", side_effect=invoke),
            ):
                result = runner.execute(
                    make_spec("f2-historical", "A"), make_task()
                )
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "f2-historical"
            binding = json.loads((run_dir / "execution_binding.json").read_text())
            authority = json.loads((run_dir / "run_authority.json").read_text())
            terminal = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(
                binding["harness_protocol_version"],
                HISTORICAL_HARNESS_PROTOCOL_VERSION,
            )
            self.assertEqual(
                authority["harness_protocol_version"],
                HISTORICAL_HARNESS_PROTOCOL_VERSION,
            )
            self.assertEqual(
                terminal["harness_protocol_version"],
                HISTORICAL_HARNESS_PROTOCOL_VERSION,
            )
            self.assertNotIn("provider_identity_policy", binding)
            self.assertNotIn("provider_identity_policy_version", binding)

            report = ArtifactStore.verify_terminal_run(runs_root, "f2-historical")
            self.assertTrue(report["terminal_verified"])
            self.assertFalse(report["provider_identity_policy_verified"])
            self.assertIsNone(report["provider_identity_policy_schema"])


class TestF2RemainingBlockers(unittest.TestCase):
    def test_identity_rejection_cannot_coexist_with_success_topology(self):
        for role in ("solver", "verifier", "reviser"):
            with self.subTest(role=role), TempRoot() as root:
                result, runs, _, _ = _run_with_observations(
                    root, "contradiction", "C",
                    {r: OPENAI_IDENTITY.model_id for r in ("solver", "verifier", "reviser")},
                )
                self.assertEqual(result.status, "succeeded")
                run = runs / "contradiction"
                record = json.loads(
                    (run / f"invocations/{role}/attempt-0001/invocation.json").read_text()
                )
                evidence = record["adapter_evidence"]
                evidence["provider_call_outcome"]["provider_resolved_identity"]["value"][
                    "model_id"
                ] = "wrong-model"
                for field, value in {
                    "adapter_evidence": evidence,
                    "identity_verdict": "failed",
                    "retry_decision": "stop",
                    "retry_rationale": "identity_policy_rejected",
                    "failure_class": "governance",
                    "promoted_artifact_refs": [],
                }.items():
                    _rewrite_invocation_field(run, role, 1, field, value)
                # Actual seals, later invocations, evaluation and success remain.
                self.assertTrue((run / f"seals/{role}.json").is_file())
                self.assertTrue((run / "evaluation.json").is_file())
                self.assertTrue((run / "invocations/reviser/attempt-0001/invocation.json").is_file())
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "contradiction")

    def test_not_evaluated_stop_cannot_coexist_with_success_topology(self):
        with TempRoot() as root:
            _, runs, _, _ = _run_with_observations(
                root, "no-identity-success", "C",
                {r: OPENAI_IDENTITY.model_id for r in ("solver", "verifier", "reviser")},
            )
            run = runs / "no-identity-success"
            record = json.loads((run / "invocations/solver/attempt-0001/invocation.json").read_text())
            evidence = record["adapter_evidence"]
            evidence["provider_call_outcome"] = None
            for field, value in {
                "adapter_evidence": evidence,
                "identity_verdict": "not_evaluated",
                "retry_decision": "stop",
            }.items():
                _rewrite_invocation_field(run, "solver", 1, field, value)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "no-identity-success")

    def test_terminal_failure_class_must_agree_with_identity_rejection(self):
        for status in ("infrastructure_failure", "retry_exhausted"):
            with self.subTest(status=status), TempRoot() as root:
                _, runs, _, _ = _run_with_observations(
                    root, "classification", "A", {"solver": "wrong-model"}
                )
                path = runs / "classification/run_result.json"
                terminal = json.loads(path.read_text())
                terminal["status"] = status
                path.write_text(json.dumps(terminal))
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "classification")

    def _timed_run(self, root, observed, elapsed, *, retries=0):
        clock = [0.0]
        runner, runs = make_runner(
            root, kind="openai_responses", identity=OPENAI_IDENTITY,
            monotonic=lambda: clock[0],
        )
        def invoke(request):
            outcome = _outcome(request, observed)
            clock[0] = elapsed
            return outcome
        with patch.object(runner.adapter, "invoke_live", side_effect=invoke):
            result = runner.execute(
                _spec("timed", max_stage_retries=retries, stage_timeout_seconds=1), make_task()
            )
        return result, runs

    def test_late_outcomes_keep_timeout_and_verify(self):
        for observed in (OPENAI_IDENTITY.model_id, "wrong-model", None):
            for elapsed in (1.0, 2.0):
                with self.subTest(observed=observed, elapsed=elapsed), TempRoot() as root:
                    result, runs = self._timed_run(root, observed, elapsed)
                    self.assertEqual(result.status, "retry_exhausted")
                    run = runs / "timed"
                    record = json.loads((run / "invocations/solver/attempt-0001/invocation.json").read_text())
                    self.assertEqual(record["failure_class"], "timeout")
                    self.assertEqual(record["identity_verdict"], "not_evaluated")
                    self.assertEqual(record["harness_observed_latency_seconds"], elapsed)
                    self.assertEqual(record["attempt_timeout_seconds"], 1.0)
                    self.assertEqual(record["promoted_artifact_refs"], [])
                    self.assertIsNotNone(record["adapter_evidence"]["provider_call_outcome"])
                    self.assertTrue((run / "invocations/solver/attempt-0001/raw-output.txt").is_file())
                    self.assertFalse((run / "seals/solver.json").exists())
                    self.assertFalse((run / "evaluation.json").exists())
                    self.assertTrue(ArtifactStore.verify_terminal_run(runs, "timed")["terminal_verified"])

    def test_timely_mismatch_cannot_be_reclassified_as_unevaluated_timeout(self):
        with TempRoot() as root:
            result, runs = self._timed_run(root, "wrong-model", 0.25)
            self.assertEqual(result.status, "failed_governance")
            run = runs / "timed"
            for field, value in {
                "failure_class": "timeout",
                "identity_verdict": "not_evaluated",
                "retry_rationale": "retry_budget_exhausted",
            }.items():
                _rewrite_invocation_field(run, "solver", 1, field, value)
            path = run / "run_result.json"
            terminal = json.loads(path.read_text())
            terminal["status"] = "retry_exhausted"
            path.write_text(json.dumps(terminal))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "timed")

    def test_successful_seal_requires_matching_promotion_decision_and_refs(self):
        for field, value in (("retry_decision", "stop"), ("promoted_artifact_refs", [])):
            with self.subTest(field=field), TempRoot() as root:
                _, runs, _, _ = _run_with_observations(
                    root, "promotion", "A", {"solver": OPENAI_IDENTITY.model_id}
                )
                _rewrite_invocation_field(runs / "promotion", "solver", 1, field, value)
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "promotion")

    def test_late_outcome_with_retry_budget_does_not_dispatch_again(self):
        with TempRoot() as root:
            result, runs = self._timed_run(root, "wrong-model", 2.0, retries=2)
            self.assertEqual(result.status, "retry_exhausted")
            records = [json.loads(path.read_text()) for path in sorted(
                (runs / "timed/invocations/solver").glob("*/invocation.json")
            )]
            self.assertEqual(len(records), 3)
            self.assertEqual([r["invocation_began"] for r in records], [True, False, False])
            self.assertEqual([r["identity_verdict"] for r in records], ["not_evaluated"] * 3)
            self.assertTrue(ArtifactStore.verify_terminal_run(runs, "timed")["terminal_verified"])

    def test_late_outcome_cannot_be_forced_into_identity_evaluation(self):
        for observed, forged in ((OPENAI_IDENTITY.model_id, "passed"), ("wrong", "failed"), (None, "failed")):
            with self.subTest(observed=observed), TempRoot() as root:
                _, runs = self._timed_run(root, observed, 2.0)
                _rewrite_invocation_field(runs / "timed", "solver", 1, "identity_verdict", forged)
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "timed")

    def test_invalid_or_changed_timing_cannot_authorize_success(self):
        for timing in (None, -1, float("nan"), float("inf"), "0.1", True, 1.0):
            with self.subTest(timing=timing), TempRoot() as root:
                _, runs = self._timed_run(root, OPENAI_IDENTITY.model_id, 0.25)
                # Use JSON directly for non-finite values: production serialization
                # rejects them, but an on-disk attacker need not use that serializer.
                if type(timing) is float and (timing != timing or timing == float("inf")):
                    from model_council.artifacts import _verify_provider_identity_policy_evidence
                    run = runs / "timed"
                    path = run / "invocations/solver/attempt-0001/invocation.json"
                    record = json.loads(path.read_text())
                    record["harness_observed_latency_seconds"] = timing
                    path.write_text(json.dumps(record))
                    binding = json.loads((run / "execution_binding.json").read_text())
                    entries = [json.loads(line) for line in (run / "manifest.jsonl").read_text().splitlines()]
                    with self.assertRaises(IntegrityViolation):
                        _verify_provider_identity_policy_evidence(run, binding, entries)
                else:
                    _rewrite_invocation_field(runs / "timed", "solver", 1, "harness_observed_latency_seconds", timing)
                    with self.assertRaises(IntegrityViolation):
                        ArtifactStore.verify_terminal_run(runs, "timed")

    def test_identity_rejection_forbids_unmanifested_promotion_or_evaluation(self):
        for ref in ("solver/candidate.md", "evaluation.json"):
            with self.subTest(ref=ref), TempRoot() as root:
                _, runs, _, _ = _run_with_observations(root, "residue", "A", {"solver": "wrong"})
                (runs / "residue" / ref).write_text("{}")
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "residue")

    def test_successful_retry_does_not_allow_an_earlier_stop(self):
        with TempRoot() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            calls = []
            def invoke(request):
                calls.append(request)
                if len(calls) == 1:
                    outcome = live_stub_generate({"neutral_error_category": "rate_limit"}, {}, request)
                    raise NeutralProviderFailure(outcome.error, outcome=outcome)
                return _outcome(request)
            with patch.object(runner.adapter, "invoke_live", side_effect=invoke):
                result = runner.execute(_spec("retry", max_stage_retries=1), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertTrue(ArtifactStore.verify_terminal_run(runs, "retry")["terminal_verified"])
            _rewrite_invocation_field(runs / "retry", "solver", 1, "retry_decision", "stop")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "retry")

    def test_each_b_c_stage_rejects_missing_malformed_or_mismatching_identity(self):
        for condition, roles in (("B", ("draft", "self_review", "reviser")), ("C", ("solver", "verifier", "reviser"))):
            for index, role in enumerate(roles):
                for observed in (None, "<malformed>", "wrong"):
                    with self.subTest(condition=condition, role=role, observed=observed), TempRoot() as root:
                        observations = {r: OPENAI_IDENTITY.model_id for r in roles}
                        observations[role] = observed
                        result, runs, called, evaluated = _run_with_observations(root, "stage", condition, observations)
                        self.assertEqual(result.status, "failed_governance")
                        self.assertEqual(called, list(roles[:index + 1]))
                        self.assertEqual(evaluated, [])
                        self.assertFalse((runs / "stage" / "seals" / f"{role}.json").exists())
                        self.assertTrue(ArtifactStore.verify_terminal_run(runs, "stage")["terminal_verified"])


if __name__ == "__main__":
    unittest.main()
