"""Deterministic tests for the provider-neutral live invocation contract.

No network, SDK, API key, provider daemon, or spending is required.
"""

from __future__ import annotations

import copy
import importlib
import json
import sys
import unittest
from pathlib import Path

import helpers  # noqa: F401 - installs src on sys.path
from model_council import (
    LIVE_CONTRACT_VERSION,
    AdapterIdentity,
    LiveContractError,
    ProviderCallKind,
    ProviderErrorCategory,
    UnavailableReason,
    build_live_invocation_request,
    parse_live_invocation_request,
    parse_provider_call_outcome,
)
from model_council.live_contract import (
    PROVIDER_RETRY_HINT_SUGGESTED,
    CallTiming,
    FinishReason,
    NeutralError,
    ObservedInt,
    ObservedNumber,
    ObservedStr,
    ProviderUsage,
    UntrustedStructured,
    build_provider_call_outcome,
    dumps_live_invocation_request,
    dumps_provider_call_outcome,
    loads_live_invocation_request,
    loads_provider_call_outcome,
    observed_identity,
    observed_int,
    observed_metrics,
    observed_number,
    observed_str,
    observed_structured,
    parse_neutral_error,
    unavailable,
    unavailable_identity,
    unavailable_int,
    unavailable_metrics,
    unavailable_number,
    unavailable_structured,
    validate_closed_schema,
)
from model_council.security import canonical_json

IDENTITY = AdapterIdentity(
    provider="example-provider",
    model_id="example-model",
    model_version="v1",
    adapter_name="live-example",
    adapter_version="v0",
)
OTHER_IDENTITY = AdapterIdentity(
    provider="other-provider",
    model_id="other-model",
    model_version="v2",
    adapter_name="live-example",
    adapter_version="v0",
)

SRC_TEXT = Path(__file__).resolve().parents[1] / "src" / "model_council" / "live_contract.py"


def make_request(**overrides):
    kwargs = dict(
        condition="A",
        role="solver",
        role_instruction="role:solver produce a candidate",
        stage_inputs={"task": "repair the parser"},
        requested_identity=IDENTITY,
        configured_identity=IDENTITY,
        seed=7,
        max_output_tokens=1024,
        max_tool_calls=0,
        attempt_timeout_seconds=60.0,
    )
    kwargs.update(overrides)
    return build_live_invocation_request(**kwargs)


def usage_all_unavailable():
    reason = UnavailableReason.NOT_EXPOSED
    return ProviderUsage(
        input_tokens=unavailable_int(reason),
        cached_input_tokens=unavailable_int(reason),
        cache_write_tokens=unavailable_int(reason),
        output_tokens=unavailable_int(reason),
        reasoning_tokens=unavailable_int(reason),
        total_tokens=unavailable_int(reason),
        extra=unavailable_metrics(UnavailableReason.NOT_APPLICABLE),
    )


def make_outcome(**overrides):
    kwargs = dict(
        kind=ProviderCallKind.SUCCESS,
        requested_identity=IDENTITY,
        configured_identity=IDENTITY,
        provider_resolved_identity=unavailable_identity(UnavailableReason.NOT_EXPOSED),
        invocation_returned_identity=observed_identity(model_id="example-model"),
        provider_snapshot_identity=unavailable(UnavailableReason.NOT_EXPOSED),
        provider_response_id=observed_str("resp_123"),
        provider_request_id=unavailable(UnavailableReason.NOT_EXPOSED),
        provider_response_status=observed_int(200),
        finish_reason=ObservedStr(value=FinishReason.COMPLETED.value, unavailable_reason=None),
        raw_output=ObservedStr(value="candidate text", unavailable_reason=None),
        structured_output=unavailable_structured(UnavailableReason.NOT_APPLICABLE),
        tool_use_count=0,
        usage=usage_all_unavailable(),
        timing=CallTiming(
            provider_processing_ms=unavailable_number(UnavailableReason.NOT_EXPOSED),
        ),
        adapter_internal_retry_count=0,
        error=None,
        stage_output={
            "text": "candidate text",
            "artifacts": {"candidate": "candidate text", "evidence": "evidence"},
            "structured": None,
        },
    )
    kwargs.update(overrides)
    return build_provider_call_outcome(**kwargs)


def make_error_outcome(kind=ProviderCallKind.PROVIDER_ERROR, **overrides):
    error = NeutralError(
        category=ProviderErrorCategory.RATE_LIMIT,
        sanitized_message="provider rate limit",
        http_status=observed_int(429),
    )
    defaults = dict(
        kind=kind,
        raw_output=unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
        finish_reason=unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
        error=error,
        stage_output=None,
    )
    defaults.update(overrides)
    return make_outcome(**defaults)


class TestLiveInvocationRequest(unittest.TestCase):
    def test_build_round_trip_is_deterministic(self):
        request = make_request()
        encoded = dumps_live_invocation_request(request)
        again = dumps_live_invocation_request(loads_live_invocation_request(encoded))
        self.assertEqual(encoded, again)
        self.assertEqual(encoded, canonical_json(json.loads(encoded)))
        self.assertEqual(request.contract_version, LIVE_CONTRACT_VERSION)
        self.assertEqual(request.authority["may_retry"], False)
        self.assertEqual(request.authority["may_select_alternate_model"], False)
        self.assertEqual(request.authority["may_write_artifacts"], False)
        self.assertEqual(request.authority["may_access_evaluator"], False)

    def test_input_digest_binds_model_visible_content(self):
        first = make_request(stage_inputs={"task": "alpha"})
        second = make_request(stage_inputs={"task": "beta"})
        self.assertNotEqual(first.input_content_digest, second.input_content_digest)
        self.assertNotEqual(first.request_parameter_digest, second.request_parameter_digest)

    def test_remaining_timeout_is_recorded_but_excluded_from_treatment_digest(self):
        first = make_request(attempt_timeout_seconds=60.0)
        second = make_request(attempt_timeout_seconds=1.25)
        self.assertEqual(first.request_parameter_digest, second.request_parameter_digest)
        self.assertNotEqual(first.attempt_timeout_seconds, second.attempt_timeout_seconds)
        payload = first.to_dict()
        self.assertEqual(payload["attempt_timeout_seconds"], 60.0)
        payload["attempt_timeout_seconds"] = 0.5
        parsed = parse_live_invocation_request(payload)
        self.assertEqual(parsed.request_parameter_digest, first.request_parameter_digest)
        self.assertEqual(parsed.attempt_timeout_seconds, 0.5)

    def test_seed_change_still_changes_treatment_digest(self):
        first = make_request(seed=7)
        second = make_request(seed=8)
        self.assertNotEqual(first.request_parameter_digest, second.request_parameter_digest)

    def test_seed_is_the_declared_runspec_value(self):
        request = make_request(seed=7)
        self.assertEqual(request.seed, 7)
        payload = request.to_dict()
        self.assertNotIn("attempt", payload)
        self.assertNotIn("max_stage_retries", payload)

    def test_verifier_carries_structured_schema_without_evaluator_secrets(self):
        request = make_request(
            condition="C",
            role="verifier",
            role_instruction="role:verifier inspect the candidate",
            stage_inputs={
                "task": "repair the parser",
                "solver_candidate": "candidate",
                "solver_evidence": "evidence",
            },
        )
        contract = dict(request.output_contract)
        self.assertTrue(contract["structured_required"])
        self.assertEqual(contract["structured_schema_id"], "verifier_findings_v1")
        self.assertEqual(list(contract["expected_artifacts"]), ["findings"])
        encoded = request.to_json()
        self.assertNotIn("hidden_tests", encoded)
        self.assertNotIn("evaluator_config", encoded)
        self.assertNotIn("PROPOSED_FIX", encoded)
        self.assertIn('"may_access_evaluator":false', encoded)

    def test_request_rejects_unauthorized_and_secret_fields(self):
        payload = make_request().to_dict()
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request({**payload, "api_key": "sk-test"})
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request({**payload, "headers": {"authorization": "Bearer x"}})
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request({**payload, "evaluator_config": {"secret": "x"}})
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request({**payload, "runs_root": "/tmp/runs"})

    def test_missing_mandatory_field_rejected(self):
        payload = make_request().to_dict()
        del payload["seed"]
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)

    def test_wrong_types_rejected(self):
        payload = make_request().to_dict()
        payload["seed"] = "7"
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)
        payload = make_request().to_dict()
        payload["max_output_tokens"] = True
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)
        payload = make_request().to_dict()
        payload["stage_inputs"] = ["task"]
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)

    def test_unsupported_contract_version_rejected(self):
        payload = make_request().to_dict()
        payload["contract_version"] = "m1-live-contract-v0"
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)

    def test_digest_tampering_rejected(self):
        payload = make_request().to_dict()
        payload["role_instruction"] = "role:solver mutated"
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)
        payload = make_request().to_dict()
        payload["input_content_digest"] = "0" * 64
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)

    def test_authority_true_rejected(self):
        payload = make_request().to_dict()
        payload["authority"]["may_retry"] = True
        payload["request_parameter_digest"] = ""
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)

    def test_negative_ceilings_and_timeout_rejected(self):
        with self.assertRaises(LiveContractError):
            make_request(max_output_tokens=-1)
        with self.assertRaises(LiveContractError):
            make_request(max_tool_calls=-1)
        with self.assertRaises(LiveContractError):
            make_request(attempt_timeout_seconds=0)
        with self.assertRaises(LiveContractError):
            make_request(attempt_timeout_seconds=-1.5)

    def test_unauthorized_stage_input_rejected(self):
        with self.assertRaises(LiveContractError):
            make_request(stage_inputs={"task": "x", "hidden_tests": "nope"})
        with self.assertRaises(LiveContractError):
            make_request(
                role="solver",
                stage_inputs={"task": "x", "solver_candidate": "not for solver"},
            )

    def test_condition_b_reviser_accepts_only_b_context_and_omits_c_dispositions(self):
        request = make_request(
            condition="B",
            role="reviser",
            role_instruction="role:reviser revise the draft",
            stage_inputs={
                "task": "repair the parser",
                "draft": "draft text",
                "self_review": "review text",
            },
        )
        contract = dict(request.output_contract)
        self.assertFalse(contract["structured_required"])
        self.assertIsNone(contract["structured_schema_id"])
        self.assertIsNone(contract["structured_schema"])
        self.assertEqual(list(contract["expected_artifacts"]), ["final_candidate"])
        self.assertEqual(
            set(request.stage_inputs),
            {"task", "draft", "self_review"},
        )

    def test_condition_c_reviser_requires_dispositions_and_c_context(self):
        request = make_request(
            condition="C",
            role="reviser",
            role_instruction="role:reviser revise the candidate",
            stage_inputs={
                "task": "repair the parser",
                "solver_candidate": "candidate",
                "verifier_findings": "findings",
            },
        )
        contract = dict(request.output_contract)
        self.assertTrue(contract["structured_required"])
        self.assertEqual(contract["structured_schema_id"], "reviser_dispositions_v1")
        self.assertEqual(contract["structured_schema"]["additionalProperties"], False)
        self.assertEqual(
            contract["structured_schema"]["properties"]["dispositions"]["items"]["additionalProperties"],
            False,
        )
        self.assertEqual(set(request.stage_inputs), {"task", "solver_candidate", "verifier_findings"})

    def test_mixed_b_c_reviser_context_rejected(self):
        with self.assertRaises(LiveContractError):
            make_request(
                condition="B",
                role="reviser",
                role_instruction="role:reviser revise the draft",
                stage_inputs={
                    "task": "repair the parser",
                    "draft": "draft text",
                    "self_review": "review text",
                    "solver_candidate": "c-only",
                    "verifier_findings": "c-only",
                },
            )
        with self.assertRaises(LiveContractError):
            make_request(
                condition="C",
                role="reviser",
                role_instruction="role:reviser revise the candidate",
                stage_inputs={
                    "task": "repair the parser",
                    "draft": "b-only",
                    "self_review": "b-only",
                    "solver_candidate": "candidate",
                    "verifier_findings": "findings",
                },
            )

    def test_nested_structured_schema_rejects_extra_properties(self):
        request = make_request(
            condition="C",
            role="verifier",
            role_instruction="role:verifier inspect the candidate",
            stage_inputs={
                "task": "repair the parser",
                "solver_candidate": "candidate",
                "solver_evidence": "evidence",
            },
        )
        schema = request.output_contract["structured_schema"]
        valid = {
            "findings": [
                {"finding_id": "V1", "description": "x", "material": True}
            ]
        }
        validate_closed_schema(valid, schema)
        with self.assertRaises(LiveContractError):
            validate_closed_schema(
                {
                    "findings": [
                        {
                            "finding_id": "V1",
                            "description": "x",
                            "material": True,
                            "severity": "high",
                        }
                    ]
                },
                schema,
            )
        with self.assertRaises(LiveContractError):
            validate_closed_schema({**valid, "sufficiency": "enough"}, schema)

    def test_malformed_identity_rejected(self):
        payload = make_request().to_dict()
        payload["configured_identity"]["model_id"] = ""
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)
        payload = make_request().to_dict()
        payload["requested_identity"]["identity_key"] = "tampered"
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(payload)


class TestProviderCallOutcome(unittest.TestCase):
    def test_success_round_trip_preserves_four_identities(self):
        outcome = make_outcome(
            requested_identity=IDENTITY,
            configured_identity=OTHER_IDENTITY,
            provider_resolved_identity=observed_identity(
                provider="example-provider", model_id="example-model"
            ),
            invocation_returned_identity=observed_identity(model_id="example-model-hosted"),
            provider_snapshot_identity=observed_str("snap-1"),
        )
        encoded = dumps_provider_call_outcome(outcome)
        loaded = loads_provider_call_outcome(encoded)
        self.assertEqual(encoded, dumps_provider_call_outcome(loaded))
        self.assertEqual(loaded.requested_identity.key(), IDENTITY.key())
        self.assertEqual(loaded.configured_identity.key(), OTHER_IDENTITY.key())
        self.assertEqual(dict(loaded.provider_resolved_identity.value)["model_id"], "example-model")
        self.assertEqual(loaded.invocation_returned_identity.value["model_id"], "example-model-hosted")
        self.assertEqual(loaded.provider_snapshot_identity.value, "snap-1")
        self.assertIsNone(loaded.error)
        self.assertEqual(loaded.adapter_internal_retry_count, 0)
        self.assertTrue(loaded.structured_output.to_dict()["untrusted"])

    def test_zero_usage_is_not_unavailable(self):
        usage = ProviderUsage(
            input_tokens=observed_int(0),
            cached_input_tokens=observed_int(0),
            cache_write_tokens=observed_int(0),
            output_tokens=observed_int(12),
            reasoning_tokens=unavailable_int(UnavailableReason.NOT_EXPOSED),
            total_tokens=observed_int(12),
            extra=observed_metrics("provider_neutral", {"cached_write_ms": 0}),
        )
        outcome = make_outcome(usage=usage)
        payload = outcome.to_dict()
        self.assertEqual(payload["usage"]["input_tokens"]["value"], 0)
        self.assertIsNone(payload["usage"]["input_tokens"]["unavailable_reason"])
        self.assertIsNone(payload["usage"]["reasoning_tokens"]["value"])
        self.assertEqual(
            payload["usage"]["reasoning_tokens"]["unavailable_reason"],
            UnavailableReason.NOT_EXPOSED.value,
        )

    def test_provider_and_transport_errors_are_distinct(self):
        provider = make_error_outcome(ProviderCallKind.PROVIDER_ERROR)
        transport = make_error_outcome(
            ProviderCallKind.TRANSPORT_ERROR,
            error=NeutralError(
                category=ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                sanitized_message="connection refused",
                http_status=unavailable_int(UnavailableReason.NO_RESPONSE_RECEIVED),
            ),
        )
        self.assertEqual(provider.kind, ProviderCallKind.PROVIDER_ERROR)
        self.assertEqual(transport.kind, ProviderCallKind.TRANSPORT_ERROR)
        self.assertEqual(provider.error.category, ProviderErrorCategory.RATE_LIMIT)
        self.assertEqual(
            transport.error.category, ProviderErrorCategory.TRANSPORT_CONNECTIVITY
        )

    def test_invalid_outcome_kind_rejected(self):
        payload = make_outcome().to_dict()
        payload["kind"] = "retry_exhausted"
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload["kind"] = "failed_budget"
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_unsupported_version_rejected(self):
        payload = make_outcome().to_dict()
        payload["contract_version"] = "not-a-version"
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_nonzero_adapter_retry_count_rejected(self):
        payload = make_outcome().to_dict()
        payload["adapter_internal_retry_count"] = 1
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        with self.assertRaises(LiveContractError):
            make_outcome(adapter_internal_retry_count=2)

    def test_negative_usage_and_timing_rejected(self):
        payload = make_outcome().to_dict()
        payload["usage"]["output_tokens"] = {"value": -1, "unavailable_reason": None}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["timing"]["harness_observed_latency_seconds"] = 999.0
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["tool_use_count"] = -3
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_boolean_counts_rejected(self):
        payload = make_outcome().to_dict()
        payload["usage"]["input_tokens"] = {"value": True, "unavailable_reason": None}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["adapter_internal_retry_count"] = False
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_missing_mandatory_outcome_field_rejected(self):
        payload = make_outcome().to_dict()
        del payload["usage"]
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_invalid_unavailable_reason_rejected(self):
        payload = make_outcome().to_dict()
        payload["provider_request_id"] = {"value": None, "unavailable_reason": "unknown"}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["provider_request_id"] = {"value": None, "unavailable_reason": "missing"}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_value_and_reason_cannot_be_combined(self):
        payload = make_outcome().to_dict()
        payload["provider_response_id"] = {
            "value": "resp_1",
            "unavailable_reason": UnavailableReason.NOT_EXPOSED.value,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_malformed_identity_observation_rejected(self):
        payload = make_outcome().to_dict()
        payload["invocation_returned_identity"] = {
            "value": {"model_id": ""},
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["provider_resolved_identity"] = {
            "value": {"adapter_name": "sneak"},
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_secret_and_header_metadata_rejected(self):
        payload = make_outcome().to_dict()
        payload["usage"]["extra"] = {
            "value": {"namespace": "vendor", "metrics": {"authorization": 1}},
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_outcome().to_dict()
        payload["X-Request-Id"] = "abc"
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_nested_non_json_and_forbidden_structured_keys_rejected(self):
        payload = make_outcome().to_dict()
        payload["structured_output"] = {
            "untrusted": True,
            "value": {"headers": {"authorization": "Bearer x"}},
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        with self.assertRaises(LiveContractError):
            make_outcome(structured_output=observed_structured({"ok": object()}))

    def test_structured_output_must_be_marked_untrusted(self):
        payload = make_outcome().to_dict()
        payload["structured_output"]["untrusted"] = False
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_success_cannot_carry_error_and_error_kinds_require_error(self):
        payload = make_outcome().to_dict()
        payload["error"] = {
            "category": ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE.value,
            "sanitized_message": "should not appear on success",
            "http_status": {"value": None, "unavailable_reason": "not_applicable"},
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_error_outcome().to_dict()
        payload["error"] = None
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_error_message_rejects_traceback_and_overlong_text(self):
        with self.assertRaises(LiveContractError):
            make_error_outcome(
                error=NeutralError(
                    category=ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                    sanitized_message="Traceback (most recent call last): boom",
                    http_status=unavailable_int(UnavailableReason.NOT_APPLICABLE),
                )
            )
        with self.assertRaises(LiveContractError):
            make_error_outcome(
                error=NeutralError(
                    category=ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                    sanitized_message="x" * 513,
                    http_status=unavailable_int(UnavailableReason.NOT_APPLICABLE),
                )
            )

    def test_provider_retry_hint_is_observational_and_constrained(self):
        hinted = make_error_outcome(
            error=NeutralError(
                category=ProviderErrorCategory.RATE_LIMIT,
                sanitized_message="rate limited",
                http_status=observed_int(429),
                provider_retry_hint=ObservedStr(
                    value=PROVIDER_RETRY_HINT_SUGGESTED, unavailable_reason=None
                ),
                retry_after_seconds=ObservedNumber(value=1.5, unavailable_reason=None),
            )
        )
        payload = hinted.to_dict()["error"]
        self.assertEqual(payload["provider_retry_hint"]["value"], PROVIDER_RETRY_HINT_SUGGESTED)
        self.assertEqual(payload["retry_after_seconds"]["value"], 1.5)
        self.assertNotIn("is_retryable", payload)
        self.assertNotIn("should_retry", payload)
        self.assertNotIn("retry_decision", payload)
        parsed = parse_neutral_error(payload)
        self.assertEqual(parsed.provider_retry_hint.value, PROVIDER_RETRY_HINT_SUGGESTED)

    def test_error_policy_fields_and_secrets_rejected(self):
        payload = make_error_outcome().to_dict()
        for extra in (
            {"is_retryable": True},
            {"should_retry": False},
            {"retry_decision": "retry"},
            {"Authorization": "Bearer sk-test"},
            {"api_key": "sk-test"},
            {"cookie": "sid=1"},
            {"proxy-authorization": "Basic abc"},
        ):
            with self.subTest(extra=extra):
                error = {**payload["error"], **extra}
                with self.assertRaises(LiveContractError):
                    parse_neutral_error(error)

    def test_malformed_or_negative_retry_after_rejected(self):
        payload = make_error_outcome().to_dict()
        payload["error"]["retry_after_seconds"] = {"value": -1, "unavailable_reason": None}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_error_outcome().to_dict()
        payload["error"]["retry_after_seconds"] = {"value": "soon", "unavailable_reason": None}
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload = make_error_outcome().to_dict()
        payload["error"]["provider_retry_hint"] = {
            "value": "please_retry",
            "unavailable_reason": None,
        }
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)

    def test_empty_raw_output_is_distinct_from_no_response(self):
        empty = make_outcome(raw_output=ObservedStr(value="", unavailable_reason=None))
        missing = make_error_outcome()
        self.assertEqual(empty.raw_output.value, "")
        self.assertIsNone(empty.raw_output.unavailable_reason)
        self.assertIsNone(missing.raw_output.value)
        self.assertEqual(
            missing.raw_output.unavailable_reason, UnavailableReason.NO_RESPONSE_RECEIVED
        )

    def test_wrong_json_types_rejected(self):
        with self.assertRaises(LiveContractError):
            loads_provider_call_outcome("[]")
        with self.assertRaises(LiveContractError):
            loads_live_invocation_request("null")
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome("not-an-object")


class TestContractIsolation(unittest.TestCase):
    def test_module_has_no_provider_sdk_or_network_surface(self):
        source = SRC_TEXT.read_text(encoding="utf-8")
        lowered = source.lower()
        self.assertNotIn("openai", lowered)
        self.assertNotIn("ollama", lowered)
        self.assertNotIn("pickle", lowered)
        self.assertNotIn("requests", lowered)
        self.assertNotIn("httpx", lowered)
        self.assertNotIn("urllib", lowered)
        for name in ("runner", "evaluator", "artifacts", "executor", "worker", "adapters"):
            self.assertNotIn(f"import {name}", source)
            self.assertNotIn(f"from .{name}", source)

    def test_importing_contract_does_not_load_openai(self):
        existing = sys.modules.get("model_council.live_contract")
        sys.modules.pop("model_council.live_contract", None)
        try:
            importlib.import_module("model_council.live_contract")
            self.assertNotIn("openai", sys.modules)
            self.assertNotIn("ollama", sys.modules)
        finally:
            if existing is not None:
                sys.modules["model_council.live_contract"] = existing

    def test_deepcopy_cannot_inject_retry_authority(self):
        request = make_request()
        cloned = copy.deepcopy(request.to_dict())
        cloned["authority"]["may_retry"] = True
        with self.assertRaises(LiveContractError):
            parse_live_invocation_request(cloned)
        self.assertFalse(request.authority["may_retry"])

    def test_does_not_map_to_m1_terminal_statuses(self):
        source = SRC_TEXT.read_text(encoding="utf-8")
        for status in (
            "failed_budget",
            "retry_exhausted",
            "failed_governance",
            "infrastructure_failure",
        ):
            self.assertNotIn(status, source)

    def test_contract_does_not_own_retry_policy(self):
        source = SRC_TEXT.read_text(encoding="utf-8")
        self.assertNotIn("is_retry_candidate", source)
        self.assertNotIn("RETRYABLE_PROVIDER_CATEGORIES", source)
        self.assertNotIn("from .retry_policy", source)
        self.assertNotIn("from .runner", source)


if __name__ == "__main__":
    unittest.main()
