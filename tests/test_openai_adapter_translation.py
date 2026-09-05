"""Tranche 4: OpenAI Responses request/response translation.

Synthetic provider-shaped fixtures only. No SDK import, network, credential,
or real provider call. Production entrypoint composition is exercised with a
patched transport seam returning owned fixtures.
"""

from __future__ import annotations

import ast
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council.errors import ProtocolError
from collections.abc import Mapping

from model_council.live_contract import (
    FinishReason,
    ProviderCallKind,
    ProviderErrorCategory,
    UnavailableReason,
    dumps_provider_call_outcome,
)
from model_council.security import canonical_json, deep_freeze
from model_council.types import AdapterIdentity
from test_live_contract import make_request

REPO_ROOT = Path(__file__).resolve().parents[1]
OPENAI_ADAPTER_PATH = REPO_ROOT / "src" / "model_council" / "openai_adapter.py"
_CHILD_KEY = "MCL_OPENAI_API_KEY"
_FAKE_CREDENTIAL = "mcl-test-openai-runtime-credential-not-real"

CONFIGURED = AdapterIdentity(
    provider="openai",
    model_id="gpt-5.6-sol",
    model_version="2026-08-29",
    adapter_name="openai_responses",
    adapter_version="v0",
)
REQUESTED_ALIAS = AdapterIdentity(
    provider="openai",
    model_id="gpt-5-alias-must-not-win",
    model_version="alias",
    adapter_name="openai_responses",
    adapter_version="v0",
)
OBSERVED_MODEL = "gpt-5.6-sol-observed-not-authority"

_FORBIDDEN_REQUEST_KEYS = (
    "previous_response_id",
    "conversation",
    "conversation_id",
    "thread",
    "thread_id",
    "prompt",
    "prompt_id",
    "metadata",
    "user",
    "service_tier",
    "temperature",
    "top_p",
    "timeout",
    "max_retries",
    "retry",
    "retry_after",
    "extra_headers",
    "extra_query",
    "extra_body",
    "include",
)

_CLOSED_TREATMENT = {
    "reasoning": {"effort": "high", "summary": "concise"},
    "text": {"verbosity": "low"},
}
_OMIT = object()
_SYNTHETIC_PROVIDER_SECRET = "Bearer synthetic-provider-secret"


def _solver_envelope(**overrides):
    payload = {
        "text": "candidate text",
        "artifacts": {"candidate": "candidate text", "evidence": "evidence"},
        "structured": None,
    }
    payload.update(overrides)
    return payload


def _verifier_envelope():
    return {
        "text": "findings text",
        "artifacts": {"findings": "findings text"},
        "structured": {
            "findings": [
                {
                    "finding_id": "V1",
                    "description": "confirm the candidate",
                    "material": True,
                }
            ]
        },
    }


def _solver_request(**overrides):
    kwargs = dict(
        requested_identity=REQUESTED_ALIAS,
        configured_identity=CONFIGURED,
        role_instruction="role:solver produce a candidate",
        stage_inputs={"task": "repair the parser"},
    )
    kwargs.update(overrides)
    return make_request(**kwargs)


def _verifier_request():
    return make_request(
        condition="C",
        role="verifier",
        role_instruction="role:verifier inspect the candidate",
        stage_inputs={
            "task": "repair the parser",
            "solver_candidate": "candidate body",
            "solver_evidence": "evidence body",
        },
        requested_identity=REQUESTED_ALIAS,
        configured_identity=CONFIGURED,
    )


def _reviser_b_request():
    return make_request(
        condition="B",
        role="reviser",
        role_instruction="role:reviser revise the draft",
        stage_inputs={
            "task": "repair the parser",
            "draft": "draft body",
            "self_review": "self-review body",
        },
        requested_identity=REQUESTED_ALIAS,
        configured_identity=CONFIGURED,
    )


def _completed_fixture(
    envelope,
    *,
    model=OBSERVED_MODEL,
    response_id="resp_123",
    request_id="req_abc",
    usage=None,
    extra_items=None,
    output_text=None,
    status="completed",
    incomplete_details=None,
    error=None,
    extra_fields=None,
    message_status="completed",
    object_value="response",
):
    body_text = canonical_json(envelope) if isinstance(envelope, dict) else envelope
    if output_text is None:
        output_text = body_text
    items = list(extra_items or ())
    message = {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "output_text",
                "text": body_text,
                "annotations": [],
            }
        ],
    }
    if message_status is not _OMIT:
        message["status"] = message_status
    items.append(message)
    fixture = {
        "id": response_id,
        "status": status,
        "model": model,
        "output": items,
        "output_text": output_text,
        "error": error,
        "incomplete_details": incomplete_details,
        "usage": usage,
        "request_id": request_id,
    }
    if object_value is not _OMIT:
        fixture["object"] = object_value
    if extra_fields:
        fixture.update(extra_fields)
    return fixture


def _usage_fixture():
    return {
        "input_tokens": 11,
        "output_tokens": 22,
        "total_tokens": 33,
        "input_tokens_details": {"cached_tokens": 2},
        "output_tokens_details": {"reasoning_tokens": 4},
    }


def _assert_no_stage_output(test, outcome):
    test.assertIsNone(outcome.stage_output)
    test.assertEqual(outcome.kind, ProviderCallKind.PROVIDER_ERROR)


def _assert_json_plain(test, value):
    encoded = json.dumps(value)
    test.assertIsInstance(encoded, str)
    json.loads(encoded)


def _assert_outcome_serializable(test, outcome):
    encoded = dumps_provider_call_outcome(outcome)
    _assert_json_plain(test, json.loads(encoded))
    test.assertEqual(encoded, dumps_provider_call_outcome(outcome))
    blob = encoded.lower()
    test.assertNotIn("bearer ", blob)
    test.assertNotIn("authorization:", blob)


class _ExplodingProviderMapping(Mapping):
    def __iter__(self):
        raise RuntimeError(_SYNTHETIC_PROVIDER_SECRET)

    def __getitem__(self, key):
        raise RuntimeError(_SYNTHETIC_PROVIDER_SECRET)

    def __len__(self):
        return 1


class TestOpenAIAdapterTranslationImportBoundary(unittest.TestCase):
    def test_translation_module_does_not_import_openai_sdk(self):
        for name in list(sys.modules):
            if name == "openai" or name.startswith("openai."):
                self.fail("openai SDK must not be imported")
        from model_council import openai_adapter as openai_mod

        self.assertNotIn("openai", sys.modules)
        tree = ast.parse(OPENAI_ADAPTER_PATH.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name, "openai")
                    self.assertFalse(alias.name.startswith("openai."))
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotEqual(node.module, "openai")
                self.assertFalse(node.module.startswith("openai."))
        self.assertTrue(hasattr(openai_mod, "build_openai_responses_request"))
        self.assertTrue(hasattr(openai_mod, "translate_openai_responses_result"))


class TestOpenAIRequestConstruction(unittest.TestCase):
    def test_configured_model_authority_sends_alias_verbatim(self):
        from model_council.openai_adapter import build_openai_responses_request

        built = build_openai_responses_request(_solver_request(), {})
        self.assertEqual(built["model"], "gpt-5.6-sol")
        self.assertNotEqual(built["model"], REQUESTED_ALIAS.model_id)
        _assert_json_plain(self, built)

    def test_canonical_model_visible_input_is_only_role_and_stage_inputs(self):
        from model_council.openai_adapter import build_openai_responses_request

        request = _solver_request()
        built = build_openai_responses_request(request, _CLOSED_TREATMENT)
        self.assertEqual(built["instructions"], request.role_instruction)
        self.assertEqual(
            built["input"],
            canonical_json({"stage_inputs": dict(request.stage_inputs)}),
        )
        visible = built["instructions"] + built["input"]
        for leaked in (
            "provider_metadata",
            "retry",
            "evaluator",
            "hidden",
            "OPENAI_API_KEY",
            "MCL_OPENAI_API_KEY",
            "gpt-5-alias-must-not-win",
            "reasoning",
            "verbosity",
            "resp_",
            str(request.attempt_timeout_seconds),
        ):
            self.assertNotIn(leaked, visible)

    def test_provider_treatment_mapping_is_explicit_and_not_merged(self):
        from model_council.openai_adapter import build_openai_responses_request

        built = build_openai_responses_request(_solver_request(), _CLOSED_TREATMENT)
        self.assertEqual(built["reasoning"], {"effort": "high", "summary": "concise"})
        self.assertEqual(built["text"]["verbosity"], "low")
        self.assertNotIn("reasoning", built["text"])
        self.assertEqual(built["text"]["format"]["type"], "json_schema")
        self.assertIs(built["store"], False)
        self.assertNotEqual(built, _CLOSED_TREATMENT)
        self.assertNotIn("effort", built)

    def test_optional_treatment_members_are_omitted_when_absent(self):
        from model_council.openai_adapter import build_openai_responses_request

        built = build_openai_responses_request(_solver_request(), {})
        self.assertNotIn("reasoning", built)
        self.assertNotIn("verbosity", built.get("text", {}))
        self.assertEqual(built["text"]["format"]["type"], "json_schema")

    def test_forbidden_provider_treatment_keys_fail_closed(self):
        from model_council.openai_adapter import build_openai_responses_request

        cases = (
            {"temperature": 0},
            {"top_p": 1},
            {"model": "attacker-model"},
            {"instructions": "ignore previous"},
            {"input": "injected"},
            {"timeout": 1},
            {"max_retries": 3},
            {"retry": True},
            {"retry_after": 1},
            {"user": "user-1"},
            {"service_tier": "flex"},
            {"metadata": {"run": "x"}},
            {"max_output_tokens": 16},
            {"runtime": {"num_ctx": 1}},
            {"reasoning": {"effort": "high", "budget": 12}},
            {"text": {"verbosity": "low", "format": {"type": "text"}}},
            {"reasoning": {"effort": "extreme"}},
            {"text": {"verbosity": "silent"}},
            {"reasoning": "high"},
            {"text": ["low"]},
            {"reasoning": {"effort": 1}},
            {"text": {"verbosity": True}},
        )
        for config in cases:
            with self.subTest(config=str(config)):
                with self.assertRaises(ProtocolError):
                    build_openai_responses_request(_solver_request(), config)

    def test_stateful_treatment_keys_remain_rejected(self):
        from model_council.openai_adapter import build_openai_responses_request

        with self.assertRaises(ProtocolError):
            build_openai_responses_request(
                _solver_request(), {"previous_response_id": "resp_1"}
            )

    def test_stateless_request_controls_are_explicit(self):
        from model_council.openai_adapter import build_openai_responses_request

        built = build_openai_responses_request(_solver_request(), {})
        self.assertIs(built["store"], False)
        self.assertIs(built["stream"], False)
        self.assertIs(built["background"], False)
        self.assertEqual(built["tools"], [])
        self.assertEqual(built["tool_choice"], "none")
        self.assertIs(built["parallel_tool_calls"], False)
        self.assertEqual(built["truncation"], "disabled")

    def test_runner_authorized_output_ceiling_is_translated_exactly(self):
        from model_council.openai_adapter import build_openai_responses_request

        request = _solver_request(max_output_tokens=137)
        built = build_openai_responses_request(request, _CLOSED_TREATMENT)
        self.assertEqual(built["max_output_tokens"], 137)

    def test_continuation_and_internal_authority_fields_are_absent(self):
        from model_council.openai_adapter import build_openai_responses_request

        built = build_openai_responses_request(_solver_request(), _CLOSED_TREATMENT)
        for key in _FORBIDDEN_REQUEST_KEYS:
            self.assertNotIn(key, built)
        self.assertNotIn("attempt_timeout_seconds", built)
        self.assertNotIn("seed", built)

    def test_exact_expected_artifacts_in_output_schema(self):
        from model_council.openai_adapter import build_openai_responses_request

        schema = build_openai_responses_request(_solver_request(), {})["text"]["format"][
            "schema"
        ]
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(schema["required"], ["text", "artifacts", "structured"])
        artifacts = schema["properties"]["artifacts"]
        self.assertEqual(artifacts["type"], "object")
        self.assertIs(artifacts["additionalProperties"], False)
        self.assertEqual(artifacts["required"], ["candidate", "evidence"])
        self.assertEqual(
            artifacts["properties"],
            {"candidate": {"type": "string"}, "evidence": {"type": "string"}},
        )
        self.assertEqual(schema["properties"]["text"], {"type": "string"})

    def test_unstructured_schema_requires_structured_null(self):
        from model_council.openai_adapter import build_openai_responses_request

        schema = build_openai_responses_request(_solver_request(), {})["text"]["format"][
            "schema"
        ]
        self.assertEqual(schema["properties"]["structured"], {"type": "null"})
        b_schema = build_openai_responses_request(_reviser_b_request(), {})["text"][
            "format"
        ]["schema"]
        self.assertEqual(b_schema["properties"]["artifacts"]["required"], ["final_candidate"])
        self.assertEqual(b_schema["properties"]["structured"], {"type": "null"})

    def test_structured_stage_schema_is_embedded(self):
        from model_council.openai_adapter import build_openai_responses_request

        request = _verifier_request()
        schema = build_openai_responses_request(request, {})["text"]["format"]["schema"]
        self.assertEqual(schema["properties"]["artifacts"]["required"], ["findings"])
        embedded = schema["properties"]["structured"]
        expected = json.loads(canonical_json(request.output_contract["structured_schema"]))
        self.assertEqual(embedded, expected)
        self.assertEqual(embedded["required"], ["findings"])
        self.assertIs(embedded["additionalProperties"], False)


class TestOpenAIResponseTranslation(unittest.TestCase):
    def test_completed_structured_result_is_neutral_success(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        envelope = _solver_envelope()
        outcome = translate_openai_responses_result(
            request,
            _completed_fixture(envelope, usage=_usage_fixture()),
        )
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(outcome.finish_reason.value, FinishReason.COMPLETED.value)
        self.assertEqual(dict(outcome.stage_output), envelope)
        self.assertEqual(outcome.configured_identity, CONFIGURED)
        self.assertEqual(outcome.requested_identity, REQUESTED_ALIAS)
        self.assertEqual(outcome.adapter_internal_retry_count, 0)
        self.assertEqual(outcome.tool_use_count, 0)
        self.assertIsNone(outcome.error)
        _assert_json_plain(self, outcome.to_dict())

    def test_explicit_refusal_is_policy_refusal(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = {
            "id": "resp_ref",
            "object": "response",
            "status": "completed",
            "model": OBSERVED_MODEL,
            "output": [
                {
                    "id": "msg_1",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "refusal", "refusal": "I cannot help with that."}],
                }
            ],
            "output_text": "",
            "error": None,
            "incomplete_details": None,
            "request_id": "req_ref",
        }
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(outcome.error.category, ProviderErrorCategory.POLICY_REFUSAL)
        self.assertEqual(outcome.finish_reason.value, FinishReason.CONTENT_FILTER.value)

    def test_length_incomplete_translation(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = _completed_fixture(
            _solver_envelope(),
            status="incomplete",
            incomplete_details={"reason": "max_output_tokens"},
        )
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT
        )
        self.assertEqual(outcome.finish_reason.value, FinishReason.LENGTH.value)

    def test_content_filter_incomplete_translation(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = _completed_fixture(
            _solver_envelope(),
            status="incomplete",
            incomplete_details={"reason": "content_filter"},
        )
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT
        )
        self.assertEqual(outcome.finish_reason.value, FinishReason.CONTENT_FILTER.value)

    def test_generic_incomplete_translation(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = _completed_fixture(
            _solver_envelope(),
            status="incomplete",
            incomplete_details=None,
        )
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT
        )
        self.assertEqual(outcome.finish_reason.value, FinishReason.INCOMPLETE.value)

    def test_tool_call_response_is_rejected_without_execution(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = {
            "id": "resp_tool",
            "object": "response",
            "status": "completed",
            "model": OBSERVED_MODEL,
            "output": [
                {
                    "id": "fc_1",
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "run_shell",
                    "arguments": "{}",
                }
            ],
            "output_text": "",
            "error": None,
            "incomplete_details": None,
        }
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertEqual(outcome.finish_reason.value, FinishReason.TOOL_USE.value)
        self.assertEqual(outcome.tool_use_count, 0)
        serialized = canonical_json(outcome.to_dict())
        self.assertNotIn("run_shell", serialized)
        self.assertNotIn("call_1", serialized)

    def test_malformed_provider_json_is_not_promoted(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = _completed_fixture("{not json", output_text="{not json")
        fixture["output"][0]["content"][0]["text"] = "{not json"
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )

    def test_malformed_output_item_shapes_fail_closed(self):
        from model_council.openai_adapter import translate_openai_responses_result

        cases = (
            {"output": [{"content": []}]},
            {"output": [{"type": "message", "content": "text"}]},
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"text": "x"}],
                    }
                ]
            },
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_image", "image": "x"}],
                    }
                ]
            },
            {"output": "message"},
        )
        for extra in cases:
            with self.subTest(extra=str(extra)):
                fixture = {
                    "id": "resp_bad",
                    "object": "response",
                    "status": "completed",
                    "model": OBSERVED_MODEL,
                    "error": None,
                    "incomplete_details": None,
                    "output_text": "",
                }
                fixture.update(extra)
                outcome = translate_openai_responses_result(_solver_request(), fixture)
                _assert_no_stage_output(self, outcome)
                self.assertEqual(
                    outcome.error.category,
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                )

    def test_unknown_lifecycle_and_status_fail_closed(self):
        from model_council.openai_adapter import translate_openai_responses_result

        for status in ("failed", "cancelled", "in_progress", "queued", "exploded", 200):
            with self.subTest(status=status):
                fixture = _completed_fixture(_solver_envelope(), status=status)
                outcome = translate_openai_responses_result(_solver_request(), fixture)
                _assert_no_stage_output(self, outcome)
                self.assertEqual(
                    outcome.error.category,
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                )

    def test_provider_resolved_identity_is_evidence_only(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        outcome = translate_openai_responses_result(
            request, _completed_fixture(_solver_envelope())
        )
        self.assertEqual(outcome.configured_identity.model_id, "gpt-5.6-sol")
        self.assertEqual(outcome.configured_identity, request.configured_identity)
        self.assertEqual(outcome.provider_resolved_identity.value["model_id"], OBSERVED_MODEL)
        self.assertNotEqual(
            outcome.configured_identity.model_id,
            outcome.provider_resolved_identity.value["model_id"],
        )
        self.assertEqual(
            outcome.invocation_returned_identity.value["model_id"],
            CONFIGURED.model_id,
        )

    def test_usage_is_telemetry_only(self):
        from model_council.openai_adapter import translate_openai_responses_result

        outcome = translate_openai_responses_result(
            _solver_request(),
            _completed_fixture(_solver_envelope(), usage=_usage_fixture()),
        )
        self.assertEqual(outcome.usage.input_tokens.value, 11)
        self.assertEqual(outcome.usage.cached_input_tokens.value, 2)
        self.assertEqual(outcome.usage.output_tokens.value, 22)
        self.assertEqual(outcome.usage.reasoning_tokens.value, 4)
        self.assertEqual(outcome.usage.total_tokens.value, 33)
        self.assertIsNone(outcome.usage.extra.value)
        self.assertEqual(
            outcome.usage.cache_write_tokens.unavailable_reason,
            UnavailableReason.NOT_EXPOSED,
        )

    def test_reasoning_content_is_not_persisted(self):
        from model_council.openai_adapter import translate_openai_responses_result

        reasoning_item = {
            "id": "rs_1",
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": "SECRET_REASONING_TRACE"}],
        }
        outcome = translate_openai_responses_result(
            _solver_request(),
            _completed_fixture(_solver_envelope(), extra_items=(reasoning_item,)),
        )
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        blob = canonical_json(outcome.to_dict())
        self.assertNotIn("SECRET_REASONING_TRACE", blob)
        self.assertNotIn("summary_text", blob)
        self.assertEqual(dict(outcome.provider_metadata.value), {})

    def test_arbitrary_provider_objects_are_not_serialized(self):
        from model_council.openai_adapter import translate_openai_responses_result

        fixture = _completed_fixture(
            _solver_envelope(),
            extra_fields={
                "headers": {"x-request-id": "hdr_secret", "authorization": "Bearer x"},
                "error": None,
                "sdk_object": {"nested": True},
                "metadata": {"user": "abc"},
            },
        )
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        payload = outcome.to_dict()
        _assert_json_plain(self, payload)
        blob = canonical_json(payload)
        self.assertNotIn("hdr_secret", blob)
        self.assertNotIn("Bearer", blob)
        self.assertNotIn("sdk_object", blob)
        self.assertEqual(dict(outcome.provider_metadata.value), {})
        self.assertNotIn("headers", payload)
        self.assertNotIn("output", payload)

    def test_ambiguous_provider_shaped_fixtures_fail_closed(self):
        from model_council.openai_adapter import translate_openai_responses_result

        envelope = _solver_envelope()
        cases = (
            None,
            [],
            "completed",
            {"status": "completed"},
            _completed_fixture(envelope, extra_fields={"object": "chat.completion"}),
            _completed_fixture(
                envelope,
                incomplete_details={"reason": "max_output_tokens"},
            ),
            _completed_fixture(envelope, output_text="not-the-item-text"),
            {
                "id": "resp_both",
                "object": "response",
                "status": "completed",
                "model": OBSERVED_MODEL,
                "output": [
                    {
                        "id": "msg_1",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [
                            {"type": "output_text", "text": canonical_json(envelope)},
                            {"type": "refusal", "refusal": "no"},
                        ],
                    }
                ],
                "output_text": canonical_json(envelope),
                "error": None,
                "incomplete_details": None,
            },
        )
        for fixture in cases:
            with self.subTest(fixture=repr(fixture)[:80]):
                outcome = translate_openai_responses_result(_solver_request(), fixture)
                _assert_no_stage_output(self, outcome)
                self.assertEqual(
                    outcome.error.category,
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                )

    def test_unstructured_null_and_structured_stage_success(self):
        from model_council.openai_adapter import translate_openai_responses_result

        solver = translate_openai_responses_result(
            _solver_request(), _completed_fixture(_solver_envelope())
        )
        self.assertIsNone(solver.stage_output["structured"])
        self.assertEqual(
            solver.structured_output.unavailable_reason,
            UnavailableReason.NOT_APPLICABLE,
        )
        verifier_request = _verifier_request()
        envelope = _verifier_envelope()
        verifier = translate_openai_responses_result(
            verifier_request, _completed_fixture(envelope)
        )
        self.assertEqual(verifier.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(verifier.stage_output["structured"], envelope["structured"])
        self.assertEqual(
            canonical_json(verifier.structured_output.value),
            canonical_json(envelope["structured"]),
        )

    def test_schema_mismatch_is_malformed_not_success(self):
        from model_council.openai_adapter import translate_openai_responses_result

        bad_unstructured = _solver_envelope(structured={"sneak": True})
        outcome = translate_openai_responses_result(
            _solver_request(), _completed_fixture(bad_unstructured)
        )
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        bad_artifacts = {
            "text": "x",
            "artifacts": {"candidate": "x"},
            "structured": None,
        }
        outcome = translate_openai_responses_result(
            _solver_request(), _completed_fixture(bad_artifacts)
        )
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )

    def test_production_entrypoint_composes_transport_success_into_translation(self):
        from model_council.openai_adapter import (
            _OpenAITransportSuccess,
            openai_responses_skeleton,
        )

        request = _solver_request()
        fixture = _completed_fixture(_solver_envelope(), usage=_usage_fixture())
        isolated = {key: os.environ[key] for key in os.environ if key != "OPENAI_API_KEY"}
        isolated[_CHILD_KEY] = _FAKE_CREDENTIAL
        with patch.dict(os.environ, isolated, clear=True):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=_OpenAITransportSuccess(response=fixture),
            ) as transport:
                with patch("model_council.openai_adapter.build_openai_client") as factory:
                    outcome = openai_responses_skeleton({}, deep_freeze({}), request)
            factory.assert_not_called()
            transport.assert_called_once()
            self.assertNotIn(_CHILD_KEY, os.environ)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(dict(outcome.stage_output), _solver_envelope())
        _assert_outcome_serializable(self, outcome)


class TestOpenAIAdapterTranslationRemediation(unittest.TestCase):
    def _malformed(self, fixture):
        from model_council.openai_adapter import translate_openai_responses_result

        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        _assert_outcome_serializable(self, outcome)
        return outcome

    def test_f01_message_item_failed_status_is_not_success(self):
        self._malformed(_completed_fixture(_solver_envelope(), message_status="failed"))

    def test_f01_message_item_incomplete_status_does_not_override_completed(self):
        self._malformed(
            _completed_fixture(_solver_envelope(), message_status="incomplete")
        )

    def test_f01_unknown_and_malformed_message_status_fail_closed(self):
        self._malformed(_completed_fixture(_solver_envelope(), message_status="exploded"))
        self._malformed(_completed_fixture(_solver_envelope(), message_status=200))

    def test_f01_missing_message_status_fails_closed(self):
        self._malformed(_completed_fixture(_solver_envelope(), message_status=_OMIT))

    def test_f01_missing_or_unknown_object_discriminator_fails_closed(self):
        self._malformed(_completed_fixture(_solver_envelope(), object_value=_OMIT))
        self._malformed(_completed_fixture(_solver_envelope(), object_value="chat.completion"))
        self._malformed(_completed_fixture(_solver_envelope(), object_value=1))

    def test_f02_adversarial_mapping_cannot_escape_or_leak_secret(self):
        from model_council.openai_adapter import translate_openai_responses_result

        exploding = _ExplodingProviderMapping()
        try:
            outcome = translate_openai_responses_result(_solver_request(), exploding)
        except Exception as exc:
            text = str(exc)
            if _SYNTHETIC_PROVIDER_SECRET in text:
                self.fail("provider exception text escaped translation")
            self.fail("provider-controlled mapping exception escaped translation")
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        blob = dumps_provider_call_outcome(outcome)
        self.assertNotIn(_SYNTHETIC_PROVIDER_SECRET, blob)
        self.assertNotIn("Bearer", blob)
        _assert_outcome_serializable(self, outcome)

    def test_f02_oversized_incomplete_evidence_does_not_escape(self):
        from model_council.openai_adapter import translate_openai_responses_result

        oversized = "x" * 8_000_001
        fixture = _completed_fixture(
            oversized,
            status="incomplete",
            incomplete_details={"reason": "max_output_tokens"},
            output_text=oversized,
        )
        try:
            outcome = translate_openai_responses_result(_solver_request(), fixture)
        except Exception:
            self.fail("oversized incomplete evidence escaped translation")
        _assert_no_stage_output(self, outcome)
        self.assertIn(
            outcome.error.category,
            {
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
            },
        )
        if outcome.error.category is ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT:
            self.assertEqual(outcome.finish_reason.value, FinishReason.LENGTH.value)
        self.assertNotEqual(outcome.raw_output.value, oversized)
        blob = dumps_provider_call_outcome(outcome)
        self.assertNotIn(oversized[:80], blob)
        _assert_outcome_serializable(self, outcome)

    def test_f03_unsafe_and_oversized_observation_scalars_are_not_persisted(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        secret_id = "Authorization: Bearer sk-live-not-real"
        long_id = "id" + ("a" * 10_000)
        long_model = "m" * 10_000
        cases = (
            _completed_fixture(_solver_envelope(), request_id=secret_id),
            _completed_fixture(_solver_envelope(), response_id=long_id),
            _completed_fixture(_solver_envelope(), model=long_model),
        )
        for fixture in cases:
            with self.subTest(id=str(fixture.get("id"))[:24], model=str(fixture.get("model"))[:24]):
                outcome = translate_openai_responses_result(request, fixture)
                self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
                self.assertEqual(outcome.configured_identity.model_id, CONFIGURED.model_id)
                blob = dumps_provider_call_outcome(outcome)
                self.assertNotIn(secret_id, blob)
                self.assertNotIn("Bearer", blob)
                self.assertNotIn(long_id, blob)
                self.assertNotIn(long_model, blob)
                if fixture.get("request_id") == secret_id:
                    self.assertIsNone(outcome.provider_request_id.value)
                if fixture.get("id") == long_id:
                    self.assertIsNone(outcome.provider_response_id.value)
                if fixture.get("model") == long_model:
                    self.assertIsNone(outcome.provider_resolved_identity.value)
                _assert_outcome_serializable(self, outcome)

    def test_f03_oversized_usage_counter_fails_closed_and_serializes(self):
        from model_council.openai_adapter import translate_openai_responses_result

        huge = 10 ** 5000
        fixture = _completed_fixture(
            _solver_envelope(),
            usage={"input_tokens": huge, "output_tokens": 1, "total_tokens": huge},
        )
        outcome = translate_openai_responses_result(_solver_request(), fixture)
        _assert_no_stage_output(self, outcome)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertIsNone(outcome.usage.input_tokens.value)
        _assert_outcome_serializable(self, outcome)

    def test_f03_adversarial_fixture_matrix_outcomes_are_serializable(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        fixtures = (
            _completed_fixture(_solver_envelope(), usage=_usage_fixture()),
            _completed_fixture(_solver_envelope(), message_status="failed"),
            _completed_fixture(_solver_envelope(), object_value=_OMIT),
            _completed_fixture(
                _solver_envelope(),
                status="incomplete",
                incomplete_details={"reason": "max_output_tokens"},
            ),
            _completed_fixture(
                _solver_envelope(),
                status="incomplete",
                incomplete_details={"reason": "max_output_tokens"},
                error={"code": "server_error"},
            ),
            _completed_fixture(_solver_envelope(), request_id="Authorization: Bearer x"),
            _completed_fixture(
                _solver_envelope(),
                usage={"input_tokens": 10 ** 5000},
            ),
            _ExplodingProviderMapping(),
            None,
            [],
        )
        for fixture in fixtures:
            with self.subTest(kind=type(fixture).__name__):
                outcome = translate_openai_responses_result(request, fixture)
                _assert_outcome_serializable(self, outcome)

    def test_r01_standalone_secret_shaped_observations_are_unavailable(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        unsafe_values = (
            "sk-live-synthetic-not-real",
            "synthetic-secret-value",
            "credential-synthetic-value",
            "password-synthetic-value",
            "Traceback: synthetic frame",
        )
        fields = (
            ("request_id", "provider_request_id"),
            ("response_id", "provider_response_id"),
            ("model", "provider_resolved_identity"),
        )
        for unsafe in unsafe_values:
            for fixture_key, attr in fields:
                with self.subTest(unsafe=unsafe, field=fixture_key):
                    outcome = translate_openai_responses_result(
                        request,
                        _completed_fixture(_solver_envelope(), **{fixture_key: unsafe}),
                    )
                    self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
                    self.assertEqual(outcome.configured_identity, CONFIGURED)
                    self.assertEqual(
                        outcome.configured_identity.model_id, CONFIGURED.model_id
                    )
                    observed = getattr(outcome, attr)
                    self.assertIsNone(observed.value)
                    self.assertEqual(
                        observed.unavailable_reason,
                        UnavailableReason.NOT_APPLICABLE,
                    )
                    blob = dumps_provider_call_outcome(outcome)
                    self.assertNotIn(unsafe, blob)
                    self.assertNotIn(unsafe.lower(), blob.lower())
                    _assert_outcome_serializable(self, outcome)

    def test_r01_ordinary_observations_remain_available(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        request_id = "req_ordinary_abc"
        response_id = "resp_ordinary_123"
        model = "gpt-4.1-nano-observed"
        outcome = translate_openai_responses_result(
            request,
            _completed_fixture(
                _solver_envelope(),
                request_id=request_id,
                response_id=response_id,
                model=model,
            ),
        )
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(outcome.configured_identity, CONFIGURED)
        self.assertEqual(outcome.provider_request_id.value, request_id)
        self.assertEqual(outcome.provider_response_id.value, response_id)
        self.assertEqual(outcome.provider_resolved_identity.value["model_id"], model)
        blob = dumps_provider_call_outcome(outcome)
        self.assertIn(request_id, blob)
        self.assertIn(response_id, blob)
        self.assertIn(model, blob)
        _assert_outcome_serializable(self, outcome)

    def test_r01_observation_bound_accepts_256_and_rejects_257(self):
        from model_council.openai_adapter import translate_openai_responses_result

        request = _solver_request()
        safe_256 = "n" * 256
        over_257 = "n" * 257
        accepted = translate_openai_responses_result(
            request,
            _completed_fixture(
                _solver_envelope(),
                request_id=safe_256,
                response_id=safe_256,
                model=safe_256,
            ),
        )
        self.assertEqual(accepted.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(accepted.configured_identity, CONFIGURED)
        self.assertEqual(accepted.provider_request_id.value, safe_256)
        self.assertEqual(accepted.provider_response_id.value, safe_256)
        self.assertEqual(
            accepted.provider_resolved_identity.value["model_id"], safe_256
        )
        _assert_outcome_serializable(self, accepted)

        rejected = translate_openai_responses_result(
            request,
            _completed_fixture(
                _solver_envelope(),
                request_id=over_257,
                response_id=over_257,
                model=over_257,
            ),
        )
        self.assertEqual(rejected.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(rejected.configured_identity, CONFIGURED)
        self.assertIsNone(rejected.provider_request_id.value)
        self.assertIsNone(rejected.provider_response_id.value)
        self.assertIsNone(rejected.provider_resolved_identity.value)
        blob = dumps_provider_call_outcome(rejected)
        self.assertNotIn(over_257, blob)
        _assert_outcome_serializable(self, rejected)

    def test_f04_incomplete_with_non_null_error_is_malformed(self):
        outcome = self._malformed(
            _completed_fixture(
                _solver_envelope(),
                status="incomplete",
                incomplete_details={"reason": "max_output_tokens"},
                error={"code": "server_error", "message": "provider failed"},
            )
        )
        self.assertNotEqual(
            outcome.error.category, ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT
        )
        self.assertNotEqual(outcome.finish_reason.value, FinishReason.LENGTH.value)


if __name__ == "__main__":
    unittest.main()
