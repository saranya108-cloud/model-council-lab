"""Checkpoint 4: runner-owned retry policy and provider-neutral failure handling."""

from __future__ import annotations

import inspect
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    NONRETRYABLE_PROVIDER_CATEGORIES,
    RETRYABLE_PROVIDER_CATEGORIES,
    LiveContractError,
    NeutralError,
    NeutralProviderFailure,
    ProviderErrorCategory,
    is_retry_candidate,
)
from model_council.live_contract import (
    PROVIDER_RETRY_HINT_DISCOURAGED,
    PROVIDER_RETRY_HINT_SUGGESTED,
    UnavailableReason,
    build_live_invocation_request,
    parse_provider_call_outcome,
    unavailable_int,
)
from model_council.roles import ROLE_INSTRUCTIONS
from model_council.runner import _estimate_tokens_in

from helpers import (
    FAKE_IDENTITY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
    transient_failure_options,
)
from test_live_contract import make_outcome

SRC_ROOT = Path(__file__).resolve().parents[1] / "src" / "model_council"


class ControllableClock:
    def __init__(self, start=1_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class JumpAfterFirstRead:
    def __init__(self, start=1_000.0, jump=10.0):
        self.start = float(start)
        self.jump = float(jump)
        self.reads = 0

    def __call__(self):
        self.reads += 1
        if self.reads == 1:
            return self.start
        return self.start + self.jump


def _count_invokes(runner):
    calls = []
    original = runner.adapter.invoke

    def invoke(**kwargs):
        calls.append(dict(kwargs))
        return original(**kwargs)

    return calls, invoke


def _rate_limit_failure(message="rate limited"):
    return NeutralProviderFailure(
        NeutralError(
            category=ProviderErrorCategory.RATE_LIMIT,
            sanitized_message=message,
            http_status=unavailable_int(UnavailableReason.NO_RESPONSE_RECEIVED),
        )
    )


def _live_request_from_invoke(kwargs):
    instruction = kwargs["role_instruction"]
    role = instruction.split()[0].split(":", 1)[1]
    budget = kwargs["budget"]
    return build_live_invocation_request(
        condition="A",
        role=role,
        role_instruction=instruction,
        stage_inputs=dict(kwargs["stage_inputs"]),
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        seed=kwargs["seed"],
        max_output_tokens=budget.max_output_tokens_per_stage,
        max_tool_calls=budget.max_tool_calls_per_stage,
        attempt_timeout_seconds=float(kwargs["timeout_seconds"]),
    )


class TestRetryPolicyOwnership(unittest.TestCase):
    def test_mapping_lives_in_retry_policy_module(self):
        from model_council.retry_policy import is_retry_candidate as owned

        self.assertIs(owned, is_retry_candidate)
        self.assertEqual(list(inspect.signature(is_retry_candidate).parameters), ["category"])
        adapters = (SRC_ROOT / "adapters.py").read_text(encoding="utf-8")
        worker = (SRC_ROOT / "worker.py").read_text(encoding="utf-8")
        contract = (SRC_ROOT / "live_contract.py").read_text(encoding="utf-8")
        self.assertNotIn("is_retry_candidate", adapters)
        self.assertNotIn("RETRYABLE_PROVIDER_CATEGORIES", adapters)
        self.assertNotIn("is_retry_candidate", worker)
        self.assertNotIn("is_retry_candidate", contract)
        self.assertNotIn("RETRYABLE_PROVIDER_CATEGORIES", contract)

    def test_every_neutral_category_is_classified(self):
        classified = RETRYABLE_PROVIDER_CATEGORIES | NONRETRYABLE_PROVIDER_CATEGORIES
        self.assertEqual(classified, frozenset(ProviderErrorCategory))
        self.assertFalse(RETRYABLE_PROVIDER_CATEGORIES & NONRETRYABLE_PROVIDER_CATEGORIES)

    def test_retryable_allowlist_and_nonretryable_categories(self):
        for category in ProviderErrorCategory:
            expected = category in {
                ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
                ProviderErrorCategory.RATE_LIMIT,
                ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
            }
            self.assertEqual(is_retry_candidate(category), expected, category)

    def test_provider_retry_hint_cannot_change_frozen_policy(self):
        """Changing observational guidance cannot change runner policy."""
        for category in ProviderErrorCategory:
            self.assertEqual(
                is_retry_candidate(category),
                category in RETRYABLE_PROVIDER_CATEGORIES,
                category,
            )
        self.assertEqual(
            inspect.signature(is_retry_candidate).parameters["category"].name,
            "category",
        )


class TestNeutralFailureTerminalMapping(unittest.TestCase):
    def test_retryable_failure_with_no_retries_configured_is_one_call(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                options={"neutral_error_category": ProviderErrorCategory.RATE_LIMIT.value},
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("rp-no-retry", "A", max_stage_retries=0), make_task()
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.status, "retry_exhausted")

    def test_nonretryable_failure_with_retries_available_is_one_call(self):
        cases = [
            (ProviderErrorCategory.AUTHENTICATION_CONFIGURATION, "rp-auth"),
            (ProviderErrorCategory.PERMISSION, "rp-perm"),
            (ProviderErrorCategory.INVALID_REQUEST, "rp-invalid"),
            (ProviderErrorCategory.MODEL_UNAVAILABLE, "rp-unavail"),
            (ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, "rp-malformed"),
            (ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE, "rp-unknown"),
            (ProviderErrorCategory.QUOTA_EXHAUSTED, "rp-quota"),
            (ProviderErrorCategory.POLICY_REFUSAL, "rp-refusal"),
            (ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT, "rp-incomplete"),
        ]
        for category, run_id in cases:
            with self.subTest(category=category.value):
                with TempRoot() as root:
                    runner, _ = make_runner(
                        root, options={"neutral_error_category": category.value}
                    )
                    calls, invoke = _count_invokes(runner)
                    with patch.object(runner.adapter, "invoke", side_effect=invoke):
                        result = runner.execute(
                            make_spec(run_id, "A", max_stage_retries=3), make_task()
                        )
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(result.status, "infrastructure_failure")
                    self.assertIn(category.value, result.stage_results[0].error)

    def test_retryable_categories_retry_then_succeed(self):
        for category in RETRYABLE_PROVIDER_CATEGORIES:
            with self.subTest(category=category.value):
                with TempRoot() as root:
                    runner, _ = make_runner(
                        root,
                        options=transient_failure_options(
                            root,
                            fail_before_call_count=2,
                            neutral_error_category=category.value,
                        ),
                    )
                    calls, invoke = _count_invokes(runner)
                    with patch.object(runner.adapter, "invoke", side_effect=invoke):
                        result = runner.execute(
                            make_spec(f"rp-ok-{category.value}", "A", max_stage_retries=2),
                            make_task(),
                        )
                    self.assertEqual(result.status, "succeeded")
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(result.retries_used, 1)

    def test_auth_hint_to_retry_still_does_not_retry(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                options={
                    "neutral_error_category": ProviderErrorCategory.AUTHENTICATION_CONFIGURATION.value,
                    "provider_retry_hint": PROVIDER_RETRY_HINT_SUGGESTED,
                    "retry_after_seconds": 2,
                },
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("rp-hint-auth", "A", max_stage_retries=3), make_task()
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.status, "infrastructure_failure")

    def test_rate_limit_hint_discouraged_still_retries(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                options=transient_failure_options(
                    root,
                    fail_before_call_count=2,
                    neutral_error_category=ProviderErrorCategory.RATE_LIMIT.value,
                    provider_retry_hint=PROVIDER_RETRY_HINT_DISCOURAGED,
                ),
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("rp-hint-rate", "A", max_stage_retries=2), make_task()
                )
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(calls), 2)

    def test_exhausted_deadline_blocks_even_retryable_category(self):
        clock = JumpAfterFirstRead(start=4_000.0, jump=5.0)
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                options={"neutral_error_category": ProviderErrorCategory.RATE_LIMIT.value},
                monotonic=clock,
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "rp-deadline",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=2,
                    ),
                    make_task(),
                )
            self.assertEqual(len(calls), 0)
            self.assertEqual(result.status, "retry_exhausted")

    def test_retryable_failure_then_exhausted_deadline_no_second_call(self):
        clock = ControllableClock(2_000.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            calls = []

            def invoke(**kwargs):
                calls.append(dict(kwargs))
                clock.advance(kwargs["timeout_seconds"] + 0.01)
                raise _rate_limit_failure()

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "rp-dl-after",
                        "A",
                        stage_timeout_seconds=0.8,
                        max_stage_retries=2,
                    ),
                    make_task(),
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.status, "retry_exhausted")

    def test_cumulative_input_blocks_retryable_second_call(self):
        with TempRoot() as root:
            task = make_task()
            estimated_in = _estimate_tokens_in(
                ROLE_INSTRUCTIONS["solver"], {"task": task.agent_visible_text()}
            )
            ceiling = estimated_in + estimated_in // 2
            runner, _ = make_runner(
                root,
                options=transient_failure_options(
                    root,
                    fail_before_call_count=2,
                    neutral_error_category=ProviderErrorCategory.RATE_LIMIT.value,
                ),
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "rp-input",
                        "A",
                        max_input_tokens_per_stage=ceiling,
                        max_stage_retries=2,
                    ),
                    task,
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.status, "failed_budget")
            self.assertIn("input budget exceeded", result.stage_results[0].error)

    def test_model_contract_failure_is_not_a_transport_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="rogue")
            result = runner.execute(make_spec("rp-contract", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("artifact contract", result.stage_results[0].error)

    def test_pre_live_model_failure_still_retries(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options=transient_failure_options(root))
            result = runner.execute(make_spec("rp-model", "A", seed=7), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(result.retries_used, 1)


class TestRetryTreatmentStability(unittest.TestCase):
    def test_retried_neutral_failure_keeps_treatment_and_digest(self):
        clock = ControllableClock(3_000.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            calls = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                calls.append(dict(kwargs))
                clock.advance(0.4)
                if len(calls) == 1:
                    raise NeutralProviderFailure(
                        NeutralError(
                            category=ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                            sanitized_message="connection reset",
                            http_status=unavailable_int(UnavailableReason.NO_RESPONSE_RECEIVED),
                        )
                    )
                return original(**kwargs)

            spec = make_spec(
                "rp-treat",
                "A",
                seed=11,
                stage_timeout_seconds=2.0,
                max_stage_retries=1,
            )
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(spec, make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(calls), 2)
            self.assertEqual({call["seed"] for call in calls}, {spec.seed})
            self.assertEqual(calls[0]["role_instruction"], calls[1]["role_instruction"])
            self.assertEqual(calls[0]["stage_inputs"], calls[1]["stage_inputs"])
            self.assertEqual(calls[0]["budget"].to_dict(), calls[1]["budget"].to_dict())
            first = _live_request_from_invoke(calls[0])
            second = _live_request_from_invoke(calls[1])
            self.assertEqual(first.request_parameter_digest, second.request_parameter_digest)
            self.assertLess(second.attempt_timeout_seconds, first.attempt_timeout_seconds)
            self.assertNotEqual(first.attempt_timeout_seconds, second.attempt_timeout_seconds)
            self.assertEqual(first.seed, second.seed)
            self.assertEqual(first.output_contract, second.output_contract)
            self.assertEqual(first.requested_identity.key(), FAKE_IDENTITY.key())

    def test_adapter_cannot_cause_a_retry_by_itself(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                options={
                    "neutral_error_category": ProviderErrorCategory.PERMISSION.value,
                    "provider_retry_hint": PROVIDER_RETRY_HINT_SUGGESTED,
                },
            )
            calls, invoke = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("rp-no-adapter-retry", "A", max_stage_retries=5),
                    make_task(),
                )
            self.assertEqual(len(calls), 1)
            self.assertEqual(result.status, "infrastructure_failure")


class TestInternalRetryCount(unittest.TestCase):
    def test_zero_internal_retry_accepted_and_nonzero_rejected(self):
        ok = make_outcome(adapter_internal_retry_count=0)
        self.assertEqual(ok.adapter_internal_retry_count, 0)
        payload = ok.to_dict()
        payload["adapter_internal_retry_count"] = 1
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)
        payload["adapter_internal_retry_count"] = 4
        with self.assertRaises(LiveContractError):
            parse_provider_call_outcome(payload)


class TestRetryTotalityV4(unittest.TestCase):
    def test_exact_retry_and_nonretry_mapping_is_total_and_disjoint(self):
        retry = frozenset(
            {
                ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
                ProviderErrorCategory.RATE_LIMIT,
                ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
            }
        )
        nonretry = frozenset(
            {
                ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
                ProviderErrorCategory.PERMISSION,
                ProviderErrorCategory.MODEL_UNAVAILABLE,
                ProviderErrorCategory.INVALID_REQUEST,
                ProviderErrorCategory.QUOTA_EXHAUSTED,
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
                ProviderErrorCategory.POLICY_REFUSAL,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
            }
        )
        self.assertEqual(RETRYABLE_PROVIDER_CATEGORIES, retry)
        self.assertEqual(NONRETRYABLE_PROVIDER_CATEGORIES, nonretry)
        self.assertEqual(retry | nonretry, frozenset(ProviderErrorCategory))
        self.assertFalse(retry & nonretry)
        for category in retry:
            self.assertIs(is_retry_candidate(category), True, category)
        for category in nonretry:
            self.assertIs(is_retry_candidate(category), False, category)

    def test_non_enum_values_are_type_errors(self):
        with self.assertRaises(TypeError):
            is_retry_candidate("rate_limit")
        with self.assertRaises(TypeError):
            is_retry_candidate(ProviderErrorCategory.RATE_LIMIT.value)
        with self.assertRaises(TypeError):
            is_retry_candidate(None)

    def test_unclassified_category_raises_rather_than_falling_through(self):
        import model_council.retry_policy as retry_policy

        with patch.object(retry_policy, "RETRYABLE_PROVIDER_CATEGORIES", frozenset()):
            with patch.object(retry_policy, "NONRETRYABLE_PROVIDER_CATEGORIES", frozenset()):
                with self.assertRaises((RuntimeError, ValueError)):
                    retry_policy.is_retry_candidate(ProviderErrorCategory.RATE_LIMIT)

    def test_quota_exhausted_is_distinct_from_rate_limit(self):
        self.assertNotEqual(
            ProviderErrorCategory.RATE_LIMIT, ProviderErrorCategory.QUOTA_EXHAUSTED
        )
        self.assertNotEqual(
            ProviderErrorCategory.RATE_LIMIT.value,
            ProviderErrorCategory.QUOTA_EXHAUSTED.value,
        )
        self.assertTrue(is_retry_candidate(ProviderErrorCategory.RATE_LIMIT))
        self.assertFalse(is_retry_candidate(ProviderErrorCategory.QUOTA_EXHAUSTED))

    def test_provider_hints_cannot_alter_quota_or_refusal_policy(self):
        from model_council.retry_policy import is_retry_candidate as owned

        self.assertEqual(list(inspect.signature(owned).parameters), ["category"])
        for category in (
            ProviderErrorCategory.QUOTA_EXHAUSTED,
            ProviderErrorCategory.POLICY_REFUSAL,
            ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
            ProviderErrorCategory.RATE_LIMIT,
        ):
            first = is_retry_candidate(category)
            second = is_retry_candidate(category)
            self.assertEqual(first, second, category)
            self.assertEqual(first, category in RETRYABLE_PROVIDER_CATEGORIES)


class TestPolicyRefusalAndIncompleteLiveStub(unittest.TestCase):
    def test_policy_refusal_is_one_call_without_promotion_or_evaluation(self):
        from test_invocation_evidence import _load_record

        with TempRoot() as root:
            counter = Path(root) / "live-invocation-counter"
            runner, runs_root = make_runner(
                root,
                kind="live_stub",
                options={
                    "invocation_counter_path": str(counter),
                    "neutral_error_category": ProviderErrorCategory.POLICY_REFUSAL.value,
                    "retain_observational_evidence": True,
                    "finish_reason": "content_filter",
                    "raw_output": "refused by policy",
                    "provider_response_id": "resp_refuse",
                    "provider_response_status": 200,
                    "provider_metadata": {"service_tier": "flex"},
                },
            )
            result = runner.execute(
                make_spec("t2-refuse", "A", max_stage_retries=3), make_task()
            )
            self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)
            run_dir = runs_root / "t2-refuse"
            self.assertFalse((run_dir / "solver" / "candidate.md").exists())
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            self.assertFalse((run_dir / "evaluation.json").exists())
            self.assertIsNone(result.metadata.get("evaluation"))
            record = _load_record(run_dir, "solver", 1)
            outcome = record["adapter_evidence"]["provider_call_outcome"]
            self.assertEqual(outcome["kind"], "provider_error")
            self.assertEqual(outcome["error"]["category"], "policy_refusal")
            self.assertIsNone(outcome["stage_output"])
            self.assertEqual(outcome["provider_response_id"]["value"], "resp_refuse")
            self.assertEqual(outcome["finish_reason"]["value"], "content_filter")
            self.assertEqual(outcome["raw_output"]["value"], "refused by policy")
            self.assertEqual(outcome["provider_metadata"]["value"], {"service_tier": "flex"})
            self.assertEqual(record["retry_decision"], "stop")
            self.assertEqual(record["failure_class"], "provider")
            self.assertEqual(len(list((run_dir / "invocations" / "solver").iterdir())), 1)

    def test_incomplete_result_retains_raw_evidence_without_promotion(self):
        from model_council.invocation import MAX_RAW_EVIDENCE_BYTES
        from test_invocation_evidence import _load_record

        long_raw = "partial-" + ("x" * (MAX_RAW_EVIDENCE_BYTES + 80))
        with TempRoot() as root:
            counter = Path(root) / "live-invocation-counter"
            runner, runs_root = make_runner(
                root,
                kind="live_stub",
                options={
                    "invocation_counter_path": str(counter),
                    "neutral_error_category": ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT.value,
                    "retain_observational_evidence": True,
                    "finish_reason": "incomplete",
                    "raw_output": long_raw,
                    "provider_response_id": "resp_incomplete",
                    "provider_response_status": 200,
                    "provider_metadata": {"done": False, "total_duration_ns": 0},
                },
            )
            result = runner.execute(
                make_spec("t2-incomplete", "A", max_stage_retries=3), make_task()
            )
            self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
            self.assertEqual(result.status, "infrastructure_failure")
            run_dir = runs_root / "t2-incomplete"
            self.assertFalse((run_dir / "solver" / "candidate.md").exists())
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            record = _load_record(run_dir, "solver", 1)
            outcome = record["adapter_evidence"]["provider_call_outcome"]
            self.assertEqual(outcome["error"]["category"], "incomplete_provider_result")
            self.assertIsNone(outcome["stage_output"])
            self.assertEqual(outcome["raw_output"]["value"], long_raw)
            self.assertTrue(record["raw_output"]["truncated"])
            self.assertNotEqual(outcome["error"]["category"], "malformed_provider_protocol")
            self.assertNotEqual(outcome["error"]["category"], "transport_provider_timeout")
            self.assertEqual(len(list((run_dir / "invocations" / "solver").iterdir())), 1)

    def test_quota_exhausted_does_not_retry_even_with_retry_hint(self):
        with TempRoot() as root:
            counter = Path(root) / "live-invocation-counter"
            runner, _ = make_runner(
                root,
                kind="live_stub",
                options={
                    "invocation_counter_path": str(counter),
                    "neutral_error_category": ProviderErrorCategory.QUOTA_EXHAUSTED.value,
                    "provider_retry_hint": PROVIDER_RETRY_HINT_SUGGESTED,
                    "retry_after_seconds": 2,
                },
            )
            result = runner.execute(
                make_spec("t2-quota", "A", max_stage_retries=3), make_task()
            )
            self.assertEqual(counter.read_text(encoding="utf-8").strip(), "1")
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertIn("quota_exhausted", result.stage_results[0].error)


if __name__ == "__main__":
    unittest.main()
