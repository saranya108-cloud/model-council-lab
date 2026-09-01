"""Identity, budget, contract, failure-taxonomy, and atomicity boundaries."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    AdapterIdentity,
    ArtifactStore,
    Condition,
    GovernanceViolation,
    IntegrityViolation,
    ResourceLimits,
    RunSpec,
)
from model_council.artifacts import EVENT_EVALUATION, EVENT_RUN_RESULT, RUN_AUTHORITY
from model_council.security import sha256_text
from model_council.sanitize import (
    INTERRUPTED_EVALUATION_MESSAGE,
    INTERRUPTED_INFRASTRUCTURE_MESSAGE,
)
from helpers import (
    IDENTITY_KEY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
    transient_failure_options,
)

OTHER_IDENTITY = AdapterIdentity(
    provider="other-provider",
    model_id="other-model",
    model_version="v9",
    adapter_name="fake",
    adapter_version="v0",
)


def terminal(root, run_id):
    return json.loads((Path(root) / "runs" / run_id / "run_result.json").read_text())


class TestIdentityEnforcement(unittest.TestCase):
    def test_preflight_mismatch_yields_terminal_governance_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)  # configured: fake identity
            spec = RunSpec(
                run_id="id-1",
                task_id="dev-001",
                condition=Condition.A,
                model_identifier=OTHER_IDENTITY.key(),
                prompt_version="p",
                resource_limits=ResourceLimits(),
            )
            result = runner.execute(spec, make_task())
            self.assertEqual(result.status, "failed_governance")
            payload = terminal(root, "id-1")
            self.assertEqual(payload["status"], "failed_governance")
            self.assertIn("identity mismatch", payload["error"])
            # A safe run namespace existed, so a terminal record is mandatory.
            self.assertTrue((Path(root) / "runs" / "id-1" / "run_result.json").exists())

    def _drift_scenario(self, root, condition, role, run_id):
        runner, _ = make_runner(
            root, kind="drift", options={"wrong_identity_from_role": role}
        )
        return runner.execute(make_spec(run_id, condition), make_task())

    def test_identity_change_at_stage_1_rejected(self):
        with TempRoot() as root:
            result = self._drift_scenario(root, "A", "solver", "id-drift-1")
            self.assertEqual(result.status, "failed_governance")
            self.assertNotIn("succeeded", [s.status.value for s in result.stage_results])
            self.assertIsNone(result.final_candidate_ref)

    def test_identity_change_at_stage_2_rejected(self):
        with TempRoot() as root:
            result = self._drift_scenario(root, "C", "verifier", "id-drift-2")
            self.assertEqual(result.status, "failed_governance")
            succeeded = [s for s in result.stage_results if s.status.value == "succeeded"]
            self.assertEqual([s.role for s in succeeded], ["solver"])

    def test_identity_change_at_stage_3_rejected(self):
        with TempRoot() as root:
            result = self._drift_scenario(root, "C", "reviser", "id-drift-3")
            self.assertEqual(result.status, "failed_governance")
            payload = terminal(root, "id-drift-3")
            self.assertIn("identity mismatch", payload["error"])
            self.assertIn("drift", json.dumps(payload["stages"][-1].get("error") or "") + payload["error"])

    def test_successful_run_has_uniform_verified_identity_everywhere(self):
        for cond in ("A", "B", "C"):
            with TempRoot() as root:
                runner, _ = make_runner(root)
                result = runner.execute(make_spec(f"id-ok-{cond}", cond), make_task())
                self.assertEqual(result.status, "succeeded")
                identities = {
                    s.verified_identity["identity_key"] for s in result.stage_results
                }
                self.assertEqual(identities, {IDENTITY_KEY}, cond)


class TestBudgetEnforcement(unittest.TestCase):
    def test_over_input_budget_rejected_on_harness_estimate(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            calls = {"n": 0}
            original = runner.adapter.invoke

            def invoke(**kwargs):
                calls["n"] += 1
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("bud-1", "A", max_input_tokens_per_stage=5), make_task()
                )
            self.assertEqual(result.status, "failed_budget")
            self.assertIn("input budget exceeded", result.stage_results[0].error)
            self.assertEqual(calls["n"], 0)
            self.assertIsNone(result.final_candidate_ref)

    def test_over_output_budget_counts_full_structured_response(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            result = runner.execute(
                make_spec("bud-2", "C", max_output_tokens_per_stage=25), make_task()
            )
            # The verifier's structured findings + text exceed 25 estimated words.
            self.assertEqual(result.status, "failed_budget")
            self.assertIn("output budget exceeded", result.stage_results[-1].error)

    def test_underreported_usage_cannot_hide_budget_breach(self):
        """Child reports tokens_out=1 but harness estimate enforces the ceiling."""
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="introspect")  # reports 1/1
            result = runner.execute(
                make_spec("bud-3", "A", max_output_tokens_per_stage=1), make_task()
            )
            self.assertEqual(result.status, "failed_budget")

    def test_over_tool_budget_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"tool_uses": 3})
            result = runner.execute(
                make_spec("bud-4", "A", max_tool_calls_per_stage=0), make_task()
            )
            self.assertEqual(result.status, "failed_budget")
            self.assertIn("tool-call budget exceeded", result.stage_results[0].error)

    def test_valid_execution_within_limits_succeeds(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            result = runner.execute(make_spec("bud-5", "C"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertTrue(result.evaluation.passed)
            for s in result.stage_results:
                self.assertEqual(s.usage_source, "harness_estimated_enforced")
                self.assertGreater(s.tokens_in, 0)
                self.assertGreater(s.tokens_out, 0)

    def _patched_solver_response(self, runner, mutate):
        response = runner.adapter.invoke(
            role_instruction="role:solver test",
            stage_inputs={"task": "small task"},
            budget=ResourceLimits(),
            seed=0,
        )
        mutate(response)
        return response

    def test_newline_heavy_input_exceeds_harness_ceiling(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._patched_solver_response(runner, lambda _: None)
            task = make_task(bug_report=("word\n" * 1200))
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(
                    make_spec("bud-newline-in", "A", max_input_tokens_per_stage=100), task
                )
            self.assertEqual(result.status, "failed_budget")

    def test_tab_heavy_input_exceeds_harness_ceiling(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._patched_solver_response(runner, lambda _: None)
            task = make_task(bug_report=("word\t" * 1200))
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(
                    make_spec("bud-tab-in", "A", max_input_tokens_per_stage=100), task
                )
            self.assertEqual(result.status, "failed_budget")

    def test_newline_heavy_output_exceeds_harness_ceiling(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._patched_solver_response(
                runner,
                lambda value: value.update(
                    {
                        "text": "word\n" * 1200,
                        "artifacts": {
                            "candidate": "word\n" * 1200,
                            "evidence": "evidence",
                        },
                    }
                ),
            )
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(
                    make_spec("bud-newline-out", "A", max_output_tokens_per_stage=100),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")

    def test_tab_heavy_output_exceeds_harness_ceiling(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._patched_solver_response(
                runner,
                lambda value: value.update(
                    {
                        "text": "word\t" * 1200,
                        "artifacts": {
                            "candidate": "word\t" * 1200,
                            "evidence": "evidence",
                        },
                    }
                ),
            )
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(
                    make_spec("bud-tab-out", "A", max_output_tokens_per_stage=100),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")

    def test_nested_structured_output_is_included_in_estimate(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            original = runner.adapter.invoke

            def invoke(**kwargs):
                response = original(**kwargs)
                if "role:verifier" in kwargs["role_instruction"]:
                    response["structured"]["findings"][0]["description"] = "word\n" * 1200
                return response

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("bud-structured", "C", max_output_tokens_per_stage=100),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")

    def test_valid_multiline_content_within_ceiling_succeeds(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            result = runner.execute(
                make_spec("bud-multiline-valid", "A"),
                make_task(bug_report="one\ntwo\tthree"),
            )
            self.assertEqual(result.status, "succeeded")

    def test_b_and_c_equivalent_enforcement(self):
        with TempRoot() as root:
            runner_b, _ = make_runner(root, options={"tool_uses": 2})
            result_b = runner_b.execute(
                make_spec("bud-6b", "B", max_tool_calls_per_stage=1), make_task()
            )
            runner_c, _ = make_runner(root, options={"tool_uses": 2})
            result_c = runner_c.execute(
                make_spec("bud-6c", "C", max_tool_calls_per_stage=1), make_task()
            )
            self.assertEqual(result_b.status, "failed_budget")
            self.assertEqual(result_c.status, "failed_budget")

    def test_invalid_resource_limits_rejected_at_construction(self):
        for kwargs in (
            {"max_input_tokens_per_stage": 0},
            {"max_input_tokens_per_stage": -5},
            {"max_output_tokens_per_stage": 0},
            {"stage_timeout_seconds": 0},
            {"stage_timeout_seconds": -1},
            {"max_tool_calls_per_stage": -1},
            {"max_stage_retries": -1},
        ):
            with self.assertRaises(ValueError):
                ResourceLimits(**kwargs)


class TestUsageMetricValidation(unittest.TestCase):
    def test_missing_usage_field_is_infrastructure_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root,
                kind="bad_usage",
                options={"bad_usage_field": "tokens_in", "bad_usage_mode": "none"},
            )
            result = runner.execute(make_spec("usage-1", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)

    def test_negative_usage_rejected_without_model_retry(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="bad_usage", options={"bad_usage_mode": "negative"})
            result = runner.execute(make_spec("usage-2", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)

    def test_boolean_usage_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="bad_usage", options={"bad_usage_mode": "boolean"})
            result = runner.execute(make_spec("usage-3", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")

    def test_string_usage_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="bad_usage", options={"bad_usage_mode": "string"})
            result = runner.execute(make_spec("usage-4", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")


class TestContractEnforcement(unittest.TestCase):
    def run_c_with_mode(self, root, mode=None, extra=None):
        options = dict(extra or {})
        if mode:
            options["disposition_mode"] = mode
        runner, _ = make_runner(root, options=options or None)
        tag = mode or (extra and list(extra)[0]) or "ok"
        return runner.execute(make_spec(f"con-{tag}", "C"), make_task())

    def test_all_findings_addressed_succeeds(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root)
            self.assertEqual(result.status, "succeeded")

    def test_all_findings_addressed_with_two_findings_succeeds(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, extra={"verifier_extra_finding": True})
            self.assertEqual(result.status, "succeeded")

    def test_missing_dispositions_rejected(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "missing")
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("without exactly one disposition", result.stage_results[-1].error)

    def test_unknown_finding_id_rejected(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "unknown_id")
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("unknown finding id", result.stage_results[-1].error)

    def test_duplicate_disposition_rejected(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "duplicate")
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("duplicate disposition", result.stage_results[-1].error)

    def test_missing_rationale_rejected(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "no_rationale")
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("rationale", result.stage_results[-1].error)

    def test_invalid_decision_value_genuinely_rejected(self):
        """Regression (F12): fixture must produce an otherwise well-formed
        disposition whose decision value is invalid — not an empty set."""
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "bad_decision")
            self.assertEqual(result.status, "failed_contract")
            error_text = result.stage_results[-1].error or ""
            self.assertIn("'partially'", error_text)
            self.assertIn("accept", error_text)

    def test_findings_not_an_array_rejected_as_contract(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"malformed_verifier": "findings_scalar"})
            result = runner.execute(make_spec("con-shape-1", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("must be an array", result.stage_results[-1].error)

    def test_structured_not_an_object_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"malformed_verifier": "structured_scalar"})
            result = runner.execute(make_spec("con-shape-2", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")

    def test_material_flag_coercion_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"malformed_verifier": "material_string"})
            result = runner.execute(make_spec("con-coerce", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("boolean", result.stage_results[-1].error)

    def test_malformed_response_writes_no_final_artifacts_or_seals(self):
        with TempRoot() as root:
            result = self.run_c_with_mode(root, "missing")
            run_dir = Path(root) / "runs" / "con-missing"
            self.assertFalse((run_dir / "reviser" / "final_candidate.md").exists())
            self.assertFalse((run_dir / "seals" / "reviser.json").exists())


class TestFailureTaxonomy(unittest.TestCase):
    def assert_terminal_record(self, root, run_id, expected_status):
        path = Path(root) / "runs" / run_id / "run_result.json"
        self.assertTrue(path.exists(), f"terminal record missing for {run_id}")
        payload = json.loads(path.read_text())
        self.assertEqual(payload["status"], expected_status)
        return payload

    def test_transient_model_failure_retries_then_succeeds(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options=transient_failure_options(root))
            result = runner.execute(make_spec("tax-1", "A", seed=7), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(result.retries_used, 1)

    def test_model_failure_exhaustion_is_retry_exhausted(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"fail_if_seed_lt": 10**9})
            result = runner.execute(make_spec("tax-2", "A", max_stage_retries=1), make_task())
            self.assertEqual(result.status, "retry_exhausted")
            self.assertIsNone(result.evaluation)
            self.assert_terminal_record(root, "tax-2", "retry_exhausted")

    def test_worker_crash_is_infrastructure_failure_not_model_retry(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="crash_worker")
            result = runner.execute(make_spec("tax-3", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)
            payload = self.assert_terminal_record(root, "tax-3", "infrastructure_failure")
            self.assertIn("worker process crashed", payload["error"])

    def test_malformed_stdout_is_infrastructure_failure_not_model_retry(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="raw_garbage")
            result = runner.execute(make_spec("tax-4", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)

    def test_unknown_adapter_kind_is_infrastructure_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="nonexistent-kind")
            result = runner.execute(make_spec("tax-5", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")

    def test_timeout_exhaustion_is_retry_exhausted(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="sleep", options={"seconds": 15})
            result = runner.execute(
                make_spec("tax-6", "A", stage_timeout_seconds=0.5, max_stage_retries=1),
                make_task(),
            )
            self.assertEqual(result.status, "retry_exhausted")
            self.assertIn("timeout", result.stage_results[0].error)
            self.assert_terminal_record(root, "tax-6", "retry_exhausted")

    def test_evaluator_exception_yields_failed_evaluation_terminal(self):
        with TempRoot() as root:
            class ExplodingEvaluator:
                version = "exploding-v1"
                config_digest = "digest"

                @staticmethod
                def evaluate(candidate):
                    raise RuntimeError("hidden test harness crashed")

            runner, _ = make_runner(root)
            runner.evaluator = ExplodingEvaluator()
            result = runner.execute(make_spec("tax-7", "A"), make_task())
            self.assertEqual(result.status, "failed_evaluation")
            self.assertIsNotNone(result.final_candidate_ref)
            payload = self.assert_terminal_record(root, "tax-7", "failed_evaluation")
            self.assertIn("harness crashed", payload["evaluation_error"])
            self.assertTrue((Path(root) / "runs" / "tax-7" / "solver" / "candidate.md").exists())

    def test_invalid_model_artifact_contract_records_terminal_state(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="rogue")
            result = runner.execute(make_spec("tax-8", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")
            payload = self.assert_terminal_record(root, "tax-8", "failed_contract")
            self.assertIn("artifact contract", payload["stages"][0]["error"])

    def test_pre_namespace_failures_raise_before_any_record(self):
        """Policy: no safe run namespace -> no terminal record, raise instead."""
        with TempRoot() as root:
            runner, _ = make_runner(root)
            with self.assertRaises(ValueError):
                runner.execute(
                    RunSpec(
                        run_id="pre-1",
                        task_id="wrong-task",
                        condition=Condition.A,
                        model_identifier=IDENTITY_KEY,
                        prompt_version="p",
                        resource_limits=ResourceLimits(),
                    ),
                    make_task(),
                )
            self.assertFalse((Path(root) / "runs" / "pre-1").exists())

    def test_post_namespace_setup_failure_records_terminal_state(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(runner, "_treatment_hash", side_effect=RuntimeError("setup failed")):
                result = runner.execute(make_spec("tax-setup", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertTrue((runs_root / "tax-setup" / "run_result.json").exists())


SECRET_MARKER = "SYNTHETIC_SECRET_MARKER_sk-leak"


def _persisted_text_blobs(run_dir: Path) -> str:
    parts = []
    for path in sorted(run_dir.rglob("*")):
        parts.append(path.name)
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


class SecretBearingInterrupt(BaseException):
    def __str__(self):
        return SECRET_MARKER


class TestBaseExceptionTerminalization(unittest.TestCase):
    def _assert_secret_absent(self, run_dir: Path) -> None:
        blob = _persisted_text_blobs(run_dir)
        self.assertNotIn(SECRET_MARKER, blob)
        self.assertNotIn("sk-leak", blob.lower())

    def test_keyboard_interrupt_during_adapter_invocation_is_non_success(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(runner.adapter, "invoke", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-ki-stage", "A"), make_task())
            run_dir = runs_root / "l2-ki-stage"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertEqual(payload["error"], INTERRUPTED_INFRASTRUCTURE_MESSAGE)
            self.assertIsNone(payload["evaluation"])
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-ki-stage")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_system_exit_during_adapter_invocation_is_sanitized_and_re_raised(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                runner.adapter, "invoke", side_effect=SystemExit(SECRET_MARKER)
            ):
                with self.assertRaises(SystemExit) as raised:
                    runner.execute(make_spec("l2-exit-stage", "A"), make_task())
            self.assertEqual(raised.exception.args, (SECRET_MARKER,))
            run_dir = runs_root / "l2-exit-stage"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertEqual(payload["error"], INTERRUPTED_INFRASTRUCTURE_MESSAGE)
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-exit-stage")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_keyboard_interrupt_during_evaluation_records_failed_evaluation(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                runner.evaluator, "evaluate", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-ki-eval", "A"), make_task())
            run_dir = runs_root / "l2-ki-eval"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual(payload["evaluation_error"], INTERRUPTED_EVALUATION_MESSAGE)
            self.assertIsNone(payload["evaluation"])
            evaluation = json.loads((run_dir / "evaluation.json").read_text())
            self.assertEqual(evaluation["status"], "failed_evaluation")
            self.assertEqual(evaluation["error"], INTERRUPTED_EVALUATION_MESSAGE)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-ki-eval")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_system_exit_during_evaluation_records_failed_evaluation(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                runner.evaluator, "evaluate", side_effect=SystemExit(SECRET_MARKER)
            ):
                with self.assertRaises(SystemExit) as raised:
                    runner.execute(make_spec("l2-exit-eval", "A"), make_task())
            self.assertEqual(raised.exception.args, (SECRET_MARKER,))
            run_dir = runs_root / "l2-exit-eval"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual(payload["evaluation_error"], INTERRUPTED_EVALUATION_MESSAGE)
            self.assertIsNone(payload["evaluation"])
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-exit-eval")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_secret_bearing_interrupt_during_evaluation_is_sanitized(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                runner.evaluator, "evaluate", side_effect=SecretBearingInterrupt()
            ):
                with self.assertRaises(SecretBearingInterrupt):
                    runner.execute(make_spec("l2-secret-eval", "A"), make_task())
            run_dir = runs_root / "l2-secret-eval"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual(payload["evaluation_error"], INTERRUPTED_EVALUATION_MESSAGE)
            self.assertNotIn(SECRET_MARKER, payload["evaluation_error"])
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-secret-eval")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_ordinary_evaluator_exception_still_records_failed_evaluation(self):
        class ExplodingEvaluator:
            version = "exploding-v1"
            config_digest = "digest"

            @staticmethod
            def evaluate(candidate):
                raise RuntimeError("hidden test harness crashed")

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.evaluator = ExplodingEvaluator()
            result = runner.execute(make_spec("l2-eval-exc", "A"), make_task())
            self.assertEqual(result.status, "failed_evaluation")
            payload = json.loads((runs_root / "l2-eval-exc" / "run_result.json").read_text())
            self.assertIn("harness crashed", payload["evaluation_error"])
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-eval-exc")
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_successful_evaluation_is_unchanged(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("l2-eval-ok", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertTrue(result.evaluation.passed)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-eval-ok")
            self.assertEqual(report["terminal_status"], "succeeded")
            self.assertTrue(report["terminal_verified"])

    def test_partial_evaluation_json_does_not_fabricate_success(self):
        """Sol L2 remainder: interrupt after a partial evaluation.json write."""
        original = ArtifactStore.record_event

        def wrapped(store, filename, payload, **kwargs):
            if filename == EVENT_EVALUATION and payload.get("outcome") is not None:
                path = store.run_dir / filename
                path.write_text('{"outcome":', encoding="utf-8")
                raise KeyboardInterrupt
            return original(store, filename, payload, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "record_event", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-partial-eval", "A"), make_task())
            run_dir = runs_root / "l2-partial-eval"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual(payload["evaluation_error"], INTERRUPTED_EVALUATION_MESSAGE)
            self.assertIsNone(payload["evaluation"])
            evaluation = json.loads((run_dir / EVENT_EVALUATION).read_text())
            self.assertEqual(evaluation["status"], "failed_evaluation")
            self.assertEqual(evaluation["error"], INTERRUPTED_EVALUATION_MESSAGE)
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-partial-eval")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_interrupt_after_solver_seal_is_verifier_coherent(self):
        """Sol L2 remainder: success seal persisted, in-memory stage not committed."""
        original = ArtifactStore.seal_stage

        def wrapped(store, role, expected_attempts=None, before_persist=None):
            result = original(
                store,
                role,
                expected_attempts=expected_attempts,
                before_persist=before_persist,
            )
            if role == "solver":
                raise KeyboardInterrupt
            return result

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-post-seal-solver", "A"), make_task())
            run_dir = runs_root / "l2-post-seal-solver"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual([stage["role"] for stage in payload["stages"]], ["solver"])
            self.assertEqual(payload["stages"][0]["status"], "succeeded")
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-post-seal-solver")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def test_interrupt_after_verifier_seal_does_not_succeed_later_stages(self):
        original = ArtifactStore.seal_stage

        def wrapped(store, role, expected_attempts=None, before_persist=None):
            result = original(
                store,
                role,
                expected_attempts=expected_attempts,
                before_persist=before_persist,
            )
            if role == "verifier":
                raise KeyboardInterrupt
            return result

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-post-seal-verifier", "C"), make_task())
            run_dir = runs_root / "l2-post-seal-verifier"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertNotEqual(payload["status"], "succeeded")
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertEqual(
                [(stage["role"], stage["status"]) for stage in payload["stages"]],
                [("solver", "succeeded"), ("verifier", "succeeded")],
            )
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            self.assertTrue((run_dir / "seals" / "verifier.json").is_file())
            self.assertFalse((run_dir / "seals" / "reviser.json").exists())
            self._assert_secret_absent(run_dir)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-post-seal-verifier")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_interrupt_after_solver_seal_on_condition_c_does_not_succeed_later_stages(self):
        original = ArtifactStore.seal_stage

        def wrapped(store, role, expected_attempts=None, before_persist=None):
            result = original(
                store,
                role,
                expected_attempts=expected_attempts,
                before_persist=before_persist,
            )
            if role == "solver":
                raise KeyboardInterrupt
            return result

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-post-seal-c-solver", "C"), make_task())
            run_dir = runs_root / "l2-post-seal-c-solver"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertEqual(
                [(stage["role"], stage["status"]) for stage in payload["stages"]],
                [("solver", "succeeded")],
            )
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            self.assertFalse((run_dir / "seals" / "verifier.json").exists())
            self.assertFalse((run_dir / "seals" / "reviser.json").exists())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-post-seal-c-solver")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_terminal_write_failure_does_not_mask_system_exit(self):
        original = ArtifactStore.record_event

        def wrapped(store, filename, payload, **kwargs):
            if filename == EVENT_RUN_RESULT:
                raise OSError("synthetic terminal-record failure")
            return original(store, filename, payload, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            injected = SystemExit(SECRET_MARKER)
            with patch.object(runner.adapter, "invoke", side_effect=injected):
                with patch.object(ArtifactStore, "record_event", wrapped):
                    with self.assertRaises(SystemExit) as raised:
                        runner.execute(make_spec("l2-term-mask-exit", "A"), make_task())
            self.assertIs(raised.exception, injected)
            run_dir = runs_root / "l2-term-mask-exit"
            result_path = run_dir / EVENT_RUN_RESULT
            self.assertFalse(result_path.exists())
            self._assert_secret_absent(run_dir)

    def test_terminal_write_failure_does_not_mask_keyboard_interrupt(self):
        original = ArtifactStore.record_event

        def wrapped(store, filename, payload, **kwargs):
            if filename == EVENT_RUN_RESULT:
                raise OSError("synthetic terminal-record failure")
            return original(store, filename, payload, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            injected = KeyboardInterrupt()
            with patch.object(runner.adapter, "invoke", side_effect=injected):
                with patch.object(ArtifactStore, "record_event", wrapped):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        runner.execute(make_spec("l2-term-mask-ki", "A"), make_task())
            self.assertIs(raised.exception, injected)
            self.assertFalse((runs_root / "l2-term-mask-ki" / EVENT_RUN_RESULT).exists())
            self._assert_secret_absent(runs_root / "l2-term-mask-ki")

    def test_ordinary_terminal_write_failure_still_surfaces(self):
        original = ArtifactStore.record_event

        def wrapped(store, filename, payload, **kwargs):
            if filename == EVENT_RUN_RESULT:
                raise OSError("synthetic terminal-record failure")
            return original(store, filename, payload, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "record_event", wrapped):
                with self.assertRaises(OSError) as raised:
                    runner.execute(make_spec("l2-term-oserror", "A"), make_task())
            self.assertIn("synthetic terminal-record failure", str(raised.exception))
            self.assertFalse((runs_root / "l2-term-oserror" / EVENT_RUN_RESULT).exists())


class TestAtomicStageFinalization(unittest.TestCase):
    def test_rogue_artifact_never_yields_successful_stage(self):
        """Regression (F7/SOL): partial persistence must not be recorded as a
        successful stage, must not seal, and must not assign final_candidate_ref."""
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="rogue")
            result = runner.execute(make_spec("atom-1", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")
            succeeded = [s for s in result.stage_results if s.status.value == "succeeded"]
            self.assertEqual(succeeded, [], "no stage may be marked successful after partial write")
            run_dir = runs_root / "atom-1"
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            self.assertIsNone(result.final_candidate_ref)
            payload = terminal(root, "atom-1")
            self.assertIsNone(payload["final_candidate_ref"])
            self.assertEqual(payload["final_candidate_ref"], None)

    def test_failed_stage_leaves_no_sealed_state(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options={"disposition_mode": "missing"})
            result = runner.execute(make_spec("atom-2", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            run_dir = runs_root / "atom-2"
            self.assertFalse((run_dir / "seals" / "reviser.json").exists())

    def _response_for_solver(self, runner, mutate):
        response = runner.adapter.invoke(
            role_instruction="role:solver test",
            stage_inputs={"task": "small task"},
            budget=ResourceLimits(),
            seed=0,
        )
        mutate(response)
        return response

    def test_missing_primary_artifact_is_contract_failure_before_persistence(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            response = self._response_for_solver(
                runner, lambda value: value.update({"artifacts": {"evidence": "only evidence"}})
            )
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(make_spec("atom-missing-primary", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertEqual([s.status.value for s in result.stage_results], ["failed"])
            self.assertEqual(result.stage_results[0].output_refs, ())
            self.assertFalse((runs_root / "atom-missing-primary" / "seals" / "solver.json").exists())

    def test_non_string_artifact_is_contract_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._response_for_solver(
                runner, lambda value: value["artifacts"].update({"candidate": 123})
            )
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(make_spec("atom-bad-type", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertIn("artifact", result.stage_results[0].error)

    def test_list_or_none_artifact_values_are_contract_failures(self):
        for bad_value in (["not text"], None):
            with self.subTest(bad_value=bad_value):
                with TempRoot() as root:
                    runner, _ = make_runner(root)
                    response = self._response_for_solver(
                        runner, lambda value, bad=bad_value: value["artifacts"].update({"candidate": bad})
                    )
                    with patch.object(runner.adapter, "invoke", return_value=response):
                        result = runner.execute(
                            make_spec(f"atom-bad-{type(bad_value).__name__}", "A"), make_task()
                        )
                    self.assertEqual(result.status, "failed_contract")

    def test_missing_verifier_findings_artifact_is_contract_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            original = runner.adapter.invoke

            def invoke(**kwargs):
                response = original(**kwargs)
                if "role:verifier" in kwargs["role_instruction"]:
                    response["artifacts"] = {}
                return response

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(make_spec("atom-missing-findings", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertEqual([s.role for s in result.stage_results if s.status.value == "succeeded"], ["solver"])

    def test_missing_reviser_final_candidate_is_contract_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            original = runner.adapter.invoke

            def invoke(**kwargs):
                response = original(**kwargs)
                if "role:reviser" in kwargs["role_instruction"]:
                    response["artifacts"] = {}
                return response

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(make_spec("atom-missing-final", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertEqual(
                [s.role for s in result.stage_results if s.status.value == "succeeded"],
                ["solver", "verifier"],
            )

    def test_unexpected_artifact_is_contract_failure(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            response = self._response_for_solver(
                runner, lambda value: value["artifacts"].update({"unexpected": "x"})
            )
            with patch.object(runner.adapter, "invoke", return_value=response):
                result = runner.execute(make_spec("atom-extra", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")

    def test_valid_exact_artifact_set_is_preserved(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("atom-valid", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(
                sorted(result.stage_results[0].output_refs),
                ["solver/candidate.md", "solver/evidence.md"],
            )
            self.assertTrue((runs_root / "atom-valid" / "seals" / "solver.json").exists())


def _interrupt_after_solver_seal(mutator=None):
    original = ArtifactStore.seal_stage

    def wrapped(store, role, expected_attempts=None, before_persist=None):
        result = original(
            store,
            role,
            expected_attempts=expected_attempts,
            before_persist=before_persist,
        )
        if role == "solver":
            if mutator is not None:
                mutator(store)
            raise KeyboardInterrupt
        return result

    return wrapped


def _recompute_seal_digest(seal: dict) -> None:
    body = {
        "artifacts": seal.get("artifacts"),
        "invocations": seal.get("invocations") if "invocations" in seal else [],
        "expected_attempts": seal.get("expected_attempts", 0),
    }
    seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))


def _mutate_solver_seal(store, mutator) -> None:
    path = store.run_dir / "seals" / "solver.json"
    seal = json.loads(path.read_text(encoding="utf-8"))
    mutator(seal)
    _recompute_seal_digest(seal)
    path.write_text(json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")


def _rewrite_run_result(run_dir: Path, mutator) -> dict:
    path = run_dir / EVENT_RUN_RESULT
    payload = json.loads(path.read_text(encoding="utf-8"))
    mutator(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


class TestInvalidSealReconciliation(unittest.TestCase):
    def _assert_invalid_seal_not_succeeded(self, run_dir: Path, payload: dict) -> None:
        self.assertNotEqual(payload["status"], "succeeded")
        succeeded = [stage["role"] for stage in payload["stages"] if stage.get("status") == "succeeded"]
        self.assertEqual(succeeded, [])
        self.assertNotIn("verifier", [stage["role"] for stage in payload["stages"]])
        self.assertNotIn("reviser", [stage["role"] for stage in payload["stages"]])
        self.assertFalse((run_dir / "seals" / "solver.json").exists())

    def test_parseable_incomplete_seal_is_not_succeeded(self):
        def mutate(store):
            path = store.run_dir / "seals" / "solver.json"
            path.write_text(
                json.dumps({"role": "solver", "expected_attempts": 1}),
                encoding="utf-8",
            )

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", _interrupt_after_solver_seal(mutate)):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-seal-incomplete", "A"), make_task())
            run_dir = runs_root / "l2-seal-incomplete"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self._assert_invalid_seal_not_succeeded(run_dir, payload)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-seal-incomplete")
            self.assertTrue(report["terminal_verified"])
            self.assertNotEqual(report["terminal_status"], "succeeded")

    def test_wrong_artifact_hash_binding_is_not_succeeded(self):
        def mutate(store):
            path = store.run_dir / "seals" / "solver.json"
            seal = json.loads(path.read_text(encoding="utf-8"))
            seal["artifacts"][0]["sha256"] = "0" * 64
            body = {
                "artifacts": seal["artifacts"],
                "invocations": seal.get("invocations") or [],
                "expected_attempts": seal.get("expected_attempts", 0),
            }
            seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
            path.write_text(json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", _interrupt_after_solver_seal(mutate)):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-seal-bad-hash", "A"), make_task())
            run_dir = runs_root / "l2-seal-bad-hash"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self._assert_invalid_seal_not_succeeded(run_dir, payload)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-seal-bad-hash")
            self.assertTrue(report["terminal_verified"])
            self.assertNotEqual(report["terminal_status"], "succeeded")

    def test_authoritative_hash_mismatch_is_not_succeeded(self):
        def mutate(store):
            for key in list(store._authoritative):
                if key[0] == "solver":
                    store._authoritative[key] = "0" * 64

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", _interrupt_after_solver_seal(mutate)):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-seal-auth-mismatch", "A"), make_task())
            run_dir = runs_root / "l2-seal-auth-mismatch"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self._assert_invalid_seal_not_succeeded(run_dir, payload)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-seal-auth-mismatch")
            self.assertTrue(report["terminal_verified"])
            self.assertNotEqual(report["terminal_status"], "succeeded")

    def test_valid_canonical_seal_still_reconciles(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", _interrupt_after_solver_seal()):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-seal-valid-control", "A"), make_task())
            run_dir = runs_root / "l2-seal-valid-control"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertEqual(payload["status"], "failed_evaluation")
            self.assertEqual([stage["role"] for stage in payload["stages"]], ["solver"])
            self.assertEqual(payload["stages"][0]["status"], "succeeded")
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-seal-valid-control")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")

    def _run_malformed_solver_seal(self, run_id: str, mutator):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore,
                "seal_stage",
                _interrupt_after_solver_seal(lambda store: _mutate_solver_seal(store, mutator)),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec(run_id, "A"), make_task())
            run_dir = runs_root / run_id
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self._assert_invalid_seal_not_succeeded(run_dir, payload)
            self.assertEqual(payload["status"], "infrastructure_failure")
            report = ArtifactStore.verify_terminal_run(runs_root, run_id)
            self.assertTrue(report["terminal_verified"])
            self.assertNotEqual(report["terminal_status"], "succeeded")
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_invocations_explicit_null_is_not_succeeded(self):
        def mutate(store):
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

        injected = KeyboardInterrupt()
        original = ArtifactStore.seal_stage

        def wrapped(store, role, expected_attempts=None, before_persist=None):
            result = original(
                store,
                role,
                expected_attempts=expected_attempts,
                before_persist=before_persist,
            )
            if role == "solver":
                mutate(store)
                raise injected
            return result

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", wrapped):
                with self.assertRaises(KeyboardInterrupt) as raised:
                    runner.execute(make_spec("l2-seal-inv-explicit-null", "A"), make_task())
            self.assertIs(raised.exception, injected)
            run_dir = runs_root / "l2-seal-inv-explicit-null"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self._assert_invalid_seal_not_succeeded(run_dir, payload)
            self.assertEqual(payload["status"], "infrastructure_failure")
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-seal-inv-explicit-null")
            self.assertTrue(report["terminal_verified"])
            self.assertNotEqual(report["terminal_status"], "succeeded")
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_invocations_list_of_int_is_not_succeeded(self):
        self._run_malformed_solver_seal(
            "l2-seal-inv-int",
            lambda seal: seal.update({"invocations": [1]}),
        )

    def test_invocation_entry_as_string_is_not_succeeded(self):
        self._run_malformed_solver_seal(
            "l2-seal-inv-str",
            lambda seal: seal.update({"invocations": ["not-an-object"]}),
        )

    def test_invocation_entry_as_null_is_not_succeeded(self):
        self._run_malformed_solver_seal(
            "l2-seal-inv-null",
            lambda seal: seal.update({"invocations": [None]}),
        )

    def test_artifact_entry_wrong_container_is_not_succeeded(self):
        self._run_malformed_solver_seal(
            "l2-seal-art-list",
            lambda seal: seal.update({"artifacts": [["candidate"]]}),
        )

    def test_nested_artifact_digest_wrong_type_is_not_succeeded(self):
        def mutate(seal):
            seal["artifacts"][0]["sha256"] = 123

        self._run_malformed_solver_seal("l2-seal-digest-type", mutate)

    def test_nested_invocation_digest_wrong_type_is_not_succeeded(self):
        def mutate(seal):
            seal["invocations"][0]["sha256"] = 123

        self._run_malformed_solver_seal("l2-seal-inv-digest-type", mutate)


class TestPreAuthorityInterrupt(unittest.TestCase):
    def test_keyboard_interrupt_before_task_record_is_verifiable(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-preauth-task", "A"), make_task())
            run_dir = runs_root / "l2-preauth-task"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertIs(payload["authority_committed"], False)
            self.assertFalse((run_dir / RUN_AUTHORITY).exists())
            self.assertNotEqual(payload["status"], "succeeded")
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-preauth-task")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")
            self.assertFalse(report.get("authority_committed", True))

    def test_keyboard_interrupt_immediately_before_authority_freeze_is_verifiable(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "freeze_run_authority", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-preauth-before-freeze", "A"), make_task())
            run_dir = runs_root / "l2-preauth-before-freeze"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertIs(payload["authority_committed"], False)
            self.assertFalse((run_dir / RUN_AUTHORITY).exists())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-preauth-before-freeze")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_keyboard_interrupt_immediately_after_authority_freeze_is_verifiable(self):
        original = ArtifactStore.freeze_run_authority

        def wrapped(store):
            original(store)
            raise KeyboardInterrupt

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "freeze_run_authority", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-preauth-after-freeze", "A"), make_task())
            run_dir = runs_root / "l2-preauth-after-freeze"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertEqual(payload["status"], "infrastructure_failure")
            self.assertTrue(payload["authority_committed"])
            self.assertTrue((run_dir / RUN_AUTHORITY).is_file())
            self.assertEqual(payload["stages"], [])
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-preauth-after-freeze")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_missing_authority_after_progress_remains_an_error(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(runner.adapter, "invoke", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-preauth-progress", "A"), make_task())
            run_dir = runs_root / "l2-preauth-progress"
            self.assertTrue((run_dir / RUN_AUTHORITY).is_file())
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertTrue(payload["authority_committed"])
            (run_dir / RUN_AUTHORITY).chmod(0o644)
            (run_dir / RUN_AUTHORITY).unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-preauth-progress")


class TestAuthorityCommittedSchema(unittest.TestCase):
    def test_genuine_pre_authority_interrupted_run_verifies(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-pre-ok", "A"), make_task())
            run_dir = runs_root / "l2-auth-pre-ok"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertIs(payload["authority_committed"], False)
            self.assertFalse((run_dir / RUN_AUTHORITY).exists())
            self.assertEqual(payload["stages"], [])
            self.assertIsNone(payload.get("evaluation"))
            self.assertEqual(payload["run_id"], "l2-auth-pre-ok")
            self.assertEqual(payload["condition"], "A")
            self.assertEqual(payload["model_identifier"], IDENTITY_KEY)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-auth-pre-ok")
            self.assertTrue(report["terminal_verified"])
            self.assertFalse(report.get("authority_committed", True))

    def test_post_authority_interrupted_run_verifies(self):
        original = ArtifactStore.freeze_run_authority

        def wrapped(store):
            original(store)
            raise KeyboardInterrupt

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "freeze_run_authority", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-post-ok", "A"), make_task())
            run_dir = runs_root / "l2-auth-post-ok"
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertIs(payload["authority_committed"], True)
            self.assertTrue((run_dir / RUN_AUTHORITY).is_file())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-auth-post-ok")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "infrastructure_failure")

    def test_successful_run_has_authority_committed_true(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("l2-auth-success", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            payload = json.loads((runs_root / "l2-auth-success" / EVENT_RUN_RESULT).read_text())
            self.assertIs(payload["authority_committed"], True)
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-auth-success")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "succeeded")

    def _assert_rejects_authority_committed(self, run_id: str, mutator) -> None:
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec(run_id, "A"), make_task())
            run_dir = runs_root / run_id
            _rewrite_run_result(run_dir, mutator)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, run_id)

    def test_missing_authority_committed_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-missing",
            lambda payload: payload.pop("authority_committed"),
        )

    def test_authority_committed_false_string_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-str-false",
            lambda payload: payload.update({"authority_committed": "false"}),
        )

    def test_authority_committed_true_string_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-str-true",
            lambda payload: payload.update({"authority_committed": "true"}),
        )

    def test_authority_committed_integer_zero_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-int-0",
            lambda payload: payload.update({"authority_committed": 0}),
        )

    def test_authority_committed_integer_one_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-int-1",
            lambda payload: payload.update({"authority_committed": 1}),
        )

    def test_authority_committed_null_is_rejected(self):
        self._assert_rejects_authority_committed(
            "l2-auth-null",
            lambda payload: payload.update({"authority_committed": None}),
        )

    def test_false_flag_with_authority_file_is_rejected(self):
        original = ArtifactStore.freeze_run_authority

        def wrapped(store):
            original(store)
            raise KeyboardInterrupt

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "freeze_run_authority", wrapped):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-false-file", "A"), make_task())
            run_dir = runs_root / "l2-auth-false-file"
            self.assertTrue((run_dir / RUN_AUTHORITY).is_file())
            _rewrite_run_result(run_dir, lambda payload: payload.update({"authority_committed": False}))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-file")

    def test_post_authority_deleted_authority_flag_rewritten_false_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "seal_stage", _interrupt_after_solver_seal()):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-downgrade", "A"), make_task())
            run_dir = runs_root / "l2-auth-downgrade"
            self.assertTrue((run_dir / RUN_AUTHORITY).is_file())
            self.assertTrue((run_dir / "seals" / "solver.json").is_file())
            payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
            self.assertIs(payload["authority_committed"], True)
            (run_dir / RUN_AUTHORITY).chmod(0o644)
            (run_dir / RUN_AUTHORITY).unlink()
            _rewrite_run_result(run_dir, lambda body: body.update({"authority_committed": False}))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-downgrade")

    def test_false_flag_with_seal_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-false-seal", "A"), make_task())
            run_dir = runs_root / "l2-auth-false-seal"
            seals = run_dir / "seals"
            seals.mkdir()
            (seals / "solver.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-seal")

    def test_false_flag_with_invocation_evidence_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-false-inv", "A"), make_task())
            run_dir = runs_root / "l2-auth-false-inv"
            inv = run_dir / "invocations" / "solver" / "attempt-0001"
            inv.mkdir(parents=True)
            (inv / "invocation.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-inv")

    def test_false_flag_with_succeeded_stage_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-false-stage", "A"), make_task())
            run_dir = runs_root / "l2-auth-false-stage"

            def mutate(payload):
                payload["stages"] = [
                    {
                        "role": "solver",
                        "status": "succeeded",
                        "attempt": 1,
                        "output_refs": ["solver/candidate.md", "solver/evidence.md"],
                    }
                ]

            _rewrite_run_result(run_dir, mutate)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-stage")

    def test_false_flag_with_evaluation_evidence_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-false-eval", "A"), make_task())
            run_dir = runs_root / "l2-auth-false-eval"
            (run_dir / EVENT_EVALUATION).write_text(
                json.dumps({"outcome": {"passed": True}}),
                encoding="utf-8",
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-eval")

    def _genuine_pre_authority(self, run_id: str):
        root_cm = TempRoot()
        root = root_cm.__enter__()
        self.addCleanup(root_cm.__exit__, None, None, None)
        runner, runs_root = make_runner(root)
        with patch.object(
            ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                runner.execute(make_spec(run_id, "A"), make_task())
        run_dir = runs_root / run_id
        payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
        self.assertIs(payload["authority_committed"], False)
        self.assertFalse((run_dir / RUN_AUTHORITY).exists())
        return runs_root, run_dir

    def test_false_flag_with_stage_artifact_file_is_rejected(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-false-artifact")
        (run_dir / "solver" / "evidence.md").write_text("planted-artifact", encoding="utf-8")
        with self.assertRaises(IntegrityViolation):
            ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-artifact")

    def test_false_flag_with_non_empty_manifest_is_rejected(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-false-manifest")
        (run_dir / "manifest.jsonl").write_text(
            json.dumps(
                {
                    "kind": "model_artifact",
                    "role": "solver",
                    "name": "candidate",
                    "sha256": "0" * 64,
                    "bytes": 1,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(IntegrityViolation):
            ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-manifest")

    def test_false_flag_with_final_candidate_ref_is_rejected(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-false-final-ref")
        _rewrite_run_result(
            run_dir,
            lambda payload: payload.update({"final_candidate_ref": "solver/candidate.md"}),
        )
        with self.assertRaises(IntegrityViolation):
            ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-final-ref")

    def test_false_flag_with_terminal_integrity_is_rejected(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-false-integrity")
        _rewrite_run_result(
            run_dir,
            lambda payload: payload.update(
                {"integrity": {"integrity_verified": True, "stages": {"solver": "verified"}}}
            ),
        )
        with self.assertRaises(IntegrityViolation):
            ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-integrity")

    def test_false_flag_with_verified_identity_is_rejected(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-false-identity")
        _rewrite_run_result(
            run_dir,
            lambda payload: payload.update(
                {"verified_identity": {"identity_key": IDENTITY_KEY}}
            ),
        )
        with self.assertRaises(IntegrityViolation):
            ArtifactStore.verify_terminal_run(runs_root, "l2-auth-false-identity")

    def test_empty_manifest_pre_authority_still_verifies(self):
        runs_root, run_dir = self._genuine_pre_authority("l2-auth-empty-manifest")
        manifest = run_dir / "manifest.jsonl"
        self.assertTrue(manifest.is_file())
        self.assertEqual(manifest.read_text(encoding="utf-8").strip(), "")
        report = ArtifactStore.verify_terminal_run(runs_root, "l2-auth-empty-manifest")
        self.assertTrue(report["terminal_verified"])
        self.assertFalse(report.get("authority_committed", True))

    def test_pre_authority_wrong_run_id_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-wrong-id", "A"), make_task())
            run_dir = runs_root / "l2-auth-wrong-id"
            _rewrite_run_result(run_dir, lambda payload: payload.update({"run_id": "other-run"}))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-wrong-id")

    def test_pre_authority_wrong_condition_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-wrong-cond", "A"), make_task())
            run_dir = runs_root / "l2-auth-wrong-cond"
            _rewrite_run_result(run_dir, lambda payload: payload.update({"condition": "C"}))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-wrong-cond")

    def test_pre_authority_wrong_model_identity_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                ArtifactStore, "write_task_record", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-auth-wrong-model", "A"), make_task())
            run_dir = runs_root / "l2-auth-wrong-model"
            _rewrite_run_result(
                run_dir,
                lambda payload: payload.update({"model_identifier": OTHER_IDENTITY.key()}),
            )
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "l2-auth-wrong-model")


class TestNestedRecoveryExceptionPreservation(unittest.TestCase):
    def _assert_secret_absent(self, run_dir: Path) -> None:
        blob = _persisted_text_blobs(run_dir)
        self.assertNotIn(SECRET_MARKER, blob)
        self.assertNotIn("sk-leak", blob.lower())

    def test_evaluator_recovery_preserves_original_keyboard_interrupt(self):
        original = ArtifactStore.record_event
        injected = KeyboardInterrupt()

        def wrapped(store, filename, payload, **kwargs):
            if filename == EVENT_EVALUATION and payload.get("status") == "failed_evaluation":
                raise SystemExit(SECRET_MARKER)
            return original(store, filename, payload, **kwargs)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(runner.evaluator, "evaluate", side_effect=injected):
                with patch.object(ArtifactStore, "record_event", wrapped):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        runner.execute(make_spec("l2-nested-eval", "A"), make_task())
            self.assertIs(raised.exception, injected)
            run_dir = runs_root / "l2-nested-eval"
            result_path = run_dir / EVENT_RUN_RESULT
            if result_path.exists():
                payload = json.loads(result_path.read_text())
                self.assertNotEqual(payload["status"], "succeeded")
            self._assert_secret_absent(run_dir)

    def test_setup_recovery_preserves_original_keyboard_interrupt(self):
        original_abort = ArtifactStore.abort_uncommitted_stage
        injected = KeyboardInterrupt()

        def wrapped(store, role):
            original_abort(store, role)
            raise SystemExit(SECRET_MARKER)

        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(ArtifactStore, "write_task_record", side_effect=injected):
                with patch.object(ArtifactStore, "abort_uncommitted_stage", wrapped):
                    with self.assertRaises(KeyboardInterrupt) as raised:
                        runner.execute(make_spec("l2-nested-setup", "A"), make_task())
            self.assertIs(raised.exception, injected)
            run_dir = runs_root / "l2-nested-setup"
            if (run_dir / EVENT_RUN_RESULT).exists():
                payload = json.loads((run_dir / EVENT_RUN_RESULT).read_text())
                self.assertNotEqual(payload["status"], "succeeded")
            self._assert_secret_absent(run_dir)

    def test_ordinary_recovery_without_secondary_failure_remains_verifier_coherent(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            with patch.object(
                runner.evaluator, "evaluate", side_effect=KeyboardInterrupt
            ):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(make_spec("l2-nested-eval-ok", "A"), make_task())
            report = ArtifactStore.verify_terminal_run(runs_root, "l2-nested-eval-ok")
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], "failed_evaluation")


if __name__ == "__main__":
    unittest.main()
