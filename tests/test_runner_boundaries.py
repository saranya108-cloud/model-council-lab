"""Identity, budget, contract, failure-taxonomy, and atomicity boundaries."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    AdapterIdentity,
    Condition,
    GovernanceViolation,
    ResourceLimits,
    RunSpec,
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


if __name__ == "__main__":
    unittest.main()
