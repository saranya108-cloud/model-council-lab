"""Offline regression contract for the separate bounded Condition B launcher."""

from __future__ import annotations

import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from helpers import SRC
from model_council import ArtifactStore, Condition
from model_council.adapters import live_stub_generate
from model_council.errors import InfrastructureError, StageTimeout
from model_council.live_contract import parse_live_invocation_request
from model_council.protocol import HARNESS_PROTOCOL_VERSION
from model_council.openai_adapter import build_openai_responses_request

REPO = SRC.parent
sys.path.insert(0, str(REPO))


def load_launcher():
    return importlib.import_module("experiments.development.run_openai_condition_b_canary")


class TestConditionBCanary(unittest.TestCase):
    def setUp(self):
        self.b = load_launcher()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(self.b, "REPO_ROOT", self.root))
        self.real_runtime_guard = self.b.require_repository_venv
        self.stack.enter_context(patch.object(self.b, "require_repository_venv", return_value=sys.executable))
        self.real_spawn = self.b.SubprocessAdapter._spawn_worker
        # Never let an accidental gap in a synthetic fixture reach credentials or transport.
        for target in (
            "model_council.openai_adapter.validate_openai_runtime_credential",
            "model_council.openai_adapter.build_openai_client",
            "model_council.openai_adapter._perform_openai_responses_transport",
        ):
            self.stack.enter_context(patch(target, side_effect=AssertionError("real boundary forbidden")))
        self.spawn = self.stack.enter_context(patch.object(
            self.b.SubprocessAdapter, "_spawn_worker", autospec=True,
            side_effect=AssertionError("unconfigured worker forbidden"),
        ))

    def args(self, *, execute=False, run_id="b-test", extra=()):
        argv = ["--run-id", run_id, "--runs-root", str(self.root / "runs")]
        if execute:
            argv += ["--execute", "--acknowledge", self.b.ACKNOWLEDGEMENT]
        return argv + list(extra)

    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.b.main(argv)
        return code, out.getvalue(), err.getvalue()

    def synthetic(self, *, bad_role=None, mode=None, usage=False):
        calls = []
        directory = self.root / "runs" / "b-test"

        def spawn(adapter, envelope, timeout):
            request = parse_live_invocation_request(envelope["live_invocation_request"])
            for earlier in calls:
                self.assertTrue((directory / "seals" / f"{earlier.role}.json").is_file())
            self.assertEqual(adapter.python_executable, sys.executable)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 30)
            calls.append(request)
            if request.role == bad_role:
                if mode == "infrastructure":
                    raise InfrastructureError("synthetic failure")
                if mode == "timeout":
                    raise StageTimeout("synthetic timeout")
                if mode == "interrupt":
                    raise KeyboardInterrupt()
            outcome = live_stub_generate({}, {}, request).to_dict()
            outcome["provider_resolved_identity"] = {
                "value": {"model_id": "gpt-5.6-luna"}, "unavailable_reason": None,
            }
            if usage:
                for key, value in (("input_tokens", 10), ("output_tokens", 4),
                                   ("total_tokens", 14), ("reasoning_tokens", 2),
                                   ("cached_input_tokens", 1)):
                    outcome["usage"][key] = {"value": value, "unavailable_reason": None}
            if request.role == bad_role:
                if mode == "mismatch":
                    outcome["provider_resolved_identity"]["value"] = {"model_id": "other-model"}
                elif mode == "missing":
                    outcome["provider_resolved_identity"] = {
                        "value": None, "unavailable_reason": "not_exposed",
                    }
                elif mode == "malformed":
                    outcome["provider_resolved_identity"]["value"] = {"provider": "openai"}
                elif mode == "protocol":
                    outcome["provider_resolved_identity"] = "invalid envelope"
                elif mode == "provider":
                    outcome = live_stub_generate({"neutral_error_category": "rate_limit"}, {}, request).to_dict()
                elif mode == "unconfirmed_provider":
                    outcome = live_stub_generate({"neutral_error_category": "rate_limit"}, {}, request).to_dict()
                    for field in ("provider_response_id", "provider_request_id", "provider_response_status"):
                        outcome[field] = {"value": None, "unavailable_reason": "not_exposed"}
                elif mode == "evaluation":
                    outcome["stage_output"]["artifacts"]["final_candidate"] = "MODIFIED_HIDDEN_TESTS"
            return {
                "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                "execution_profile": "live_contract_v1", "outcome": outcome,
            }

        self.spawn.side_effect = spawn
        return calls

    def test_preflight_has_no_side_effects(self):
        with patch.object(self.b, "ExperimentRunner", side_effect=AssertionError("runner forbidden")), \
             patch.object(self.b, "SubprocessAdapter", side_effect=AssertionError("adapter forbidden")), \
             patch.dict(os.environ, {}, clear=True):
            code, out, err = self.main(self.args())
        self.assertEqual(code, 0, err)
        self.assertIn("PREFLIGHT ONLY", out)
        self.assertFalse((self.root / "runs").exists())
        self.spawn.assert_not_called()

    def test_live_execution_requires_acknowledgement(self):
        for extra in (("--execute",), ("--execute", "--acknowledge", "wrong")):
            with self.subTest(extra=extra):
                code, _, _ = self.main(self.args(extra=extra))
                self.assertEqual(code, 2)
        self.spawn.assert_not_called()
        self.assertFalse((self.root / "runs").exists())

    def test_exact_frozen_configuration_and_override_rejection(self):
        plan = self.b.prepare_canary(self.b.build_parser().parse_args(self.args()))
        self.assertEqual(plan.run_spec.resource_limits.to_dict(), {
            "max_input_tokens_per_stage": 2048, "max_output_tokens_per_stage": 1024,
            "stage_timeout_seconds": 30.0, "max_tool_calls_per_stage": 0, "max_stage_retries": 0,
        })
        self.assertEqual(plan.identity.model_id, "gpt-5.6-luna")
        self.assertEqual(plan.identity.model_version, "gpt-5.6-luna")
        self.assertEqual(plan.provider_treatment_config, {})
        for flag, value in (("--condition", "A"), ("--model-id", "other"),
                            ("--model-version", "other"), ("--max-input-tokens", "4096"),
                            ("--max-output-tokens", "2048"), ("--stage-timeout-seconds", "60"),
                            ("--retries", "1"), ("--tools", "1"), ("--reasoning-effort", "high")):
            with self.subTest(flag=flag), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.b.build_parser().parse_args(self.args(extra=(flag, value)))
        for changed in (
            replace(plan, run_spec=replace(plan.run_spec, condition=Condition.A)),
            replace(plan, run_spec=replace(plan.run_spec, resource_limits=replace(
                plan.run_spec.resource_limits, max_stage_retries=1))),
            replace(plan, identity=replace(plan.identity, model_id="other")),
            replace(plan, provider_treatment_config={"reasoning": {"effort": "high"}}),
            replace(plan, destination=self.root / "elsewhere"),
        ):
            with self.subTest(plan=changed), self.assertRaises(self.b.CanaryError):
                self.b.execute_prepared_canary(changed, acknowledge=self.b.ACKNOWLEDGEMENT)
        self.spawn.assert_not_called()

    def test_wrong_topology_rejected(self):
        for roles in (("draft",), ("self_review", "draft", "reviser"),
                      ("draft", "self_review", "reviser", "solver")):
            with patch.dict(self.b.CONDITION_STAGES, {Condition.B: roles}):
                code, _, _ = self.main(self.args(execute=True))
                self.assertEqual(code, 2)
        self.spawn.assert_not_called()

    def test_destination_reuse_and_escape_rejected(self):
        runs = self.root / "runs"
        runs.mkdir()
        (runs / "existing").mkdir()
        (runs / "file").write_text("preserve")
        (runs / "dangling").symlink_to(self.root / "absent")
        for run_id in ("existing", "file", "dangling", "../escape"):
            with self.subTest(run_id=run_id):
                self.assertEqual(self.main(self.args(execute=True, run_id=run_id))[0], 2)
        argv = ["--run-id", "b-test", "--runs-root", str(self.root.parent / "outside")]
        self.assertEqual(self.main(argv)[0], 2)
        self.assertEqual((runs / "file").read_text(), "preserve")
        self.spawn.assert_not_called()

    def test_three_stage_success_exact_handoffs_and_seals(self):
        calls = self.synthetic()
        evaluated = []
        real_evaluate = self.b.ExternalEvaluator.evaluate

        def evaluate(evaluator, candidate):
            evaluated.append(candidate)
            return real_evaluate(evaluator, candidate)

        with patch.object(self.b.ExternalEvaluator, "evaluate", autospec=True, side_effect=evaluate):
            code, out, err = self.main(self.args(execute=True))
        self.assertEqual(code, 0, err + out)
        self.assertEqual([r.role for r in calls], ["draft", "self_review", "reviser"])
        directory = self.root / "runs" / "b-test"
        draft = (directory / "draft/draft.md").read_text()
        review = (directory / "self_review/self_review.md").read_text()
        task = calls[0].stage_inputs["task"]
        self.assertEqual(dict(calls[0].stage_inputs), {"task": task})
        self.assertEqual(dict(calls[1].stage_inputs), {"task": task, "draft": draft})
        self.assertEqual(dict(calls[2].stage_inputs), {"task": task, "draft": draft, "self_review": review})
        for request in calls:
            self.assertEqual(request.configured_identity.model_id, "gpt-5.6-luna")
            self.assertEqual(request.max_output_tokens, 1024)
            self.assertEqual(request.max_tool_calls, 0)
            wire = build_openai_responses_request(request, {})
            self.assertEqual(wire["model"], "gpt-5.6-luna")
            self.assertEqual(wire["max_output_tokens"], 1024)
            self.assertEqual(wire["tools"], [])
            self.assertFalse(wire["parallel_tool_calls"])
            seal = json.loads((directory / "seals" / f"{request.role}.json").read_text())
            self.assertEqual(seal["expected_attempts"], 1)
            record = json.loads((directory / "invocations" / request.role / "attempt-0001/invocation.json").read_text())
            self.assertEqual(record["identity_verdict"], "passed")
            self.assertEqual(record["adapter_evidence"]["provider_call_outcome"]["adapter_internal_retry_count"], 0)
            for name, content in record["adapter_evidence"]["provider_call_outcome"]["stage_output"]["artifacts"].items():
                self.assertEqual((directory / request.role / f"{name}.md").read_text(), content)
        report = ArtifactStore.verify_terminal_run(directory.parent, directory.name)
        self.assertTrue(report["provider_identity_policy_verified"])
        self.assertTrue(report["terminal_verified"])
        terminal = json.loads((directory / "run_result.json").read_text())
        self.assertEqual(terminal["status"], "succeeded")
        self.assertEqual(terminal["final_candidate_ref"], "reviser/final_candidate.md")
        self.assertEqual(evaluated, [(directory / "reviser/final_candidate.md").read_text()])
        self.assertTrue((directory / "evaluation.json").is_file())
        self.assertIn("CONDITION B LIVE PASS", out)

    def test_identity_rejection_stops_at_each_stage(self):
        roles = ["draft", "self_review", "reviser"]
        for role in roles:
            for mode in ("mismatch", "missing", "malformed"):
                with self.subTest(role=role, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.b, "REPO_ROOT", Path(tmp).resolve()):
                        calls = self.synthetic(bad_role=role, mode=mode)
                        code, out, err = self.main(self.args(execute=True))
                        self.assertEqual(code, 1, err + out)
                        self.assertEqual([r.role for r in calls], roles[:roles.index(role) + 1])
                        directory = self.root / "runs/b-test"
                        self.assertFalse((directory / "seals" / f"{role}.json").exists())
                        self.assertEqual(list((directory / role).iterdir()), [])
                        self.assertFalse((directory / "evaluation.json").exists())
                        report = ArtifactStore.verify_terminal_run(directory.parent, directory.name)
                        self.assertEqual(report["terminal_status"], "failed_governance")
                        self.assertTrue(report["terminal_verified"])
                        record = json.loads((directory / "invocations" / role / "attempt-0001/invocation.json").read_text())
                        self.assertEqual(record["identity_verdict"], "failed")
                        self.assertEqual(record["promoted_artifact_refs"], [])
                        self.assertEqual(record["retry_decision"], "stop")
                        self.assertIn("DEFINITIVE RESULT", out)

    def test_stage_failure_and_ambiguity_stop_at_each_position(self):
        roles = ["draft", "self_review", "reviser"]
        for role in roles:
            for mode in ("infrastructure", "timeout", "interrupt", "protocol", "provider"):
                with self.subTest(role=role, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.b, "REPO_ROOT", Path(tmp).resolve()):
                        calls = self.synthetic(bad_role=role, mode=mode)
                        code, out, err = self.main(self.args(execute=True))
                        self.assertNotEqual(code, 0, err + out)
                        self.assertEqual([r.role for r in calls], roles[:roles.index(role) + 1])
                        directory = self.root / "runs/b-test"
                        self.assertFalse((directory / "evaluation.json").exists())
                        self.assertFalse((directory / "seals" / f"{role}.json").exists())
                        ArtifactStore.verify_terminal_run(directory.parent, directory.name)
                        if mode != "provider":
                            self.assertIn("INCONCLUSIVE", out)
                            self.assertIn("DO NOT AUTOMATICALLY RERUN", out)

    def test_repository_venv_required(self):
        with patch.object(self.b, "REPO_ROOT", REPO):
            self.assertEqual(self.real_runtime_guard(), sys.executable)
            for prefix, executable in ((sys.base_prefix, sys.executable),
                                       (str(self.root / "other-venv"), sys.executable),
                                       (sys.prefix, str(Path(sys.executable).resolve()))):
                with self.subTest(prefix=prefix, executable=executable), \
                     patch.object(sys, "prefix", prefix), patch.object(sys, "executable", executable):
                    with self.assertRaises(self.b.CanaryError):
                        self.real_runtime_guard()

    def test_worker_command_uses_validated_interpreter(self):
        plan = self.b.prepare_canary(self.b.build_parser().parse_args(self.args()))
        adapter = self.b.SubprocessAdapter(plan.identity, kind="openai_responses",
                                          python_executable=sys.executable, options={})
        # Exercise the real executor up to a synthetic spawn failure. No worker,
        # SDK client, real credential or network operation is possible here.
        with patch.object(os, "environ", {"OPENAI_API_KEY": "synthetic-offline-only"}), \
             patch("model_council.openai_adapter.validate_openai_runtime_credential",
                   return_value="synthetic-offline-only"), \
             patch("model_council.executor.subprocess.run", side_effect=OSError("synthetic spawn failure")) as run:
            with self.assertRaises(InfrastructureError):
                self.real_spawn(adapter, {}, 30.0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [sys.executable, "-B", "-m", "model_council.worker"])

    def test_attempt_and_usage_summary_preserves_unavailable_values(self):
        self.synthetic(usage=True)
        self.assertEqual(self.main(self.args(execute=True))[0], 0)
        # Summary is read-only, so the persisted destination can be inspected.
        prepared = self.b.prepare_canary(self.b.build_parser().parse_args(self.args(run_id="unused")))
        prepared = replace(prepared, run_spec=replace(prepared.run_spec, run_id="b-test"),
                           destination=self.root / "runs/b-test")
        report = self.b.evidence_summary(prepared)
        self.assertEqual(report["provider_attempts"], 3)
        self.assertEqual(report["provider_usage_total"], {
            "input_tokens": 30, "output_tokens": 12, "total_tokens": 42,
            "reasoning_tokens": 6, "cached_input_tokens": 3,
        })
        self.assertEqual([row["provider_usage"]["input_tokens"] for row in report["stages"]], [10] * 3)
        ambiguous = self.b.evidence_summary(prepared, interrupted=True)
        self.assertIsNone(ambiguous["provider_attempts"])
        self.assertTrue(all(value is None for value in ambiguous["provider_usage_total"].values()))

    def test_missing_usage_and_unconfirmed_provider_outcome_are_not_zero(self):
        for mode in (None, "unconfirmed_provider"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.b, "REPO_ROOT", Path(tmp).resolve()):
                    prepared = self.b.prepare_canary(self.b.build_parser().parse_args(self.args()))
                    calls = self.synthetic(bad_role="draft", mode=mode)
                    code, out, _ = self.main(self.args(execute=True))
                    report = self.b.evidence_summary(prepared)
                    self.assertTrue(all(value is None for value in report["provider_usage_total"].values()))
                    if mode:
                        self.assertEqual(code, 1)
                        self.assertEqual(len(calls), 1)
                        self.assertIsNone(report["provider_attempts"])
                        self.assertIn("INCONCLUSIVE", out)
                    else:
                        self.assertEqual(code, 0)
                        self.assertEqual(report["provider_attempts"], 3)

    def test_terminal_acceptance_fails_closed(self):
        self.synthetic(bad_role="reviser", mode="evaluation")
        code, out, _ = self.main(self.args(execute=True))
        self.assertEqual(code, 1)
        self.assertNotIn("LIVE PASS", out)
        self.assertEqual(ArtifactStore.verify_terminal_run(self.root / "runs", "b-test")["terminal_status"],
                         "failed_evaluation")

    def test_verifier_exception_and_status_mismatch_never_pass(self):
        real_verify = ArtifactStore.verify_terminal_run
        for mode in ("exception", "status", "unverified"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.b, "REPO_ROOT", Path(tmp).resolve()):
                    calls = self.synthetic()

                    def verify(*args):
                        if mode == "exception":
                            raise ValueError("synthetic private exception")
                        value = real_verify(*args)
                        if mode == "status":
                            value["terminal_status"] = "failed_governance"
                        else:
                            value["terminal_verified"] = False
                        return value

                    with patch.object(ArtifactStore, "verify_terminal_run", side_effect=verify):
                        code, out, err = self.main(self.args(execute=True))
                    self.assertEqual(code, 1)
                    self.assertEqual(len(calls), 3)
                    self.assertIn("INCONCLUSIVE", out)
                    self.assertNotIn("synthetic private exception", out + err)

    def test_missing_terminal_evidence_is_inconclusive_without_second_execution(self):
        with patch.object(self.b.ExperimentRunner, "execute", side_effect=KeyboardInterrupt()) as execute:
            code, out, _ = self.main(self.args(execute=True))
        self.assertEqual(code, 1)
        self.assertEqual(execute.call_count, 1)
        self.assertIn("attempt count unknown", out)
        self.assertIn("DO NOT AUTOMATICALLY RERUN", out)

    def test_import_help_and_preflight_do_not_read_credentials(self):
        class NoCredentials(dict):
            def get(self, key, default=None):
                if "KEY" in key or "CREDENTIAL" in key:
                    raise AssertionError("credential read")
                return super().get(key, default)

            def __getitem__(self, key):
                if "KEY" in key or "CREDENTIAL" in key:
                    raise AssertionError("credential read")
                return super().__getitem__(key)

        with patch.object(os, "environ", NoCredentials()), \
             patch.object(self.b, "ExperimentRunner", side_effect=AssertionError("runner construction")):
            with patch.object(sys, "dont_write_bytecode", False):
                spec = importlib.util.spec_from_file_location(
                    "condition_b_import_probe", Path(self.b.__file__),
                )
                module = importlib.util.module_from_spec(spec)
                # Compile the source directly: a Python loader could write its
                # own cache before executing the module's suppression line.
                exec(compile(Path(self.b.__file__).read_text(), self.b.__file__, "exec"), module.__dict__)
                self.assertTrue(sys.dont_write_bytecode)
            self.assertEqual(self.main(self.args())[0], 0)
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                self.b.main(["--help"])
            self.assertEqual(caught.exception.code, 0)
        self.spawn.assert_not_called()
        self.assertFalse((self.root / "runs").exists())


if __name__ == "__main__":
    unittest.main()
