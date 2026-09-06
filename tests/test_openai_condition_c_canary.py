"""Offline regression contract for the separate bounded Condition C launcher."""

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
from model_council.openai_adapter import build_openai_responses_request, translate_openai_responses_result
from test_openai_adapter_translation import _completed_fixture

REPO = SRC.parent
sys.path.insert(0, str(REPO))


def load_launcher():
    return importlib.import_module("experiments.development.run_openai_condition_c_canary")


class TestConditionCCanary(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec(
            "experiments.development.run_openai_condition_c_canary"
        ), "dedicated Condition C launcher is missing")
        self.c = load_launcher()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(self.c, "REPO_ROOT", self.root))
        self.real_runtime_guard = self.c.require_repository_venv
        self.stack.enter_context(patch.object(self.c, "require_repository_venv", return_value=sys.executable))
        self.real_spawn = self.c.SubprocessAdapter._spawn_worker
        # Never let an accidental gap in a synthetic fixture reach credentials or transport.
        for target in (
            "model_council.openai_adapter.validate_openai_runtime_credential",
            "model_council.openai_adapter.build_openai_client",
            "model_council.openai_adapter._perform_openai_responses_transport",
        ):
            self.stack.enter_context(patch(target, side_effect=AssertionError("real boundary forbidden")))
        self.spawn = self.stack.enter_context(patch.object(
            self.c.SubprocessAdapter, "_spawn_worker", autospec=True,
            side_effect=AssertionError("unconfigured worker forbidden"),
        ))

    def args(self, *, execute=False, run_id="c-test", extra=()):
        argv = ["--run-id", run_id, "--runs-root", str(self.root / "runs")]
        if execute:
            argv += ["--execute", "--acknowledge", self.c.ACKNOWLEDGEMENT]
        return argv + list(extra)

    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.c.main(argv)
        return code, out.getvalue(), err.getvalue()

    def synthetic(self, *, bad_role=None, mode=None, usage=False, options=None, mutate=None):
        calls = []
        directory = self.root / "runs" / "c-test"

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
            outcome = live_stub_generate(options or {}, {}, request).to_dict()
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
            if mutate is not None:
                mutate(request, outcome)
            return {
                "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                "execution_profile": "live_contract_v1", "outcome": outcome,
            }

        self.spawn.side_effect = spawn
        return calls

    def test_preflight_has_no_side_effects(self):
        with patch.object(self.c, "ExperimentRunner", side_effect=AssertionError("runner forbidden")), \
             patch.object(self.c, "SubprocessAdapter", side_effect=AssertionError("adapter forbidden")), \
             patch.dict(os.environ, {}, clear=True):
            code, out, err = self.main(self.args())
        self.assertEqual(code, 0, err)
        self.assertIn("PREFLIGHT ONLY", out)
        preview = json.loads(out.splitlines()[1])
        self.assertEqual(preview["condition"], "C")
        self.assertEqual(preview["stages"], ["solver", "verifier", "reviser"])
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
        plan = self.c.prepare_canary(self.c.build_parser().parse_args(self.args()))
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
                self.c.build_parser().parse_args(self.args(extra=(flag, value)))
        for changed in (
            replace(plan, run_spec=replace(plan.run_spec, condition=Condition.A)),
            replace(plan, run_spec=replace(plan.run_spec, resource_limits=replace(
                plan.run_spec.resource_limits, max_stage_retries=1))),
            replace(plan, identity=replace(plan.identity, model_id="other")),
            replace(plan, provider_treatment_config={"reasoning": {"effort": "high"}}),
            replace(plan, destination=self.root / "elsewhere"),
        ):
            with self.subTest(plan=changed), self.assertRaises(self.c.CanaryError):
                self.c.execute_prepared_canary(changed, acknowledge=self.c.ACKNOWLEDGEMENT)
        self.spawn.assert_not_called()

    def test_wrong_topology_rejected(self):
        for roles in (("draft",), ("self_review", "draft", "reviser"),
                      ("draft", "self_review", "reviser", "solver")):
            with patch.dict(self.c.CONDITION_STAGES, {Condition.C: roles}):
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
        argv = ["--run-id", "c-test", "--runs-root", str(self.root.parent / "outside")]
        self.assertEqual(self.main(argv)[0], 2)
        self.assertEqual((runs / "file").read_text(), "preserve")
        self.spawn.assert_not_called()

    def test_three_stage_success_exact_handoffs_and_seals(self):
        calls = self.synthetic()
        evaluated = []
        real_evaluate = self.c.ExternalEvaluator.evaluate

        def evaluate(evaluator, candidate):
            evaluated.append(candidate)
            return real_evaluate(evaluator, candidate)

        with patch.object(self.c.ExternalEvaluator, "evaluate", autospec=True, side_effect=evaluate):
            code, out, err = self.main(self.args(execute=True))
        self.assertEqual(code, 0, err + out)
        self.assertEqual([r.role for r in calls], ["solver", "verifier", "reviser"])
        directory = self.root / "runs" / "c-test"
        candidate = (directory / "solver/candidate.md").read_text()
        evidence = (directory / "solver/evidence.md").read_text()
        findings = (directory / "verifier/findings.md").read_text()
        task = calls[0].stage_inputs["task"]
        self.assertEqual(dict(calls[0].stage_inputs), {"task": task})
        self.assertEqual(dict(calls[1].stage_inputs), {
            "task": task, "solver_candidate": candidate, "solver_evidence": evidence,
        })
        self.assertEqual(dict(calls[2].stage_inputs), {
            "task": task, "solver_candidate": candidate, "verifier_findings": findings,
        })
        self.assertEqual(json.loads(findings), {"findings": [{
            "finding_id": "V1", "description": "confirm fix addresses reported behavior", "material": True,
        }]})
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
                if request.role != "verifier":
                    self.assertEqual((directory / request.role / f"{name}.md").read_text(), content)
        report = ArtifactStore.verify_terminal_run(directory.parent, directory.name)
        self.assertTrue(report["provider_identity_policy_verified"])
        self.assertTrue(report["terminal_verified"])
        terminal = json.loads((directory / "run_result.json").read_text())
        self.assertEqual(terminal["status"], "succeeded")
        self.assertEqual(terminal["final_candidate_ref"], "reviser/final_candidate.md")
        self.assertEqual(evaluated, [(directory / "reviser/final_candidate.md").read_text()])
        self.assertTrue((directory / "evaluation.json").is_file())
        self.assertIn("CONDITION C LIVE PASS", out)

    def test_identity_rejection_stops_at_each_stage(self):
        roles = ["solver", "verifier", "reviser"]
        for role in roles:
            for mode in ("mismatch", "missing", "malformed"):
                with self.subTest(role=role, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                        calls = self.synthetic(bad_role=role, mode=mode)
                        code, out, err = self.main(self.args(execute=True))
                        self.assertEqual(code, 1, err + out)
                        self.assertEqual([r.role for r in calls], roles[:roles.index(role) + 1])
                        directory = self.root / "runs/c-test"
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
        roles = ["solver", "verifier", "reviser"]
        for role in roles:
            for mode in ("infrastructure", "timeout", "interrupt", "protocol", "provider"):
                with self.subTest(role=role, mode=mode), tempfile.TemporaryDirectory() as tmp:
                    with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                        calls = self.synthetic(bad_role=role, mode=mode)
                        code, out, err = self.main(self.args(execute=True))
                        self.assertNotEqual(code, 0, err + out)
                        self.assertEqual([r.role for r in calls], roles[:roles.index(role) + 1])
                        directory = self.root / "runs/c-test"
                        self.assertFalse((directory / "evaluation.json").exists())
                        self.assertFalse((directory / "seals" / f"{role}.json").exists())
                        ArtifactStore.verify_terminal_run(directory.parent, directory.name)
                        if mode != "provider":
                            self.assertIn("INCONCLUSIVE", out)
                            self.assertIn("DO NOT AUTOMATICALLY RERUN", out)

    def test_repository_venv_required(self):
        with patch.object(self.c, "REPO_ROOT", REPO):
            self.assertEqual(self.real_runtime_guard(), sys.executable)
            for prefix, executable in ((sys.base_prefix, sys.executable),
                                       (str(self.root / "other-venv"), sys.executable),
                                       (sys.prefix, str(Path(sys.executable).resolve()))):
                with self.subTest(prefix=prefix, executable=executable), \
                     patch.object(sys, "prefix", prefix), patch.object(sys, "executable", executable):
                    with self.assertRaises(self.c.CanaryError):
                        self.real_runtime_guard()

    def test_worker_command_uses_validated_interpreter(self):
        plan = self.c.prepare_canary(self.c.build_parser().parse_args(self.args()))
        adapter = self.c.SubprocessAdapter(plan.identity, kind="openai_responses",
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
        prepared = self.c.prepare_canary(self.c.build_parser().parse_args(self.args(run_id="unused")))
        prepared = replace(prepared, run_spec=replace(prepared.run_spec, run_id="c-test"),
                           destination=self.root / "runs/c-test")
        report = self.c.evidence_summary(prepared)
        self.assertEqual(report["provider_attempts"], 3)
        self.assertEqual(report["provider_usage_total"], {
            "input_tokens": 30, "output_tokens": 12, "total_tokens": 42,
            "reasoning_tokens": 6, "cached_input_tokens": 3,
        })
        self.assertEqual([row["provider_usage"]["input_tokens"] for row in report["stages"]], [10] * 3)
        ambiguous = self.c.evidence_summary(prepared, interrupted=True)
        self.assertIsNone(ambiguous["provider_attempts"])
        self.assertTrue(all(value is None for value in ambiguous["provider_usage_total"].values()))

    def test_missing_usage_and_unconfirmed_provider_outcome_are_not_zero(self):
        for mode in (None, "unconfirmed_provider"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    prepared = self.c.prepare_canary(self.c.build_parser().parse_args(self.args()))
                    calls = self.synthetic(bad_role="solver", mode=mode)
                    code, out, _ = self.main(self.args(execute=True))
                    report = self.c.evidence_summary(prepared)
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
        self.assertEqual(ArtifactStore.verify_terminal_run(self.root / "runs", "c-test")["terminal_status"],
                         "failed_evaluation")

    def test_verifier_exception_and_status_mismatch_never_pass(self):
        real_verify = ArtifactStore.verify_terminal_run
        for mode in ("exception", "status", "unverified"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
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
        with patch.object(self.c.ExperimentRunner, "execute", side_effect=KeyboardInterrupt()) as execute:
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
             patch.object(self.c, "ExperimentRunner", side_effect=AssertionError("runner construction")):
            with patch.object(sys, "dont_write_bytecode", False):
                spec = importlib.util.spec_from_file_location(
                    "condition_c_import_probe", Path(self.c.__file__),
                )
                module = importlib.util.module_from_spec(spec)
                # Compile the source directly: a Python loader could write its
                # own cache before executing the module's suppression line.
                exec(compile(Path(self.c.__file__).read_text(), self.c.__file__, "exec"), module.__dict__)
                self.assertTrue(sys.dont_write_bytecode)
            self.assertEqual(self.main(self.args())[0], 0)
            with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
                self.c.main(["--help"])
            self.assertEqual(caught.exception.code, 0)
        self.spawn.assert_not_called()
        self.assertFalse((self.root / "runs").exists())

    def summary(self):
        plan = self.c.prepare_canary(self.c.build_parser().parse_args(self.args(run_id="unused")))
        return self.c.evidence_summary(replace(
            plan, run_spec=replace(plan.run_spec, run_id="c-test"),
            destination=self.root / "runs/c-test",
        ))

    def test_zero_findings_and_material_findings_have_distinct_coverage(self):
        for empty in (True, False):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    calls = self.synthetic(options={"empty_verifier_findings": empty, "verifier_extra_finding": True})
                    code, out, err = self.main(self.args(execute=True))
                    self.assertEqual(code, 0, out + err)
                    self.assertEqual(len(calls), 3)
                    report = self.summary()
                    self.assertEqual(report["findings_count"], 0 if empty else 2)
                    self.assertEqual(report["material_findings_count"], 0 if empty else 2)
                    self.assertEqual(report["disposition_count"], 0 if empty else 2)
                    self.assertEqual(report["findings_branch"], "zero_findings" if empty else "with_findings")
                    for key in ("canonical_findings_verified", "reviser_input_verified", "dispositions_verified"):
                        self.assertIs(report[key], True)
                    if empty:
                        self.assertEqual(calls[2].stage_inputs["verifier_findings"], '{"findings":[]}')

    def test_divergent_prose_is_evidence_only(self):
        calls = self.synthetic(options={"divergent_findings_prose": True})
        code, out, err = self.main(self.args(execute=True))
        self.assertEqual(code, 0, out + err)
        directory = self.root / "runs/c-test"
        promoted = (directory / "verifier/findings.md").read_text()
        self.assertEqual(promoted, calls[2].stage_inputs["verifier_findings"])
        self.assertNotIn("V9", promoted)
        record = json.loads((directory / "invocations/verifier/attempt-0001/invocation.json").read_text())
        prose = record["adapter_evidence"]["provider_call_outcome"]["stage_output"]["artifacts"]["findings"]
        self.assertIn("V9", prose)
        self.assertNotEqual(prose, promoted)
        self.assertTrue(self.summary()["canonical_findings_verified"])

    def test_invalid_findings_stop_before_reviser(self):
        for mode in ("duplicate", "blank", "wrong_type", "missing", "extra"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    def mutate(request, outcome):
                        if request.role != "verifier":
                            return
                        structured = outcome["stage_output"]["structured"]
                        finding = structured["findings"][0]
                        if mode == "duplicate":
                            structured["findings"].append(dict(finding))
                        elif mode == "blank":
                            finding["description"] = "   "
                        elif mode == "wrong_type":
                            finding["material"] = "true"
                        elif mode == "missing":
                            structured.clear()
                        else:
                            finding["unapproved"] = True
                        outcome["structured_output"]["value"] = structured
                    calls = self.synthetic(mutate=mutate)
                    code, out, _ = self.main(self.args(execute=True))
                    self.assertEqual(code, 1)
                    self.assertEqual([r.role for r in calls], ["solver", "verifier"])
                    directory = self.root / "runs/c-test"
                    self.assertFalse((directory / "seals/verifier.json").exists())
                    self.assertFalse((directory / "verifier/findings.md").exists())
                    self.assertFalse((directory / "evaluation.json").exists())
                    self.assertNotIn("LIVE PASS", out)
                    ArtifactStore.verify_terminal_run(directory.parent, directory.name)

    def test_invalid_dispositions_block_final_promotion(self):
        for mode in ("missing", "duplicate", "unknown", "decision", "rationale", "null"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    def mutate(request, outcome):
                        if request.role != "reviser":
                            return
                        structured = outcome["stage_output"]["structured"]
                        dispositions = structured["dispositions"]
                        if mode == "missing":
                            dispositions.clear()
                        elif mode == "duplicate":
                            dispositions.append(dict(dispositions[0]))
                        elif mode == "unknown":
                            dispositions[0]["finding_id"] = "UNKNOWN"
                        elif mode == "decision":
                            dispositions[0]["decision"] = "maybe"
                        elif mode == "rationale":
                            dispositions[0]["rationale"] = "   "
                        else:
                            outcome["stage_output"]["structured"] = None
                        if mode != "null":
                            outcome["structured_output"]["value"] = structured
                    calls = self.synthetic(mutate=mutate)
                    code, out, _ = self.main(self.args(execute=True))
                    self.assertEqual(code, 1)
                    self.assertEqual(len(calls), 3)
                    directory = self.root / "runs/c-test"
                    self.assertTrue((directory / "seals/verifier.json").exists())
                    self.assertFalse((directory / "seals/reviser.json").exists())
                    self.assertFalse((directory / "reviser/final_candidate.md").exists())
                    self.assertFalse((directory / "evaluation.json").exists())
                    self.assertNotIn("LIVE PASS", out)
                    ArtifactStore.verify_terminal_run(directory.parent, directory.name)

    def test_nonmaterial_findings_do_not_require_dispositions(self):
        def mutate(request, outcome):
            if request.role == "verifier":
                outcome["stage_output"]["structured"]["findings"][0]["material"] = False
                outcome["structured_output"]["value"]["findings"][0]["material"] = False
            elif request.role == "reviser":
                outcome["stage_output"]["structured"] = {"dispositions": []}
                outcome["structured_output"]["value"] = {"dispositions": []}
        self.synthetic(mutate=mutate)
        code, out, err = self.main(self.args(execute=True))
        self.assertEqual(code, 0, out + err)
        report = self.summary()
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["material_findings_count"], 0)
        self.assertEqual(report["disposition_count"], 0)
        self.assertTrue(report["dispositions_verified"])

    def test_findings_or_seal_tampering_blocks_downstream(self):
        original = ArtifactStore.seal_stage
        for target in ("verifier/findings.md", "seals/verifier.json"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    calls = self.synthetic()
                    def seal(store, role, **kwargs):
                        result = original(store, role, **kwargs)
                        if role == "verifier":
                            # Corrupt only this isolated offline fixture.
                            with (store.run_dir / target).open("a") as stream:
                                stream.write("tampered")
                        return result
                    with patch.object(ArtifactStore, "seal_stage", autospec=True, side_effect=seal):
                        code, out, _ = self.main(self.args(execute=True))
                    self.assertEqual(code, 1)
                    self.assertEqual([r.role for r in calls], ["solver", "verifier"])
                    self.assertFalse((self.root / "runs/c-test/evaluation.json").exists())
                    self.assertNotIn("LIVE PASS", out)

    def test_budget_and_tool_failures_never_dispatch_downstream(self):
        for mode in ("input", "output", "tools"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    def mutate(request, outcome):
                        if request.role == "solver":
                            if mode == "output":
                                outcome["stage_output"]["artifacts"]["candidate"] = "word " * 1025
                            elif mode == "tools":
                                outcome["tool_use_count"] = 1
                    calls = self.synthetic(mutate=mutate)
                    with ExitStack() as stack:
                        if mode == "input":
                            # Test predispatch enforcement on the fixed task seam.
                            task = self.c.load_development_task()
                            stack.enter_context(patch.object(self.c, "load_development_task", return_value=replace(
                                task, bug_report="word " * 2049,
                            )))
                        code, out, _ = self.main(self.args(execute=True))
                    self.assertEqual(code, 1)
                    self.assertEqual(len(calls), 0 if mode == "input" else 1)
                    self.assertFalse((self.root / "runs/c-test/evaluation.json").exists())
                    self.assertNotIn("LIVE PASS", out)

    def test_c_acceptance_rejects_inconsistent_stored_projection(self):
        self.synthetic()
        self.assertEqual(self.main(self.args(execute=True))[0], 0)
        original_read = Path.read_text
        # Keep terminal verification real. Change just the launcher's subsequent
        # view to prove its C-specific comparison does not trust prose or flags.
        real_verify = ArtifactStore.verify_terminal_run
        verified = False
        def verify(*args):
            nonlocal verified
            value = real_verify(*args)
            verified = True
            return value
        def read(path, *args, **kwargs):
            value = original_read(path, *args, **kwargs)
            if verified and str(path).endswith("verifier/findings.md"):
                return '{"findings":[]}'
            return value
        with patch.object(ArtifactStore, "verify_terminal_run", side_effect=verify), \
             patch.object(Path, "read_text", read):
            with self.assertRaises(self.c.CanaryError):
                self.summary()

    def test_acceptance_revalidates_closed_findings_schema(self):
        self.synthetic()
        self.assertEqual(self.main(self.args(execute=True))[0], 0)
        original_read = Path.read_text
        real_verify = ArtifactStore.verify_terminal_run
        verified = False
        def verify(*args):
            nonlocal verified
            value = real_verify(*args)
            verified = True
            return value
        def read(path, *args, **kwargs):
            value = original_read(path, *args, **kwargs)
            if verified and str(path).endswith("verifier/attempt-0001/invocation.json"):
                record = json.loads(value)
                finding = record["adapter_evidence"]["provider_call_outcome"]["stage_output"]["structured"]["findings"][0]
                # Finding's dataclass default must not mask a missing required
                # provider field during acceptance.
                del finding["material"]
                return json.dumps(record)
            return value
        with patch.object(ArtifactStore, "verify_terminal_run", side_effect=verify), \
             patch.object(Path, "read_text", read):
            with self.assertRaises(self.c.CanaryError):
                self.summary()

    def test_provider_shaped_responses_cover_both_findings_branches(self):
        for empty in (True, False):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as tmp:
                with patch.object(self, "root", Path(tmp).resolve()), patch.object(self.c, "REPO_ROOT", Path(tmp).resolve()):
                    calls = []
                    def spawn(adapter, envelope, timeout):
                        request = parse_live_invocation_request(envelope["live_invocation_request"])
                        calls.append(request)
                        if request.role == "solver":
                            stage = {"text": "candidate", "artifacts": {
                                "candidate": "def parse_date(text): return date.fromisoformat(text)",
                                "evidence": "proposed leap-day handling; no tests executed",
                            }, "structured": None}
                        elif request.role == "verifier":
                            stage = {"text": "reviewed", "artifacts": {"findings": "Noncanonical commentary"},
                                     "structured": {"findings": [] if empty else [{
                                         "finding_id": "V1", "description": "import date", "material": True,
                                     }]}}
                        else:
                            stage = {"text": "revision", "artifacts": {"final_candidate": "from datetime import date"},
                                     "structured": {"dispositions": [] if empty else [{
                                         "finding_id": "V1", "decision": "accept", "rationale": "added import",
                                     }]}}
                        wire = build_openai_responses_request(request, {})
                        self.assertEqual(wire["max_output_tokens"], 1024)
                        outcome = translate_openai_responses_result(request, _completed_fixture(
                            stage, model="gpt-5.6-luna", response_id=f"resp_{request.role}",
                        ))
                        return {"harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                                "execution_profile": "live_contract_v1", "outcome": outcome.to_dict()}
                    self.spawn.side_effect = spawn
                    code, out, err = self.main(self.args(execute=True))
                    self.assertEqual(code, 0, out + err)
                    self.assertEqual([r.role for r in calls], ["solver", "verifier", "reviser"])
                    report = self.summary()
                    self.assertEqual(report["provider_attempts"], 3)
                    self.assertEqual(report["findings_count"], 0 if empty else 1)
                    self.assertTrue(report["dispositions_verified"])

    def test_summary_rejects_unconfirmed_terminal_verification(self):
        self.synthetic()
        self.assertEqual(self.main(self.args(execute=True))[0], 0)
        real_verify = ArtifactStore.verify_terminal_run
        for field, invalid in (("terminal_verified", False), ("terminal_status", "failed_contract"),
                               ("run_id", "other-run")):
            with self.subTest(field=field):
                def verify(*args):
                    value = real_verify(*args)
                    value[field] = invalid
                    return value
                with patch.object(ArtifactStore, "verify_terminal_run", side_effect=verify):
                    with self.assertRaises(self.c.CanaryError):
                        self.summary()


if __name__ == "__main__":
    unittest.main()
