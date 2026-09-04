"""Offline tests for the guarded development-only OpenAI canary entrypoint."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import math
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from helpers import TempRoot
from model_council import (
    ArtifactStore,
    EvaluationOutcome,
    STATUS_FAILED_EVALUATION,
    STATUS_INFRASTRUCTURE_FAILURE,
    STATUS_SUCCEEDED,
    Condition,
    RunResult,
)
from model_council.roles import CONDITION_STAGES, ROLE_SOLVER

REPO_ROOT = Path(__file__).resolve().parents[1]
CANARY_PATH = REPO_ROOT / "experiments" / "development" / "run_openai_canary.py"
DEVELOPMENT_TASK = (
    REPO_ROOT / "experiments" / "development" / "tasks" / "task_dev_001.json"
)
HOST_KEY = "OPENAI_API_KEY"
CHILD_KEY = "MCL_OPENAI_API_KEY"
ACK = "NETWORK_CREDENTIALS_AND_PAID_CAPACITY"
SYNTHETIC_SECRET = "sk-test-canary-secret-not-real"
_LOADED = {}


def _load_canary(name: str = "run_openai_canary"):
    existing = _LOADED.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, CANARY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    _LOADED[name] = module
    return module


def _valid_argv(runs_root: Path, run_id: str = "canary-run-001", **overrides):
    values = {
        "--acknowledge": ACK,
        "--model-id": "gpt-test-canary",
        "--model-version": "canary-identity-v0",
        "--run-id": run_id,
        "--runs-root": str(runs_root),
        "--max-input-tokens": "2048",
        "--max-output-tokens": "512",
        "--stage-timeout-seconds": "30",
    }
    for key, value in overrides.items():
        flag = key if key.startswith("--") else f"--{key.replace('_', '-')}"
        if value is None:
            values.pop(flag, None)
        else:
            values[flag] = value
    argv = []
    for flag, value in values.items():
        argv.extend([flag, str(value)])
    return argv


def _flatten_with_extra(base: list[str], extra: list[str]) -> list[str]:
    return list(base) + list(extra)


def _fake_evaluation(passed):
    return EvaluationOutcome(
        passed=passed,
        reasons=("synthetic canary evaluation",),
        evaluated_at="2026-09-04T00:00:00+00:00",
    )


def _fake_result(spec, status=STATUS_SUCCEEDED, *, evaluation=None):
    if evaluation is None and status == STATUS_SUCCEEDED:
        evaluation = _fake_evaluation(True)
    return RunResult(
        run_id=spec.run_id,
        task_id=spec.task_id,
        condition=spec.condition,
        model_identifier=spec.model_identifier,
        spec_hash=spec.spec_hash,
        status=status,
        stage_results=[],
        evaluation=evaluation,
    )


def _fake_verification(spec, status=STATUS_SUCCEEDED, *, verified=True, **overrides):
    payload = {
        "run_id": spec.run_id,
        "verification_scope": "terminal_run",
        "terminal_verified": verified,
        "terminal_status": status,
    }
    payload.update(overrides)
    return payload


def _action(parser, option):
    return parser._option_string_actions[option]


def _forbid_worker_spawn():
    import subprocess as subprocess_mod

    real_run = subprocess_mod.run

    def guarded_run(*args, **kwargs):
        command = args[0] if args else kwargs.get("args")
        if isinstance(command, (list, tuple)) and "model_council.worker" in command:
            raise AssertionError("provider worker spawn must not occur")
        return real_run(*args, **kwargs)

    return patch.object(subprocess_mod, "run", side_effect=guarded_run)


def _capture_main(module, argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = module.main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class _ExecutionProbe:
    def __init__(self, module, *, execute=None, verify=None):
        self.module = module
        self.execute_calls = []
        self.verify_calls = []
        self._execute = execute
        self._verify = verify
        self._execute_patch = None
        self._verify_patch = None

    def _wrapped_execute(self, runner, spec, task):
        self.execute_calls.append((runner, spec, task))
        if self._execute is not None:
            return self._execute(runner, spec, task)
        raise AssertionError("ExperimentRunner.execute must not be called")

    def _wrapped_verify(self, runs_root, run_id):
        self.verify_calls.append((runs_root, run_id))
        if self._verify is not None:
            return self._verify(runs_root, run_id)
        raise AssertionError("ArtifactStore.verify_terminal_run must not be called")

    def __enter__(self):
        self._execute_patch = patch.object(
            self.module.ExperimentRunner,
            "execute",
            autospec=True,
            side_effect=self._wrapped_execute,
        )
        self._verify_patch = patch.object(
            self.module.ArtifactStore,
            "verify_terminal_run",
            autospec=False,
            side_effect=self._wrapped_verify,
        )
        self._execute_patch.start()
        self._verify_patch.start()
        return self

    def __exit__(self, *exc):
        self._verify_patch.stop()
        self._execute_patch.stop()
        return False


class _CredentialReadProbe:
    FORBIDDEN = (HOST_KEY, CHILD_KEY)

    def __init__(self):
        self.reads = []
        self._original = os.environ

    def __getitem__(self, key):
        if key in self.FORBIDDEN:
            self.reads.append(("getitem", key))
        return self._original[key]

    def get(self, key, default=None):
        if key in self.FORBIDDEN:
            self.reads.append(("get", key))
        return self._original.get(key, default)

    def __contains__(self, key):
        if key in self.FORBIDDEN:
            self.reads.append(("contains", key))
        return key in self._original

    def pop(self, key, *args):
        if key in self.FORBIDDEN:
            self.reads.append(("pop", key))
        return self._original.pop(key, *args)

    def __getattr__(self, name):
        return getattr(self._original, name)

    def __iter__(self):
        return iter(self._original)

    def keys(self):
        return self._original.keys()

    def items(self):
        return self._original.items()

    def values(self):
        return self._original.values()

    def __len__(self):
        return len(self._original)


class TestOpenAICanary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _load_canary()

    def setUp(self):
        self.assertNotIn(HOST_KEY, os.environ)
        self.assertNotIn(CHILD_KEY, os.environ)

    def _assert_secret_free(self, *blobs):
        for blob in blobs:
            text = blob if type(blob) is str else str(blob)
            lowered = text.lower()
            self.assertNotIn(SYNTHETIC_SECRET, text)
            self.assertNotIn(HOST_KEY, text)
            self.assertNotIn(CHILD_KEY, text)
            self.assertNotIn("sk-test-canary-secret-not-real", lowered)

    def test_01_importing_the_module_is_inert(self):
        self.assertTrue(CANARY_PATH.is_file())
        self.assertIsNotNone(self.module.main)
        self.assertEqual(self.module.DEVELOPMENT_TASK_PATH, DEVELOPMENT_TASK)

    def test_02_help_is_inert(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as ctx:
                self.module.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)
        help_text = stdout.getvalue()
        self.assertIn("acknowledge", help_text)
        self.assertIn("model-id", help_text)
        self.assertNotIn("--task", help_text)
        self.assertEqual(stderr.getvalue(), "")

    def test_03_import_and_help_cause_no_credential_access(self):
        probe = _CredentialReadProbe()
        stdout = io.StringIO()
        with patch.object(os, "environ", probe):
            fresh = _load_canary("run_openai_canary_cred_probe")
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    fresh.main(["--help"])
        self.assertEqual(probe.reads, [])

    def test_04_import_and_help_construct_no_sdk_client(self):
        def boom(*_args, **_kwargs):
            self.fail("OpenAI client factory must not run")

        stdout = io.StringIO()
        with patch(
            "model_council.openai_adapter.build_openai_client", side_effect=boom
        ), patch(
            "model_council.openai_adapter._default_openai_client_factory",
            side_effect=boom,
        ), patch(
            "model_council.openai_adapter._perform_openai_responses_transport",
            side_effect=boom,
        ):
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    self.module.main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_05_import_and_help_cause_no_execution_or_network_call(self):
        with _ExecutionProbe(self.module) as probe:
            with patch(
                "model_council.executor.subprocess.run",
                side_effect=AssertionError("network/process must not run"),
            ):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.module.main(["--help"])
        self.assertEqual(probe.execute_calls, [])
        self.assertEqual(probe.verify_calls, [])

    def test_06_import_and_help_create_no_output_directory(self):
        with TempRoot() as root:
            sentinel = Path(root) / "must-not-exist"
            with _ExecutionProbe(self.module):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.module.main(["--help"])
            self.assertFalse(sentinel.exists())
            self.assertFalse((REPO_ROOT / "runs").exists())

    def test_07_missing_or_incorrect_acknowledgement_fails_before_execution(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            with _ExecutionProbe(self.module) as probe:
                argv = _valid_argv(runs)
                ack_index = argv.index("--acknowledge")
                del argv[ack_index : ack_index + 2]
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        self.module.main(argv)
                self.assertEqual(ctx.exception.code, 2)
                code, _out, err = _capture_main(
                    self.module, _valid_argv(runs, **{"--acknowledge": "WRONG"})
                )
            self.assertEqual(code, 2)
            self.assertIn("acknowledgement", err)
            self.assertEqual(probe.execute_calls, [])

    def test_08_no_model_default_exists(self):
        parser = self.module.build_parser()
        model_id = _action(parser, "--model-id")
        model_version = _action(parser, "--model-version")
        self.assertTrue(model_id.required)
        self.assertTrue(model_version.required)
        self.assertIsNone(model_id.default)
        self.assertIsNone(model_version.default)
        self.assertNotIn("gpt-4", str(model_id.default))
        self.assertNotIn("gpt-5", parser.description.lower() + parser.format_help().lower())

    def test_09_model_id_is_caller_supplied(self):
        with TempRoot() as root:
            args = self.module.parse_args(
                _valid_argv(Path(root) / "runs", **{"--model-id": "caller-model"})
            )
            plan = self.module.prepare_canary(args)
        self.assertEqual(plan.identity.model_id, "caller-model")
        self.assertEqual(plan.run_spec.model_identifier, plan.identity.key())

    def test_10_model_version_identity_label_is_caller_supplied(self):
        with TempRoot() as root:
            args = self.module.parse_args(
                _valid_argv(
                    Path(root) / "runs", **{"--model-version": "caller-identity-label"}
                )
            )
            plan = self.module.prepare_canary(args)
        self.assertEqual(plan.identity.model_version, "caller-identity-label")

    def test_11_task_is_fixed_to_task_dev_001(self):
        parser = self.module.build_parser()
        self.assertNotIn("--task", parser._option_string_actions)
        self.assertEqual(self.module.DEVELOPMENT_TASK_PATH.name, "task_dev_001.json")
        self.assertEqual(self.module.DEVELOPMENT_TASK_PATH, DEVELOPMENT_TASK)
        task = self.module.load_development_task()
        self.assertEqual(task.task_id, "dev-001")

    def test_12_development_only_and_heldout_exclusion_markers_are_verified(self):
        task = self.module.load_development_task()
        self.assertIs(task.metadata["development_only"], True)
        self.assertIs(task.metadata["excluded_from_heldout"], True)
        with patch.object(
            self.module,
            "DEVELOPMENT_TASK_PATH",
            Path("/tmp/not-the-fixture.json"),
        ):
            with self.assertRaises(self.module.CanaryError):
                self.module.load_development_task()

    def test_13_condition_a_is_exact(self):
        self.assertIs(self.module.CANARY_CONDITION, Condition.A)
        self.assertEqual(CONDITION_STAGES[Condition.A], (ROLE_SOLVER,))
        with TempRoot() as root:
            plan = self.module.prepare_canary(
                self.module.parse_args(_valid_argv(Path(root) / "runs"))
            )
        self.assertIs(plan.run_spec.condition, Condition.A)
        self.assertEqual(CONDITION_STAGES[plan.run_spec.condition], (ROLE_SOLVER,))

    def test_14_adapter_kind_openai_responses_is_exact(self):
        self.assertEqual(self.module.ADAPTER_KIND, "openai_responses")
        with TempRoot() as root:
            plan = self.module.prepare_canary(
                self.module.parse_args(_valid_argv(Path(root) / "runs"))
            )
        self.assertEqual(plan.adapter_kind, "openai_responses")
        self.assertEqual(plan.identity.adapter_name, "openai_responses")
        self.assertEqual(plan.identity.provider, "openai")
        self.assertEqual(plan.identity.adapter_version, "v0")

    def test_15_computed_identity_key_is_exact(self):
        identity = self.module.build_adapter_identity(
            "gpt-test-canary", "canary-identity-v0"
        )
        self.assertEqual(
            identity.key(),
            "openai:gpt-test-canary:canary-identity-v0:openai_responses:v0",
        )
        with TempRoot() as root:
            plan = self.module.prepare_canary(
                self.module.parse_args(_valid_argv(Path(root) / "runs"))
            )
        self.assertEqual(plan.run_spec.model_identifier, identity.key())
        self.assertEqual(plan.identity.key(), identity.key())

    def test_16_resource_limits_contain_zero_tools_and_zero_retries(self):
        limits = self.module.build_resource_limits(2048, 512, 30)
        self.assertEqual(limits.max_tool_calls_per_stage, 0)
        self.assertEqual(limits.max_stage_retries, 0)
        with TempRoot() as root:
            plan = self.module.prepare_canary(
                self.module.parse_args(_valid_argv(Path(root) / "runs"))
            )
        self.assertEqual(plan.run_spec.resource_limits.max_tool_calls_per_stage, 0)
        self.assertEqual(plan.run_spec.resource_limits.max_stage_retries, 0)

    def test_17_accepted_caller_resource_ceilings_propagate(self):
        with TempRoot() as root:
            plan = self.module.prepare_canary(
                self.module.parse_args(
                    _valid_argv(
                        Path(root) / "runs",
                        **{
                            "--max-input-tokens": "2048",
                            "--max-output-tokens": "512",
                            "--stage-timeout-seconds": "30",
                        },
                    )
                )
            )
        limits = plan.run_spec.resource_limits
        self.assertEqual(limits.max_input_tokens_per_stage, 2048)
        self.assertEqual(limits.max_output_tokens_per_stage, 512)
        self.assertEqual(limits.stage_timeout_seconds, 30.0)

    def test_18_invalid_resource_values_fail_before_execution(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            cases = (
                ("--max-input-tokens", "0"),
                ("--max-input-tokens", "-1"),
                ("--max-input-tokens", "True"),
                ("--max-input-tokens", "nan"),
                ("--max-input-tokens", "inf"),
                ("--max-input-tokens", "4096.0"),
                ("--max-input-tokens", "4097"),
                ("--max-output-tokens", "0"),
                ("--max-output-tokens", "1025"),
                ("--max-output-tokens", "1e3"),
                ("--stage-timeout-seconds", "0"),
                ("--stage-timeout-seconds", "-1"),
                ("--stage-timeout-seconds", "True"),
                ("--stage-timeout-seconds", "nan"),
                ("--stage-timeout-seconds", "inf"),
                ("--stage-timeout-seconds", "61"),
                ("--stage-timeout-seconds", "1e2"),
            )
            with _ExecutionProbe(self.module) as probe:
                for flag, value in cases:
                    with self.subTest(flag=flag, value=value):
                        code, _out, err = _capture_main(
                            self.module, _valid_argv(runs, **{flag: value})
                        )
                        self.assertEqual(code, 2)
                        self.assertIn("canary rejected", err)
            self.assertEqual(probe.execute_calls, [])
            with self.assertRaises(self.module.CanaryError):
                self.module.require_token_ceiling(
                    True, name="max input tokens", maximum=4096
                )
            with self.assertRaises(self.module.CanaryError):
                self.module.require_token_ceiling(
                    False, name="max output tokens", maximum=1024
                )
            with self.assertRaises(self.module.CanaryError):
                self.module.require_stage_timeout(True)
            with self.assertRaises(self.module.CanaryError):
                self.module.require_stage_timeout(float("nan"))
            with self.assertRaises(self.module.CanaryError):
                self.module.require_stage_timeout(float("inf"))
            with self.assertRaises(self.module.CanaryError):
                self.module.require_stage_timeout(math.inf)
            with self.assertRaises(self.module.CanaryError):
                self.module.require_token_ceiling(
                    4096.1, name="max input tokens", maximum=4096
                )

    def test_19_unsupported_and_stateful_treatment_values_fail_before_execution(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            with _ExecutionProbe(self.module) as probe:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.module.main(
                            _flatten_with_extra(
                                _valid_argv(runs),
                                ["--reasoning-effort", "previous_response_id"],
                            )
                        )
                    with self.assertRaises(SystemExit):
                        self.module.main(
                            _flatten_with_extra(
                                _valid_argv(runs), ["--store", "true"]
                            )
                        )
                    with self.assertRaises(SystemExit):
                        self.module.main(
                            _flatten_with_extra(
                                _valid_argv(runs),
                                ["--service-tier", "flex"],
                            )
                        )
            self.assertEqual(probe.execute_calls, [])
            for config in (
                {"previous_response_id": "resp_x"},
                {"conversation": "c"},
                {"store": True},
                {"background": True},
                {"service_tier": "flex"},
                {"temperature": 0.2},
            ):
                with self.subTest(config=config):
                    with self.assertRaises(self.module.CanaryError):
                        self.module.require_treatment_configuration(config)

    def test_20_unsafe_run_ids_fail(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            unsafe = (
                "../escape",
                "a/b",
                ".",
                "..",
                ".hidden",
                "run id",
                "",
            )
            with _ExecutionProbe(self.module) as probe:
                for run_id in unsafe:
                    with self.subTest(run_id=run_id):
                        if run_id == "":
                            argv = _valid_argv(runs)
                            idx = argv.index("--run-id")
                            argv[idx + 1] = ""
                            code, _out, err = _capture_main(self.module, argv)
                        else:
                            code, _out, err = _capture_main(
                                self.module, _valid_argv(runs, run_id=run_id)
                            )
                        self.assertEqual(code, 2)
                        self.assertIn("canary rejected", err)
            self.assertEqual(probe.execute_calls, [])

    def test_21_missing_output_location_fails(self):
        parser = self.module.build_parser()
        self.assertTrue(_action(parser, "--runs-root").required)
        self.assertIsNone(_action(parser, "--runs-root").default)
        with self.assertRaises(self.module.CanaryError):
            self.module.require_runs_root("")
        with self.assertRaises(self.module.CanaryError):
            self.module.require_runs_root(None)
        with TempRoot() as root:
            argv = _valid_argv(Path(root) / "runs")
            idx = argv.index("--runs-root")
            del argv[idx : idx + 2]
            with _ExecutionProbe(self.module) as probe:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        self.module.main(argv)
            self.assertEqual(ctx.exception.code, 2)
            self.assertEqual(probe.execute_calls, [])

    def test_22_existing_destination_directory_fails_without_modification(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            dest = runs / "canary-run-001"
            dest.mkdir(parents=True)
            marker = dest / "keep-me.txt"
            marker.write_text("untouched", encoding="utf-8")
            before = marker.read_text(encoding="utf-8")
            with _ExecutionProbe(self.module) as probe:
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 2)
            self.assertIn("already exists", err)
            self.assertEqual(probe.execute_calls, [])
            self.assertTrue(dest.is_dir())
            self.assertEqual(marker.read_text(encoding="utf-8"), before)

    def test_23_existing_destination_file_fails_without_modification(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            runs.mkdir()
            dest = runs / "canary-run-001"
            dest.write_text("do-not-replace", encoding="utf-8")
            before = dest.read_bytes()
            mode = dest.stat().st_mode
            with _ExecutionProbe(self.module) as probe:
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 2)
            self.assertIn("already exists", err)
            self.assertEqual(probe.execute_calls, [])
            self.assertTrue(dest.is_file())
            self.assertFalse(dest.is_dir())
            self.assertEqual(dest.read_bytes(), before)
            self.assertEqual(dest.stat().st_mode, mode)

    def test_24_existing_destination_symlink_fails_without_modification(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            runs.mkdir()
            target = Path(root) / "target-dir"
            target.mkdir()
            marker = target / "inside.txt"
            marker.write_text("symlink-target", encoding="utf-8")
            dest = runs / "canary-run-001"
            dest.symlink_to(target)
            self.assertTrue(dest.is_symlink())
            with _ExecutionProbe(self.module) as probe:
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 2)
            self.assertIn("already exists", err)
            self.assertEqual(probe.execute_calls, [])
            self.assertTrue(dest.is_symlink())
            self.assertEqual(dest.resolve(), target.resolve())
            self.assertEqual(marker.read_text(encoding="utf-8"), "symlink-target")

    def test_25_missing_runtime_credentials_reach_only_existing_boundary(self):
        source = CANARY_PATH.read_text(encoding="utf-8")
        self.assertNotIn(HOST_KEY, source)
        self.assertNotIn(CHILD_KEY, source)
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}:
                self.fail("canary must not read process environment")

    def test_26_missing_credentials_fail_before_provider_client_network(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            with _forbid_worker_spawn(), patch(
                "model_council.openai_adapter.build_openai_client",
                side_effect=AssertionError("client must not be built"),
            ), patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                side_effect=AssertionError("transport must not run"),
            ):
                code, out, err = _capture_main(
                    self.module, _valid_argv(runs, run_id="missing-cred-canary")
                )
            self.assertEqual(code, 1)
            self.assertIn("infrastructure_failure", out)
            self.assertIn("plumbing/integration evidence only", out)
            self.assertNotIn(SYNTHETIC_SECRET, out + err)
            dest = runs / "missing-cred-canary"
            self.assertTrue(dest.is_dir())

    def test_27_missing_credentials_produce_no_secret_output(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            with _forbid_worker_spawn():
                code, out, err = _capture_main(
                    self.module, _valid_argv(runs, run_id="missing-cred-secret")
                )
            self.assertEqual(code, 1)
            self._assert_secret_free(out, err)
            blob = ""
            dest = runs / "missing-cred-secret"
            if dest.exists():
                for path in dest.rglob("*"):
                    if path.is_file():
                        blob += path.read_text(encoding="utf-8", errors="replace")
            self._assert_secret_free(blob)
            self.assertNotIn("Traceback", out)
            self.assertNotIn("Traceback", err)

    def test_28_valid_guarded_configuration_reaches_fake_runner_without_openai_client(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            captured = {}

            def execute_fn(runner, spec, task):
                captured["runner"] = runner
                captured["spec"] = spec
                captured["task"] = task
                self.assertEqual(runner.adapter.kind, "openai_responses")
                self.assertEqual(spec.condition, Condition.A)
                self.assertEqual(task.task_id, "dev-001")
                captured["result"] = _fake_result(spec)
                return captured["result"]

            def verify_fn(_runs_root, _run_id):
                captured["verified"] = True
                return _fake_verification(captured["spec"])
            with _ExecutionProbe(
                self.module, execute=execute_fn, verify=verify_fn
            ) as probe:
                with patch(
                    "model_council.openai_adapter.build_openai_client",
                    side_effect=AssertionError("client must not be built"),
                ), patch(
                    "model_council.openai_adapter._default_openai_client_factory",
                    side_effect=AssertionError("sdk factory must not run"),
                ):
                    code, out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 0)
            self.assertEqual(len(probe.execute_calls), 1)
            self.assertEqual(captured["runner"].adapter.kind, "openai_responses")
            self.assertIn("succeeded", out)
            self.assertIn("plumbing/integration evidence only", out)
            self.assertEqual(err, "")
            self.assertFalse((runs / "canary-run-001").exists())

    def test_29_normal_success_invokes_terminal_verification(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            seen = {"verify": 0}

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, run_id):
                seen["verify"] += 1
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_SUCCEEDED,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, out, _err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 0)
            self.assertEqual(seen["verify"], 1)
            self.assertIn("terminal_verified=True", out)

    def test_30_success_requires_matching_terminal_verified_true(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, run_id):
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_SUCCEEDED,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, _err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 0)

    def test_success_gate_rejects_failed_evaluation(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec, evaluation=_fake_evaluation(False))

            def verify(_runs_root, run_id):
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_SUCCEEDED,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(
                    self.module, _valid_argv(runs)
                )
            self.assertEqual(code, 1)
            self.assertIn("terminal verification failed", err)

    def test_31_normal_terminal_non_success_still_invokes_verification(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            seen = {"verify": 0}

            def execute(_runner, spec, _task):
                return _fake_result(spec, STATUS_INFRASTRUCTURE_FAILURE)

            def verify(_runs_root, run_id):
                seen["verify"] += 1
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_INFRASTRUCTURE_FAILURE,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, out, _err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertEqual(seen["verify"], 1)
            self.assertIn("infrastructure_failure", out)

    def test_normal_negative_evaluation_is_a_verified_failed_canary(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            real_adapter = self.module.SubprocessAdapter

            def offline_adapter(identity, *, kind, options, provider_treatment_config):
                self.assertEqual(kind, self.module.ADAPTER_KIND)
                return real_adapter(
                    identity,
                    kind="fake",
                    options={
                        "identity_override": identity.to_dict(),
                        "inject_prohibited_content": True,
                    },
                    provider_treatment_config=provider_treatment_config,
                )

            with patch.object(self.module, "SubprocessAdapter", side_effect=offline_adapter):
                code, out, err = _capture_main(
                    self.module,
                    _valid_argv(runs, run_id="negative-evaluation-canary"),
                )

            self.assertEqual(code, 1)
            self.assertEqual(err, "")
            self.assertIn("terminal_status=failed_evaluation", out)
            self.assertIn("terminal_verified=True", out)

            run_dir = runs / "negative-evaluation-canary"
            payload = json.loads((run_dir / "run_result.json").read_text())
            self.assertEqual(payload["status"], STATUS_FAILED_EVALUATION)
            self.assertIsNotNone(payload["evaluation"])
            self.assertFalse(payload["evaluation"]["passed"])
            report = ArtifactStore.verify_terminal_run(
                runs, "negative-evaluation-canary"
            )
            self.assertTrue(report["terminal_verified"])
            self.assertEqual(report["terminal_status"], STATUS_FAILED_EVALUATION)

    def test_32_terminal_non_success_remains_non_success_with_nonzero_exit(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec, STATUS_INFRASTRUCTURE_FAILURE)

            def verify(_runs_root, run_id):
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_INFRASTRUCTURE_FAILURE,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, out, _err = _capture_main(self.module, _valid_argv(runs))
            self.assertNotEqual(code, 0)
            self.assertIn("infrastructure_failure", out)
            self.assertNotIn("terminal_status=succeeded", out)

    def test_33_missing_verification_result_fails_closed(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, _run_id):
                return None

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertIn("terminal verification failed", err)

    def test_34_malformed_verification_result_fails_closed(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, _run_id):
                return ["not", "a", "report"]

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertIn("terminal verification failed", err)

    def test_35_mismatched_verification_result_fails_closed(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, _run_id):
                return {
                    "run_id": "other-run",
                    "terminal_verified": True,
                    "terminal_status": STATUS_SUCCEEDED,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertIn("terminal verification failed", err)

    def test_36_terminal_verified_false_fails_closed(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec)

            def verify(_runs_root, run_id):
                return {
                    "run_id": run_id,
                    "terminal_verified": False,
                    "terminal_status": STATUS_SUCCEEDED,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertIn("terminal verification failed", err)

    def test_terminal_status_mismatch_fails_closed(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, spec, _task):
                return _fake_result(spec, STATUS_SUCCEEDED)

            def verify(_runs_root, run_id):
                return {
                    "run_id": run_id,
                    "terminal_verified": True,
                    "terminal_status": STATUS_INFRASTRUCTURE_FAILURE,
                }

            with _ExecutionProbe(self.module, execute=execute, verify=verify):
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertEqual(
                err, "canary rejected: terminal verification failed\n"
            )

    def test_37_synthetic_secret_bearing_exception_is_neither_printed_nor_persisted(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"

            def execute(_runner, _spec, _task):
                raise RuntimeError(
                    f"Authorization: Bearer {SYNTHETIC_SECRET} {HOST_KEY}=leak"
                )

            with _ExecutionProbe(self.module, execute=execute, verify=lambda *_: {}):
                code, out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 1)
            self.assertIn("sanitized infrastructure failure", err)
            self._assert_secret_free(out, err)
            self.assertNotIn("RuntimeError", out)
            self.assertNotIn("RuntimeError", err)
            self.assertNotIn("Traceback", out)
            self.assertNotIn("Traceback", err)
            self.assertFalse((runs / "canary-run-001").exists())
            if runs.exists():
                for path in runs.rglob("*"):
                    if path.is_file():
                        self._assert_secret_free(
                            path.read_text(encoding="utf-8", errors="replace")
                        )

    def test_38_no_test_invokes_real_network_credentials_or_spend(self):
        self.assertNotIn(HOST_KEY, os.environ)
        self.assertNotIn(CHILD_KEY, os.environ)
        source = CANARY_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name, "openai")
                    self.assertFalse(alias.name.startswith("openai."))
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotEqual(node.module, "openai")
                self.assertFalse(node.module.startswith("openai."))
        self.assertNotIn("openai_responses_skeleton", source)
        self.assertNotIn("socket", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("httpx", source)
        self.assertNotIn("requests", source)

    def test_parser_has_no_credential_budget_or_task_options(self):
        parser = self.module.build_parser()
        options = set(parser._option_string_actions)
        for forbidden in (
            "--task",
            "--api-key",
            "--openai-api-key",
            "--budget",
            "--dollar-budget",
            "--condition",
            "--adapter",
            "--tools",
            "--max-retries",
            "--service-tier",
            "--store",
        ):
            self.assertNotIn(forbidden, options)

    def test_accepted_treatment_arguments_are_closed_and_optional(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            args = self.module.parse_args(
                _flatten_with_extra(
                    _valid_argv(runs),
                    [
                        "--reasoning-effort",
                        "low",
                        "--reasoning-summary",
                        "concise",
                        "--text-verbosity",
                        "low",
                    ],
                )
            )
            plan = self.module.prepare_canary(args)
        self.assertEqual(
            dict(plan.provider_treatment_config),
            {
                "reasoning": {"effort": "low", "summary": "concise"},
                "text": {"verbosity": "low"},
            },
        )

    def test_dangling_symlink_destination_is_rejected(self):
        with TempRoot() as root:
            runs = Path(root) / "runs"
            runs.mkdir()
            dest = runs / "canary-run-001"
            dest.symlink_to(Path(root) / "missing-target")
            self.assertTrue(dest.is_symlink())
            self.assertFalse(dest.exists())
            self.assertTrue(os.path.lexists(dest))
            with _ExecutionProbe(self.module) as probe:
                code, _out, err = _capture_main(self.module, _valid_argv(runs))
            self.assertEqual(code, 2)
            self.assertIn("already exists", err)
            self.assertEqual(probe.execute_calls, [])
            self.assertTrue(dest.is_symlink())
            self.assertEqual(os.readlink(dest), str(Path(root) / "missing-target"))

    def test_help_and_import_do_not_touch_artifact_store(self):
        with patch.object(
            self.module.ArtifactStore,
            "__init__",
            side_effect=AssertionError("ArtifactStore must not construct"),
        ):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.module.main(["--help"])


if __name__ == "__main__":
    unittest.main()
