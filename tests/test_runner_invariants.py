"""Checkpoint 3: input preflight, cumulative stage deadline, stable retry treatment."""

from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council.roles import ROLE_INSTRUCTIONS
from model_council.runner import _estimate_tokens_in
from model_council.security import digest_json
from model_council.types import ModelFailure, ResourceLimits, StageTimeout

from helpers import (
    IDENTITY_KEY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
    transient_failure_options,
)


class ControllableClock:
    def __init__(self, start=1_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


class JumpAfterFirstRead:
    """Establish a deadline, then report that it is already exhausted."""

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

    return calls, invoke, original


def _treatment_payload(kwargs, identity_key=IDENTITY_KEY):
    budget = kwargs["budget"]
    return {
        "seed": kwargs["seed"],
        "role_instruction": kwargs["role_instruction"],
        "stage_inputs": dict(kwargs["stage_inputs"]),
        "resource_limits": budget.to_dict(),
        "configured_identity": identity_key,
        "max_output_tokens_per_stage": budget.max_output_tokens_per_stage,
        "max_tool_calls_per_stage": budget.max_tool_calls_per_stage,
    }


class TestInputPreflight(unittest.TestCase):
    def test_input_already_over_ceiling_makes_zero_adapter_calls(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            calls, invoke, _ = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("pre-over-in", "A", max_input_tokens_per_stage=5),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")
            self.assertEqual(len(calls), 0)
            self.assertIsNone(result.final_candidate_ref)
            self.assertFalse((runs_root / "pre-over-in" / "seals" / "solver.json").exists())
            self.assertFalse((runs_root / "pre-over-in" / "solver" / "candidate.md").exists())
            payload = json.loads((runs_root / "pre-over-in" / "run_result.json").read_text())
            self.assertEqual(payload["status"], "failed_budget")
            self.assertIn("input budget exceeded", result.stage_results[0].error)

    def test_retry_would_exceed_cumulative_input_ceiling(self):
        with TempRoot() as root:
            task = make_task()
            estimated_in = _estimate_tokens_in(
                ROLE_INSTRUCTIONS["solver"], {"task": task.agent_visible_text()}
            )
            ceiling = estimated_in + estimated_in // 2
            self.assertGreater(2 * estimated_in, ceiling)
            runner, runs_root = make_runner(
                root,
                options=transient_failure_options(root),
            )
            calls, invoke, _ = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "pre-cum-in",
                        "A",
                        seed=7,
                        max_input_tokens_per_stage=ceiling,
                        max_stage_retries=2,
                    ),
                    task,
                )
            self.assertEqual(result.status, "failed_budget")
            self.assertEqual(len(calls), 1)
            self.assertIn("input budget exceeded", result.stage_results[0].error)
            self.assertEqual(
                result.stage_results[0].usage_estimated["cumulative_tokens_in"],
                estimated_in,
            )
            first = json.loads(
                (
                    runs_root / "pre-cum-in" / "invocations" / "solver"
                    / "attempt-0001" / "invocation.json"
                ).read_text()
            )
            blocked = json.loads(
                (
                    runs_root / "pre-cum-in" / "invocations" / "solver"
                    / "attempt-0002" / "invocation.json"
                ).read_text()
            )
            self.assertTrue(first["invocation_began"])
            self.assertFalse(blocked["invocation_began"])
            self.assertEqual(first["consumed_tokens_in"], estimated_in)
            self.assertEqual(blocked["consumed_tokens_in"], 0)
            self.assertEqual(blocked["projected_tokens_in"], estimated_in)
            self.assertEqual(blocked["cumulative_tokens_in"], estimated_in)

    def test_preflight_budget_failure_does_not_create_successful_artifacts(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(
                make_spec("pre-no-success", "C", max_input_tokens_per_stage=8),
                make_task(),
            )
            self.assertEqual(result.status, "failed_budget")
            self.assertEqual([s.status.value for s in result.stage_results], ["failed"])
            self.assertIsNone(result.evaluation)
            run_dir = runs_root / "pre-no-success"
            self.assertFalse((run_dir / "seals" / "solver.json").exists())
            self.assertFalse((run_dir / "solver" / "candidate.md").exists())
            self.assertIsNone(result.final_candidate_ref)

    def test_output_budget_still_enforced_after_invocation(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            calls, invoke, _ = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("post-out", "A", max_output_tokens_per_stage=1),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")
            self.assertGreaterEqual(len(calls), 1)
            self.assertIn("output budget exceeded", result.stage_results[0].error)

    def test_tool_budget_still_enforced_after_invocation(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options={"tool_uses": 3})
            calls, invoke, _ = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec("post-tool", "A", max_tool_calls_per_stage=0),
                    make_task(),
                )
            self.assertEqual(result.status, "failed_budget")
            self.assertEqual(len(calls), 1)
            self.assertIn("tool-call budget exceeded", result.stage_results[0].error)


class TestRetryTreatmentStability(unittest.TestCase):
    def test_retries_keep_identical_seed_and_treatment(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options=transient_failure_options(root))
            calls, invoke, _ = _count_invokes(runner)
            spec = make_spec("treat-1", "A", seed=7)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(spec, make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(result.retries_used, 1)
            self.assertGreaterEqual(len(calls), 2)
            treatments = [_treatment_payload(call) for call in calls]
            self.assertEqual(treatments[0], treatments[1])
            self.assertEqual({call["seed"] for call in calls}, {spec.seed})
            self.assertNotIn("attempt", calls[0])
            digests = [digest_json(payload) for payload in treatments]
            self.assertEqual(digests[0], digests[1])
            serialized = [
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
                for payload in treatments
            ]
            self.assertEqual(serialized[0], serialized[1])
            # Remaining timeout is enforcement metadata, not treatment.
            self.assertIn("timeout_seconds", calls[0])
            self.assertIn("timeout_seconds", calls[1])

    def test_redesigned_transient_fake_does_not_change_seed(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, options=transient_failure_options(root))
            seeds = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                seeds.append(kwargs["seed"])
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(make_spec("treat-2", "A", seed=11), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(seeds, [11, 11])

    def test_production_adapter_call_has_no_attempt_parameter(self):
        import inspect

        from model_council.adapters import REGISTRY, fake_generate
        from model_council import worker as worker_mod

        self.assertNotIn("attempt", inspect.signature(fake_generate).parameters)
        for name, fn in REGISTRY.items():
            self.assertNotIn("attempt", inspect.signature(fn).parameters, name)
        source = inspect.getsource(worker_mod)
        self.assertNotIn('request["attempt"]', source)
        self.assertIn('request["seed"]', source)


class TestCumulativeStageDeadline(unittest.TestCase):
    def test_single_attempt_receives_no_more_than_remaining_deadline(self):
        clock = ControllableClock(5_000.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            granted = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                granted.append(kwargs["timeout_seconds"])
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "dl-single",
                        "A",
                        stage_timeout_seconds=1.5,
                        max_stage_retries=0,
                    ),
                    make_task(),
                )
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(granted), 1)
            self.assertLessEqual(granted[0], 1.5)
            self.assertGreater(granted[0], 0)

    def test_retry_receives_residual_time_not_fresh_timeout(self):
        clock = ControllableClock(2_000.0)
        stage_timeout = 1.0
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            granted = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                granted.append(kwargs["timeout_seconds"])
                clock.advance(0.4)
                if len(granted) == 1:
                    raise StageTimeout("simulated first-attempt timeout")
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "dl-retry",
                        "A",
                        stage_timeout_seconds=stage_timeout,
                        max_stage_retries=1,
                    ),
                    make_task(),
                )
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(len(granted), 2)
            self.assertLessEqual(granted[0], stage_timeout)
            self.assertLess(granted[1], granted[0])
            self.assertLess(granted[1], stage_timeout)
            self.assertNotEqual(granted[1], stage_timeout)
            self.assertAlmostEqual(granted[1], stage_timeout - 0.4, places=6)

    def test_fresh_timeout_regression_fails_if_attempt_2_gets_full_budget(self):
        clock = ControllableClock(3_000.0)
        stage_timeout = 2.0
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            granted = []
            original = runner.adapter.invoke

            def invoke(**kwargs):
                granted.append(kwargs["timeout_seconds"])
                clock.advance(0.75)
                if len(granted) == 1:
                    raise ModelFailure("transient")
                return original(**kwargs)

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                runner.execute(
                    make_spec(
                        "dl-fresh",
                        "A",
                        stage_timeout_seconds=stage_timeout,
                        max_stage_retries=1,
                    ),
                    make_task(),
                )
            self.assertEqual(len(granted), 2)
            self.assertNotAlmostEqual(granted[1], stage_timeout, places=3)
            self.assertLess(granted[1], granted[0])

    def test_exhausted_deadline_makes_zero_adapter_calls(self):
        clock = JumpAfterFirstRead(start=4_000.0, jump=5.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            calls, invoke, _ = _count_invokes(runner)
            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "dl-exhausted",
                        "A",
                        stage_timeout_seconds=1.0,
                        max_stage_retries=1,
                    ),
                    make_task(),
                )
            self.assertEqual(len(calls), 0)
            self.assertEqual(result.status, "retry_exhausted")
            self.assertIn("timeout", result.stage_results[0].error)
            self.assertIsNone(result.final_candidate_ref)
            payload = json.loads(
                (Path(root) / "runs" / "dl-exhausted" / "run_result.json").read_text()
            )
            self.assertEqual(payload["status"], "retry_exhausted")

    def test_timeout_plus_retry_exhaustion_records_no_success(self):
        clock = ControllableClock(6_000.0)
        with TempRoot() as root:
            runner, _ = make_runner(root, monotonic=clock)
            granted = []

            def invoke(**kwargs):
                granted.append(kwargs["timeout_seconds"])
                clock.advance(kwargs["timeout_seconds"] + 0.01)
                raise StageTimeout("simulated timeout")

            with patch.object(runner.adapter, "invoke", side_effect=invoke):
                result = runner.execute(
                    make_spec(
                        "dl-exh-retry",
                        "A",
                        stage_timeout_seconds=0.8,
                        max_stage_retries=2,
                    ),
                    make_task(),
                )
            self.assertEqual(result.status, "retry_exhausted")
            self.assertTrue(granted)
            self.assertLessEqual(sum(granted), 0.8 + 1e-9)
            self.assertIsNone(result.evaluation)
            self.assertEqual([s.status.value for s in result.stage_results], ["retry_exhausted"])

    def test_executor_cannot_enlarge_runner_deadline(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            captured = {}

            def fake_run(*args, **kwargs):
                captured["timeout"] = kwargs["timeout"]
                raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

            with patch("model_council.executor.subprocess.run", side_effect=fake_run):
                with self.assertRaises(StageTimeout):
                    runner.adapter.invoke(
                        role_instruction="role:solver x",
                        stage_inputs={"task": "t"},
                        budget=ResourceLimits(stage_timeout_seconds=1.0),
                        seed=0,
                        timeout_seconds=99.0,
                    )
            self.assertEqual(captured["timeout"], 1.0)
            self.assertEqual(runner.adapter.last_attempt_timeout_seconds, 1.0)

    def test_subprocess_receives_runner_remaining_timeout_not_declared_budget(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            captured = {}

            def fake_run(*args, **kwargs):
                captured["timeout"] = kwargs["timeout"]
                raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs["timeout"])

            with patch("model_council.executor.subprocess.run", side_effect=fake_run):
                with self.assertRaises(StageTimeout):
                    runner.adapter.invoke(
                        role_instruction="role:solver x",
                        stage_inputs={"task": "t"},
                        budget=ResourceLimits(stage_timeout_seconds=60.0),
                        seed=0,
                        timeout_seconds=0.25,
                    )
            self.assertEqual(captured["timeout"], 0.25)
            request = runner.adapter.last_request
            self.assertEqual(request["budget"]["stage_timeout_seconds"], 60.0)
            self.assertEqual(request["seed"], 0)
            self.assertNotIn("timeout_seconds", request)
            self.assertNotIn("attempt", request)

    def test_zero_remaining_timeout_does_not_spawn_child(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(StageTimeout):
                    runner.adapter.invoke(
                        role_instruction="role:solver x",
                        stage_inputs={"task": "t"},
                        budget=ResourceLimits(stage_timeout_seconds=1.0),
                        seed=0,
                        timeout_seconds=0.0,
                    )
            mocked.assert_not_called()


class TestExistingTimeoutPath(unittest.TestCase):
    def test_sleeping_adapter_still_retry_exhausted(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="sleep", options={"seconds": 15})
            result = runner.execute(
                make_spec("inv-sleep", "A", stage_timeout_seconds=0.4, max_stage_retries=0),
                make_task(),
            )
            self.assertEqual(result.status, "retry_exhausted")
            self.assertIn("timeout", result.stage_results[0].error)


if __name__ == "__main__":
    unittest.main()
