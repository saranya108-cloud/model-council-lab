#!/usr/bin/env python3
"""Guarded development-only OpenAI Condition A canary.

Plumbing/integration infrastructure only. Implementing this entrypoint does
not authorize executing a real provider call. Any real invocation requires
later explicit Human Chair authorization. A canary is not evidence of repair,
benchmark, tool-use, council, held-out, or broader M1-hypothesis performance.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

_SRC = Path(__file__).resolve().parents[2] / "src"
_SRC_STR = str(_SRC)
if _SRC_STR not in sys.path:
    sys.path.insert(0, _SRC_STR)

from model_council import (  # noqa: E402
    STATUS_SUCCEEDED,
    AdapterIdentity,
    ArtifactStore,
    Condition,
    EvaluationConfig,
    ExperimentRunner,
    ExternalEvaluator,
    ResourceLimits,
    RunResult,
    RunSpec,
    SubprocessAdapter,
    TaskSpec,
)
from model_council.openai_adapter import validate_openai_provider_treatment  # noqa: E402
from model_council.roles import CONDITION_STAGES, ROLE_SOLVER  # noqa: E402
from model_council.security import safe_identifier  # noqa: E402

ACKNOWLEDGEMENT = "NETWORK_CREDENTIALS_AND_PAID_CAPACITY"
ADAPTER_KIND = "openai_responses"
ADAPTER_PROVIDER = "openai"
ADAPTER_NAME = "openai_responses"
ADAPTER_VERSION = "v0"
CANARY_CONDITION = Condition.A
PROMPT_VERSION = "prompts-dev-v0"
CANARY_SEED = 0
MAX_INPUT_TOKENS_PER_STAGE = 4096
MAX_OUTPUT_TOKENS_PER_STAGE = 1024
MAX_STAGE_TIMEOUT_SECONDS = 60.0
DEVELOPMENT_TASK_PATH = Path(__file__).resolve().parent / "tasks" / "task_dev_001.json"
PLUMBING_STATEMENT = (
    "This is plumbing/integration evidence only; it is not repair, benchmark, "
    "tool-use, council, held-out, or M1-hypothesis performance evidence."
)
_REASONING_EFFORT_CHOICES = ("none", "low", "medium", "high", "xhigh", "max")
_REASONING_SUMMARY_CHOICES = ("auto", "concise", "detailed")
_TEXT_VERBOSITY_CHOICES = ("low", "medium", "high")
_TOKEN_PATTERN = re.compile(r"^[0-9]+$")
_TIMEOUT_PATTERN = re.compile(r"^[0-9]+(\.[0-9]+)?$")


class CanaryError(Exception):
    """Secret-free operator guard failure. Never include credentials or provider text."""


@dataclass(frozen=True)
class CanaryPlan:
    task: TaskSpec
    identity: AdapterIdentity
    run_spec: RunSpec
    runs_root: Path
    destination: Path
    provider_treatment_config: Mapping[str, Any]
    evaluation_config: EvaluationConfig
    adapter_kind: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_openai_canary.py",
        description=(
            "Guarded development-only OpenAI Condition A canary. "
            "Plumbing/integration evidence only. Implementing this entrypoint "
            "does not authorize executing a real provider call."
        ),
        allow_abbrev=False,
    )
    parser.add_argument(
        "--acknowledge",
        required=True,
        default=None,
        help="must equal NETWORK_CREDENTIALS_AND_PAID_CAPACITY",
    )
    parser.add_argument("--model-id", required=True, default=None)
    parser.add_argument(
        "--model-version",
        required=True,
        default=None,
        help="model-version / identity label required for AdapterIdentity",
    )
    parser.add_argument("--run-id", required=True, default=None)
    parser.add_argument("--runs-root", required=True, default=None)
    parser.add_argument("--max-input-tokens", required=True, default=None)
    parser.add_argument("--max-output-tokens", required=True, default=None)
    parser.add_argument("--stage-timeout-seconds", required=True, default=None)
    parser.add_argument("--reasoning-effort", choices=_REASONING_EFFORT_CHOICES, default=None)
    parser.add_argument("--reasoning-summary", choices=_REASONING_SUMMARY_CHOICES, default=None)
    parser.add_argument("--text-verbosity", choices=_TEXT_VERBOSITY_CHOICES, default=None)
    return parser


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def require_acknowledgement(value: object) -> str:
    if type(value) is not str or value != ACKNOWLEDGEMENT:
        raise CanaryError("acknowledgement is missing or incorrect")
    return value


def load_development_task() -> TaskSpec:
    path = DEVELOPMENT_TASK_PATH
    if path.name != "task_dev_001.json":
        raise CanaryError("canary task is not the fixed development fixture")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CanaryError("development task fixture is unreadable") from None
    if type(payload) is not dict:
        raise CanaryError("development task fixture is malformed")
    metadata = payload.get("metadata")
    if type(metadata) is not dict:
        raise CanaryError("development task fixture metadata is missing")
    if metadata.get("development_only") is not True:
        raise CanaryError("development task is not marked development_only")
    if metadata.get("excluded_from_heldout") is not True:
        raise CanaryError("development task is not excluded from held-out evaluation")
    try:
        return TaskSpec(
            task_id=payload["task_id"],
            bug_report=payload["bug_report"],
            workspace_id=payload["workspace_id"],
            allowed_files=tuple(payload["allowed_files"]),
            visible_test_command=payload.get("visible_test_command"),
            metadata=metadata,
        )
    except Exception:
        raise CanaryError("development task fixture is malformed") from None


def require_condition_a() -> Condition:
    if CANARY_CONDITION is not Condition.A:
        raise CanaryError("canary condition must be A")
    stages = CONDITION_STAGES[CANARY_CONDITION]
    if stages != (ROLE_SOLVER,):
        raise CanaryError("canary must use exactly one solver stage")
    return CANARY_CONDITION


def require_model_identity_parts(model_id: object, model_version: object) -> tuple[str, str]:
    if type(model_id) is not str or model_id == "" or model_id.strip() != model_id:
        raise CanaryError("model id must be an explicit caller-supplied string")
    if type(model_version) is not str or model_version == "" or model_version.strip() != model_version:
        raise CanaryError("model version must be an explicit caller-supplied string")
    return model_id, model_version


def build_adapter_identity(model_id: str, model_version: str) -> AdapterIdentity:
    identity = AdapterIdentity(
        provider=ADAPTER_PROVIDER,
        model_id=model_id,
        model_version=model_version,
        adapter_name=ADAPTER_NAME,
        adapter_version=ADAPTER_VERSION,
    )
    if identity.adapter_name != ADAPTER_KIND:
        raise CanaryError("canary adapter identity is invalid")
    return identity


def require_run_id(value: object) -> str:
    try:
        return safe_identifier(value, "run_id")
    except Exception:
        raise CanaryError("run id is unsafe") from None


def require_runs_root(value: object) -> Path:
    if isinstance(value, Path):
        if str(value) == "":
            raise CanaryError("output location is missing")
        return value
    if type(value) is not str or value == "":
        raise CanaryError("output location is missing")
    return Path(value)


def require_token_ceiling(value: object, *, name: str, maximum: int) -> int:
    if type(value) is bool:
        raise CanaryError(f"{name} must not be a boolean")
    if type(value) is int:
        number = value
    elif type(value) is str:
        if _TOKEN_PATTERN.fullmatch(value) is None:
            raise CanaryError(f"{name} is malformed")
        number = int(value)
    else:
        raise CanaryError(f"{name} is malformed")
    if number <= 0:
        raise CanaryError(f"{name} must be positive")
    if number > maximum:
        raise CanaryError(f"{name} exceeds the permitted maximum")
    return number


def require_stage_timeout(value: object) -> float:
    if type(value) is bool:
        raise CanaryError("stage timeout must not be a boolean")
    if type(value) is int or type(value) is float:
        number = float(value)
    elif type(value) is str:
        if _TIMEOUT_PATTERN.fullmatch(value) is None:
            raise CanaryError("stage timeout is malformed")
        number = float(value)
    else:
        raise CanaryError("stage timeout is malformed")
    if number != number or number in (float("inf"), float("-inf")):
        raise CanaryError("stage timeout must be finite")
    if number <= 0:
        raise CanaryError("stage timeout must be positive")
    if number > MAX_STAGE_TIMEOUT_SECONDS:
        raise CanaryError("stage timeout exceeds the permitted maximum")
    return number


def build_resource_limits(
    max_input_tokens: int, max_output_tokens: int, timeout_seconds: float
) -> ResourceLimits:
    limits = ResourceLimits(
        max_input_tokens_per_stage=max_input_tokens,
        max_output_tokens_per_stage=max_output_tokens,
        max_tool_calls_per_stage=0,
        stage_timeout_seconds=timeout_seconds,
        max_stage_retries=0,
    )
    if limits.max_tool_calls_per_stage != 0 or limits.max_stage_retries != 0:
        raise CanaryError("canary resource limits must disable tools and retries")
    return limits


def build_provider_treatment(
    *,
    reasoning_effort: str | None = None,
    reasoning_summary: str | None = None,
    text_verbosity: str | None = None,
) -> dict[str, Any]:
    treatment: dict[str, Any] = {}
    reasoning: dict[str, str] = {}
    if reasoning_effort is not None:
        reasoning["effort"] = reasoning_effort
    if reasoning_summary is not None:
        reasoning["summary"] = reasoning_summary
    if reasoning:
        treatment["reasoning"] = reasoning
    if text_verbosity is not None:
        treatment["text"] = {"verbosity": text_verbosity}
    return treatment


def require_treatment_configuration(treatment: object) -> dict[str, Any]:
    try:
        return validate_openai_provider_treatment(treatment)
    except Exception:
        raise CanaryError("provider treatment is unsupported") from None


def require_destination_absent(runs_root: Path, run_id: str) -> Path:
    destination = Path(runs_root) / run_id
    try:
        destination.lstat()
    except FileNotFoundError:
        return destination
    except OSError:
        raise CanaryError("canary destination is not available") from None
    raise CanaryError("canary destination already exists")


def build_evaluation_config() -> EvaluationConfig:
    return EvaluationConfig(
        required_markers=(),
        prohibited_markers=("MODIFIED_HIDDEN_TESTS",),
        metadata={
            "development_only": True,
            "excluded_from_heldout": True,
            "quality_claim": False,
            "benchmark_claim": False,
            "purpose": "openai_canary_plumbing",
        },
    )


def prepare_canary(args: argparse.Namespace) -> CanaryPlan:
    require_acknowledgement(args.acknowledge)
    task = load_development_task()
    condition = require_condition_a()
    model_id, model_version = require_model_identity_parts(args.model_id, args.model_version)
    identity = build_adapter_identity(model_id, model_version)
    run_id = require_run_id(args.run_id)
    runs_root = require_runs_root(args.runs_root)
    max_input = require_token_ceiling(
        args.max_input_tokens,
        name="max input tokens",
        maximum=MAX_INPUT_TOKENS_PER_STAGE,
    )
    max_output = require_token_ceiling(
        args.max_output_tokens,
        name="max output tokens",
        maximum=MAX_OUTPUT_TOKENS_PER_STAGE,
    )
    timeout = require_stage_timeout(args.stage_timeout_seconds)
    limits = build_resource_limits(max_input, max_output, timeout)
    treatment = require_treatment_configuration(
        build_provider_treatment(
            reasoning_effort=args.reasoning_effort,
            reasoning_summary=args.reasoning_summary,
            text_verbosity=args.text_verbosity,
        )
    )
    destination = require_destination_absent(runs_root, run_id)
    run_spec = RunSpec(
        run_id=run_id,
        task_id=task.task_id,
        condition=condition,
        model_identifier=identity.key(),
        prompt_version=PROMPT_VERSION,
        resource_limits=limits,
        seed=CANARY_SEED,
        metadata={
            "development_only": True,
            "excluded_from_heldout": True,
            "plumbing_evidence_only": True,
        },
    )
    return CanaryPlan(
        task=task,
        identity=identity,
        run_spec=run_spec,
        runs_root=runs_root,
        destination=destination,
        provider_treatment_config=treatment,
        evaluation_config=build_evaluation_config(),
        adapter_kind=ADAPTER_KIND,
    )


def execute_prepared_canary(plan: CanaryPlan) -> tuple[RunResult, object, Path]:
    adapter = SubprocessAdapter(
        plan.identity,
        kind=ADAPTER_KIND,
        options={},
        provider_treatment_config=dict(plan.provider_treatment_config),
    )
    runner = ExperimentRunner(
        adapter,
        ExternalEvaluator(plan.evaluation_config),
        runs_root=plan.runs_root,
    )
    result = runner.execute(plan.run_spec, plan.task)
    verification = ArtifactStore.verify_terminal_run(plan.runs_root, plan.run_spec.run_id)
    return result, verification, plan.destination


def accept_terminal_verification(
    plan: CanaryPlan, result: RunResult, verification: object
) -> None:
    if verification is None:
        raise CanaryError("terminal verification result is missing")
    if type(verification) is not dict:
        raise CanaryError("terminal verification result is malformed")
    if verification.get("run_id") != plan.run_spec.run_id:
        raise CanaryError("terminal verification run id mismatch")
    if verification.get("terminal_status") != result.status:
        raise CanaryError("terminal verification status mismatch")
    if verification.get("terminal_verified") is not True:
        raise CanaryError("terminal verification did not confirm the run")
    if result.status == STATUS_SUCCEEDED:
        evaluation = result.evaluation
        if getattr(evaluation, "passed", None) is not True:
            raise CanaryError("configured evaluation did not pass")


def operator_summary(plan: CanaryPlan, result: RunResult, verification: object) -> str:
    terminal_verified = None
    if type(verification) is dict:
        terminal_verified = verification.get("terminal_verified")
    return "\n".join(
        (
            f"run_id={plan.run_spec.run_id}",
            f"terminal_status={result.status}",
            f"run_directory={plan.destination}",
            f"terminal_verified={terminal_verified}",
            PLUMBING_STATEMENT,
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        plan = prepare_canary(args)
        result, verification, _destination = execute_prepared_canary(plan)
    except CanaryError as exc:
        print(f"canary rejected: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        raise
    except Exception:
        print("canary failed: sanitized infrastructure failure", file=sys.stderr)
        return 1
    verification_ok = True
    try:
        accept_terminal_verification(plan, result, verification)
    except CanaryError:
        verification_ok = False
        print("canary rejected: terminal verification failed", file=sys.stderr)
    print(operator_summary(plan, result, verification))
    if not verification_ok:
        return 1
    if result.status != STATUS_SUCCEEDED:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
