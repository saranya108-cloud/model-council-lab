"""Separate, fixed Luna Condition B plumbing canary; no quality claims.

Inspect without credentials or writes:
  .venv/bin/python -B experiments/development/run_openai_condition_b_canary.py \
      --runs-root runs --run-id <fresh-approved-id>

Only after explicit live authorization, append --execute and
--acknowledge NETWORK_CREDENTIALS_AND_PAID_CAPACITY. There are no model,
condition, treatment, budget, retry, or recovery overrides. Each invocation
executes one run at most. Never repeat an ambiguous request under another ID.
Evidence remains in <runs-root>/<run-id>; this launcher never repairs it.

F5 remains open: missing evidence cannot establish absence of dispatch.
F6 remains open: all existing response materialization ceilings are unchanged.
The 2048 input ceiling is harness-estimated, not provider-tokenizer parity.
"""

from __future__ import annotations

import sys

# Dry inspection must not create import caches even if the caller omits -B.
sys.dont_write_bytecode = True

import argparse
import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Reuse only condition-independent helpers; the validated A flow is untouched.
from experiments.development.run_openai_canary import (  # noqa: E402
    ACKNOWLEDGEMENT,
    CanaryError,
    CanaryPlan,
    accept_terminal_verification,
    build_adapter_identity,
    build_evaluation_config,
    load_development_task,
    require_acknowledgement,
    require_destination_absent,
    require_run_id,
)
from model_council import (  # noqa: E402
    ArtifactStore, Condition, ExperimentRunner, ExternalEvaluator,
    ResourceLimits, RunSpec, SubprocessAdapter,
)
from model_council.protocol import HARNESS_PROTOCOL_VERSION  # noqa: E402
from model_council.roles import (  # noqa: E402
    CONDITION_STAGES, ROLE_DRAFT, ROLE_SELF_REVIEW, ROLE_REVISER,
)

STAGES = (ROLE_DRAFT, ROLE_SELF_REVIEW, ROLE_REVISER)
MODEL = "gpt-5.6-luna"
INCONCLUSIVE = "CONDITION B LIVE INCONCLUSIVE — DO NOT AUTOMATICALLY RERUN"
FAIL = "CONDITION B LIVE FAIL — DEFINITIVE RESULT, NO RERUN PERFORMED"
PASS = "CONDITION B LIVE PASS — THREE-STAGE PATH VALIDATED"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Condition B only: Luna draft -> self_review -> reviser. "
        "Default is read-only preflight; live execution requires separate authorization.",
        allow_abbrev=False,
    )
    parser.add_argument("--run-id", required=True, help="fresh, explicitly selected run ID; never reused")
    parser.add_argument("--runs-root", required=True, help="artifact root inside this repository")
    parser.add_argument("--execute", action="store_true", help="execute once, only with live authorization")
    parser.add_argument("--acknowledge", help=f"live execution requires {ACKNOWLEDGEMENT}")
    return parser


def require_repository_venv() -> str:
    """Check prefix AND lexical executable location; symlinks alone prove too little."""
    venv = REPO_ROOT / ".venv"
    executable = Path(sys.executable).absolute()
    if (
        Path(sys.prefix).resolve() != venv.resolve()
        or sys.prefix == sys.base_prefix
        or executable.parent.resolve() != (venv / "bin").resolve()
        or not (venv / "bin/python").is_file()
        or not os.access(venv / "bin/python", os.X_OK)
        or not executable.is_file()
        or not os.access(executable, os.X_OK)
    ):
        raise CanaryError("repository .venv interpreter is required")
    return sys.executable


def _prepare(run_id: str, runs_root: str | Path) -> CanaryPlan:
    require_repository_venv()
    if CONDITION_STAGES.get(Condition.B) != ("draft", "self_review", "reviser") or STAGES != (
        "draft", "self_review", "reviser"
    ):
        raise CanaryError("Condition B requires exactly draft, self_review, reviser in order")
    if HARNESS_PROTOCOL_VERSION != "m1-dev-harness-v14":
        raise CanaryError("reviewed v14 harness is required")
    run_id = require_run_id(run_id)
    root = Path(runs_root).resolve()
    if root == REPO_ROOT.resolve() or not root.is_relative_to(REPO_ROOT.resolve()):
        raise CanaryError("runs root must be a directory below this repository")
    destination = require_destination_absent(root, run_id)
    task = load_development_task()
    identity = build_adapter_identity(MODEL, MODEL)
    spec = RunSpec(
        run_id=run_id, task_id=task.task_id, condition=Condition.B,
        model_identifier=identity.key(), prompt_version="prompts-dev-v0", seed=0,
        resource_limits=ResourceLimits(
            max_input_tokens_per_stage=2048, max_output_tokens_per_stage=1024,
            stage_timeout_seconds=30.0, max_tool_calls_per_stage=0, max_stage_retries=0,
        ),
        metadata={"development_only": True, "excluded_from_heldout": True,
                  "plumbing_evidence_only": True},
    )
    return CanaryPlan(
        task=task, identity=identity, run_spec=spec, runs_root=root,
        destination=destination, provider_treatment_config=MappingProxyType({}),
        evaluation_config=build_evaluation_config(), adapter_kind="openai_responses",
    )


def prepare_canary(args: argparse.Namespace) -> CanaryPlan:
    if args.execute:
        require_acknowledgement(args.acknowledge)
    return _prepare(args.run_id, args.runs_root)


def execute_prepared_canary(plan: CanaryPlan, *, acknowledge: str):
    """One runner call; recheck every prepared field before constructing the adapter."""
    require_acknowledgement(acknowledge)
    if type(plan) is not CanaryPlan:
        raise CanaryError("invalid Condition B plan")
    expected = _prepare(plan.run_spec.run_id, plan.runs_root)
    if plan != expected:
        raise CanaryError("Condition B plan differs from the fixed configuration")
    adapter = SubprocessAdapter(
        plan.identity, kind="openai_responses", python_executable=sys.executable,
        options={}, provider_treatment_config={},
    )
    runner = ExperimentRunner(adapter, ExternalEvaluator(plan.evaluation_config), runs_root=plan.runs_root)
    return runner.execute(plan.run_spec, plan.task)


def evidence_summary(plan: CanaryPlan, *, interrupted: bool = False) -> dict:
    """Report verified records, never infer processing from configured identity or gaps.

    This is conservative operator reporting, not F5 dispatch reconstruction.
    It runs only after execution; it cannot authorize any further attempt.
    """
    verification = ArtifactStore.verify_terminal_run(plan.runs_root, plan.run_spec.run_id)
    terminal = json.loads((plan.destination / "run_result.json").read_text())
    binding_path = plan.destination / "execution_binding.json"
    binding = json.loads(binding_path.read_text()) if binding_path.is_file() else {}
    wire = (binding.get("provider_identity_policy") or {}).get("wire_model")
    rows = []
    ambiguous = interrupted or terminal["status"] in {"infrastructure_failure", "retry_exhausted"}
    fields = ("input_tokens", "output_tokens", "total_tokens", "reasoning_tokens", "cached_input_tokens")
    for role in STAGES:
        records = sorted((plan.destination / "invocations" / role).glob("attempt-*/invocation.json"))
        if len(records) > 1:
            raise CanaryError("Condition B attempt ceiling violated")
        record = json.loads(records[0].read_text()) if records else {}
        outcome = (record.get("adapter_evidence") or {}).get("provider_call_outcome") or {}
        response_id = (outcome.get("provider_response_id") or {}).get("value")
        request_id = (outcome.get("provider_request_id") or {}).get("value")
        response_status = (outcome.get("provider_response_status") or {}).get("value")
        began = record.get("invocation_began")
        response_observed = bool(response_id or request_id or response_status is not None
                                 or outcome.get("kind") == "success")
        if began and not response_observed:
            ambiguous = True
        rows.append({
            "role": role, "invocation_records": len(records), "invocation_began": began,
            "provider_response_observed": response_observed,
            "configured_model": plan.identity.model_id,
            "model_version_label": plan.identity.model_version, "wire_model": wire,
            "provider_observed_identity": (outcome.get("provider_resolved_identity") or {}).get("value"),
            "f2_verdict": record.get("identity_verdict", "not_evaluated"),
            "sealed": (plan.destination / "seals" / f"{role}.json").is_file(),
            "promoted_artifact_refs": record.get("promoted_artifact_refs", []),
            "provider_usage": {key: (outcome.get("usage", {}).get(key) or {}).get("value") for key in fields},
            "harness_latency_seconds": record.get("harness_observed_latency_seconds"),
            "finish_reason": (outcome.get("finish_reason") or {}).get("value"),
            "response_id": response_id, "request_id": request_id,
        })
    if terminal["status"] == "succeeded" and (
        verification.get("provider_identity_policy_verified") is not True
        or any(row["invocation_records"] != 1 or not row["sealed"] for row in rows)
    ):
        raise CanaryError("Condition B success evidence is incomplete")
    observed_rows = [row for row in rows if row["provider_response_observed"]]
    totals = {}
    for key in fields:
        values = [row["provider_usage"][key] for row in observed_rows]
        totals[key] = sum(values) if not ambiguous and all(v is not None for v in values) else None
    return {
        "run_id": plan.run_spec.run_id, "run_directory": str(plan.destination),
        "terminal_status": terminal["status"], "terminal_verified": verification["terminal_verified"],
        "provider_identity_policy_verified": verification.get("provider_identity_policy_verified", False),
        "evaluation_passed": (terminal.get("evaluation") or {}).get("passed"),
        "ambiguous_dispatch": ambiguous, "maximum_provider_attempts": 3,
        "invocation_records": sum(row["invocation_records"] for row in rows),
        "provider_responses_observed": len(observed_rows),
        "provider_attempts": None if ambiguous else len(observed_rows),
        "stages": rows, "provider_usage_total": totals,
        "retry_or_rerun_performed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = prepare_canary(args)
    except Exception:
        print("Condition B preflight rejected; no execution started", file=sys.stderr)
        return 2
    if not args.execute:
        print("PREFLIGHT ONLY — no execution, credential access, or artifacts")
        print(json.dumps({
            "run_id": plan.run_spec.run_id, "destination": str(plan.destination),
            "condition": "B", "stages": STAGES, "model": plan.identity.model_id,
            "model_version": plan.identity.model_version,
            "limits": plan.run_spec.resource_limits.to_dict(), "maximum_provider_attempts": 3,
            "credential_readiness": "not_checked", "provider_treatment_config": {},
        }, sort_keys=True))
        return 0
    try:
        result = execute_prepared_canary(plan, acknowledge=args.acknowledge)
    except CanaryError:
        print("Condition B execution guard rejected; no execution started", file=sys.stderr)
        return 2
    except BaseException:
        # The runner owns terminalization. No repair, restart, or replacement ID.
        try:
            print(json.dumps(evidence_summary(plan, interrupted=True), sort_keys=True))
        except BaseException:
            print("Evidence incomplete; provider attempt count unknown; maximum authorized 3")
        print(INCONCLUSIVE)
        return 1
    try:
        verification = ArtifactStore.verify_terminal_run(plan.runs_root, plan.run_spec.run_id)
        accept_terminal_verification(plan, result, verification)
        summary = evidence_summary(plan)
        print(json.dumps(summary, sort_keys=True))
        if summary["ambiguous_dispatch"]:
            print(INCONCLUSIVE)
            return 1
        if result.status != "succeeded":
            print(FAIL)
            return 1
    except BaseException:
        print("Terminal acceptance unconfirmed; preserve evidence; no redispatch")
        print(INCONCLUSIVE)
        return 1
    print(PASS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
