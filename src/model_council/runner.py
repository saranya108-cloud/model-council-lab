"""Deterministic Experiment Runner: software process control, not an agent.

Second-audit remediation:
  - F1: expected model identity is frozen in RunSpec; the CHILD-RETURNED
    actual identity is compared against it after EVERY invocation; drift is a
    terminal governance failure. Parent attributes are not trusted alone.
  - F2: usage metrics are validated protocol data (integers, non-negative,
    required). Budgets are enforced on an independently computed, documented
    deterministic approximation covering ALL model-visible input (role
    instruction + stage inputs) and the COMPLETE structured response
    (artifacts + structured fields), not just one text field. Child-reported
    values are recorded separately and never labeled "verified".
  - F5: sealed stages are re-verified against authoritative parent hashes
    before every downstream transition and before evaluation.
  - F6: once a safe run namespace exists, ANY later failure produces a
    terminal record; pre-namespace failures (invalid condition/task/run-id)
    raise before any record exists — by policy.
  - F7: stage success is atomic — a StageResult is appended only after
    artifacts are persisted, sealed, and verified.
  - F9: worker crashes and protocol/metric violations are infrastructure
    failures; they never consume model retry budget.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .artifacts import (
    EVENT_EVALUATION,
    EVENT_GOVERNANCE_VIOLATION,
    EVENT_INTEGRITY,
    EVENT_RUN_RESULT,
    ArtifactStore,
)
from .executor import SubprocessAdapter
from .evaluator import EvaluationConfig, ExternalEvaluator
from .roles import (
    ALLOWED_INPUT_KEYS,
    CONDITION_STAGES,
    CONTEXT_POLICY_VERSION,
    EXPECTED_ARTIFACTS,
    PRIMARY_ARTIFACT,
    ROLE_INSTRUCTIONS,
    STAGE_OUTPUT_KEYS,
    WORKFLOW_NOTES,
    validate_stage_sequence,
)
from .security import digest_json, source_revision
from .types import (
    STATUS_FAILED_BUDGET,
    STATUS_FAILED_CONTRACT,
    STATUS_FAILED_EVALUATION,
    STATUS_FAILED_GOVERNANCE,
    STATUS_INFRASTRUCTURE_FAILURE,
    STATUS_RETRY_EXHAUSTED,
    STATUS_SUCCEEDED,
    ContractViolation,
    Disposition,
    Finding,
    GovernanceViolation,
    InfrastructureError,
    IntegrityViolation,
    ModelFailure,
    ProtocolError,
    RunResult,
    RunSpec,
    StageResult,
    StageStatus,
    StageTimeout,
    TaskSpec,
    validate_dispositions,
    validate_findings,
)

HARNESS_PROTOCOL_VERSION = "m1-dev-harness-v3"

# Documented deterministic usage approximation (Finding 2):
# tokens ~= whitespace-delimited word count over the original model-visible
# values, before JSON transport escaping. Input covers role instruction + all
# stage inputs. Output covers text + every artifact + every structured field
# (findings, dispositions, rationales included). Exact provider tokenizer
# accounting is deferred to live adapters; these estimates enforce M1 ceilings
# and are labeled "harness_estimated" everywhere they appear.


def _approximate_tokens(value) -> int:
    """Count original string/scalar content without JSON escape undercounting."""
    if isinstance(value, str):
        return len(value.split())
    if value is None:
        return 0
    if isinstance(value, bool):
        return 1
    if isinstance(value, (int, float)):
        return 1
    if isinstance(value, Mapping):
        return sum(_approximate_tokens(str(key)) + _approximate_tokens(item) for key, item in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return sum(_approximate_tokens(item) for item in value)
    return len(str(value).split())


def _estimate_tokens_in(role_instruction: str, stage_inputs: Mapping[str, str]) -> int:
    return _approximate_tokens(role_instruction) + _approximate_tokens(dict(stage_inputs))


def _estimate_tokens_out(response: Mapping) -> int:
    return _approximate_tokens(
        {
            "text": response.get("text", ""),
            "artifacts": response.get("artifacts"),
            "structured": response.get("structured"),
        }
    )


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class _RunState:
    def __init__(self) -> None:
        self.status: str = STATUS_SUCCEEDED
        self.stage_results: list[StageResult] = []
        self.executed_roles: list[str] = []
        self.final_candidate_ref: str | None = None
        self.retries_used: int = 0
        self.error: str | None = None
        self.integrity: dict | None = None
        self.treatment_hash: str | None = None
        self.task_text: str = ""
        self.verifier_findings: tuple[Finding, ...] = ()
        self.evaluation_error: str | None = None
        self.evaluation_outcome = None
        self.source_provenance: dict | None = None


class ExperimentRunner:
    def __init__(
        self,
        adapter: SubprocessAdapter,
        evaluator: ExternalEvaluator,
        runs_root: Path | str,
    ) -> None:
        self.adapter = adapter
        self.evaluator = evaluator
        self.runs_root = Path(runs_root)

    # ------------------------------------------------------------------ public

    def execute(self, run_spec: RunSpec, task_spec: TaskSpec) -> RunResult:
        # Pre-namespace validation: no terminal record exists for these by
        # policy, because no safe run directory can be established for them.
        if run_spec.condition not in CONDITION_STAGES:
            raise ValueError(f"unsupported condition: {run_spec.condition}")
        if run_spec.task_id != task_spec.task_id:
            raise ValueError(
                f"run_spec.task_id {run_spec.task_id!r} does not match task {task_spec.task_id!r}"
            )

        run_started = _utcnow()
        wall_start = time.monotonic()
        state = _RunState()
        # Capture provenance before the runner creates any repository-local
        # output, so the run itself cannot make a clean source tree appear
        # dirty.
        state.source_provenance = source_revision()
        store = ArtifactStore(self.runs_root, run_spec)  # unsafe run IDs raise here

        try:
            # All initialization after a safe namespace exists is inside the
            # terminalization boundary.  Setup failures therefore cannot leave
            # a valid run directory without run_result.json.
            state.task_text = task_spec.agent_visible_text()
            state.treatment_hash = self._treatment_hash(run_spec, task_spec)
            # Preflight identity check uses the configured adapter identity;
            # per-invocation actual identity is re-verified from child output.
            if self.adapter.identity.key() != run_spec.model_identifier:
                raise GovernanceViolation(
                    f"adapter identity mismatch: declared {run_spec.model_identifier!r}, "
                    f"configured {self.adapter.identity.key()!r}"
                )
            self._run_stages(run_spec, store, state)
            if state.status == STATUS_SUCCEEDED:
                self._finalize_evaluation(store, state)
        except GovernanceViolation as exc:
            state.status = STATUS_FAILED_GOVERNANCE
            state.error = f"{type(exc).__name__}: {exc}"
            store.record_event(
                EVENT_GOVERNANCE_VIOLATION,
                {
                    "status": state.status,
                    "executed_stages": list(state.executed_roles),
                    "error": state.error,
                },
            )
        except Exception as exc:  # noqa: BLE001 - terminal finalization boundary (F6)
            state.status = STATUS_INFRASTRUCTURE_FAILURE
            state.error = f"{type(exc).__name__}: {exc}"
        finally:
            self._write_terminal_record(store, run_spec, task_spec, state, run_started, wall_start)

        return self._build_result(run_spec, state, run_started)

    # ------------------------------------------------------------- provenance

    def _treatment_hash(self, run_spec: RunSpec, task_spec: TaskSpec) -> str:
        """Hash of the DECLARED experimental treatment/configuration.

        Proves: condition, prompts, context policy, limits, seed, expected
        model identity, adapter behavior configuration, evaluator configuration,
        and harness protocol version were exactly these values.
        Does NOT cryptographically prove the entire source tree; see the
        separately recorded Git source revision / dirty flag for that.
        """
        return digest_json(
            {
                "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                "condition": run_spec.condition.value,
                "prompt_version": run_spec.prompt_version,
                "context_policy_version": CONTEXT_POLICY_VERSION,
                "resource_limits": run_spec.resource_limits.to_dict(),
                "seed": run_spec.seed,
                "model_identifier": run_spec.model_identifier,
                "adapter_kind": self.adapter.kind,
                "adapter_config_digest": digest_json(self.adapter.options),
                "evaluator_version": self.evaluator.version,
                "evaluator_config_digest": self.evaluator.config_digest,
                "task_id": task_spec.task_id,
                "task_content_hash": task_spec.content_hash,
            }
        )

    # ----------------------------------------------------------------- stages

    def _run_stages(self, run_spec: RunSpec, store: ArtifactStore, state: _RunState) -> None:
        context: dict[str, str] = {"task": state.task_text}
        workflow = CONDITION_STAGES[run_spec.condition]
        for role in workflow:
            if state.status != STATUS_SUCCEEDED:
                return
            # F5: verify all previously sealed stages against authoritative hashes.
            for sealed_role in list(state.executed_roles):
                store.verify_sealed_stage(sealed_role)

            outcome = self._execute_stage(run_spec, role, context, store, state)

            if not outcome.ok:
                state.stage_results.append(outcome.failure_result)
                state.retries_used += max(outcome.failure_result.attempt - 1, 0)
                state.status = _terminal_for_failure(outcome)
                return

            # F7 atomic finalization: persist everything BEFORE any success is
            # recorded. A persistence failure raises GovernanceViolation /
            # IntegrityViolation and leaves this stage unrecorded-as-successful.
            validate_stage_sequence(run_spec.condition, tuple(state.executed_roles) + (role,))
            refs: list[str] = []
            is_final = tuple(state.executed_roles) + (role,) == workflow
            for artifact_name, content in outcome.artifacts.items():
                ref = store.write(role, artifact_name, content)
                refs.append(ref)
                key = STAGE_OUTPUT_KEYS[role].get(artifact_name)
                if key:
                    context[key] = content
            store.seal_stage(role)
            store.verify_sealed_stage(role)

            result = StageResult(
                role=role,
                attempt=outcome.attempt,
                status=StageStatus.SUCCEEDED,
                input_refs=tuple(f"<context:{k}>" for k in sorted(outcome.stage_inputs)),
                output_refs=tuple(refs),
                started_at=outcome.started_at,
                ended_at=_utcnow(),
                verified_identity=_verified_identity_dict(outcome.identity_used),
                tokens_in=outcome.usage_estimated["tokens_in"],
                tokens_out=outcome.usage_estimated["tokens_out"],
                cost_units=outcome.response.get("cost_units"),
                tool_uses=outcome.response.get("tool_uses"),
                usage_estimated=dict(outcome.usage_estimated),
                usage_reported={
                    k: outcome.response.get(k)
                    for k in ("tokens_in", "tokens_out", "tool_uses")
                },
                usage_source="harness_estimated_enforced",
            )
            state.stage_results.append(result)
            state.executed_roles.append(role)
            state.retries_used += outcome.attempt - 1
            if is_final and PRIMARY_ARTIFACT.get(role) in outcome.artifacts:
                state.final_candidate_ref = next(
                    r
                    for name, r in zip(
                        [n for n in outcome.artifacts], refs
                    )
                    if name == PRIMARY_ARTIFACT.get(role)
                )

    def _execute_stage(self, run_spec: RunSpec, role: str, context, store, state: _RunState):
        allowed_keys = sorted(ALLOWED_INPUT_KEYS[(run_spec.condition, role)])
        missing = [key for key in allowed_keys if key not in context]
        if missing:
            raise GovernanceViolation(
                f"stage {role} requires context keys {missing} not produced by prior stages"
            )
        stage_inputs = {key: context[key] for key in allowed_keys}
        budget = run_spec.resource_limits
        max_attempts = budget.max_stage_retries + 1

        for attempt in range(1, max_attempts + 1):
            started = _utcnow()
            try:
                response = self.adapter.invoke(
                    role_instruction=ROLE_INSTRUCTIONS[role],
                    stage_inputs=stage_inputs,
                    budget=budget,
                    seed=run_spec.seed + attempt - 1,
                )
            except StageTimeout as exc:
                if attempt == max_attempts:
                    return _StageOutcome.retry_exhausted(
                        role, attempt, started, "timeout", str(exc)
                    )
                continue  # enforced timeouts consume preregistered retry budget
            except ModelFailure as exc:
                if attempt == max_attempts:
                    return _StageOutcome.retry_exhausted(role, attempt, started, "model", str(exc))
                continue  # structured provider failure consumes retry budget
            # ProtocolError / InfrastructureError propagate immediately:
            # infrastructure failures never consume model retry budget (F9).

            identity_error = self._check_identity(run_spec, role, response)
            if identity_error:
                raise GovernanceViolation(identity_error)

            budget_error = self._check_budget(
                role, budget, response, role_instruction=ROLE_INSTRUCTIONS[role],
                stage_inputs=stage_inputs,
            )
            if budget_error:
                return _StageOutcome.hard_failure(role, attempt, started, budget_error)

            contract_error = self._check_contract(role, response, state)
            if contract_error:
                return _StageOutcome.hard_failure(role, attempt, started, contract_error)

            return _StageOutcome.success(
                role=role,
                attempt=attempt,
                started_at=started,
                response=response,
                artifacts=dict(response["artifacts"]),
                stage_inputs=stage_inputs,
                usage_estimated={
                    "tokens_in": _estimate_tokens_in(ROLE_INSTRUCTIONS[role], stage_inputs),
                    "tokens_out": _estimate_tokens_out(response),
                },
                identity_used=response["identity_used"],
            )

        raise InfrastructureError("unreachable retry loop exit")

    @staticmethod
    def _check_identity(run_spec: RunSpec, role: str, response: dict) -> str | None:
        used = response.get("identity_used") or {}
        used_key = ":".join(
            str(used.get(k, "")) for k in
            ("provider", "model_id", "model_version", "adapter_name", "adapter_version")
        )
        if used_key != run_spec.model_identifier:
            return (
                f"identity mismatch in stage {role!r}: frozen RunSpec expects "
                f"{run_spec.model_identifier!r}, invocation resolved {used_key!r}"
            )
        return None

    @staticmethod
    def _check_budget(role, budget, response, *, role_instruction, stage_inputs) -> str | None:
        est_in = _estimate_tokens_in(role_instruction, stage_inputs)
        est_out = _estimate_tokens_out(response)
        if est_in > budget.max_input_tokens_per_stage:
            return (
                f"input budget exceeded in stage {role!r} (harness-estimated): "
                f"{est_in} > {budget.max_input_tokens_per_stage}"
            )
        if est_out > budget.max_output_tokens_per_stage:
            return (
                f"output budget exceeded in stage {role!r} (harness-estimated over full "
                f"structured response): {est_out} > {budget.max_output_tokens_per_stage}"
            )
        tool_uses = response.get("tool_uses")
        if isinstance(tool_uses, int) and not isinstance(tool_uses, bool) and (
            tool_uses > budget.max_tool_calls_per_stage
        ):
            return (
                f"tool-call budget exceeded in stage {role!r}: {tool_uses} > "
                f"{budget.max_tool_calls_per_stage}"
            )
        return None

    @staticmethod
    def _check_contract(role: str, response: dict, state: _RunState) -> str | None:
        try:
            text = response.get("text")
            if type(text) is not str:
                raise ContractViolation(
                    f"model response text must be a string, got {type(text).__name__}"
                )
            artifacts = response.get("artifacts")
            if type(artifacts) is not dict:
                raise ContractViolation(
                    f"artifacts must be an object, got {type(artifacts).__name__}"
                )
            if any(type(name) is not str for name in artifacts):
                raise ContractViolation("artifact names must be strings")
            expected = EXPECTED_ARTIFACTS[role]
            actual = set(artifacts)
            if actual != expected:
                missing = sorted(expected - actual)
                extra = sorted(actual - expected)
                raise ContractViolation(
                    f"artifact contract for stage {role!r} requires exactly {sorted(expected)}; "
                    f"missing={missing}, extra={extra}"
                )
            for name, content in artifacts.items():
                if type(name) is not str or type(content) is not str:
                    raise ContractViolation(
                        f"artifact {name!r} must contain a string value"
                    )

            structured = response.get("structured")
            if role == "verifier":
                findings_payload = _require_structured(structured, "findings")
                findings = tuple(_parse_finding(item) for item in findings_payload)
                validate_findings(findings)
                state.verifier_findings = findings
                return None
            if role == "reviser":
                if not state.verifier_findings:
                    return None  # Condition B reviser has no finding registry
                dispositions_payload = _require_structured(structured, "dispositions")
                dispositions = tuple(
                    _parse_disposition(item) for item in dispositions_payload
                )
                validate_dispositions(state.verifier_findings, dispositions)
                return None
        except ContractViolation as exc:
            return f"contract violation in stage {role!r}: {exc}"
        return None

    # ------------------------------------------------------------- evaluation

    def _finalize_evaluation(self, store: ArtifactStore, state: _RunState) -> None:
        integrity = store.verify_completed_run()
        state.integrity = integrity
        store.record_event(EVENT_INTEGRITY, integrity)
        candidate_text = store.read(state.final_candidate_ref)
        try:
            outcome = self.evaluator.evaluate(candidate_text)
        except Exception as exc:  # noqa: BLE001 - evaluator failure is terminal, never success
            state.status = STATUS_FAILED_EVALUATION
            state.evaluation_error = f"{type(exc).__name__}: {exc}"
            store.record_event(
                EVENT_EVALUATION,
                {"status": state.status, "error": state.evaluation_error},
            )
            return
        state.evaluation_outcome = outcome
        store.record_event(EVENT_EVALUATION, {"outcome": outcome.to_dict()})

    # --------------------------------------------------------------- terminal

    def _write_terminal_record(
        self,
        store: ArtifactStore,
        run_spec: RunSpec,
        task_spec: TaskSpec,
        state: _RunState,
        run_started: str,
        wall_start: float,
    ) -> None:
        payload = {
            "status": state.status,
            "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
            "condition": run_spec.condition.value,
            "model_identifier": run_spec.model_identifier,
            "verified_identity": (
                state.stage_results[-1].verified_identity if state.stage_results else None
            ),
            "spec_hash": run_spec.spec_hash,
            "treatment_hash": state.treatment_hash,
            "treatment_hash_scope": (
                "declared experimental configuration only; see source_provenance "
                "for code revision; not a cryptographic hash of the source tree"
            ),
            "source_provenance": state.source_provenance,
            "final_candidate_ref": state.final_candidate_ref,
            "retries_used": state.retries_used,
            "interventions": [],
            "workflow_note": WORKFLOW_NOTES[run_spec.condition],
            "started_at": run_started,
            "ended_at": _utcnow(),
            "wall_clock_seconds": round(time.monotonic() - wall_start, 6),
            "timeout_enforcement": "direct_child_process_terminated",
            "usage_accounting": "harness_estimated_word_count_approximation",
            "integrity": state.integrity,
            "error": state.error,
            "evaluation_error": state.evaluation_error,
            "evaluation": (
                state.evaluation_outcome.to_dict() if state.evaluation_outcome else None
            ),
            "stages": [
                {
                    "role": s.role,
                    "attempt": s.attempt,
                    "status": s.status.value,
                    "input_refs": list(s.input_refs),
                    "output_refs": list(s.output_refs),
                    "error": s.error,
                    "verified_identity": s.verified_identity,
                    "tokens_in": s.tokens_in,
                    "tokens_out": s.tokens_out,
                    "cost_units": s.cost_units,
                    "tool_uses": s.tool_uses,
                    "usage_estimated": s.usage_estimated,
                    "usage_reported": s.usage_reported,
                    "usage_source": s.usage_source,
                }
                for s in state.stage_results
            ],
        }
        store.record_event(EVENT_RUN_RESULT, payload)

    def _build_result(self, run_spec: RunSpec, state: _RunState, run_started: str) -> RunResult:
        return RunResult(
            run_id=run_spec.run_id,
            task_id=run_spec.task_id,
            condition=run_spec.condition,
            model_identifier=run_spec.model_identifier,
            spec_hash=run_spec.spec_hash,
            status=state.status,
            stage_results=list(state.stage_results),
            final_candidate_ref=state.final_candidate_ref,
            evaluation=state.evaluation_outcome,
            retries_used=state.retries_used,
            interventions=(),
            started_at=run_started,
            ended_at=_utcnow(),
            workflow_note=WORKFLOW_NOTES[run_spec.condition],
            treatment_hash=state.treatment_hash,
            metadata={
                "runs_root": str(self.runs_root),
                "integrity": state.integrity,
                "error": state.error,
                "source_provenance": state.source_provenance,
            },
        )


# ------------------------------------------------------------------ helpers


class _StageOutcome:
    def __init__(self, ok, **kwargs):
        self.ok = ok
        self.__dict__.update(kwargs)

    @classmethod
    def success(cls, **kwargs):
        return cls(True, **kwargs)

    @classmethod
    def retry_exhausted(cls, role, attempt, started, kind, message):
        return cls(
            ok=False,
            failure_result=StageResult(
                role=role,
                attempt=attempt,
                status=StageStatus.RETRY_EXHAUSTED,
                started_at=started,
                ended_at=_utcnow(),
                error=f"retry budget exhausted ({kind}); last error: {message}",
            ),
        )

    @classmethod
    def hard_failure(cls, role, attempt, started, error):
        return cls(
            ok=False,
            failure_result=StageResult(
                role=role,
                attempt=attempt,
                status=StageStatus.FAILED,
                started_at=started,
                ended_at=_utcnow(),
                error=error,
            ),
        )


def _verified_identity_dict(identity_used: Mapping[str, str]) -> dict:
    d = {k: str(v) for k, v in identity_used.items()}
    d["identity_key"] = ":".join(
        d.get(k, "")
        for k in ("provider", "model_id", "model_version", "adapter_name", "adapter_version")
    )
    return d


def _terminal_for_failure(outcome: "_StageOutcome") -> str:
    error = outcome.failure_result.error or ""
    if outcome.failure_result.status is StageStatus.RETRY_EXHAUSTED:
        return STATUS_RETRY_EXHAUSTED
    if "budget exceeded" in error:
        return STATUS_FAILED_BUDGET
    if "contract violation" in error:
        return STATUS_FAILED_CONTRACT
    return STATUS_INFRASTRUCTURE_FAILURE


def _require_structured(structured, key: str):
    if not isinstance(structured, dict):
        raise ContractViolation(
            f"structured payload must be an object, got {type(structured).__name__}"
        )
    value = structured.get(key)
    if not isinstance(value, list):
        raise ContractViolation(
            f"'{key}' must be an array, got {type(value).__name__}"
        )
    return value


def _parse_finding(item) -> Finding:
    if not isinstance(item, dict):
        raise ContractViolation(f"finding must be an object, got {type(item).__name__}")
    finding_id = item.get("finding_id")
    description = item.get("description")
    material = item.get("material", True)
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ContractViolation("finding_id must be a non-empty string")
    if not isinstance(description, str) or not description.strip():
        raise ContractViolation("finding description must be a non-empty string")
    if not isinstance(material, bool):
        raise ContractViolation(
            f"finding material flag must be a boolean, got {type(material).__name__}"
        )
    return Finding(finding_id=finding_id, description=description, material=material)


def _parse_disposition(item) -> Disposition:
    if not isinstance(item, dict):
        raise ContractViolation(f"disposition must be an object, got {type(item).__name__}")
    finding_id = item.get("finding_id")
    decision = item.get("decision")
    rationale = item.get("rationale")
    if not isinstance(finding_id, str) or not finding_id.strip():
        raise ContractViolation("disposition finding_id must be a non-empty string")
    if decision not in ("accept", "reject"):
        raise ContractViolation(
            f"disposition decision must be 'accept' or 'reject', got {decision!r}"
        )
    if not isinstance(rationale, str) or not rationale.strip():
        raise ContractViolation("disposition rationale must be a non-empty string")
    return Disposition(finding_id=finding_id, decision=decision, rationale=rationale)
