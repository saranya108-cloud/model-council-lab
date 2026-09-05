"""Deterministic Experiment Runner: software process control, not an agent.

Second-audit remediation:
  - F1: expected model identity is frozen in RunSpec; the CHILD-RETURNED
    actual identity is compared against it after EVERY invocation; drift is a
    terminal governance failure. Parent attributes are not trusted alone.
  - F2: usage metrics are validated protocol data (integers, non-negative,
    required). Input ceilings are enforced BEFORE every runner-authorized
    adapter invocation on a cumulative per-stage estimate. Output and tool
    ceilings are enforced after the response is received. Budgets use an
    independently computed, documented deterministic approximation covering
    ALL model-visible input (role instruction + stage inputs) and the COMPLETE
    structured response (artifacts + structured fields), not just one text
    field. Child-reported values are recorded separately and never labeled
    "verified". A single monotonic stage deadline spans all attempts; retries
    reuse the original treatment parameters including seed.
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

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping

from .artifacts import (
    EVENT_EVALUATION,
    EVENT_GOVERNANCE_VIOLATION,
    EVENT_INTEGRITY,
    EVENT_RUN_RESULT,
    MANIFEST,
    RUN_AUTHORITY,
    ArtifactStore,
)
from .executor import SubprocessAdapter
from .evaluator import EvaluationConfig, ExternalEvaluator
from .invocation import (
    build_invocation_record,
    raw_text_from_untrusted_response,
    treatment_digest_for_attempt,
)
from .live_contract import (
    LIVE_CONTRACT_VERSION,
    LiveContractError,
    NeutralProviderFailure,
    ProviderCallKind,
    build_exact_provider_identity_policy,
    build_live_invocation_request,
    evaluate_provider_identity_policy,
    provider_identity_evaluation_eligible,
    map_live_outcome_to_stage_response,
)
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from .retry_policy import is_retry_candidate
from .sanitize import (
    INTERRUPTED_EVALUATION_MESSAGE,
    INTERRUPTED_INFRASTRUCTURE_MESSAGE,
    WORKER_SANITIZED_FAILURE,
    sanitize_exception,
)
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
    Condition,
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
    canonical_findings_text,
    validate_dispositions,
    validate_findings,
)

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


class _StageDeadline:
    """Runner-owned monotonic deadline covering the entire stage lifecycle."""

    def __init__(self, monotonic, timeout_seconds: float) -> None:
        self._monotonic = monotonic
        self.timeout_seconds = float(timeout_seconds)
        self.started_at = float(monotonic())
        self.deadline_at = self.started_at + self.timeout_seconds

    def remaining(self) -> float:
        return self.deadline_at - float(self._monotonic())

    def require(self, where: str) -> float:
        remaining = self.remaining()
        if remaining <= 0:
            raise StageTimeout(f"stage deadline expired {where}")
        return remaining


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
        self.evaluation_started: bool = False
        self.evaluation_committed: bool = False
        self.authority_committed: bool = False
        self.provider_identity_policy: dict | None = None


class ExperimentRunner:
    def __init__(
        self,
        adapter: SubprocessAdapter,
        evaluator: ExternalEvaluator,
        runs_root: Path | str,
        monotonic=None,
    ) -> None:
        self.adapter = adapter
        self.evaluator = evaluator
        self.runs_root = Path(runs_root)
        # Injectable monotonic clock for stage-deadline tests. Production uses
        # time.monotonic; wall-clock UTC is used only for human-readable records.
        self._monotonic = monotonic or time.monotonic

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

        pending_interrupt = None
        try:
            # All initialization after a safe namespace exists is inside the
            # terminalization boundary.  Setup failures therefore cannot leave
            # a valid run directory without run_result.json.
            state.task_text = task_spec.agent_visible_text()
            store.write_source_provenance(dict(state.source_provenance or {}))
            store.write_task_record(
                {
                    "task_id": task_spec.task_id,
                    "bug_report": task_spec.bug_report,
                    "workspace_id": task_spec.workspace_id,
                    "allowed_files": list(task_spec.allowed_files),
                    "visible_test_command": task_spec.visible_test_command,
                    "snapshot_hash": task_spec.snapshot_hash,
                    "task_content_hash": task_spec.content_hash,
                }
            )
            profile = execution_profile_for_kind(self.adapter.kind)
            state.provider_identity_policy = (
                build_exact_provider_identity_policy(
                    self.adapter.identity, self.adapter.identity
                )
                if self.adapter.kind == "openai_responses"
                else None
            )
            execution_binding = {
                "adapter_kind": self.adapter.kind,
                "adapter_config_digest": digest_json(self.adapter.options),
                "adapter_identity": self.adapter.identity.to_dict(),
                "provider_treatment_config": self.adapter.persisted_provider_treatment_config(),
                "execution_profile": profile,
                "live_contract_version": LIVE_CONTRACT_VERSION,
                "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                "context_policy_version": CONTEXT_POLICY_VERSION,
            }
            if state.provider_identity_policy is not None:
                execution_binding["provider_identity_policy"] = state.provider_identity_policy
                execution_binding["provider_identity_policy_version"] = (
                    state.provider_identity_policy["schema"]
                )
            store.write_execution_binding(execution_binding)
            store.write_evaluator_binding(
                {
                    "evaluator_version": self.evaluator.version,
                    "evaluator_config_digest": self.evaluator.config_digest,
                }
            )
            declaration = self._treatment_declaration(run_spec, task_spec)
            state.treatment_hash = self._treatment_hash(run_spec, task_spec)
            store.write_treatment_declaration(declaration, state.treatment_hash)
            store.freeze_run_authority()
            state.authority_committed = True
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
            state.error = sanitize_exception(exc, fallback=WORKER_SANITIZED_FAILURE)
        except BaseException as exc:
            pending_interrupt = exc
            try:
                self._finalize_interrupted_run(store, run_spec, state)
            except BaseException:
                if not state.evaluation_committed and state.status == STATUS_SUCCEEDED:
                    if state.evaluation_started or _completed_stage_topology(run_spec, state):
                        state.status = STATUS_FAILED_EVALUATION
                        state.evaluation_error = INTERRUPTED_EVALUATION_MESSAGE
                    else:
                        state.status = STATUS_INFRASTRUCTURE_FAILURE
                        state.error = INTERRUPTED_INFRASTRUCTURE_MESSAGE
            raise pending_interrupt from None
        finally:
            try:
                self._write_terminal_record(
                    store, run_spec, task_spec, state, run_started, wall_start
                )
            except BaseException:
                if pending_interrupt is not None:
                    raise pending_interrupt from None
                raise

        return self._build_result(run_spec, state, run_started)

    # ------------------------------------------------------------- provenance

    def _treatment_declaration(self, run_spec: RunSpec, task_spec: TaskSpec) -> dict:
        declaration = {
            "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
            "condition": run_spec.condition.value,
            "prompt_version": run_spec.prompt_version,
            "context_policy_version": CONTEXT_POLICY_VERSION,
            "resource_limits": run_spec.resource_limits.to_dict(),
            "seed": run_spec.seed,
            "model_identifier": run_spec.model_identifier,
            "adapter_kind": self.adapter.kind,
            "adapter_config_digest": digest_json(self.adapter.options),
            "provider_treatment_config": self.adapter.persisted_provider_treatment_config(),
            "evaluator_version": self.evaluator.version,
            "evaluator_config_digest": self.evaluator.config_digest,
            "task_id": task_spec.task_id,
            "task_content_hash": task_spec.content_hash,
            "execution_profile": execution_profile_for_kind(self.adapter.kind),
            "live_contract_version": LIVE_CONTRACT_VERSION,
        }
        if self.adapter.kind == "openai_responses":
            declaration["provider_identity_policy"] = build_exact_provider_identity_policy(
                self.adapter.identity, self.adapter.identity
            )
            declaration["provider_identity_policy_version"] = (
                declaration["provider_identity_policy"]["schema"]
            )
        return declaration

    def _treatment_hash(self, run_spec: RunSpec, task_spec: TaskSpec) -> str:
        """Hash of the DECLARED experimental treatment/configuration.

        Proves: condition, prompts, context policy, limits, seed, expected
        model identity, adapter behavior configuration, evaluator configuration,
        and harness protocol version were exactly these values.
        Does NOT cryptographically prove the entire source tree; see the
        separately recorded Git source revision / dirty flag for that.
        """
        return digest_json(self._treatment_declaration(run_spec, task_spec))

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

            validate_stage_sequence(run_spec.condition, tuple(state.executed_roles) + (role,))
            # F7 atomic finalization: persist everything BEFORE any success is
            # recorded. Deadline expiry at any point before the success
            # transition rolls back promoted artifacts and seals.
            try:
                refs = self._commit_stage_transaction(
                    store=store,
                    run_spec=run_spec,
                    role=role,
                    outcome=outcome,
                )
                # Authoritative success transition: no committed topology may
                # remain if this check expires. This closes the post-commit
                # gap before StageResult / context / evaluation.
                outcome.deadline.require("before applying stage success")
            except StageTimeout as exc:
                store.abort_uncommitted_stage(role)
                if not store.invocation_attempt_exists(role, outcome.attempt):
                    self._record_stage_invocation(
                        store=store,
                        run_spec=run_spec,
                        role=role,
                        attempt=outcome.attempt,
                        attempt_timeout_seconds=(
                            outcome.attempt_timeout_seconds
                            if self.adapter.kind == "openai_responses"
                            else outcome.deadline.remaining()
                        ),
                        stage_inputs=outcome.stage_inputs,
                        tokens_in=outcome.usage_estimated["tokens_in"],
                        tokens_out=outcome.usage_estimated["tokens_out"],
                        cumulative_tokens_in=outcome.usage_estimated.get(
                            "cumulative_tokens_in", outcome.usage_estimated["tokens_in"]
                        ),
                        retry_decision="stop",
                        retry_rationale="retry_budget_exhausted",
                        contract_verdict="passed",
                        identity_verdict="passed",
                        failure_class="timeout",
                        response=outcome.response,
                        provider_outcome=getattr(outcome, "provider_outcome", None),
                        response_latency_seconds=outcome.response_latency_seconds,
                        invocation_began=True,
                        projected_tokens_in=outcome.usage_estimated["tokens_in"],
                        consumed_tokens_in=outcome.usage_estimated["tokens_in"],
                        promoted_artifact_refs=(),
                    )
                state.stage_results.append(
                    _StageOutcome.retry_exhausted(
                        role,
                        outcome.attempt,
                        outcome.started_at,
                        "timeout",
                        str(exc),
                    ).failure_result
                )
                state.retries_used += max(outcome.attempt - 1, 0)
                state.status = STATUS_RETRY_EXHAUSTED
                return
            except Exception:
                store.abort_uncommitted_stage(role)
                raise
            is_final = tuple(state.executed_roles) + (role,) == workflow
            for artifact_name, content in outcome.artifacts.items():
                key = STAGE_OUTPUT_KEYS[role].get(artifact_name)
                if key:
                    context[key] = content

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

    def _commit_stage_transaction(
        self,
        *,
        store: ArtifactStore,
        run_spec: RunSpec,
        role: str,
        outcome,
    ) -> list[str]:
        deadline = outcome.deadline
        deadline.require("before promoted artifact writes")
        for artifact_name, content in outcome.artifacts.items():
            store.write_staged(role, artifact_name, content)
            deadline.require("during artifact persistence")
        deadline.require("before promoted artifact commit")
        promoted = store.commit_staged_artifacts(role)
        refs = [promoted[name] for name in outcome.artifacts]
        deadline.require("before invocation evidence bind")
        self._record_stage_invocation(
            store=store,
            run_spec=run_spec,
            role=role,
            attempt=outcome.attempt,
            attempt_timeout_seconds=outcome.attempt_timeout_seconds,
            stage_inputs=outcome.stage_inputs,
            tokens_in=outcome.usage_estimated["tokens_in"],
            tokens_out=outcome.usage_estimated["tokens_out"],
            cumulative_tokens_in=outcome.usage_estimated.get(
                "cumulative_tokens_in", outcome.usage_estimated["tokens_in"]
            ),
            retry_decision="promote",
            retry_rationale="stage_succeeded",
            contract_verdict="passed",
            identity_verdict="passed",
            failure_class=None,
            response=outcome.response,
            provider_outcome=getattr(outcome, "provider_outcome", None),
            response_latency_seconds=outcome.response_latency_seconds,
            promoted_artifact_refs=tuple(refs),
            invocation_began=True,
            projected_tokens_in=outcome.usage_estimated["tokens_in"],
            consumed_tokens_in=outcome.usage_estimated["tokens_in"],
        )
        deadline.require("before successful stage sealing")
        store.seal_stage(
            role,
            expected_attempts=outcome.attempt,
            before_persist=lambda: deadline.require("before seal persist"),
        )
        deadline.require("before declaring stage success")
        store.verify_sealed_stage(role)
        return refs

    def _execute_stage(self, run_spec: RunSpec, role: str, context, store, state: _RunState):
        budget = run_spec.resource_limits
        deadline = _StageDeadline(self._monotonic, budget.stage_timeout_seconds)
        allowed_keys = sorted(ALLOWED_INPUT_KEYS[(run_spec.condition, role)])
        missing = [key for key in allowed_keys if key not in context]
        if missing:
            raise GovernanceViolation(
                f"stage {role} requires context keys {missing} not produced by prior stages"
            )
        stage_inputs = {key: context[key] for key in allowed_keys}
        role_instruction = ROLE_INSTRUCTIONS[role]
        max_attempts = budget.max_stage_retries + 1
        estimated_in = _estimate_tokens_in(role_instruction, stage_inputs)
        cumulative_input = 0

        for attempt in range(1, max_attempts + 1):
            started = _utcnow()
            remaining = deadline.remaining()
            persist = {
                "store": store,
                "run_spec": run_spec,
                "role": role,
                "attempt": attempt,
                "attempt_timeout_seconds": remaining,
                "stage_inputs": stage_inputs,
                "tokens_in": estimated_in,
                "projected_tokens_in": estimated_in,
                "invocation_began": False,
                "consumed_tokens_in": 0,
                "response_latency_seconds": None,
            }
            try:
                deadline.require("before starting an attempt")
            except StageTimeout:
                remaining = deadline.remaining()
                persist["attempt_timeout_seconds"] = remaining
                if attempt == max_attempts:
                    self._record_stage_invocation(
                        **persist,
                        tokens_out=0,
                        cumulative_tokens_in=cumulative_input,
                        retry_decision="stop",
                        retry_rationale="retry_budget_exhausted",
                        contract_verdict="not_evaluated",
                        identity_verdict="not_evaluated",
                        failure_class="timeout",
                    )
                    return _StageOutcome.retry_exhausted(
                        role,
                        attempt,
                        started,
                        "timeout",
                        "stage deadline exhausted before adapter invocation",
                    )
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="retry",
                    retry_rationale="retry_candidate_remaining",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="timeout",
                )
                continue  # exhausted time still consumes preregistered retry budget
            if cumulative_input + estimated_in > budget.max_input_tokens_per_stage:
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="failed_budget",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="budget",
                )
                return _StageOutcome.hard_failure(
                    role,
                    attempt,
                    started,
                    (
                        f"input budget exceeded in stage {role!r} (harness-estimated): "
                        f"{cumulative_input + estimated_in} > {budget.max_input_tokens_per_stage}"
                    ),
                    tokens_in=0,
                    tokens_out=0,
                    usage_estimated={
                        "tokens_in": 0,
                        "tokens_out": 0,
                        "projected_tokens_in": estimated_in,
                        "consumed_tokens_in": 0,
                        "cumulative_tokens_in": cumulative_input,
                        "invocation_began": False,
                    },
                    usage_source="harness_estimated_enforced",
                )
            response = None
            provider_outcome = None
            try:
                # Remaining time is executor enforcement, not treatment.
                # Seed and resource limits stay identical across retries.
                remaining = deadline.require("immediately before process launch")
                persist["attempt_timeout_seconds"] = remaining
                persist["invocation_began"] = True
                persist["consumed_tokens_in"] = estimated_in
                response, provider_outcome = self._invoke_authorized_attempt(
                    run_spec,
                    role,
                    role_instruction,
                    stage_inputs,
                    budget,
                    remaining,
                )
                if state.provider_identity_policy is not None:
                    # Sample the same runner clock used to grant the remaining
                    # deadline. Preserve this interval through later validation
                    # and promotion; executor latency excludes mapping overhead.
                    persist["response_latency_seconds"] = remaining - deadline.remaining()
                    if not provider_identity_evaluation_eligible(
                        provider_outcome,
                        attempt_timeout_seconds=remaining,
                        harness_observed_latency_seconds=persist["response_latency_seconds"],
                    ):
                        raise StageTimeout("stage deadline expired immediately after invocation returns")
                else:
                    deadline.require("immediately after invocation returns")
            except StageTimeout as exc:
                if persist["invocation_began"]:
                    cumulative_input += estimated_in
                if attempt == max_attempts:
                    self._record_stage_invocation(
                        **persist,
                        tokens_out=0,
                        cumulative_tokens_in=cumulative_input,
                        retry_decision="stop",
                        retry_rationale="retry_budget_exhausted",
                        contract_verdict="not_evaluated",
                        identity_verdict="not_evaluated",
                        failure_class="timeout",
                        response=response,
                        provider_outcome=provider_outcome,
                    )
                    return _StageOutcome.retry_exhausted(
                        role, attempt, started, "timeout", str(exc)
                    )
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="retry",
                    retry_rationale="retry_candidate_remaining",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="timeout",
                    response=response,
                    provider_outcome=provider_outcome,
                )
                continue  # enforced timeouts consume preregistered retry budget
            except ModelFailure as exc:
                cumulative_input += estimated_in
                if attempt == max_attempts:
                    self._record_stage_invocation(
                        **persist,
                        tokens_out=0,
                        cumulative_tokens_in=cumulative_input,
                        retry_decision="stop",
                        retry_rationale="retry_budget_exhausted",
                        contract_verdict="not_evaluated",
                        identity_verdict="not_evaluated",
                        failure_class="model",
                    )
                    return _StageOutcome.retry_exhausted(role, attempt, started, "model", str(exc))
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="retry",
                    retry_rationale="retry_candidate_remaining",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="model",
                )
                continue  # structured pre-live model failure consumes retry budget
            except NeutralProviderFailure as exc:
                cumulative_input += estimated_in
                # Provider retry hints are evidence only. Runner policy, remaining
                # attempts, deadline, and input ceiling decide whether another call
                # is authorized.
                if is_retry_candidate(exc.error.category):
                    if attempt == max_attempts:
                        self._record_stage_invocation(
                            **persist,
                            tokens_out=0,
                            cumulative_tokens_in=cumulative_input,
                            retry_decision="stop",
                            retry_rationale="retry_budget_exhausted",
                            contract_verdict="not_evaluated",
                            identity_verdict="not_evaluated",
                            failure_class="provider",
                            neutral_error=exc.error,
                            provider_outcome=exc.outcome,
                        )
                        return _StageOutcome.retry_exhausted(
                            role,
                            attempt,
                            started,
                            "provider",
                            f"{exc.error.category.value}: {exc.error.sanitized_message}",
                        )
                    self._record_stage_invocation(
                        **persist,
                        tokens_out=0,
                        cumulative_tokens_in=cumulative_input,
                        retry_decision="retry",
                        retry_rationale="retry_candidate_remaining",
                        contract_verdict="not_evaluated",
                        identity_verdict="not_evaluated",
                        failure_class="provider",
                        neutral_error=exc.error,
                        provider_outcome=exc.outcome,
                    )
                    continue
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="provider_nonretryable",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="provider",
                    neutral_error=exc.error,
                    provider_outcome=exc.outcome,
                )
                return _StageOutcome.hard_failure(
                    role,
                    attempt,
                    started,
                    (
                        f"provider/transport failure in stage {role!r} "
                        f"({exc.error.category.value}): {exc.error.sanitized_message}"
                    ),
                )
            except (ProtocolError, InfrastructureError):
                if persist["invocation_began"]:
                    cumulative_input += estimated_in
                    persist["consumed_tokens_in"] = estimated_in
                self._record_stage_invocation(
                    **persist,
                    tokens_out=0,
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="infrastructure_failure",
                    contract_verdict="not_evaluated",
                    identity_verdict="not_evaluated",
                    failure_class="infrastructure",
                    response=response,
                    provider_outcome=provider_outcome,
                )
                raise
            # ProtocolError / InfrastructureError propagate immediately:
            # infrastructure failures never consume model retry budget (F9).

            cumulative_input += estimated_in
            persist["provider_outcome"] = provider_outcome

            identity_error = self._check_identity(
                run_spec,
                role,
                response,
                provider_outcome=provider_outcome,
                provider_identity_policy=state.provider_identity_policy,
                attempt_timeout_seconds=remaining,
                response_latency_seconds=persist["response_latency_seconds"],
            )
            if identity_error:
                self._record_stage_invocation(
                    **persist,
                    tokens_out=_estimate_tokens_out(response),
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="identity_policy_rejected",
                    contract_verdict="not_evaluated",
                    identity_verdict="failed",
                    failure_class="governance",
                    response=response,
                )
                raise GovernanceViolation(identity_error)

            budget_error = self._check_output_and_tool_budget(role, budget, response)
            if budget_error:
                self._record_stage_invocation(
                    **persist,
                    tokens_out=_estimate_tokens_out(response),
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="failed_budget",
                    contract_verdict="not_evaluated",
                    identity_verdict="passed",
                    failure_class="budget",
                    response=response,
                )
                return _StageOutcome.hard_failure(
                    role,
                    attempt,
                    started,
                    budget_error,
                    tokens_in=estimated_in,
                    tokens_out=_estimate_tokens_out(response),
                    usage_estimated={
                        "tokens_in": estimated_in,
                        "tokens_out": _estimate_tokens_out(response),
                    },
                    usage_source="harness_estimated_enforced",
                )

            contract_error = self._check_contract(
                role, response, state, run_spec.condition
            )
            if contract_error:
                self._record_stage_invocation(
                    **persist,
                    tokens_out=_estimate_tokens_out(response),
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="stop",
                    retry_rationale="failed_contract",
                    contract_verdict="failed",
                    identity_verdict="passed",
                    failure_class="contract",
                    response=response,
                )
                return _StageOutcome.hard_failure(
                    role,
                    attempt,
                    started,
                    contract_error,
                    tokens_in=estimated_in,
                    tokens_out=_estimate_tokens_out(response),
                    usage_estimated={
                        "tokens_in": estimated_in,
                        "tokens_out": _estimate_tokens_out(response),
                    },
                    usage_source="harness_estimated_enforced",
                )

            try:
                deadline.require("after live response validation")
            except StageTimeout as exc:
                if attempt == max_attempts:
                    self._record_stage_invocation(
                        **persist,
                        tokens_out=_estimate_tokens_out(response),
                        cumulative_tokens_in=cumulative_input,
                        retry_decision="stop",
                        retry_rationale="retry_budget_exhausted",
                        contract_verdict="passed",
                        identity_verdict="passed",
                        failure_class="timeout",
                        response=response,
                    )
                    return _StageOutcome.retry_exhausted(
                        role, attempt, started, "timeout", str(exc)
                    )
                self._record_stage_invocation(
                    **persist,
                    tokens_out=_estimate_tokens_out(response),
                    cumulative_tokens_in=cumulative_input,
                    retry_decision="retry",
                    retry_rationale="retry_candidate_remaining",
                    contract_verdict="passed",
                    identity_verdict="passed",
                    failure_class="timeout",
                    response=response,
                )
                continue

            artifacts = dict(response["artifacts"])
            if role == "verifier":
                artifacts["findings"] = canonical_findings_text(state.verifier_findings)
            return _StageOutcome.success(
                role=role,
                attempt=attempt,
                started_at=started,
                response=response,
                artifacts=artifacts,
                stage_inputs=stage_inputs,
                attempt_timeout_seconds=remaining,
                usage_estimated={
                    "tokens_in": estimated_in,
                    "tokens_out": _estimate_tokens_out(response),
                    "cumulative_tokens_in": cumulative_input,
                },
                identity_used=response["identity_used"],
                provider_outcome=provider_outcome,
                deadline=deadline,
                response_latency_seconds=persist["response_latency_seconds"],
            )

        raise InfrastructureError("unreachable retry loop exit")

    def _record_stage_invocation(
        self,
        *,
        store: ArtifactStore,
        run_spec: RunSpec,
        role: str,
        attempt: int,
        attempt_timeout_seconds: float,
        stage_inputs: Mapping[str, str],
        tokens_in: int,
        tokens_out: int,
        cumulative_tokens_in: int,
        retry_decision: str,
        retry_rationale: str,
        contract_verdict: str,
        identity_verdict: str,
        failure_class: str | None,
        response=None,
        neutral_error=None,
        provider_outcome=None,
        promoted_artifact_refs=(),
        invocation_began: bool = False,
        projected_tokens_in: int | None = None,
        consumed_tokens_in: int | None = None,
        response_latency_seconds: float | None = None,
    ) -> None:
        budget = run_spec.resource_limits
        profile = execution_profile_for_kind(self.adapter.kind)
        input_digest, treatment_digest = treatment_digest_for_attempt(
            condition=run_spec.condition.value,
            role=role,
            role_instruction=ROLE_INSTRUCTIONS[role],
            stage_inputs=stage_inputs,
            requested_identity=self.adapter.identity,
            configured_identity=self.adapter.identity,
            seed=run_spec.seed,
            resource_limits=budget,
            execution_profile=profile,
            adapter_kind=self.adapter.kind,
            adapter_config_digest=digest_json(self.adapter.options),
            provider_treatment_config=self.adapter.provider_treatment_config,
            provider_identity_policy=(
                build_exact_provider_identity_policy(
                    self.adapter.identity, self.adapter.identity
                )
                if self.adapter.kind == "openai_responses"
                else None
            ),
        )
        identity_used = None
        reported_usage = None
        if profile == EXECUTION_PROFILE_PRE_LIVE_LEGACY and isinstance(response, Mapping):
            identity_used = response.get("identity_used")
            reported_usage = {
                key: response.get(key) for key in ("tokens_in", "tokens_out", "tool_uses")
            }
        raw_text = None
        if profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
            if provider_outcome is not None and provider_outcome.raw_output.value is not None:
                raw_text = provider_outcome.raw_output.value
            elif provider_outcome is not None and provider_outcome.stage_output is not None:
                raw_text = provider_outcome.stage_output.get("text")
        else:
            raw_text = raw_text_from_untrusted_response(response)
        latency = None
        if invocation_began:
            latency = self.adapter.last_harness_observed_latency_seconds
        if self.adapter.kind == "openai_responses" and response_latency_seconds is not None:
            latency = response_latency_seconds
        record = build_invocation_record(
            run_id=run_spec.run_id,
            condition=run_spec.condition.value,
            role=role,
            attempt=attempt,
            requested_identity=self.adapter.identity,
            configured_identity=self.adapter.identity,
            stage_timeout_seconds=budget.stage_timeout_seconds,
            attempt_timeout_seconds=float(attempt_timeout_seconds),
            input_content_digest=input_digest,
            treatment_digest=treatment_digest,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cumulative_tokens_in=cumulative_tokens_in,
            retry_decision=retry_decision,
            retry_rationale=retry_rationale,
            contract_verdict=contract_verdict,
            identity_verdict=identity_verdict,
            failure_class=failure_class,
            promoted_artifact_refs=promoted_artifact_refs,
            identity_used=identity_used,
            reported_usage=reported_usage,
            neutral_error=neutral_error,
            provider_outcome=provider_outcome,
            execution_profile=profile,
            invocation_began=invocation_began,
            projected_tokens_in=projected_tokens_in,
            consumed_tokens_in=consumed_tokens_in,
            harness_observed_latency_seconds=latency,
        )
        store.record_invocation(role, attempt, record, raw_text)

    def _invoke_authorized_attempt(
        self,
        run_spec: RunSpec,
        role: str,
        role_instruction: str,
        stage_inputs: Mapping[str, str],
        budget,
        remaining: float,
    ):
        profile = execution_profile_for_kind(self.adapter.kind)
        if profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
            live_request = build_live_invocation_request(
                condition=run_spec.condition.value,
                role=role,
                role_instruction=role_instruction,
                stage_inputs=stage_inputs,
                requested_identity=self.adapter.identity,
                configured_identity=self.adapter.identity,
                seed=run_spec.seed,
                max_output_tokens=budget.max_output_tokens_per_stage,
                max_tool_calls=budget.max_tool_calls_per_stage,
                attempt_timeout_seconds=remaining,
            )
            outcome = self.adapter.invoke_live(live_request)
            if outcome.kind is not ProviderCallKind.SUCCESS:
                raise ProtocolError("invoke_live returned a non-success outcome without raising")
            try:
                response = map_live_outcome_to_stage_response(outcome, live_request)
            except LiveContractError as exc:
                raise ProtocolError(f"live outcome could not map to stage artifacts: {exc}") from exc
            return response, outcome
        if profile == EXECUTION_PROFILE_PRE_LIVE_LEGACY:
            response = self.adapter.invoke(
                role_instruction=role_instruction,
                stage_inputs=stage_inputs,
                budget=budget,
                seed=run_spec.seed,
                timeout_seconds=remaining,
            )
            return response, None
        raise ProtocolError(f"unsupported execution profile {profile!r}")

    def _check_identity(
        self,
        run_spec: RunSpec,
        role: str,
        response: dict,
        *,
        provider_outcome=None,
        provider_identity_policy=None,
        attempt_timeout_seconds=None,
        response_latency_seconds=None,
    ) -> str | None:
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
        if provider_identity_policy is not None:
            verdict, reason = evaluate_provider_identity_policy(
                provider_identity_policy,
                requested_identity=self.adapter.identity,
                configured_identity=self.adapter.identity,
                outcome=provider_outcome,
                attempt_timeout_seconds=attempt_timeout_seconds,
                harness_observed_latency_seconds=response_latency_seconds,
            )
            if verdict != "passed":
                return f"provider identity governance failure in stage {role!r}: {reason}"
        return None

    @staticmethod
    def _check_output_and_tool_budget(role, budget, response) -> str | None:
        est_out = _estimate_tokens_out(response)
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
    def _check_contract(
        role: str, response: dict, state: _RunState, condition: Condition
    ) -> str | None:
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
                if condition is Condition.B:
                    if structured is not None:
                        raise ContractViolation(
                            "Condition B reviser must not emit Condition C structured dispositions"
                        )
                    return None
                if condition is not Condition.C:
                    return None
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
        state.evaluation_started = True
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
            state.evaluation_committed = True
            return
        state.evaluation_outcome = outcome
        if outcome.passed is not True:
            state.status = STATUS_FAILED_EVALUATION
        store.record_event(EVENT_EVALUATION, {"outcome": outcome.to_dict()})
        state.evaluation_committed = True

    def _finalize_interrupted_run(
        self, store: ArtifactStore, run_spec: RunSpec, state: _RunState
    ) -> None:
        self._reconcile_persisted_stage_seals(store, run_spec, state)
        if state.evaluation_committed:
            return
        if state.evaluation_started or _completed_stage_topology(run_spec, state):
            state.status = STATUS_FAILED_EVALUATION
            state.evaluation_error = INTERRUPTED_EVALUATION_MESSAGE
            state.evaluation_outcome = None
            store.record_event(
                EVENT_EVALUATION,
                {"status": STATUS_FAILED_EVALUATION, "error": state.evaluation_error},
                overwrite=True,
            )
            state.evaluation_committed = True
            return
        state.status = STATUS_INFRASTRUCTURE_FAILURE
        state.error = INTERRUPTED_INFRASTRUCTURE_MESSAGE
        manifest_path = store.run_dir / MANIFEST
        if not manifest_path.exists():
            manifest_path.write_text("", encoding="utf-8")

    def _reconcile_persisted_stage_seals(
        self, store: ArtifactStore, run_spec: RunSpec, state: _RunState
    ) -> None:
        """Make in-memory topology match durable success seals before terminalizing.

        A seal that has already been replaced onto disk is authoritative. The
        corresponding stage is recorded as succeeded so the terminal record
        cannot disagree with persisted evidence. A missing or malformed seal
        is not success: uncommitted residue for that role is aborted, and
        later stages are left unstarted.
        """
        expected = CONDITION_STAGES[run_spec.condition]
        recorded = {stage.role for stage in state.stage_results}
        for role in expected:
            reconstructed = _succeeded_stage_from_persisted_seal(store, role)
            if reconstructed is None:
                store.abort_uncommitted_stage(role)
                break
            store._sealed.add(role)
            if role not in recorded:
                state.stage_results.append(reconstructed)
                recorded.add(role)
            if role not in state.executed_roles:
                state.executed_roles.append(role)
        last = expected[-1] if expected else None
        if (
            last is not None
            and state.final_candidate_ref is None
            and any(
                stage.role == last and stage.status is StageStatus.SUCCEEDED
                for stage in state.stage_results
            )
        ):
            primary = PRIMARY_ARTIFACT.get(last)
            if primary:
                state.final_candidate_ref = f"{last}/{primary}.md"

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
            "run_id": run_spec.run_id,
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
            "authority_committed": bool(state.authority_committed)
            or (store.run_dir / RUN_AUTHORITY).is_file(),
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
    def hard_failure(cls, role, attempt, started, error, **result_fields):
        return cls(
            ok=False,
            failure_result=StageResult(
                role=role,
                attempt=attempt,
                status=StageStatus.FAILED,
                started_at=started,
                ended_at=_utcnow(),
                error=error,
                **result_fields,
            ),
        )


def _verified_identity_dict(identity_used: Mapping[str, str]) -> dict:
    d = {k: str(v) for k, v in identity_used.items()}
    d["identity_key"] = ":".join(
        d.get(k, "")
        for k in ("provider", "model_id", "model_version", "adapter_name", "adapter_version")
    )
    return d


def _completed_stage_topology(run_spec: RunSpec, state: _RunState) -> bool:
    expected = CONDITION_STAGES[run_spec.condition]
    if tuple(state.executed_roles) != expected:
        return False
    if len(state.stage_results) != len(expected):
        return False
    return all(stage.status is StageStatus.SUCCEEDED for stage in state.stage_results)


def _succeeded_stage_from_persisted_seal(store: ArtifactStore, role: str) -> StageResult | None:
    """Return a succeeded StageResult iff the active-run seal validator accepts it."""
    try:
        store.verify_sealed_stage(role)
        seal = json.loads((store.run_dir / "seals" / f"{role}.json").read_text(encoding="utf-8"))
        attempt = seal.get("expected_attempts")
        if type(attempt) is not int or isinstance(attempt, bool) or attempt < 1:
            return None
        refs = tuple(f"{role}/{name}.md" for name in EXPECTED_ARTIFACTS[role])
    except (IntegrityViolation, OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return None
    return StageResult(
        role=role,
        attempt=attempt,
        status=StageStatus.SUCCEEDED,
        output_refs=refs,
    )


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
    extra = set(structured) - {key}
    if extra:
        raise ContractViolation(
            f"structured payload has unexpected fields: {sorted(extra)}"
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
    extra = set(item) - {"finding_id", "description", "material"}
    if extra:
        raise ContractViolation(f"finding has unexpected fields: {sorted(extra)}")
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
    extra = set(item) - {"finding_id", "decision", "rationale"}
    if extra:
        raise ContractViolation(f"disposition has unexpected fields: {sorted(extra)}")
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
