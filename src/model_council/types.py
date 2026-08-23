"""Core typed structures for the M1 development harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

from .errors import (  # noqa: F401 - re-exported for compatibility
    ContractViolation,
    GovernanceViolation,
    InfrastructureError,
    IntegrityViolation,
    ModelFailure,
    ProtocolError,
    StageTimeout,
)
from .security import canonical_json, deep_freeze, digest_json


class Condition(str, Enum):
    A = "A"
    B = "B"
    C = "C"


class StageStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RETRY_EXHAUSTED = "retry_exhausted"


# Terminal run statuses. Every listed status has a concrete execution path:
#   succeeded              - all stages sealed + verified + evaluation passed/recorded
#   retry_exhausted        - model failures or enforced timeouts consumed the retry budget
#   failed_budget          - harness-estimated usage exceeded a stage ceiling
#   failed_contract        - structured output schema/disposition violation
#   failed_governance      - authority/boundary/integrity violation mid-run
#   failed_evaluation      - the External Evaluator itself raised
#   infrastructure_failure - worker crash, spawn failure, malformed protocol/metrics
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED_BUDGET = "failed_budget"
STATUS_FAILED_CONTRACT = "failed_contract"
STATUS_FAILED_GOVERNANCE = "failed_governance"
STATUS_FAILED_EVALUATION = "failed_evaluation"
STATUS_RETRY_EXHAUSTED = "retry_exhausted"
STATUS_INFRASTRUCTURE_FAILURE = "infrastructure_failure"


@dataclass(frozen=True)
class AdapterIdentity:
    """Stable identity contract for an adapter/model pair (Finding 3)."""

    provider: str
    model_id: str
    model_version: str
    adapter_name: str
    adapter_version: str

    def key(self) -> str:
        return f"{self.provider}:{self.model_id}:{self.model_version}:{self.adapter_name}:{self.adapter_version}"

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "identity_key": self.key(),
        }


@dataclass(frozen=True)
class Finding:
    finding_id: str
    description: str
    material: bool = True


@dataclass(frozen=True)
class Disposition:
    finding_id: str
    decision: str  # "accept" | "reject"
    rationale: str

    def validated(self) -> "Disposition":
        if self.decision not in ("accept", "reject"):
            raise ContractViolation(
                f"disposition for {self.finding_id!r} must be 'accept' or 'reject', got {self.decision!r}"
            )
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ContractViolation(
                f"disposition for {self.finding_id!r} is missing required rationale"
            )
        return self


def validate_findings(findings: tuple[Finding, ...]) -> None:
    seen: set[str] = set()
    for finding in findings:
        if not finding.finding_id or not isinstance(finding.finding_id, str):
            raise ContractViolation("verifier finding missing stable finding_id")
        if not isinstance(finding.description, str) or not finding.description.strip():
            raise ContractViolation(f"finding {finding.finding_id!r} missing description")
        if finding.finding_id in seen:
            raise ContractViolation(f"duplicate verifier finding id: {finding.finding_id!r}")
        seen.add(finding.finding_id)


def validate_dispositions(findings: tuple[Finding, ...], dispositions: tuple[Disposition, ...]) -> None:
    material_ids = [f.finding_id for f in findings if f.material]
    known_ids = {f.finding_id for f in findings}
    seen: set[str] = set()
    validated = []
    for disposition in dispositions:
        if disposition.finding_id not in known_ids:
            raise ContractViolation(
                f"disposition references unknown finding id {disposition.finding_id!r}"
            )
        if disposition.finding_id in seen:
            raise ContractViolation(
                f"duplicate disposition for finding {disposition.finding_id!r}"
            )
        seen.add(disposition.finding_id)
        validated.append(disposition.validated())
    missing = [fid for fid in material_ids if fid not in seen]
    if missing:
        raise ContractViolation(
            f"material findings without exactly one disposition: {missing}"
        )


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    bug_report: str
    workspace_id: str
    allowed_files: tuple[str, ...]
    visible_test_command: str | None = None
    snapshot_hash: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", deep_freeze(dict(self.metadata)))
        object.__setattr__(
            self, "allowed_files", tuple(str(f) for f in self.allowed_files)
        )

    @property
    def content_hash(self) -> str:
        return digest_json(
            {
                "task_id": self.task_id,
                "bug_report": self.bug_report,
                "workspace_id": self.workspace_id,
                "allowed_files": list(self.allowed_files),
                "visible_test_command": self.visible_test_command,
                "snapshot_hash": self.snapshot_hash,
            }
        )

    def agent_visible_text(self) -> str:
        parts = [
            f"# Bug report ({self.task_id})",
            self.bug_report,
            "",
            f"Workspace: {self.workspace_id}",
            f"In-scope files: {', '.join(self.allowed_files)}",
        ]
        if self.visible_test_command:
            parts.append(f"Visible test command: {self.visible_test_command}")
        return "\n".join(parts)


@dataclass(frozen=True)
class ResourceLimits:
    max_input_tokens_per_stage: int = 4096
    max_output_tokens_per_stage: int = 1024
    max_tool_calls_per_stage: int = 0
    stage_timeout_seconds: float = 60.0
    max_stage_retries: int = 2

    def __post_init__(self) -> None:
        if self.max_input_tokens_per_stage <= 0:
            raise ValueError("max_input_tokens_per_stage must be positive")
        if self.max_output_tokens_per_stage <= 0:
            raise ValueError("max_output_tokens_per_stage must be positive")
        if self.max_tool_calls_per_stage < 0:
            raise ValueError("max_tool_calls_per_stage must be non-negative")
        if self.stage_timeout_seconds <= 0:
            raise ValueError("stage_timeout_seconds must be positive")
        if self.max_stage_retries < 0:
            raise ValueError("max_stage_retries must be non-negative")

    def to_dict(self) -> dict:
        return {
            "max_input_tokens_per_stage": self.max_input_tokens_per_stage,
            "max_output_tokens_per_stage": self.max_output_tokens_per_stage,
            "max_tool_calls_per_stage": self.max_tool_calls_per_stage,
            "stage_timeout_seconds": self.stage_timeout_seconds,
            "max_stage_retries": self.max_stage_retries,
        }


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    task_id: str
    condition: Condition
    model_identifier: str
    prompt_version: str
    resource_limits: ResourceLimits
    seed: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", deep_freeze(dict(self.metadata)))

    def canonical(self) -> dict:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "condition": self.condition.value,
            "model_identifier": self.model_identifier,
            "prompt_version": self.prompt_version,
            "resource_limits": self.resource_limits.to_dict(),
            "seed": self.seed,
            "metadata": dict(self.metadata),
        }

    def canonical_json(self) -> str:
        return canonical_json(self.canonical())

    @property
    def spec_hash(self) -> str:
        import hashlib

        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass
class StageResult:
    role: str
    attempt: int
    status: StageStatus
    input_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()
    started_at: str | None = None
    ended_at: str | None = None
    error: str | None = None
    verified_identity: dict | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_units: float | None = None
    tool_uses: int | None = None
    # Usage accounting distinguishes harness-estimated (enforced against
    # ceilings) from adapter/provider-reported values. Estimated values are
    # NOT claimed to be independently verified provider numbers.
    usage_estimated: dict | None = None
    usage_reported: dict | None = None
    usage_source: str | None = None


@dataclass
class RunResult:
    run_id: str
    task_id: str
    condition: Condition
    model_identifier: str
    spec_hash: str
    status: str
    stage_results: list[StageResult]
    final_candidate_ref: str | None = None
    evaluation: Any = None
    retries_used: int = 0
    interventions: tuple[str, ...] = ()
    started_at: str | None = None
    ended_at: str | None = None
    workflow_note: str = ""
    treatment_hash: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
