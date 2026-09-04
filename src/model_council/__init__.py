"""Model Council Lab — M1 development harness.

The development harness now contains an activated OpenAI Responses live adapter.
SDK/request translation and offline transport evidence exist; no real provider
response has yet been exercised end-to-end. The Checkpoint 7 canary entrypoint
is development-only and guarded. Implementing the entrypoint does not authorize
executing it. Any real invocation requires later explicit Human Chair
authorization. A canary provides plumbing/integration evidence only.
"""

from .artifacts import ArtifactStore
from .executor import SubprocessAdapter
from .evaluator import EvaluationConfig, EvaluationOutcome, ExternalEvaluator
from .roles import (
    ALLOWED_INPUT_KEYS,
    CONDITION_STAGES,
    CONTEXT_POLICY_VERSION,
    validate_stage_sequence,
)
from .live_contract import (
    LIVE_CONTRACT_VERSION,
    LiveContractError,
    LiveInvocationRequest,
    NeutralError,
    NeutralProviderFailure,
    ProviderCallKind,
    ProviderCallOutcome,
    ProviderErrorCategory,
    UnavailableReason,
    build_live_invocation_request,
    parse_live_invocation_request,
    parse_neutral_error,
    parse_provider_call_outcome,
)
from .retry_policy import (
    NONRETRYABLE_PROVIDER_CATEGORIES,
    RETRYABLE_PROVIDER_CATEGORIES,
    is_retry_candidate,
)
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from .runner import ExperimentRunner
from .security import safe_identifier
from .types import (
    STATUS_FAILED_BUDGET,
    STATUS_FAILED_CONTRACT,
    STATUS_FAILED_EVALUATION,
    STATUS_FAILED_GOVERNANCE,
    STATUS_INFRASTRUCTURE_FAILURE,
    STATUS_RETRY_EXHAUSTED,
    STATUS_SUCCEEDED,
    AdapterIdentity,
    Condition,
    ContractViolation,
    Disposition,
    Finding,
    GovernanceViolation,
    InfrastructureError,
    IntegrityViolation,
    ModelFailure,
    ResourceLimits,
    RunResult,
    RunSpec,
    StageResult,
    StageStatus,
    StageTimeout,
    TaskSpec,
    validate_dispositions,
)

__all__ = [
    "ALLOWED_INPUT_KEYS",
    "AdapterIdentity",
    "ArtifactStore",
    "CONDITION_STAGES",
    "CONTEXT_POLICY_VERSION",
    "Condition",
    "ContractViolation",
    "Disposition",
    "EvaluationConfig",
    "EvaluationOutcome",
    "ExternalEvaluator",
    "ExperimentRunner",
    "EXECUTION_PROFILE_LIVE_CONTRACT_V1",
    "EXECUTION_PROFILE_PRE_LIVE_LEGACY",
    "HARNESS_PROTOCOL_VERSION",
    "LIVE_CONTRACT_VERSION",
    "LiveContractError",
    "LiveInvocationRequest",
    "Finding",
    "GovernanceViolation",
    "InfrastructureError",
    "IntegrityViolation",
    "ModelFailure",
    "NONRETRYABLE_PROVIDER_CATEGORIES",
    "NeutralError",
    "NeutralProviderFailure",
    "ProviderCallKind",
    "ProviderCallOutcome",
    "ProviderErrorCategory",
    "RETRYABLE_PROVIDER_CATEGORIES",
    "ResourceLimits",
    "RunResult",
    "RunSpec",
    "STATUS_FAILED_BUDGET",
    "STATUS_FAILED_CONTRACT",
    "STATUS_FAILED_EVALUATION",
    "STATUS_FAILED_GOVERNANCE",
    "STATUS_INFRASTRUCTURE_FAILURE",
    "STATUS_RETRY_EXHAUSTED",
    "STATUS_SUCCEEDED",
    "StageResult",
    "StageStatus",
    "StageTimeout",
    "SubprocessAdapter",
    "TaskSpec",
    "UnavailableReason",
    "build_live_invocation_request",
    "execution_profile_for_kind",
    "is_retry_candidate",
    "parse_live_invocation_request",
    "parse_neutral_error",
    "parse_provider_call_outcome",
    "safe_identifier",
    "validate_dispositions",
]
