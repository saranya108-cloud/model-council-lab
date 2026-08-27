"""Provider-neutral live invocation contract.

Types, JSON serialization, and validation. Adapters report evidence and a
neutral classification. This module does not decide whether another attempt
occurs; ExperimentRunner owns retry policy.

One LiveInvocationRequest represents exactly one runner-authorized attempt.
One ProviderCallOutcome represents exactly one provider request.

Remaining attempt timeout is recorded as enforcement metadata and is excluded
from the treatment/request-parameter digest.

Provider-reported usage is observational and must not be confused with the
harness-estimated token accounting used for M1 budget enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .errors import GovernanceViolation
from .roles import (
    ALLOWED_INPUT_KEYS,
    CONDITION_STAGES,
    EXPECTED_ARTIFACTS,
    PRIMARY_ARTIFACT,
    ROLE_REVISER,
    ROLE_VERIFIER,
)
from .security import (
    MAX_PROVIDER_TREATMENT_CONFIG_BYTES,
    MAX_PROVIDER_TREATMENT_CONFIG_DEPTH,
    MAX_PROVIDER_TREATMENT_CONFIG_ITEMS,
    MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES,
    SAFE_IDENTIFIER_RE,
    canonical_json,
    deep_freeze,
    digest_json,
    normalize_provider_treatment_config,
)
from .types import AdapterIdentity, Condition

LIVE_CONTRACT_VERSION = "m1-live-contract-v4"
MAX_PROVIDER_METADATA_BYTES = MAX_PROVIDER_TREATMENT_CONFIG_BYTES
MAX_PROVIDER_METADATA_DEPTH = MAX_PROVIDER_TREATMENT_CONFIG_DEPTH
MAX_PROVIDER_METADATA_ITEMS = MAX_PROVIDER_TREATMENT_CONFIG_ITEMS
MAX_PROVIDER_METADATA_STRING_BYTES = MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES
MESSAGE_REQUEST = "live_invocation_request"
MESSAGE_OUTCOME = "provider_call_outcome"

MAX_SANITIZED_MESSAGE_CHARS = 512
MAX_TRANSPORT_RAW_BYTES = 8_000_000
MAX_RAW_EVIDENCE_BYTES = 1_000_000
MAX_STRUCTURED_EVIDENCE_BYTES = 262_144
MAX_STRUCTURED_STRING_BYTES = 65_536
MAX_STRUCTURED_DEPTH = 8
MAX_STRUCTURED_KEYS = 256
# Hard live-contract transport bounds for the neutral stage_output envelope.
# These are safety ceilings, not the M1 experimental token budget.
MAX_STAGE_OUTPUT_STRING_BYTES = 1_000_000
MAX_STAGE_OUTPUT_ARTIFACTS = 32
MAX_STAGE_OUTPUT_ENVELOPE_BYTES = 1_500_000

DENIED_AUTHORITY = MappingProxyType(
    {
        "may_retry": False,
        "may_select_alternate_model": False,
        "may_write_artifacts": False,
        "may_access_evaluator": False,
    }
)

_AUTHORITY_FIELDS = tuple(DENIED_AUTHORITY.keys())

_FINDING_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id", "description", "material"],
    "properties": {
        "finding_id": {"type": "string"},
        "description": {"type": "string"},
        "material": {"type": "boolean"},
    },
}

_DISPOSITION_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["finding_id", "decision", "rationale"],
    "properties": {
        "finding_id": {"type": "string"},
        "decision": {"type": "string", "enum": ["accept", "reject"]},
        "rationale": {"type": "string"},
    },
}

_VERIFIER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": _FINDING_ITEM_SCHEMA,
        }
    },
}

_REVISER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["dispositions"],
    "properties": {
        "dispositions": {
            "type": "array",
            "items": _DISPOSITION_ITEM_SCHEMA,
        }
    },
}

_STRUCTURED_SCHEMAS: dict[str, tuple[str, dict[str, Any]]] = {
    "verifier": ("verifier_findings_v1", _VERIFIER_SCHEMA),
    "reviser": ("reviser_dispositions_v1", _REVISER_SCHEMA),
}

_IDENTITY_FIELDS = ("provider", "model_id", "model_version", "adapter_name", "adapter_version")
_OBSERVED_IDENTITY_FIELDS = frozenset({"provider", "model_id", "model_version"})
_USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_tokens",
    "output_tokens",
    "reasoning_tokens",
    "total_tokens",
)

_FORBIDDEN_KEYS = frozenset(
    {
        "authorization",
        "authentication",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "secrets",
        "cookie",
        "cookies",
        "header",
        "headers",
        "set_cookie",
        "env",
        "environment",
        "traceback",
        "stack",
        "stack_trace",
        "stacktrace",
        "credential",
        "credentials",
        "bearer",
        "private_key",
        "x_api_key",
        "runs_root",
        "run_dir",
        "artifact_path",
        "artifact_paths",
        "manifest_path",
        "evaluator_config",
        "evaluation_config",
        "hidden_tests",
        "hidden_checks",
        "retry_policy",
        "is_retryable",
        "should_retry",
        "retry_decision",
        "retryable",
        "max_stage_retries",
        "alternate_model",
        "alternate_models",
        "__reduce__",
        "__class__",
        "__dict__",
        "__module__",
    }
)

_FORBIDDEN_KEY_FRAGMENTS = (
    "header",
    "secret",
    "password",
    "credential",
    "traceback",
    "api_key",
    "authorization",
)

_FORBIDDEN_MESSAGE_MARKERS = (
    "traceback (most recent call last)",
    "authorization:",
    "bearer ",
    "x-api-key",
)

_REQUEST_FIELDS = frozenset(
    {
        "contract_version",
        "message_type",
        "condition",
        "role",
        "role_instruction",
        "stage_inputs",
        "input_content_digest",
        "output_contract",
        "requested_identity",
        "configured_identity",
        "seed",
        "max_output_tokens",
        "max_tool_calls",
        "attempt_timeout_seconds",
        "authority",
        "request_parameter_digest",
    }
)

_OUTPUT_CONTRACT_FIELDS = frozenset(
    {
        "expected_artifacts",
        "structured_required",
        "structured_schema_id",
        "structured_schema",
    }
)

_OUTCOME_FIELDS = frozenset(
    {
        "contract_version",
        "message_type",
        "kind",
        "requested_identity",
        "configured_identity",
        "provider_resolved_identity",
        "invocation_returned_identity",
        "provider_snapshot_identity",
        "provider_response_id",
        "provider_request_id",
        "provider_response_status",
        "finish_reason",
        "raw_output",
        "structured_output",
        "tool_use_count",
        "usage",
        "timing",
        "adapter_internal_retry_count",
        "error",
        "stage_output",
        "provider_metadata",
    }
)

_USAGE_OBJECT_FIELDS = frozenset({*_USAGE_FIELDS, "extra"})
_STAGE_OUTPUT_FIELDS = frozenset({"text", "artifacts", "structured"})
_TIMING_FIELDS = frozenset({"provider_processing_ms"})
_ERROR_FIELDS = frozenset(
    {
        "category",
        "sanitized_message",
        "http_status",
        "provider_retry_hint",
        "retry_after_seconds",
    }
)
_TREATMENT_DIGEST_EXCLUDED = frozenset({"request_parameter_digest", "attempt_timeout_seconds"})
PROVIDER_RETRY_HINT_SUGGESTED = "retry_suggested"
PROVIDER_RETRY_HINT_DISCOURAGED = "retry_discouraged"
_PROVIDER_RETRY_HINT_VALUES = frozenset(
    {PROVIDER_RETRY_HINT_SUGGESTED, PROVIDER_RETRY_HINT_DISCOURAGED}
)
_EXTRA_METRIC_FIELDS = frozenset({"namespace", "metrics"})
_PROVIDER_METADATA_OMITTED = object()


class LiveContractError(ValueError):
    """Malformed, incomplete, or unauthorized live-contract payload."""


class UnavailableReason(str, Enum):
    NOT_EXPOSED = "not_exposed"
    NO_RESPONSE_RECEIVED = "no_response_received"
    NOT_APPLICABLE = "not_applicable"


class ProviderCallKind(str, Enum):
    SUCCESS = "success"
    PROVIDER_ERROR = "provider_error"
    TRANSPORT_ERROR = "transport_error"


class ProviderErrorCategory(str, Enum):
    AUTHENTICATION_CONFIGURATION = "authentication_configuration"
    PERMISSION = "permission"
    MODEL_UNAVAILABLE = "model_unavailable"
    INVALID_REQUEST = "invalid_request"
    TRANSPORT_CONNECTIVITY = "transport_connectivity"
    TRANSPORT_PROVIDER_TIMEOUT = "transport_provider_timeout"
    RATE_LIMIT = "rate_limit"
    PROVIDER_OVERLOAD_INTERNAL = "provider_overload_internal"
    MALFORMED_PROVIDER_PROTOCOL = "malformed_provider_protocol"
    UNKNOWN_SANITIZED_FAILURE = "unknown_sanitized_failure"
    QUOTA_EXHAUSTED = "quota_exhausted"
    POLICY_REFUSAL = "policy_refusal"
    INCOMPLETE_PROVIDER_RESULT = "incomplete_provider_result"


_PROVIDER_ERROR_ONLY_CATEGORIES = frozenset(
    {
        ProviderErrorCategory.QUOTA_EXHAUSTED,
        ProviderErrorCategory.POLICY_REFUSAL,
        ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
    }
)


class FinishReason(str, Enum):
    COMPLETED = "completed"
    LENGTH = "length"
    INCOMPLETE = "incomplete"
    TOOL_USE = "tool_use"
    CONTENT_FILTER = "content_filter"
    ERROR = "error"


@dataclass(frozen=True)
class ObservedStr:
    value: str | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class ObservedInt:
    value: int | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class ObservedNumber:
    value: int | float | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class IdentityObservation:
    value: Mapping[str, str] | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": None if self.value is None else dict(self.value),
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class NamespacedMetrics:
    namespace: str
    metrics: Mapping[str, int | float]

    def to_dict(self) -> dict[str, Any]:
        return {"namespace": self.namespace, "metrics": dict(self.metrics)}


@dataclass(frozen=True)
class ObservedMetrics:
    value: NamespacedMetrics | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": None if self.value is None else self.value.to_dict(),
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class UntrustedStructured:
    value: Mapping[str, Any] | None
    unavailable_reason: UnavailableReason | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "untrusted": True,
            "value": None if self.value is None else _plain_json(self.value),
            "unavailable_reason": (
                None if self.unavailable_reason is None else self.unavailable_reason.value
            ),
        }


@dataclass(frozen=True)
class ProviderUsage:
    input_tokens: ObservedInt
    cached_input_tokens: ObservedInt
    cache_write_tokens: ObservedInt
    output_tokens: ObservedInt
    reasoning_tokens: ObservedInt
    total_tokens: ObservedInt
    extra: ObservedMetrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens.to_dict(),
            "cached_input_tokens": self.cached_input_tokens.to_dict(),
            "cache_write_tokens": self.cache_write_tokens.to_dict(),
            "output_tokens": self.output_tokens.to_dict(),
            "reasoning_tokens": self.reasoning_tokens.to_dict(),
            "total_tokens": self.total_tokens.to_dict(),
            "extra": self.extra.to_dict(),
        }


@dataclass(frozen=True)
class CallTiming:
    """Provider-reported timing only. Harness-observed latency is executor-owned."""

    provider_processing_ms: ObservedNumber

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_processing_ms": self.provider_processing_ms.to_dict(),
        }


@dataclass(frozen=True)
class NeutralError:
    """Sanitized provider/transport evidence. Not a retry decision."""

    category: ProviderErrorCategory
    sanitized_message: str
    http_status: ObservedInt
    provider_retry_hint: ObservedStr = field(
        default_factory=lambda: ObservedStr(
            value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED
        )
    )
    retry_after_seconds: ObservedNumber = field(
        default_factory=lambda: ObservedNumber(
            value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "sanitized_message": self.sanitized_message,
            "http_status": self.http_status.to_dict(),
            "provider_retry_hint": self.provider_retry_hint.to_dict(),
            "retry_after_seconds": self.retry_after_seconds.to_dict(),
        }


class NeutralProviderFailure(Exception):
    """Adapter-reported provider/transport failure evidence.

    Carries a NeutralError. Does not authorize another attempt; ExperimentRunner
    is the sole retry authority.
    """

    def __init__(self, error: NeutralError, *, outcome: ProviderCallOutcome | None = None):
        super().__init__(error.sanitized_message)
        self.error = error
        self.outcome = outcome


@dataclass(frozen=True)
class LiveInvocationRequest:
    """Runner-to-adapter payload for one authorized live attempt.

    `attempt_timeout_seconds` is remaining-time enforcement, not treatment.
    `request_parameter_digest` hashes frozen treatment parameters only.
    """

    contract_version: str
    condition: str
    role: str
    role_instruction: str
    stage_inputs: Mapping[str, str]
    input_content_digest: str
    output_contract: Mapping[str, Any]
    requested_identity: AdapterIdentity
    configured_identity: AdapterIdentity
    seed: int
    max_output_tokens: int
    max_tool_calls: int
    attempt_timeout_seconds: float
    authority: Mapping[str, bool]
    request_parameter_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "message_type": MESSAGE_REQUEST,
            "condition": self.condition,
            "role": self.role,
            "role_instruction": self.role_instruction,
            "stage_inputs": dict(self.stage_inputs),
            "input_content_digest": self.input_content_digest,
            "output_contract": _plain_json(self.output_contract),
            "requested_identity": self.requested_identity.to_dict(),
            "configured_identity": self.configured_identity.to_dict(),
            "seed": self.seed,
            "max_output_tokens": self.max_output_tokens,
            "max_tool_calls": self.max_tool_calls,
            "attempt_timeout_seconds": self.attempt_timeout_seconds,
            "authority": dict(self.authority),
            "request_parameter_digest": self.request_parameter_digest,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class ProviderCallOutcome:
    """Adapter-to-runner evidence for exactly one provider request."""

    contract_version: str
    kind: ProviderCallKind
    requested_identity: AdapterIdentity
    configured_identity: AdapterIdentity
    provider_resolved_identity: IdentityObservation
    invocation_returned_identity: IdentityObservation
    provider_snapshot_identity: ObservedStr
    provider_response_id: ObservedStr
    provider_request_id: ObservedStr
    provider_response_status: ObservedInt
    finish_reason: ObservedStr
    raw_output: ObservedStr
    structured_output: UntrustedStructured
    tool_use_count: int
    usage: ProviderUsage
    timing: CallTiming
    adapter_internal_retry_count: int
    error: NeutralError | None
    stage_output: Mapping[str, Any] | None
    provider_metadata: UntrustedStructured

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "message_type": MESSAGE_OUTCOME,
            "kind": self.kind.value,
            "requested_identity": self.requested_identity.to_dict(),
            "configured_identity": self.configured_identity.to_dict(),
            "provider_resolved_identity": self.provider_resolved_identity.to_dict(),
            "invocation_returned_identity": self.invocation_returned_identity.to_dict(),
            "provider_snapshot_identity": self.provider_snapshot_identity.to_dict(),
            "provider_response_id": self.provider_response_id.to_dict(),
            "provider_request_id": self.provider_request_id.to_dict(),
            "provider_response_status": self.provider_response_status.to_dict(),
            "finish_reason": self.finish_reason.to_dict(),
            "raw_output": self.raw_output.to_dict(),
            "structured_output": self.structured_output.to_dict(),
            "tool_use_count": self.tool_use_count,
            "usage": self.usage.to_dict(),
            "timing": self.timing.to_dict(),
            "adapter_internal_retry_count": self.adapter_internal_retry_count,
            "error": None if self.error is None else self.error.to_dict(),
            "stage_output": None if self.stage_output is None else _plain_json(self.stage_output),
            "provider_metadata": self.provider_metadata.to_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def build_live_invocation_request(
    *,
    condition: str | Condition,
    role: str,
    role_instruction: str,
    stage_inputs: Mapping[str, str],
    requested_identity: AdapterIdentity,
    configured_identity: AdapterIdentity,
    seed: int,
    max_output_tokens: int,
    max_tool_calls: int,
    attempt_timeout_seconds: float,
) -> LiveInvocationRequest:
    """Construct a validated request. Digests and denied authority are harness-owned."""
    parsed_condition = _parse_condition(condition)
    role = _parse_role_for_condition(parsed_condition, role)
    role_instruction = _require_text(role_instruction, "role_instruction")
    inputs = _parse_stage_inputs(parsed_condition, role, stage_inputs)
    _require_adapter_identity(requested_identity, "requested_identity")
    _require_adapter_identity(configured_identity, "configured_identity")
    seed = _require_int(seed, "seed", minimum=None)
    max_output_tokens = _require_int(max_output_tokens, "max_output_tokens", minimum=1)
    max_tool_calls = _require_int(max_tool_calls, "max_tool_calls", minimum=0)
    attempt_timeout_seconds = _require_positive_number(
        attempt_timeout_seconds, "attempt_timeout_seconds"
    )
    output_contract = _output_contract_for_stage(parsed_condition, role)
    input_digest = _input_content_digest(role_instruction, inputs)
    payload = {
        "contract_version": LIVE_CONTRACT_VERSION,
        "message_type": MESSAGE_REQUEST,
        "condition": parsed_condition.value,
        "role": role,
        "role_instruction": role_instruction,
        "stage_inputs": dict(inputs),
        "input_content_digest": input_digest,
        "output_contract": output_contract,
        "requested_identity": requested_identity.to_dict(),
        "configured_identity": configured_identity.to_dict(),
        "seed": seed,
        "max_output_tokens": max_output_tokens,
        "max_tool_calls": max_tool_calls,
        "attempt_timeout_seconds": attempt_timeout_seconds,
        "authority": dict(DENIED_AUTHORITY),
        "request_parameter_digest": "",
    }
    payload["request_parameter_digest"] = _request_parameter_digest(payload)
    return parse_live_invocation_request(payload)


def parse_live_invocation_request(payload: Any) -> LiveInvocationRequest:
    data = _closed_object(payload, _REQUEST_FIELDS, "live invocation request")
    version = _require_text(data["contract_version"], "contract_version")
    if version != LIVE_CONTRACT_VERSION:
        raise LiveContractError(f"unsupported contract version: {version!r}")
    message_type = _require_text(data["message_type"], "message_type")
    if message_type != MESSAGE_REQUEST:
        raise LiveContractError(f"invalid message_type: {message_type!r}")
    condition = _parse_condition(data["condition"])
    role = _parse_role_for_condition(condition, data["role"])
    role_instruction = _require_text(data["role_instruction"], "role_instruction")
    inputs = _parse_stage_inputs(condition, role, data["stage_inputs"])
    expected_contract = _output_contract_for_stage(condition, role)
    actual_contract = _parse_output_contract(data["output_contract"])
    if actual_contract != expected_contract:
        raise LiveContractError("output_contract does not match the condition/role frozen contract")
    requested = _parse_adapter_identity(data["requested_identity"], "requested_identity")
    configured = _parse_adapter_identity(data["configured_identity"], "configured_identity")
    seed = _require_int(data["seed"], "seed", minimum=None)
    max_output_tokens = _require_int(data["max_output_tokens"], "max_output_tokens", minimum=1)
    max_tool_calls = _require_int(data["max_tool_calls"], "max_tool_calls", minimum=0)
    attempt_timeout_seconds = _require_positive_number(
        data["attempt_timeout_seconds"], "attempt_timeout_seconds"
    )
    authority = _parse_authority(data["authority"])
    input_digest = _require_sha256(data["input_content_digest"], "input_content_digest")
    expected_input = _input_content_digest(role_instruction, inputs)
    if input_digest != expected_input:
        raise LiveContractError("input_content_digest does not match model-visible content")
    param_digest = _require_sha256(data["request_parameter_digest"], "request_parameter_digest")
    expected_param = _request_parameter_digest(data)
    if param_digest != expected_param:
        raise LiveContractError("request_parameter_digest does not match request parameters")
    return LiveInvocationRequest(
        contract_version=version,
        condition=condition.value,
        role=role,
        role_instruction=role_instruction,
        stage_inputs=MappingProxyType(dict(inputs)),
        input_content_digest=input_digest,
        output_contract=deep_freeze(expected_contract),
        requested_identity=requested,
        configured_identity=configured,
        seed=seed,
        max_output_tokens=max_output_tokens,
        max_tool_calls=max_tool_calls,
        attempt_timeout_seconds=attempt_timeout_seconds,
        authority=MappingProxyType(dict(authority)),
        request_parameter_digest=param_digest,
    )


def build_provider_call_outcome(
    *,
    kind: ProviderCallKind | str,
    requested_identity: AdapterIdentity,
    configured_identity: AdapterIdentity,
    provider_resolved_identity: IdentityObservation,
    invocation_returned_identity: IdentityObservation,
    provider_snapshot_identity: ObservedStr,
    provider_response_id: ObservedStr,
    provider_request_id: ObservedStr,
    provider_response_status: ObservedInt,
    finish_reason: ObservedStr,
    raw_output: ObservedStr,
    structured_output: UntrustedStructured,
    tool_use_count: int,
    usage: ProviderUsage,
    timing: CallTiming,
    adapter_internal_retry_count: int = 0,
    error: NeutralError | None = None,
    stage_output: Mapping[str, Any] | None = None,
    provider_metadata: UntrustedStructured | object = _PROVIDER_METADATA_OMITTED,
) -> ProviderCallOutcome:
    if not isinstance(provider_metadata, UntrustedStructured):
        raise LiveContractError(
            "provider_metadata must be an explicit UntrustedStructured observation; "
            "builder omission cannot synthesize empty metadata"
        )
    payload = {
        "contract_version": LIVE_CONTRACT_VERSION,
        "message_type": MESSAGE_OUTCOME,
        "kind": kind.value if isinstance(kind, ProviderCallKind) else kind,
        "requested_identity": requested_identity.to_dict(),
        "configured_identity": configured_identity.to_dict(),
        "provider_resolved_identity": provider_resolved_identity.to_dict(),
        "invocation_returned_identity": invocation_returned_identity.to_dict(),
        "provider_snapshot_identity": provider_snapshot_identity.to_dict(),
        "provider_response_id": provider_response_id.to_dict(),
        "provider_request_id": provider_request_id.to_dict(),
        "provider_response_status": provider_response_status.to_dict(),
        "finish_reason": finish_reason.to_dict(),
        "raw_output": raw_output.to_dict(),
        "structured_output": structured_output.to_dict(),
        "tool_use_count": tool_use_count,
        "usage": usage.to_dict(),
        "timing": timing.to_dict(),
        "adapter_internal_retry_count": adapter_internal_retry_count,
        "error": None if error is None else error.to_dict(),
        "stage_output": None if stage_output is None else dict(stage_output),
        "provider_metadata": provider_metadata.to_dict(),
    }
    return parse_provider_call_outcome(payload)


def parse_provider_call_outcome(payload: Any) -> ProviderCallOutcome:
    data = _closed_object(payload, _OUTCOME_FIELDS, "provider call outcome")
    version = _require_text(data["contract_version"], "contract_version")
    if version != LIVE_CONTRACT_VERSION:
        raise LiveContractError(f"unsupported contract version: {version!r}")
    message_type = _require_text(data["message_type"], "message_type")
    if message_type != MESSAGE_OUTCOME:
        raise LiveContractError(f"invalid message_type: {message_type!r}")
    kind = _parse_enum(data["kind"], ProviderCallKind, "kind")
    requested = _parse_adapter_identity(data["requested_identity"], "requested_identity")
    configured = _parse_adapter_identity(data["configured_identity"], "configured_identity")
    retry_count = _require_int(
        data["adapter_internal_retry_count"], "adapter_internal_retry_count", minimum=0
    )
    if retry_count != 0:
        raise LiveContractError("adapter_internal_retry_count must be 0; adapters may not retry")
    error = _parse_error(data["error"], kind)
    finish = _parse_observed_str(
        data["finish_reason"], "finish_reason", allowed_values={item.value for item in FinishReason}
    )
    _validate_success_finish_reason(kind, finish)
    raw_output = _parse_observed_str(
        data["raw_output"], "raw_output", allow_empty=True, max_bytes=MAX_TRANSPORT_RAW_BYTES
    )
    outcome = ProviderCallOutcome(
        contract_version=version,
        kind=kind,
        requested_identity=requested,
        configured_identity=configured,
        provider_resolved_identity=_parse_identity_observation(
            data["provider_resolved_identity"], "provider_resolved_identity"
        ),
        invocation_returned_identity=_parse_identity_observation(
            data["invocation_returned_identity"], "invocation_returned_identity"
        ),
        provider_snapshot_identity=_parse_observed_str(
            data["provider_snapshot_identity"], "provider_snapshot_identity"
        ),
        provider_response_id=_parse_observed_str(data["provider_response_id"], "provider_response_id"),
        provider_request_id=_parse_observed_str(data["provider_request_id"], "provider_request_id"),
        provider_response_status=_parse_http_status(
            data["provider_response_status"], "provider_response_status"
        ),
        finish_reason=finish,
        raw_output=raw_output,
        structured_output=_parse_structured_output(data["structured_output"]),
        tool_use_count=_require_int(data["tool_use_count"], "tool_use_count", minimum=0),
        usage=_parse_usage(data["usage"]),
        timing=_parse_timing(data["timing"]),
        adapter_internal_retry_count=retry_count,
        error=error,
        stage_output=_parse_stage_output(data["stage_output"], kind),
        provider_metadata=_parse_provider_metadata(data["provider_metadata"]),
    )
    return outcome


def dumps_live_invocation_request(request: LiveInvocationRequest) -> str:
    return request.to_json()


def dumps_provider_call_outcome(outcome: ProviderCallOutcome) -> str:
    return outcome.to_json()


def loads_live_invocation_request(raw: str) -> LiveInvocationRequest:
    return parse_live_invocation_request(_loads_object(raw, "live invocation request"))


def loads_provider_call_outcome(raw: str) -> ProviderCallOutcome:
    return parse_provider_call_outcome(_loads_object(raw, "provider call outcome"))


def unavailable(reason: UnavailableReason | str) -> ObservedStr:
    return ObservedStr(value=None, unavailable_reason=_as_reason(reason))


def unavailable_int(reason: UnavailableReason | str) -> ObservedInt:
    return ObservedInt(value=None, unavailable_reason=_as_reason(reason))


def unavailable_number(reason: UnavailableReason | str) -> ObservedNumber:
    return ObservedNumber(value=None, unavailable_reason=_as_reason(reason))


def unavailable_identity(reason: UnavailableReason | str) -> IdentityObservation:
    return IdentityObservation(value=None, unavailable_reason=_as_reason(reason))


def unavailable_metrics(reason: UnavailableReason | str) -> ObservedMetrics:
    return ObservedMetrics(value=None, unavailable_reason=_as_reason(reason))


def unavailable_structured(reason: UnavailableReason | str) -> UntrustedStructured:
    return UntrustedStructured(value=None, unavailable_reason=_as_reason(reason))


def observed_str(value: str) -> ObservedStr:
    if type(value) is not str or value == "":
        raise LiveContractError("observed string value must be a non-empty string")
    return ObservedStr(value=value, unavailable_reason=None)


def observed_int(value: int) -> ObservedInt:
    return ObservedInt(value=_require_int(value, "observed int", minimum=0), unavailable_reason=None)


def observed_number(value: int | float) -> ObservedNumber:
    return ObservedNumber(
        value=_require_non_negative_number(value, "observed number"), unavailable_reason=None
    )


def observed_identity(**fields: str) -> IdentityObservation:
    if not fields:
        raise LiveContractError("identity observation value must include at least one field")
    extra = set(fields) - _OBSERVED_IDENTITY_FIELDS
    if extra:
        raise LiveContractError(f"identity observation has unexpected fields: {sorted(extra)}")
    parsed: dict[str, str] = {}
    for key, value in fields.items():
        if type(value) is not str or not value:
            raise LiveContractError(f"identity observation {key} must be a non-empty string")
        parsed[key] = value
    return IdentityObservation(value=MappingProxyType(parsed), unavailable_reason=None)


def observed_metrics(namespace: str, metrics: Mapping[str, int | float]) -> ObservedMetrics:
    return ObservedMetrics(value=_parse_namespaced_metrics({"namespace": namespace, "metrics": dict(metrics)}, "extra"), unavailable_reason=None)


def observed_structured(value: Mapping[str, Any]) -> UntrustedStructured:
    parsed = _parse_json_object(value, "structured_output.value", depth=0)
    _reject_oversized_json(parsed, "structured_output.value")
    return UntrustedStructured(value=deep_freeze(parsed), unavailable_reason=None)


def observed_provider_metadata(value: Mapping[str, Any]) -> UntrustedStructured:
    return _parse_provider_metadata(
        {"untrusted": True, "value": dict(value), "unavailable_reason": None}
    )


def empty_provider_metadata() -> UntrustedStructured:
    return UntrustedStructured(value=MappingProxyType({}), unavailable_reason=None)


# ------------------------------------------------------------------ internals


def _loads_object(raw: str, label: str) -> dict[str, Any]:
    if type(raw) is not str:
        raise LiveContractError(f"{label} JSON must be a string")
    import json

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LiveContractError(f"{label} is not valid JSON: {exc}") from exc
    if type(payload) is not dict:
        raise LiveContractError(f"{label} JSON must be an object")
    return payload


def _plain_json(value: Any) -> Any:
    return _parse_json_value(value, "json value", depth=0, allow_object=True)


def _output_contract_for_stage(condition: Condition, role: str) -> dict[str, Any]:
    artifacts = sorted(EXPECTED_ARTIFACTS[role])
    if condition is Condition.C and role == ROLE_VERIFIER:
        schema_id, schema = _STRUCTURED_SCHEMAS["verifier"]
        return {
            "expected_artifacts": artifacts,
            "structured_required": True,
            "structured_schema_id": schema_id,
            "structured_schema": schema,
        }
    if condition is Condition.C and role == ROLE_REVISER:
        schema_id, schema = _STRUCTURED_SCHEMAS["reviser"]
        return {
            "expected_artifacts": artifacts,
            "structured_required": True,
            "structured_schema_id": schema_id,
            "structured_schema": schema,
        }
    return {
        "expected_artifacts": artifacts,
        "structured_required": False,
        "structured_schema_id": None,
        "structured_schema": None,
    }


def _input_content_digest(role_instruction: str, stage_inputs: Mapping[str, str]) -> str:
    return digest_json({"role_instruction": role_instruction, "stage_inputs": dict(stage_inputs)})


def _request_parameter_digest(payload: Mapping[str, Any]) -> str:
    """Hash frozen treatment parameters. Remaining timeout is excluded."""
    body = {
        key: payload[key]
        for key in sorted(_REQUEST_FIELDS)
        if key not in _TREATMENT_DIGEST_EXCLUDED
    }
    return digest_json(body)


def _parse_output_contract(payload: Any) -> dict[str, Any]:
    data = _closed_object(payload, _OUTPUT_CONTRACT_FIELDS, "output_contract")
    artifacts = data["expected_artifacts"]
    if type(artifacts) is not list or any(type(item) is not str for item in artifacts):
        raise LiveContractError("output_contract.expected_artifacts must be an array of strings")
    if artifacts != sorted(artifacts) or len(set(artifacts)) != len(artifacts):
        raise LiveContractError("output_contract.expected_artifacts must be unique and sorted")
    structured_required = data["structured_required"]
    if type(structured_required) is not bool:
        raise LiveContractError("output_contract.structured_required must be a boolean")
    schema_id = data["structured_schema_id"]
    schema = data["structured_schema"]
    if structured_required:
        schema_id = _require_text(schema_id, "output_contract.structured_schema_id")
        schema_obj = _parse_json_object(schema, "output_contract.structured_schema", depth=0)
        return {
            "expected_artifacts": list(artifacts),
            "structured_required": True,
            "structured_schema_id": schema_id,
            "structured_schema": schema_obj,
        }
    if schema_id is not None or schema is not None:
        raise LiveContractError("structured schema must be null when structured_required is false")
    return {
        "expected_artifacts": list(artifacts),
        "structured_required": False,
        "structured_schema_id": None,
        "structured_schema": None,
    }


def _parse_condition(value: Any) -> Condition:
    if isinstance(value, Condition):
        return value
    if type(value) is not str:
        raise LiveContractError(f"condition must be a string, got {type(value).__name__}")
    try:
        return Condition(value)
    except ValueError as exc:
        raise LiveContractError(f"invalid condition: {value!r}") from exc


def _parse_role_for_condition(condition: Condition, role: Any) -> str:
    if type(role) is not str or role not in PRIMARY_ARTIFACT:
        raise LiveContractError(f"invalid role: {role!r}")
    allowed_roles = CONDITION_STAGES[condition]
    if role not in allowed_roles:
        raise LiveContractError(
            f"role {role!r} is not part of condition {condition.value}; "
            f"allowed={list(allowed_roles)}"
        )
    return role


def _parse_role(role: Any) -> str:
    if type(role) is not str or role not in PRIMARY_ARTIFACT:
        raise LiveContractError(f"invalid role: {role!r}")
    return role


def _parse_stage_inputs(condition: Condition, role: str, payload: Any) -> dict[str, str]:
    data = _require_object(payload, "stage_inputs")
    allowed = ALLOWED_INPUT_KEYS.get((condition, role))
    if allowed is None:
        raise LiveContractError(
            f"no context policy defined for condition={condition.value} role={role}"
        )
    parsed: dict[str, str] = {}
    for key, value in data.items():
        _reject_dangerous_key(key, "stage_inputs")
        if type(key) is not str or key not in allowed:
            raise LiveContractError(
                f"stage_inputs contains unauthorized key {key!r} for "
                f"condition {condition.value} role {role!r}"
            )
        if type(value) is not str:
            raise LiveContractError(f"stage_inputs[{key!r}] must be a string")
        parsed[key] = value
    if set(parsed) != set(allowed):
        raise LiveContractError(
            f"stage_inputs must be exactly {sorted(allowed)} for "
            f"condition {condition.value} role {role!r}; got {sorted(parsed)}"
        )
    return parsed


def _parse_authority(payload: Any) -> dict[str, bool]:
    data = _closed_object(payload, frozenset(_AUTHORITY_FIELDS), "authority")
    parsed: dict[str, bool] = {}
    for key in _AUTHORITY_FIELDS:
        value = data[key]
        if type(value) is not bool:
            raise LiveContractError(f"authority.{key} must be a boolean")
        if value is not False:
            raise LiveContractError(f"authority.{key} must be false; adapters have no such authority")
        parsed[key] = False
    return parsed


def _parse_adapter_identity(payload: Any, label: str) -> AdapterIdentity:
    data = _require_object(payload, label)
    allowed = set(_IDENTITY_FIELDS) | {"identity_key"}
    extra = set(data) - allowed
    if extra:
        raise LiveContractError(f"{label} has unexpected fields: {sorted(extra)}")
    missing = (set(_IDENTITY_FIELDS) | {"identity_key"}) - set(data)
    if missing:
        raise LiveContractError(f"{label} missing mandatory fields: {sorted(missing)}")
    for key in _IDENTITY_FIELDS:
        _reject_dangerous_key(key, label)
        value = data[key]
        if type(value) is not str or not value:
            raise LiveContractError(f"{label}.{key} must be a non-empty string")
    identity = AdapterIdentity(
        provider=data["provider"],
        model_id=data["model_id"],
        model_version=data["model_version"],
        adapter_name=data["adapter_name"],
        adapter_version=data["adapter_version"],
    )
    identity_key = data["identity_key"]
    if type(identity_key) is not str or identity_key != identity.key():
        raise LiveContractError(f"{label}.identity_key does not match identity fields")
    return identity


def _require_adapter_identity(value: Any, label: str) -> AdapterIdentity:
    if not isinstance(value, AdapterIdentity):
        raise LiveContractError(f"{label} must be an AdapterIdentity")
    for field_name in _IDENTITY_FIELDS:
        field_value = getattr(value, field_name)
        if type(field_value) is not str or not field_value:
            raise LiveContractError(f"{label}.{field_name} must be a non-empty string")
    return value


def _parse_identity_observation(payload: Any, label: str) -> IdentityObservation:
    data = _closed_object(payload, frozenset({"value", "unavailable_reason"}), label)
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return IdentityObservation(value=None, unavailable_reason=_parse_reason(reason, label))
    if reason is not None:
        raise LiveContractError(f"{label} cannot combine a value with unavailable_reason")
    obj = _require_object(value, f"{label}.value")
    extra = set(obj) - _OBSERVED_IDENTITY_FIELDS
    if extra:
        raise LiveContractError(f"{label}.value has unexpected fields: {sorted(extra)}")
    if not obj:
        raise LiveContractError(f"{label}.value must contain at least one identity field")
    parsed: dict[str, str] = {}
    for key, item in obj.items():
        _reject_dangerous_key(key, label)
        if type(item) is not str or not item:
            raise LiveContractError(f"{label}.value.{key} must be a non-empty string")
        parsed[key] = item
    return IdentityObservation(value=MappingProxyType(parsed), unavailable_reason=None)


def _parse_observed_str(
    payload: Any,
    label: str,
    *,
    allowed_values: set[str] | None = None,
    allow_empty: bool = False,
    max_chars: int | None = None,
    max_bytes: int | None = None,
) -> ObservedStr:
    data = _closed_object(payload, frozenset({"value", "unavailable_reason"}), label)
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return ObservedStr(value=None, unavailable_reason=_parse_reason(reason, label))
    if reason is not None:
        raise LiveContractError(f"{label} cannot combine a value with unavailable_reason")
    if type(value) is not str:
        raise LiveContractError(f"{label}.value must be a string")
    if value == "" and not allow_empty:
        raise LiveContractError(f"{label}.value must be a non-empty string")
    if max_chars is not None and len(value) > max_chars:
        raise LiveContractError(f"{label}.value exceeds the {max_chars}-character limit")
    if max_bytes is not None and len(value.encode("utf-8")) > max_bytes:
        raise LiveContractError(f"{label}.value exceeds the {max_bytes}-byte limit")
    if allowed_values is not None and value not in allowed_values:
        raise LiveContractError(f"{label}.value is not an allowed value: {value!r}")
    return ObservedStr(value=value, unavailable_reason=None)


def _parse_observed_int(payload: Any, label: str, *, minimum: int = 0) -> ObservedInt:
    data = _closed_object(payload, frozenset({"value", "unavailable_reason"}), label)
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return ObservedInt(value=None, unavailable_reason=_parse_reason(reason, label))
    if reason is not None:
        raise LiveContractError(f"{label} cannot combine a value with unavailable_reason")
    return ObservedInt(value=_require_int(value, f"{label}.value", minimum=minimum), unavailable_reason=None)


def _parse_observed_number(payload: Any, label: str) -> ObservedNumber:
    data = _closed_object(payload, frozenset({"value", "unavailable_reason"}), label)
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return ObservedNumber(value=None, unavailable_reason=_parse_reason(reason, label))
    if reason is not None:
        raise LiveContractError(f"{label} cannot combine a value with unavailable_reason")
    return ObservedNumber(
        value=_require_non_negative_number(value, f"{label}.value"), unavailable_reason=None
    )


def _parse_http_status(payload: Any, label: str) -> ObservedInt:
    observed = _parse_observed_int(payload, label, minimum=100)
    if observed.value is not None and observed.value > 599:
        raise LiveContractError(f"{label}.value must be an HTTP status between 100 and 599")
    return observed


def _as_reason(reason: UnavailableReason | str) -> UnavailableReason:
    if isinstance(reason, UnavailableReason):
        return reason
    return _parse_reason(reason, "unavailable_reason")


def _parse_reason(value: Any, label: str) -> UnavailableReason:
    return _parse_enum(value, UnavailableReason, f"{label}.unavailable_reason")


def _parse_enum(value: Any, enum_cls: type[Enum], label: str):
    if isinstance(value, enum_cls):
        return value
    if type(value) is not str:
        raise LiveContractError(f"{label} must be a string")
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise LiveContractError(f"invalid {label}: {value!r}") from exc


def _parse_structured_output(payload: Any) -> UntrustedStructured:
    data = _closed_object(
        payload, frozenset({"untrusted", "value", "unavailable_reason"}), "structured_output"
    )
    if data["untrusted"] is not True:
        raise LiveContractError("structured_output.untrusted must be true")
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return UntrustedStructured(value=None, unavailable_reason=_parse_reason(reason, "structured_output"))
    if reason is not None:
        raise LiveContractError("structured_output cannot combine a value with unavailable_reason")
    parsed = _parse_json_object(value, "structured_output.value", depth=0)
    _reject_oversized_json(parsed, "structured_output.value")
    return UntrustedStructured(value=deep_freeze(parsed), unavailable_reason=None)


def _parse_provider_metadata(payload: Any) -> UntrustedStructured:
    data = _closed_object(
        payload, frozenset({"untrusted", "value", "unavailable_reason"}), "provider_metadata"
    )
    if data["untrusted"] is not True:
        raise LiveContractError("provider_metadata.untrusted must be true")
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return UntrustedStructured(
            value=None, unavailable_reason=_parse_reason(reason, "provider_metadata")
        )
    if reason is not None:
        raise LiveContractError("provider_metadata cannot combine a value with unavailable_reason")
    if type(value) is not dict:
        raise LiveContractError(
            f"provider_metadata.value must be a JSON object, got {type(value).__name__}"
        )
    _reject_dangerous_keys_in_json(value, "provider_metadata.value")
    try:
        parsed = normalize_provider_treatment_config(value, label="provider_metadata.value")
    except GovernanceViolation as exc:
        raise LiveContractError(str(exc)) from exc
    return UntrustedStructured(value=deep_freeze(parsed), unavailable_reason=None)


def _reject_dangerous_keys_in_json(value: Any, label: str) -> None:
    if type(value) is dict or isinstance(value, MappingProxyType):
        for key, item in value.items():
            if type(key) is not str:
                raise LiveContractError(f"{label} keys must be strings")
            _reject_dangerous_key(key, label)
            _reject_dangerous_keys_in_json(item, f"{label}.{key}")
        return
    if type(value) is list or type(value) is tuple:
        for index, item in enumerate(value):
            _reject_dangerous_keys_in_json(item, f"{label}[{index}]")


def _validate_success_finish_reason(kind: ProviderCallKind, finish: ObservedStr) -> None:
    if kind is not ProviderCallKind.SUCCESS:
        return
    if finish.value is not None:
        if finish.value != FinishReason.COMPLETED.value:
            raise LiveContractError(
                f"success outcomes cannot observe finish_reason {finish.value!r}"
            )
        return
    reason = finish.unavailable_reason
    if reason not in (UnavailableReason.NOT_EXPOSED, UnavailableReason.NOT_APPLICABLE):
        raise LiveContractError(
            "success outcomes cannot use unavailable finish_reason "
            f"{None if reason is None else reason.value!r}"
        )


def _parse_usage(payload: Any) -> ProviderUsage:
    data = _closed_object(payload, _USAGE_OBJECT_FIELDS, "usage")
    return ProviderUsage(
        input_tokens=_parse_observed_int(data["input_tokens"], "usage.input_tokens"),
        cached_input_tokens=_parse_observed_int(
            data["cached_input_tokens"], "usage.cached_input_tokens"
        ),
        cache_write_tokens=_parse_observed_int(data["cache_write_tokens"], "usage.cache_write_tokens"),
        output_tokens=_parse_observed_int(data["output_tokens"], "usage.output_tokens"),
        reasoning_tokens=_parse_observed_int(data["reasoning_tokens"], "usage.reasoning_tokens"),
        total_tokens=_parse_observed_int(data["total_tokens"], "usage.total_tokens"),
        extra=_parse_observed_metrics(data["extra"], "usage.extra"),
    )


def _parse_observed_metrics(payload: Any, label: str) -> ObservedMetrics:
    data = _closed_object(payload, frozenset({"value", "unavailable_reason"}), label)
    value = data["value"]
    reason = data["unavailable_reason"]
    if value is None:
        return ObservedMetrics(value=None, unavailable_reason=_parse_reason(reason, label))
    if reason is not None:
        raise LiveContractError(f"{label} cannot combine a value with unavailable_reason")
    return ObservedMetrics(value=_parse_namespaced_metrics(value, label), unavailable_reason=None)


def _parse_namespaced_metrics(payload: Any, label: str) -> NamespacedMetrics:
    data = _closed_object(payload, _EXTRA_METRIC_FIELDS, f"{label}.value")
    namespace = data["namespace"]
    if type(namespace) is not str or not SAFE_IDENTIFIER_RE.match(namespace):
        raise LiveContractError(f"{label}.namespace must be a safe identifier")
    _reject_dangerous_key(namespace, f"{label}.namespace")
    metrics = _require_object(data["metrics"], f"{label}.metrics")
    if not metrics:
        raise LiveContractError(f"{label}.metrics must not be empty when extra usage is present")
    parsed: dict[str, int | float] = {}
    for key, value in metrics.items():
        if type(key) is not str or not SAFE_IDENTIFIER_RE.match(key):
            raise LiveContractError(f"{label}.metrics contains an unsafe key {key!r}")
        _reject_dangerous_key(key, f"{label}.metrics")
        parsed[key] = _require_non_negative_number(value, f"{label}.metrics.{key}")
    return NamespacedMetrics(namespace=namespace, metrics=MappingProxyType(parsed))


def _parse_timing(payload: Any) -> CallTiming:
    data = _closed_object(payload, _TIMING_FIELDS, "timing")
    return CallTiming(
        provider_processing_ms=_parse_observed_number(
            data["provider_processing_ms"], "timing.provider_processing_ms"
        ),
    )


def _parse_error(payload: Any, kind: ProviderCallKind) -> NeutralError | None:
    if kind is ProviderCallKind.SUCCESS:
        if payload is not None:
            raise LiveContractError("success outcomes must not include an error record")
        return None
    if payload is None:
        raise LiveContractError(f"{kind.value} outcomes require a sanitized error record")
    data = _closed_object(payload, _ERROR_FIELDS, "error")
    message = _require_text(data["sanitized_message"], "error.sanitized_message")
    if len(message) > MAX_SANITIZED_MESSAGE_CHARS:
        raise LiveContractError("error.sanitized_message exceeds the 512-character limit")
    lowered = message.lower()
    for marker in _FORBIDDEN_MESSAGE_MARKERS:
        if marker in lowered:
            raise LiveContractError("error.sanitized_message contains forbidden secret or traceback content")
    category = _parse_enum(data["category"], ProviderErrorCategory, "error.category")
    if category in _PROVIDER_ERROR_ONLY_CATEGORIES and kind is not ProviderCallKind.PROVIDER_ERROR:
        raise LiveContractError(
            f"{category.value} must be reported as provider_error, not {kind.value}"
        )
    return NeutralError(
        category=category,
        sanitized_message=message,
        http_status=_parse_http_status(data["http_status"], "error.http_status"),
        provider_retry_hint=_parse_observed_str(
            data["provider_retry_hint"],
            "error.provider_retry_hint",
            allowed_values=_PROVIDER_RETRY_HINT_VALUES,
        ),
        retry_after_seconds=_parse_observed_number(
            data["retry_after_seconds"], "error.retry_after_seconds"
        ),
    )


def _parse_stage_output(payload: Any, kind: ProviderCallKind) -> dict[str, Any] | None:
    if kind is not ProviderCallKind.SUCCESS:
        if payload is not None:
            raise LiveContractError("non-success outcomes must not include stage_output")
        return None
    data = _closed_object(payload, _STAGE_OUTPUT_FIELDS, "stage_output")
    text = data["text"]
    if type(text) is not str:
        raise LiveContractError(f"stage_output.text must be a string, got {type(text).__name__}")
    _reject_oversized_stage_string(text, "stage_output.text")
    artifacts_raw = _require_object(data["artifacts"], "stage_output.artifacts")
    if len(artifacts_raw) > MAX_STAGE_OUTPUT_ARTIFACTS:
        raise LiveContractError(
            f"stage_output.artifacts exceeds the {MAX_STAGE_OUTPUT_ARTIFACTS}-artifact limit"
        )
    artifacts: dict[str, str] = {}
    for name, content in artifacts_raw.items():
        if type(name) is not str or not name:
            raise LiveContractError("stage_output.artifacts keys must be non-empty strings")
        if "/" in name or "\\" in name or name in {".", ".."}:
            raise LiveContractError(f"stage_output.artifacts contains a path-like name {name!r}")
        if type(content) is not str:
            raise LiveContractError(f"stage_output.artifacts[{name!r}] must be a string")
        _reject_oversized_stage_string(content, f"stage_output.artifacts[{name!r}]")
        artifacts[name] = content
    structured = data["structured"]
    if structured is not None:
        structured = _parse_json_object(structured, "stage_output.structured", depth=0)
        _reject_oversized_json(structured, "stage_output.structured")
    envelope = {
        "text": text,
        "artifacts": artifacts,
        "structured": structured,
    }
    encoded = canonical_json(envelope).encode("utf-8")
    if len(encoded) > MAX_STAGE_OUTPUT_ENVELOPE_BYTES:
        raise LiveContractError(
            "stage_output exceeds the "
            f"{MAX_STAGE_OUTPUT_ENVELOPE_BYTES}-byte envelope limit"
        )
    return envelope


def _reject_oversized_stage_string(value: str, label: str) -> None:
    size = len(value.encode("utf-8"))
    if size > MAX_STAGE_OUTPUT_STRING_BYTES:
        raise LiveContractError(
            f"{label} exceeds the {MAX_STAGE_OUTPUT_STRING_BYTES}-byte stage-output string limit"
        )


def _is_schema_object(schema: Any) -> bool:
    return type(schema) is dict or type(schema) is MappingProxyType


def validate_closed_schema(instance: Any, schema: Mapping[str, Any], label: str = "structured") -> None:
    """Fail-closed subset of JSON Schema for exact experimental structured output."""
    if not _is_schema_object(schema):
        raise LiveContractError(f"{label} schema must be an object")
    expected_type = schema.get("type")
    if expected_type == "object":
        if type(instance) is not dict:
            raise LiveContractError(f"{label} must be an object, got {type(instance).__name__}")
        properties = schema.get("properties") or {}
        required = schema.get("required") or []
        additional = schema.get("additionalProperties", True)
        missing = [key for key in required if key not in instance]
        if missing:
            raise LiveContractError(f"{label} missing required fields: {missing}")
        extra = set(instance) - set(properties)
        if additional is False and extra:
            raise LiveContractError(f"{label} has unexpected fields: {sorted(extra)}")
        for key, value in instance.items():
            if key in properties:
                validate_closed_schema(value, properties[key], f"{label}.{key}")
        return
    if expected_type == "array":
        if type(instance) is not list:
            raise LiveContractError(f"{label} must be an array, got {type(instance).__name__}")
        item_schema = schema.get("items") or {}
        for index, item in enumerate(instance):
            validate_closed_schema(item, item_schema, f"{label}[{index}]")
        return
    if expected_type == "string":
        if type(instance) is not str:
            raise LiveContractError(f"{label} must be a string, got {type(instance).__name__}")
    elif expected_type == "boolean":
        if type(instance) is not bool:
            raise LiveContractError(f"{label} must be a boolean, got {type(instance).__name__}")
    allowed = schema.get("enum")
    if allowed is not None and instance not in allowed:
        raise LiveContractError(f"{label} is not an allowed value: {instance!r}")


def map_live_outcome_to_stage_response(
    outcome: ProviderCallOutcome, request: LiveInvocationRequest
) -> dict[str, Any]:
    """Runner-owned mapping from a validated live outcome into existing stage fields.

    Artifact names are taken from the outcome but must later match the request
    contract; the adapter cannot invent a promotion path.
    """
    if outcome.kind is not ProviderCallKind.SUCCESS or outcome.stage_output is None:
        raise LiveContractError("only a successful live outcome can map to stage artifacts")
    stage = outcome.stage_output
    identity = dict(outcome.configured_identity.to_dict())
    observed = outcome.invocation_returned_identity.value
    if observed:
        for key, value in observed.items():
            identity[key] = value
    expected = set(request.output_contract["expected_artifacts"])
    actual = set(stage["artifacts"])
    if actual != expected:
        # Leave the mismatch visible to runner contract validation.
        pass
    if request.output_contract["structured_required"]:
        structured = stage["structured"]
        if structured is None:
            raise LiveContractError("structured output is required for this condition/role")
    elif stage["structured"] is not None:
        raise LiveContractError(
            "structured output is not part of this condition/role contract"
        )
    return {
        "text": stage["text"],
        "artifacts": dict(stage["artifacts"]),
        "structured": stage["structured"],
        "identity_used": identity,
        "tokens_in": 0,
        "tokens_out": 0,
        "tool_uses": outcome.tool_use_count,
        "cost_units": None,
    }


def parse_neutral_error(payload: Any) -> NeutralError:
    """Validate adapter-reported NeutralError evidence. Not a retry decision."""
    return _parse_error(payload, ProviderCallKind.PROVIDER_ERROR)


def _parse_json_object(payload: Any, label: str, *, depth: int) -> dict[str, Any]:
    data = _require_object(payload, label)
    if len(data) > MAX_STRUCTURED_KEYS:
        raise LiveContractError(f"{label} has too many keys")
    parsed: dict[str, Any] = {}
    for key, value in data.items():
        if type(key) is not str or not key:
            raise LiveContractError(f"{label} keys must be non-empty strings")
        _reject_dangerous_key(key, label)
        parsed[key] = _parse_json_value(value, f"{label}.{key}", depth=depth + 1, allow_object=True)
    return parsed


def _reject_oversized_json(payload: Any, label: str) -> None:
    encoded = canonical_json(payload).encode("utf-8")
    if len(encoded) > MAX_STRUCTURED_EVIDENCE_BYTES:
        raise LiveContractError(
            f"{label} exceeds the {MAX_STRUCTURED_EVIDENCE_BYTES}-byte structured evidence limit"
        )


def _parse_json_value(value: Any, label: str, *, depth: int, allow_object: bool) -> Any:
    if depth > MAX_STRUCTURED_DEPTH:
        raise LiveContractError(f"{label} exceeds the maximum JSON nesting depth")
    if value is None or type(value) in (str, int, float) and type(value) is not bool:
        if type(value) is str and len(value.encode("utf-8")) > MAX_STRUCTURED_STRING_BYTES:
            raise LiveContractError(
                f"{label} exceeds the {MAX_STRUCTURED_STRING_BYTES}-byte string limit"
            )
        if type(value) is float and (value != value or value in (float("inf"), float("-inf"))):
            raise LiveContractError(f"{label} must be a finite JSON number")
        return value
    if type(value) is bool:
        return value
    if type(value) is list:
        if len(value) > MAX_STRUCTURED_KEYS:
            raise LiveContractError(f"{label} has too many items")
        return [
            _parse_json_value(item, f"{label}[{index}]", depth=depth + 1, allow_object=True)
            for index, item in enumerate(value)
        ]
    if type(value) is dict and allow_object:
        return _parse_json_object(value, label, depth=depth)
    if isinstance(value, MappingProxyType):
        return _parse_json_object(dict(value), label, depth=depth)
    if isinstance(value, tuple):
        return [
            _parse_json_value(item, f"{label}[{index}]", depth=depth + 1, allow_object=True)
            for index, item in enumerate(value)
        ]
    raise LiveContractError(f"{label} is not a JSON value ({type(value).__name__})")


def _closed_object(payload: Any, allowed: frozenset[str], label: str) -> dict[str, Any]:
    data = _require_object(payload, label)
    extra = set(data) - allowed
    if extra:
        raise LiveContractError(f"{label} has unexpected fields: {sorted(extra)}")
    missing = allowed - set(data)
    if missing:
        raise LiveContractError(f"{label} missing mandatory fields: {sorted(missing)}")
    for key in data:
        _reject_dangerous_key(key, label)
    return data


def _require_object(payload: Any, label: str) -> dict[str, Any]:
    if type(payload) is not dict:
        raise LiveContractError(f"{label} must be an object, got {type(payload).__name__}")
    return payload


def _require_text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise LiveContractError(f"{label} must be a non-empty string")
    return value


def _require_sha256(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise LiveContractError(f"{label} must be a lowercase SHA-256 hex digest")
    return text


def _require_int(value: Any, label: str, *, minimum: int | None) -> int:
    if type(value) is bool or type(value) is not int:
        raise LiveContractError(f"{label} must be an integer, got {type(value).__name__}")
    if minimum is not None and value < minimum:
        raise LiveContractError(f"{label} must be >= {minimum}, got {value}")
    return value


def _require_positive_number(value: Any, label: str) -> float:
    number = _require_number(value, label)
    if number <= 0:
        raise LiveContractError(f"{label} must be positive")
    return number


def _require_non_negative_number(value: Any, label: str) -> float | int:
    number = _require_number(value, label)
    if number < 0:
        raise LiveContractError(f"{label} must be non-negative")
    return number


def _require_number(value: Any, label: str) -> int | float:
    if type(value) is bool or type(value) not in (int, float):
        raise LiveContractError(f"{label} must be a number, got {type(value).__name__}")
    if type(value) is float and (value != value or value in (float("inf"), float("-inf"))):
        raise LiveContractError(f"{label} must be a finite number")
    return value


def _reject_dangerous_key(key: str, label: str) -> None:
    if type(key) is not str:
        raise LiveContractError(f"{label} keys must be strings")
    normalized = key.strip().lower().replace("-", "_")
    if normalized in _FORBIDDEN_KEYS or key.lower().startswith("x-"):
        raise LiveContractError(f"{label} contains forbidden field {key!r}")
    for fragment in _FORBIDDEN_KEY_FRAGMENTS:
        if fragment in normalized:
            raise LiveContractError(f"{label} contains forbidden field {key!r}")
