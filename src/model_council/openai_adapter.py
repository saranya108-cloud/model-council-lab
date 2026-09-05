"""Provider-local OpenAI Responses adapter.

The official OpenAI SDK is imported only inside the default client factory.
No SDK object, credential, or provider-local handle may cross the worker JSON
boundary. The registered production entrypoint composes request translation,
one-call transport, and response/error normalization into ProviderCallOutcome.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from .errors import GovernanceViolation, InfrastructureError, ProtocolError
from .live_contract import (
    CallTiming,
    FinishReason,
    LiveContractError,
    LiveInvocationRequest,
    NeutralError,
    ProviderCallKind,
    ProviderErrorCategory,
    ProviderUsage,
    UnavailableReason,
    build_provider_call_outcome,
    empty_provider_metadata,
    observed_identity,
    observed_int,
    observed_str,
    observed_structured,
    unavailable,
    unavailable_identity,
    unavailable_int,
    unavailable_metrics,
    unavailable_number,
    unavailable_structured,
    validate_closed_schema,
)
from .security import canonical_json, normalize_provider_treatment_config

HOST_OPENAI_API_KEY_ENV = "OPENAI_API_KEY"
CHILD_OPENAI_API_KEY_ENV = "MCL_OPENAI_API_KEY"
MAX_OPENAI_RUNTIME_CREDENTIAL_BYTES = 4096
OPENAI_TRANSLATION_NOT_IMPLEMENTED = "openai responses translation is not implemented"
OPENAI_CLIENT_INIT_FAILURE = "openai client initialization failed"
OPENAI_CREDENTIAL_MISSING = "openai runtime credential is missing"
OPENAI_CREDENTIAL_MALFORMED = "openai runtime credential is malformed"
OPENAI_OPTIONS_MUST_BE_EMPTY = "openai_responses adapter runtime options must be empty"
OPENAI_STATEFUL_TREATMENT = (
    "openai provider treatment must not include stateful conversation controls"
)
OPENAI_TREATMENT_INVALID = "openai provider treatment is invalid"
OPENAI_REQUEST_TYPE = "openai request translation requires a LiveInvocationRequest"
OPENAI_SECRET_NOT_SERIALIZABLE = "openai runtime secret cannot be serialized"
OPENAI_SECRET_NOT_COPYABLE = "openai runtime secret cannot be copied"
OPENAI_REFUSAL_MESSAGE = "openai provider refused the request"
OPENAI_INCOMPLETE_MESSAGE = "openai provider result was incomplete"
OPENAI_TOOL_CALL_MESSAGE = "openai provider returned a tool call"
OPENAI_MALFORMED_MESSAGE = "openai provider response was malformed"
OPENAI_TRANSPORT_REQUEST_INVALID = "openai transport request is invalid"
OPENAI_TRANSPORT_TIMEOUT_INVALID = "openai residual timeout is invalid"
OPENAI_TRANSPORT_RESULT_INVALID = "openai transport result is invalid"
OPENAI_AUTH_MESSAGE = "openai authentication failed"
OPENAI_PERMISSION_MESSAGE = "openai permission denied"
OPENAI_MODEL_UNAVAILABLE_MESSAGE = "openai model is unavailable"
OPENAI_INVALID_REQUEST_MESSAGE = "openai request was invalid"
OPENAI_CONNECTIVITY_MESSAGE = "openai transport connectivity failed"
OPENAI_TIMEOUT_MESSAGE = "openai provider timed out"
OPENAI_RATE_LIMIT_MESSAGE = "openai rate limit exceeded"
OPENAI_OVERLOAD_MESSAGE = "openai provider is overloaded"
OPENAI_UNKNOWN_FAILURE_MESSAGE = "openai request failed"
OPENAI_QUOTA_MESSAGE = "openai quota is exhausted"

_OPENAI_REASONING_EFFORT = frozenset({"none", "low", "medium", "high", "xhigh", "max"})
_OPENAI_REASONING_SUMMARY = frozenset({"auto", "concise", "detailed"})
_OPENAI_TEXT_VERBOSITY = frozenset({"low", "medium", "high"})
_OPENAI_TREATMENT_KEYS = frozenset({"reasoning", "text"})
_OPENAI_REASONING_KEYS = frozenset({"effort", "summary"})
_OPENAI_TEXT_KEYS = frozenset({"verbosity"})
_OPENAI_TOOL_ITEM_TYPES = frozenset(
    {
        "function_call",
        "function_call_output",
        "file_search_call",
        "web_search_call",
        "computer_call",
        "computer_call_output",
        "code_interpreter_call",
        "mcp_call",
        "mcp_list_tools",
        "mcp_approval_request",
        "image_generation_call",
        "local_shell_call",
        "custom_tool_call",
    }
)
_OPENAI_INCOMPLETE_LENGTH = "max_output_tokens"
_OPENAI_INCOMPLETE_FILTER = "content_filter"
_OPENAI_OBJECT_RESPONSE = "response"
_OPENAI_MESSAGE_STATUS_COMPLETED = "completed"
_OPENAI_MESSAGE_STATUS_INCOMPLETE = "incomplete"
# Conservative provider-local observation bounds. Independent of provider
# allocation size. JSON numbers above 2**53-1 are not portably serializable.
MAX_OPENAI_OBSERVATION_CHARS = 256
MAX_OPENAI_MODEL_ID_CHARS = 256
MAX_OPENAI_USAGE_TOKENS = (1 << 53) - 1
MAX_OPENAI_RAW_EVIDENCE_BYTES = 1_000_000
MAX_OPENAI_PROVIDER_JSON_DEPTH = 16
MAX_OPENAI_PROVIDER_JSON_ITEMS = 1024
# Mirrors sanitize secret/credential/traceback markers, plus header/PEM forms.
_OPENAI_UNSAFE_OBSERVATION_MARKERS = (
    "authorization:",
    "authorization",
    "bearer ",
    "x-api-key",
    "api_key",
    "apikey",
    "api-key",
    "sk-",
    "cookie",
    "set-cookie",
    "secret",
    "password",
    "credential",
    "traceback",
    "stacktrace",
    "stack_trace",
    "access_token",
    "refresh_token",
    "private_key",
    "-----begin ",
)

_OPENAI_STATEFUL_KEYS = frozenset(
    {
        "previous_response_id",
        "conversation",
        "conversation_id",
        "thread",
        "thread_id",
        "background",
        "store",
    }
)
_OPENAI_TRANSPORT_REQUIRED_KEYS = frozenset(
    {
        "model",
        "instructions",
        "input",
        "store",
        "stream",
        "background",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "truncation",
        "text",
    }
)
_OPENAI_TRANSPORT_OPTIONAL_KEYS = frozenset({"max_output_tokens", "reasoning"})
_OPENAI_TRANSPORT_ALLOWED_KEYS = (
    _OPENAI_TRANSPORT_REQUIRED_KEYS | _OPENAI_TRANSPORT_OPTIONAL_KEYS
)
_OPENAI_TRANSPORT_TEXT_KEYS = frozenset({"format", "verbosity"})
_OPENAI_TRANSPORT_FORMAT_KEYS = frozenset({"type", "name", "strict", "schema"})
_OPENAI_TRANSPORT_REASONING_KEYS = frozenset({"effort", "summary"})
_OPENAI_TRANSPORT_MISSING = object()
_OPENAI_429_QUOTA_CODE = "insufficient_quota"
_OPENAI_429_RATE_LIMIT_CODE = "rate_limit_exceeded"


class RuntimeSecret:
    """Opaque child-only runtime credential. Not a dataclass and not serializable.

    Accidental pickle/copy/reduce attempts discard the raw value before the
    fixed rejection error is raised, so traceback-reachable wrappers cannot
    disclose the credential. That invalidation is terminal for the instance;
    a later successful client-factory call requires a fresh RuntimeSecret.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def _discard_raw_value(self) -> None:
        self._value = None

    def __repr__(self) -> str:
        return "RuntimeSecret(REDACTED)"

    def __str__(self) -> str:
        return "REDACTED"

    def __getstate__(self) -> None:
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __setstate__(self, state: object) -> None:
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __reduce__(self):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __reduce_ex__(self, protocol: int):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __getnewargs__(self):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __getnewargs_ex__(self):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_SERIALIZABLE)

    def __copy__(self):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_COPYABLE)

    def __deepcopy__(self, memo):
        self._discard_raw_value()
        raise InfrastructureError(OPENAI_SECRET_NOT_COPYABLE)

    def reveal_for_client_factory(self) -> str:
        return self._value


def validate_openai_runtime_credential(value: object) -> str:
    """Validate an opaque runtime credential. Never include the value in errors."""
    missing = False
    malformed = False
    accepted = None
    try:
        if value is None:
            missing = True
        elif type(value) is not str:
            malformed = True
        elif value == "":
            missing = True
        elif value.strip() != value:
            malformed = True
        else:
            unprintable = False
            for ch in value:
                if not ch.isprintable():
                    unprintable = True
                    break
            if unprintable:
                malformed = True
            elif len(value.encode("utf-8")) > MAX_OPENAI_RUNTIME_CREDENTIAL_BYTES:
                malformed = True
            else:
                accepted = value
    finally:
        value = None
    if missing:
        raise InfrastructureError(OPENAI_CREDENTIAL_MISSING)
    if malformed:
        raise InfrastructureError(OPENAI_CREDENTIAL_MALFORMED)
    return accepted


def acquire_child_openai_runtime_secret() -> RuntimeSecret:
    """Pop the internal child credential immediately and wrap it opaquely."""
    if CHILD_OPENAI_API_KEY_ENV not in os.environ:
        raise InfrastructureError(OPENAI_CREDENTIAL_MISSING)
    raw = os.environ.pop(CHILD_OPENAI_API_KEY_ENV)
    failure = None
    secret = None
    try:
        validate_openai_runtime_credential(raw)
        secret = RuntimeSecret(raw)
    except InfrastructureError as caught:
        message = str(caught)
        caught.__traceback__ = None
        caught = None
        if message == OPENAI_CREDENTIAL_MISSING:
            failure = OPENAI_CREDENTIAL_MISSING
        else:
            failure = OPENAI_CREDENTIAL_MALFORMED
    finally:
        raw = None
    if failure is not None:
        secret = None
        raise InfrastructureError(failure)
    return secret


def materialize_openai_runtime_options(options: Any) -> dict:
    """Snapshot caller options exactly once into a trusted plain dict."""
    if options is None:
        return {}
    if not isinstance(options, Mapping):
        raise ProtocolError(OPENAI_OPTIONS_MUST_BE_EMPTY)
    return dict(options)


def require_empty_openai_runtime_options(options: Any) -> dict:
    snapshot = materialize_openai_runtime_options(options)
    if len(snapshot) != 0:
        raise ProtocolError(OPENAI_OPTIONS_MUST_BE_EMPTY)
    return snapshot


def _require_empty_openai_options(options: Any) -> None:
    require_empty_openai_runtime_options(options)


def _classify_openai_treatment_key(key: str) -> str:
    collapsed = re.sub(r"[-.\s]+", "_", key.strip().lower())
    return re.sub(r"_+", "_", collapsed).strip("_")


def _reject_openai_stateful_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is str and _classify_openai_treatment_key(key) in _OPENAI_STATEFUL_KEYS:
                raise ProtocolError(OPENAI_STATEFUL_TREATMENT)
            _reject_openai_stateful_keys(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_openai_stateful_keys(item)


def validate_openai_provider_treatment(provider_treatment_config: Any) -> dict:
    """Materialize once with the generic validator, then reject OpenAI statefulness.

    The original mapping is not scanned for stateful keys before normalization.
    Frozen tuples from deep_freeze are reified through a JSON snapshot so the
    generic validator sees stable lists rather than caller-owned mappings.
    """
    owned = None
    try:
        owned = json.loads(canonical_json(provider_treatment_config))
    except (TypeError, ValueError):
        owned = None
    if owned is None:
        normalized = normalize_provider_treatment_config(provider_treatment_config)
    else:
        normalized = normalize_provider_treatment_config(owned)
    _reject_openai_stateful_keys(normalized)
    return _require_closed_openai_treatment(normalized)


def _require_mapping(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(message)
    return dict(value)


def _require_closed_openai_treatment(normalized: Mapping[str, Any]) -> dict[str, Any]:
    extra = set(normalized) - _OPENAI_TREATMENT_KEYS
    if extra:
        raise ProtocolError(OPENAI_TREATMENT_INVALID)
    closed: dict[str, Any] = {}
    if "reasoning" in normalized:
        closed["reasoning"] = _require_openai_reasoning(normalized["reasoning"])
    if "text" in normalized:
        closed["text"] = _require_openai_text(normalized["text"])
    return closed


def _require_openai_reasoning(value: Any) -> dict[str, str]:
    data = _require_mapping(value, OPENAI_TREATMENT_INVALID)
    extra = set(data) - _OPENAI_REASONING_KEYS
    if extra:
        raise ProtocolError(OPENAI_TREATMENT_INVALID)
    parsed: dict[str, str] = {}
    if "effort" in data:
        effort = data["effort"]
        if type(effort) is not str or effort not in _OPENAI_REASONING_EFFORT:
            raise ProtocolError(OPENAI_TREATMENT_INVALID)
        parsed["effort"] = effort
    if "summary" in data:
        summary = data["summary"]
        if type(summary) is not str or summary not in _OPENAI_REASONING_SUMMARY:
            raise ProtocolError(OPENAI_TREATMENT_INVALID)
        parsed["summary"] = summary
    return parsed


def _require_openai_text(value: Any) -> dict[str, str]:
    data = _require_mapping(value, OPENAI_TREATMENT_INVALID)
    extra = set(data) - _OPENAI_TEXT_KEYS
    if extra:
        raise ProtocolError(OPENAI_TREATMENT_INVALID)
    parsed: dict[str, str] = {}
    if "verbosity" in data:
        verbosity = data["verbosity"]
        if type(verbosity) is not str or verbosity not in _OPENAI_TEXT_VERBOSITY:
            raise ProtocolError(OPENAI_TREATMENT_INVALID)
        parsed["verbosity"] = verbosity
    return parsed


def _openai_stage_output_schema(output_contract: Mapping[str, Any]) -> dict[str, Any]:
    artifacts = [str(name) for name in output_contract["expected_artifacts"]]
    artifact_properties = {name: {"type": "string"} for name in artifacts}
    if output_contract["structured_required"]:
        structured = json.loads(canonical_json(output_contract["structured_schema"]))
    else:
        structured = {"type": "null"}
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["text", "artifacts", "structured"],
        "properties": {
            "text": {"type": "string"},
            "artifacts": {
                "type": "object",
                "additionalProperties": False,
                "required": list(artifacts),
                "properties": artifact_properties,
            },
            "structured": structured,
        },
    }


def build_openai_responses_request(
    request: Any,
    provider_treatment_config: Any,
) -> dict[str, Any]:
    """Construct a deterministic OpenAI Responses request representation."""
    if not isinstance(request, LiveInvocationRequest):
        raise ProtocolError(OPENAI_REQUEST_TYPE)
    treatment = validate_openai_provider_treatment(provider_treatment_config)
    schema = _openai_stage_output_schema(request.output_contract)
    text_block: dict[str, Any] = {
        "format": {
            "type": "json_schema",
            "name": "stage_output",
            "strict": True,
            "schema": schema,
        }
    }
    treatment_text = treatment.get("text")
    if treatment_text and "verbosity" in treatment_text:
        text_block["verbosity"] = treatment_text["verbosity"]
    payload: dict[str, Any] = {
        "model": request.configured_identity.model_id,
        "instructions": request.role_instruction,
        "input": canonical_json({"stage_inputs": dict(request.stage_inputs)}),
        "max_output_tokens": request.max_output_tokens,
        "store": False,
        "stream": False,
        "background": False,
        "tools": [],
        "tool_choice": "none",
        "parallel_tool_calls": False,
        "truncation": "disabled",
        "text": text_block,
    }
    if "reasoning" in treatment:
        payload["reasoning"] = dict(treatment["reasoning"])
    return payload


class _OpenAITranslationReject(Exception):
    def __init__(
        self,
        category: ProviderErrorCategory,
        finish: FinishReason,
        *,
        raw_output: str | None = None,
    ) -> None:
        self.category = category
        self.finish = finish
        self.raw_output = raw_output


def _malformed_protocol(*, raw_output: str | None = None) -> _OpenAITranslationReject:
    return _OpenAITranslationReject(
        ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
        FinishReason.ERROR,
        raw_output=raw_output,
    )


def _own_plain_provider_json(value: Any, *, depth: int, items: list[int]) -> Any:
    if depth > MAX_OPENAI_PROVIDER_JSON_DEPTH:
        raise _malformed_protocol()
    items[0] += 1
    if items[0] > MAX_OPENAI_PROVIDER_JSON_ITEMS:
        raise _malformed_protocol()
    value_type = type(value)
    if value is None or value_type is bool:
        return value
    if value_type is int:
        return value
    if value_type is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise _malformed_protocol()
        return value
    if value_type is str:
        return value
    if value_type is dict:
        owned: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise _malformed_protocol()
            owned[key] = _own_plain_provider_json(item, depth=depth + 1, items=items)
        return owned
    if value_type is list:
        return [
            _own_plain_provider_json(item, depth=depth + 1, items=items) for item in value
        ]
    raise _malformed_protocol()


def _ingest_provider_response(provider_response: Any) -> dict[str, Any]:
    if type(provider_response) is not dict:
        raise _malformed_protocol()
    owned = _own_plain_provider_json(provider_response, depth=0, items=[0])
    if type(owned) is not dict:
        raise _malformed_protocol()
    return owned


def _openai_observation_is_safe(
    value: Any, *, max_chars: int, allow_multiline: bool = False
) -> bool:
    if type(value) is not str or value == "":
        return False
    if len(value) > max_chars:
        return False
    try:
        encoded = value.encode("utf-8")
    except Exception:
        return False
    if len(encoded) > max_chars:
        return False
    for ch in value:
        code = ord(ch)
        if ch in ("\n", "\r"):
            if not allow_multiline:
                return False
        elif code < 32 or code == 127:
            return False
    lowered = value.lower()
    for marker in _OPENAI_UNSAFE_OBSERVATION_MARKERS:
        if marker in lowered:
            return False
    return True


def _safe_raw_output(value: str | None) -> Any:
    if type(value) is not str or value == "":
        return unavailable(UnavailableReason.NOT_APPLICABLE)
    try:
        size = len(value.encode("utf-8"))
    except Exception:
        return unavailable(UnavailableReason.NOT_APPLICABLE)
    if size > MAX_OPENAI_RAW_EVIDENCE_BYTES:
        return unavailable(UnavailableReason.NOT_APPLICABLE)
    if not _openai_observation_is_safe(
        value, max_chars=MAX_OPENAI_RAW_EVIDENCE_BYTES, allow_multiline=True
    ):
        return unavailable(UnavailableReason.NOT_APPLICABLE)
    try:
        return observed_str(value)
    except LiveContractError:
        return unavailable(UnavailableReason.NOT_APPLICABLE)


def _validate_openai_stage_envelope(
    instance: Any, schema: Mapping[str, Any], output_contract: Mapping[str, Any]
) -> dict[str, Any]:
    if type(instance) is not dict:
        raise LiveContractError("stage envelope must be an object")
    validate_closed_schema(instance, schema, "stage_output")
    expected = set(output_contract["expected_artifacts"])
    artifacts = instance.get("artifacts")
    if type(artifacts) is not dict or set(artifacts) != expected:
        raise LiveContractError("stage artifacts do not match the output contract")
    structured = instance.get("structured")
    if output_contract["structured_required"]:
        if structured is None:
            raise LiveContractError("structured output is required")
        validate_closed_schema(
            structured, output_contract["structured_schema"], "structured"
        )
    elif structured is not None:
        raise LiveContractError("unstructured stages require structured null")
    return {
        "text": instance["text"],
        "artifacts": dict(artifacts),
        "structured": None if structured is None else structured,
    }


def _inspect_openai_usage(raw: Any) -> ProviderUsage:
    if raw is None:
        reason = UnavailableReason.NOT_EXPOSED
        return ProviderUsage(
            input_tokens=unavailable_int(reason),
            cached_input_tokens=unavailable_int(reason),
            cache_write_tokens=unavailable_int(reason),
            output_tokens=unavailable_int(reason),
            reasoning_tokens=unavailable_int(reason),
            total_tokens=unavailable_int(reason),
            extra=unavailable_metrics(UnavailableReason.NOT_APPLICABLE),
        )
    if type(raw) is not dict:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )

    def _token(value: Any) -> Any:
        if value is None:
            return unavailable_int(UnavailableReason.NOT_EXPOSED)
        if type(value) is not int or value < 0 or value > MAX_OPENAI_USAGE_TOKENS:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        return observed_int(value)

    input_details = raw.get("input_tokens_details")
    output_details = raw.get("output_tokens_details")
    cached = None
    reasoning = None
    if input_details is not None:
        if type(input_details) is not dict:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        cached = input_details.get("cached_tokens")
    if output_details is not None:
        if type(output_details) is not dict:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        reasoning = output_details.get("reasoning_tokens")
    return ProviderUsage(
        input_tokens=_token(raw.get("input_tokens")),
        cached_input_tokens=_token(cached),
        cache_write_tokens=unavailable_int(UnavailableReason.NOT_EXPOSED),
        output_tokens=_token(raw.get("output_tokens")),
        reasoning_tokens=_token(reasoning),
        total_tokens=_token(raw.get("total_tokens")),
        extra=unavailable_metrics(UnavailableReason.NOT_APPLICABLE),
    )


def _inspect_optional_id(payload: Mapping[str, Any], key: str) -> Any:
    if key not in payload:
        return unavailable(UnavailableReason.NOT_EXPOSED)
    value = payload[key]
    if not _openai_observation_is_safe(value, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
        return unavailable(UnavailableReason.NOT_APPLICABLE)
    return observed_str(value)


def _inspect_resolved_model(payload: Mapping[str, Any]) -> Any:
    if "model" not in payload:
        return unavailable_identity(UnavailableReason.NOT_EXPOSED)
    model = payload["model"]
    if not _openai_observation_is_safe(model, max_chars=MAX_OPENAI_MODEL_ID_CHARS):
        return unavailable_identity(UnavailableReason.NOT_APPLICABLE)
    return observed_identity(model_id=model)


def _require_message_item_status(item: Mapping[str, Any], *, top_level_status: str) -> None:
    if "status" not in item:
        raise _malformed_protocol()
    item_status = item["status"]
    if type(item_status) is not str:
        raise _malformed_protocol()
    if top_level_status == "completed":
        if item_status != _OPENAI_MESSAGE_STATUS_COMPLETED:
            raise _malformed_protocol()
        return
    if top_level_status == "incomplete":
        if item_status not in (
            _OPENAI_MESSAGE_STATUS_COMPLETED,
            _OPENAI_MESSAGE_STATUS_INCOMPLETE,
        ):
            raise _malformed_protocol()
        return
    raise _malformed_protocol()


def _scan_openai_output_items(
    output: Any, *, top_level_status: str
) -> tuple[list[str], list[str], bool]:
    if type(output) is not list:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    texts: list[str] = []
    refusals: list[str] = []
    tool_seen = False
    for item in output:
        if type(item) is not dict:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        item_type = item.get("type")
        if type(item_type) is not str:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        if item_type in _OPENAI_TOOL_ITEM_TYPES:
            tool_seen = True
            continue
        if item_type == "reasoning":
            continue
        if item_type != "message":
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        _require_message_item_status(item, top_level_status=top_level_status)
        role = item.get("role")
        if role is not None and role != "assistant":
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        content = item.get("content")
        if type(content) is not list:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        for part in content:
            if type(part) is not dict:
                raise _OpenAITranslationReject(
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
                )
            part_type = part.get("type")
            if type(part_type) is not str:
                raise _OpenAITranslationReject(
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
                )
            if part_type in _OPENAI_TOOL_ITEM_TYPES:
                tool_seen = True
                continue
            if part_type == "output_text":
                text = part.get("text")
                if type(text) is not str:
                    raise _OpenAITranslationReject(
                        ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                        FinishReason.ERROR,
                    )
                texts.append(text)
                continue
            if part_type == "refusal":
                refusal = part.get("refusal")
                if type(refusal) is not str:
                    raise _OpenAITranslationReject(
                        ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                        FinishReason.ERROR,
                    )
                refusals.append(refusal)
                continue
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
    return texts, refusals, tool_seen


def _classify_openai_response(payload: Mapping[str, Any]) -> tuple[str, str | None]:
    if payload.get("object") != _OPENAI_OBJECT_RESPONSE:
        raise _malformed_protocol()
    status = payload.get("status")
    if type(status) is not str:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    if "output" not in payload:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    texts, refusals, tool_seen = _scan_openai_output_items(
        payload["output"], top_level_status=status
    )
    joined = "".join(texts)
    if "output_text" in payload:
        aggregated = payload["output_text"]
        if type(aggregated) is not str or aggregated != joined:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
    incomplete_details = payload.get("incomplete_details")
    error_field = payload.get("error")
    if error_field is not None and status in ("completed", "incomplete"):
        raise _malformed_protocol()
    if status == "completed" and incomplete_details is not None:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    if refusals and (texts or tool_seen):
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    if tool_seen:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
            FinishReason.TOOL_USE,
        )
    if status == "incomplete":
        if incomplete_details is not None and type(incomplete_details) is not dict:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
            )
        reason = None
        if incomplete_details is not None:
            extra = set(incomplete_details) - {"reason"}
            if extra:
                raise _OpenAITranslationReject(
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
                )
            reason = incomplete_details.get("reason")
            if reason is not None and type(reason) is not str:
                raise _OpenAITranslationReject(
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
                )
        raw = joined if joined else (refusals[0] if refusals else None)
        if reason == _OPENAI_INCOMPLETE_LENGTH:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
                FinishReason.LENGTH,
                raw_output=raw,
            )
        if reason == _OPENAI_INCOMPLETE_FILTER:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
                FinishReason.CONTENT_FILTER,
                raw_output=raw,
            )
        if reason is None:
            raise _OpenAITranslationReject(
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
                FinishReason.INCOMPLETE,
                raw_output=raw,
            )
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    if status != "completed":
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    if refusals:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.POLICY_REFUSAL,
            FinishReason.CONTENT_FILTER,
            raw_output=refusals[0] or None,
        )
    if not joined:
        raise _OpenAITranslationReject(
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL, FinishReason.ERROR
        )
    return "success", joined


def _openai_error_message(category: ProviderErrorCategory) -> str:
    if category is ProviderErrorCategory.POLICY_REFUSAL:
        return OPENAI_REFUSAL_MESSAGE
    if category is ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT:
        return OPENAI_INCOMPLETE_MESSAGE
    return OPENAI_MALFORMED_MESSAGE


def _observed_raw(value: str | None) -> Any:
    return _safe_raw_output(value)


def _base_identity_observations(request: LiveInvocationRequest, payload: Mapping[str, Any] | None):
    configured = request.configured_identity
    if payload is None:
        resolved = unavailable_identity(UnavailableReason.NOT_EXPOSED)
        response_id = unavailable(UnavailableReason.NOT_EXPOSED)
        request_id = unavailable(UnavailableReason.NOT_EXPOSED)
        usage = _inspect_openai_usage(None)
    else:
        resolved = _inspect_resolved_model(payload)
        response_id = _inspect_optional_id(payload, "id")
        request_id = _inspect_optional_id(payload, "request_id")
        usage = _inspect_openai_usage(payload.get("usage"))
    return {
        "requested_identity": request.requested_identity,
        "configured_identity": configured,
        "provider_resolved_identity": resolved,
        "invocation_returned_identity": observed_identity(
            provider=configured.provider,
            model_id=configured.model_id,
            model_version=configured.model_version,
        ),
        "provider_snapshot_identity": unavailable(UnavailableReason.NOT_EXPOSED),
        "provider_response_id": response_id,
        "provider_request_id": request_id,
        "provider_response_status": unavailable_int(UnavailableReason.NOT_EXPOSED),
        "usage": usage,
        "timing": CallTiming(
            provider_processing_ms=unavailable_number(UnavailableReason.NOT_EXPOSED),
        ),
        "adapter_internal_retry_count": 0,
        "tool_use_count": 0,
        "provider_metadata": empty_provider_metadata(),
    }


def _emit_openai_error_outcome(
    request: LiveInvocationRequest,
    payload: Mapping[str, Any] | None,
    reject: _OpenAITranslationReject,
):
    if reject.finish is FinishReason.TOOL_USE:
        message = OPENAI_TOOL_CALL_MESSAGE
    else:
        message = _openai_error_message(reject.category)
    observations = _base_identity_observations(request, payload)
    return build_provider_call_outcome(
        kind=ProviderCallKind.PROVIDER_ERROR,
        finish_reason=observed_str(reject.finish.value),
        raw_output=_observed_raw(reject.raw_output),
        structured_output=unavailable_structured(UnavailableReason.NOT_APPLICABLE),
        error=NeutralError(
            category=reject.category,
            sanitized_message=message,
            http_status=unavailable_int(UnavailableReason.NOT_EXPOSED),
        ),
        stage_output=None,
        **observations,
    )


def _openai_error_outcome(
    request: LiveInvocationRequest,
    payload: Mapping[str, Any] | None,
    reject: _OpenAITranslationReject,
):
    try:
        return _emit_openai_error_outcome(request, payload, reject)
    except (LiveContractError, _OpenAITranslationReject, Exception):
        sanitized = _OpenAITranslationReject(
            reject.category, reject.finish, raw_output=None
        )
        try:
            return _emit_openai_error_outcome(request, None, sanitized)
        except Exception:
            return _emit_openai_error_outcome(
                request,
                None,
                _malformed_protocol(),
            )


def translate_openai_responses_result(request: Any, provider_response: Any):
    """Translate a synthetic provider-shaped Responses object to ProviderCallOutcome."""
    if not isinstance(request, LiveInvocationRequest):
        raise ProtocolError(OPENAI_REQUEST_TYPE)
    owned = None
    try:
        owned = _ingest_provider_response(provider_response)
    except _OpenAITranslationReject as reject:
        return _openai_error_outcome(request, None, reject)
    except Exception:
        return _openai_error_outcome(request, None, _malformed_protocol())
    try:
        classification, joined = _classify_openai_response(owned)
        del classification
        schema = _openai_stage_output_schema(request.output_contract)
        try:
            parsed = json.loads(joined)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise _malformed_protocol() from None
        envelope = _validate_openai_stage_envelope(
            parsed, schema, request.output_contract
        )
        structured = envelope["structured"]
        return build_provider_call_outcome(
            kind=ProviderCallKind.SUCCESS,
            finish_reason=observed_str(FinishReason.COMPLETED.value),
            raw_output=_safe_raw_output(joined),
            structured_output=(
                unavailable_structured(UnavailableReason.NOT_APPLICABLE)
                if structured is None
                else observed_structured(structured)
            ),
            error=None,
            stage_output=envelope,
            **_base_identity_observations(request, owned),
        )
    except _OpenAITranslationReject as reject:
        return _openai_error_outcome(request, owned, reject)
    except LiveContractError:
        return _openai_error_outcome(request, owned, _malformed_protocol())


def _default_openai_client_factory(*, api_key: str, max_retries: int) -> Any:
    if type(max_retries) is not int or max_retries != 0:
        raise InfrastructureError(OPENAI_CLIENT_INIT_FAILURE)
    from openai import OpenAI

    return OpenAI(api_key=api_key, max_retries=0)


def build_openai_client(
    runtime_credential: RuntimeSecret,
    *,
    client_factory: Callable[..., Any] | None = None,
) -> Any:
    """Provider-local lazy client seam. Not invoked by the Tranche 3 skeleton."""
    if type(runtime_credential) is not RuntimeSecret:
        raise InfrastructureError(OPENAI_CLIENT_INIT_FAILURE)
    factory = (
        _default_openai_client_factory if client_factory is None else client_factory
    )
    failed = False
    api_key = None
    client = None
    try:
        api_key = runtime_credential.reveal_for_client_factory()
        try:
            client = factory(api_key=api_key, max_retries=0)
        except Exception:
            failed = True
            client = None
        else:
            return client
    finally:
        api_key = None
        runtime_credential = None
        factory = None
    if failed:
        raise InfrastructureError(OPENAI_CLIENT_INIT_FAILURE)
    raise InfrastructureError(OPENAI_CLIENT_INIT_FAILURE)


@dataclass(frozen=True, slots=True, repr=False)
class _OpenAITransportSuccess:
    response: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _OpenAITransportFailure:
    kind: ProviderCallKind
    category: ProviderErrorCategory
    http_status: int | None
    request_id: str | None
    error_type: str | None
    error_code: str | None
    param: str | None

    def __repr__(self) -> str:
        return (
            "_OpenAITransportFailure("
            f"kind={self.kind!r}, "
            f"category={self.category!r}, "
            f"http_status={self.http_status!r}, "
            f"request_id={self.request_id!r}, "
            f"error_type={self.error_type!r}, "
            f"error_code={self.error_code!r}, "
            f"param={self.param!r})"
        )


_OpenAITransportResult = _OpenAITransportSuccess | _OpenAITransportFailure


def _reject_openai_transport_request() -> None:
    raise ProtocolError(OPENAI_TRANSPORT_REQUEST_INVALID)


def _own_openai_transport_json(value: Any) -> Any:
    owned = None
    failed = False
    try:
        owned = json.loads(canonical_json(value))
    except Exception:
        failed = True
        owned = None
    value = None
    if failed:
        return None
    return owned


def _require_openai_transport_mapping(value: Any) -> dict[str, Any]:
    if type(value) is not dict:
        _reject_openai_transport_request()
    extra = set(value) - _OPENAI_TRANSPORT_ALLOWED_KEYS
    if extra:
        _reject_openai_transport_request()
    missing = _OPENAI_TRANSPORT_REQUIRED_KEYS - set(value)
    if missing:
        _reject_openai_transport_request()
    return value


def _require_openai_transport_text(value: Any) -> None:
    if type(value) is not dict:
        _reject_openai_transport_request()
    extra = set(value) - _OPENAI_TRANSPORT_TEXT_KEYS
    if extra or "format" not in value:
        _reject_openai_transport_request()
    if "verbosity" in value:
        verbosity = value["verbosity"]
        if type(verbosity) is not str or verbosity not in _OPENAI_TEXT_VERBOSITY:
            _reject_openai_transport_request()
    fmt = value["format"]
    if type(fmt) is not dict:
        _reject_openai_transport_request()
    extra_format = set(fmt) - _OPENAI_TRANSPORT_FORMAT_KEYS
    if extra_format or set(_OPENAI_TRANSPORT_FORMAT_KEYS) - set(fmt):
        _reject_openai_transport_request()
    if fmt["type"] != "json_schema" or fmt["name"] != "stage_output":
        _reject_openai_transport_request()
    if type(fmt["strict"]) is not bool or fmt["strict"] is not True:
        _reject_openai_transport_request()
    if type(fmt["schema"]) is not dict:
        _reject_openai_transport_request()


def _require_openai_transport_reasoning(value: Any) -> None:
    if type(value) is not dict:
        _reject_openai_transport_request()
    extra = set(value) - _OPENAI_TRANSPORT_REASONING_KEYS
    if extra:
        _reject_openai_transport_request()
    if "effort" in value:
        effort = value["effort"]
        if type(effort) is not str or effort not in _OPENAI_REASONING_EFFORT:
            _reject_openai_transport_request()
    if "summary" in value:
        summary = value["summary"]
        if type(summary) is not str or summary not in _OPENAI_REASONING_SUMMARY:
            _reject_openai_transport_request()


def _validate_openai_transport_request(translated_request: Any) -> dict[str, Any]:
    if type(translated_request) is not dict:
        translated_request = None
        _reject_openai_transport_request()
    owned = _own_openai_transport_json(translated_request)
    translated_request = None
    if type(owned) is not dict:
        owned = None
        _reject_openai_transport_request()
    closed = _require_openai_transport_mapping(owned)
    if type(closed["model"]) is not str:
        _reject_openai_transport_request()
    if type(closed["instructions"]) is not str:
        _reject_openai_transport_request()
    if type(closed["input"]) is not str:
        _reject_openai_transport_request()
    if closed["store"] is not False:
        _reject_openai_transport_request()
    if closed["stream"] is not False:
        _reject_openai_transport_request()
    if closed["background"] is not False:
        _reject_openai_transport_request()
    if closed["tools"] != []:
        _reject_openai_transport_request()
    if closed["tool_choice"] != "none":
        _reject_openai_transport_request()
    if closed["parallel_tool_calls"] is not False:
        _reject_openai_transport_request()
    if closed["truncation"] != "disabled":
        _reject_openai_transport_request()
    if "max_output_tokens" in closed:
        max_output_tokens = closed["max_output_tokens"]
        if type(max_output_tokens) is not int or max_output_tokens < 1:
            _reject_openai_transport_request()
    _require_openai_transport_text(closed["text"])
    if "reasoning" in closed:
        _require_openai_transport_reasoning(closed["reasoning"])
    return closed


def _validate_openai_residual_timeout(residual_timeout_seconds: Any) -> int | float:
    if type(residual_timeout_seconds) is bool:
        raise ProtocolError(OPENAI_TRANSPORT_TIMEOUT_INVALID)
    if type(residual_timeout_seconds) is not int and type(residual_timeout_seconds) is not float:
        raise ProtocolError(OPENAI_TRANSPORT_TIMEOUT_INVALID)
    if residual_timeout_seconds != residual_timeout_seconds:
        raise ProtocolError(OPENAI_TRANSPORT_TIMEOUT_INVALID)
    if residual_timeout_seconds in (float("inf"), float("-inf")):
        raise ProtocolError(OPENAI_TRANSPORT_TIMEOUT_INVALID)
    if residual_timeout_seconds <= 0:
        raise ProtocolError(OPENAI_TRANSPORT_TIMEOUT_INVALID)
    return residual_timeout_seconds


def _sdk_field(obj: Any, name: str) -> Any:
    if type(obj) is dict:
        if name not in obj:
            return _OPENAI_TRANSPORT_MISSING
        return obj[name]
    try:
        return object.__getattribute__(obj, name)
    except AttributeError:
        return _OPENAI_TRANSPORT_MISSING
    except BaseException:
        raise _malformed_protocol() from None


def _optional_observation(value: Any, *, max_chars: int = MAX_OPENAI_OBSERVATION_CHARS) -> str | None:
    if value is _OPENAI_TRANSPORT_MISSING:
        return None
    if not _openai_observation_is_safe(value, max_chars=max_chars):
        return None
    return value


def _safe_http_status(value: Any) -> int | None:
    if type(value) is not int:
        return None
    if value < 100 or value > 599:
        return None
    return value


def _copy_usage_int(value: Any) -> int:
    if type(value) is not int or value < 0 or value > MAX_OPENAI_USAGE_TOKENS:
        raise _malformed_protocol()
    return value


def _copy_usage_details(
    raw: Any, field: str, budget: _OpenAIExtractionBudget
) -> dict[str, int] | None:
    if raw is _OPENAI_TRANSPORT_MISSING or raw is None:
        return None
    token = _sdk_field(raw, field)
    if token is _OPENAI_TRANSPORT_MISSING or token is None:
        return None
    value = _copy_usage_int(token)
    budget.charge_container()
    budget.charge_key(field)
    budget.charge_int(value)
    return {field: value}


def _copy_openai_usage(raw: Any, budget: _OpenAIExtractionBudget) -> dict[str, Any] | None:
    if raw is _OPENAI_TRANSPORT_MISSING or raw is None:
        return None
    budget.charge_container()
    owned: dict[str, Any] = {}
    for name in ("input_tokens", "output_tokens", "total_tokens"):
        value = _sdk_field(raw, name)
        if value is _OPENAI_TRANSPORT_MISSING or value is None:
            continue
        token = _copy_usage_int(value)
        budget.charge_key(name)
        budget.charge_int(token)
        owned[name] = token
    input_details = _copy_usage_details(
        _sdk_field(raw, "input_tokens_details"), "cached_tokens", budget
    )
    if input_details is not None:
        budget.charge_key("input_tokens_details")
        owned["input_tokens_details"] = input_details
    output_details = _copy_usage_details(
        _sdk_field(raw, "output_tokens_details"), "reasoning_tokens", budget
    )
    if output_details is not None:
        budget.charge_key("output_tokens_details")
        owned["output_tokens_details"] = output_details
    return owned


# json.dumps default ensure_ascii encoding, as used by canonical_json().
_JSON_TWO_CHAR_ESCAPES = frozenset({0x08, 0x09, 0x0A, 0x0C, 0x0D, 0x22, 0x5C})


def _canonical_json_string_body_bytes(value: str) -> int:
    """Payload bytes of a JSON string under canonical ASCII escaping.

    Surrounding quotes are not included. Ordinary printable ASCII is 1 byte;
    `"` / `\\` and the two-character control escapes are 2 bytes; remaining
    C0 controls and BMP non-ASCII are 6-byte `\\uXXXX`; non-BMP code points
    are a 12-byte UTF-16 surrogate pair `\\uXXXX\\uXXXX`.
    """
    size = 0
    for ch in value:
        code = ord(ch)
        if code in _JSON_TWO_CHAR_ESCAPES:
            size += 2
        elif code < 0x20:
            size += 6
        elif code <= 0x7E:
            size += 1
        elif code < 0x10000:
            size += 6
        else:
            size += 12
    return size


class _OpenAIExtractionBudget:
    __slots__ = ("items", "nbytes")

    def __init__(self) -> None:
        self.items = 0
        self.nbytes = 0

    def consume_node(self) -> None:
        if self.items >= MAX_OPENAI_PROVIDER_JSON_ITEMS:
            raise _malformed_protocol()
        self.items += 1

    def consume_bytes(self, size: int) -> None:
        if type(size) is not int or size < 0:
            raise _malformed_protocol()
        remaining = MAX_OPENAI_RAW_EVIDENCE_BYTES - self.nbytes
        if size > remaining:
            raise _malformed_protocol()
        self.nbytes += size

    def charge_container(self) -> None:
        self.consume_node()
        self.consume_bytes(2)

    def charge_json_string_payload(self, value: str) -> None:
        try:
            utf8 = len(value.encode("utf-8"))
        except Exception:
            raise _malformed_protocol() from None
        body = _canonical_json_string_body_bytes(value)
        # Surrounding quotes plus a payload that dominates canonical ASCII
        # escaping. Printable ASCII still uses the 2×UTF-8 floor so a
        # 1MB-fitting raw payload cannot be fully traversed; BMP/astral
        # `\uXXXX` / surrogate-pair expansion uses the larger canonical size.
        self.consume_bytes(2 + max(body, 2 * utf8))

    def charge_key(self, key: str) -> None:
        if type(key) is not str:
            raise _malformed_protocol()
        self.consume_bytes(1)
        self.charge_json_string_payload(key)
        self.consume_bytes(1)

    def charge_string(self, value: str) -> None:
        if type(value) is not str:
            raise _malformed_protocol()
        self.consume_node()
        self.charge_json_string_payload(value)

    def charge_null(self) -> None:
        self.consume_node()
        self.consume_bytes(4)

    def charge_bool(self) -> None:
        self.consume_node()
        self.consume_bytes(5)

    def charge_int(self, value: int) -> None:
        if type(value) is not int:
            raise _malformed_protocol()
        self.consume_node()
        self.consume_bytes(max(1, len(str(value))))


def _require_extractable_list(value: Any, budget: _OpenAIExtractionBudget) -> list:
    if type(value) is not list:
        raise _malformed_protocol()
    remaining = MAX_OPENAI_PROVIDER_JSON_ITEMS - budget.items
    if remaining <= 0 or len(value) > remaining:
        raise _malformed_protocol()
    return value


def _copy_bounded_text(value: Any, budget: _OpenAIExtractionBudget) -> str:
    if type(value) is not str:
        raise _malformed_protocol()
    try:
        size = len(value.encode("utf-8"))
    except Exception:
        raise _malformed_protocol() from None
    if size > MAX_OPENAI_RAW_EVIDENCE_BYTES:
        raise _malformed_protocol()
    budget.charge_string(value)
    return value


def _copy_typed_object(budget: _OpenAIExtractionBudget, item_type: str) -> dict[str, str]:
    budget.charge_container()
    budget.charge_key("type")
    budget.charge_string(item_type)
    return {"type": item_type}


def _copy_content_part(part: Any, budget: _OpenAIExtractionBudget) -> dict[str, Any]:
    part_type = _sdk_field(part, "type")
    if type(part_type) is not str:
        raise _malformed_protocol()
    if part_type == "output_text":
        owned = _copy_typed_object(budget, "output_text")
        budget.charge_key("text")
        owned["text"] = _copy_bounded_text(_sdk_field(part, "text"), budget)
        return owned
    if part_type == "refusal":
        owned = _copy_typed_object(budget, "refusal")
        budget.charge_key("refusal")
        owned["refusal"] = _copy_bounded_text(_sdk_field(part, "refusal"), budget)
        return owned
    if not _openai_observation_is_safe(part_type, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
        raise _malformed_protocol()
    return _copy_typed_object(budget, part_type)


def _copy_message_item(item: Any, budget: _OpenAIExtractionBudget) -> dict[str, Any]:
    owned = _copy_typed_object(budget, "message")
    status = _sdk_field(item, "status")
    if status is not _OPENAI_TRANSPORT_MISSING:
        if not _openai_observation_is_safe(status, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
            raise _malformed_protocol()
        budget.charge_key("status")
        budget.charge_string(status)
        owned["status"] = status
    role = _sdk_field(item, "role")
    if role is not _OPENAI_TRANSPORT_MISSING:
        if not _openai_observation_is_safe(role, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
            raise _malformed_protocol()
        budget.charge_key("role")
        budget.charge_string(role)
        owned["role"] = role
    content = _sdk_field(item, "content")
    if content is _OPENAI_TRANSPORT_MISSING:
        return owned
    content = _require_extractable_list(content, budget)
    budget.charge_key("content")
    budget.charge_container()
    owned_content = []
    for part in content:
        owned_content.append(_copy_content_part(part, budget))
    owned["content"] = owned_content
    return owned


def _copy_output_item(item: Any, budget: _OpenAIExtractionBudget) -> dict[str, Any]:
    item_type = _sdk_field(item, "type")
    if type(item_type) is not str:
        raise _malformed_protocol()
    if not _openai_observation_is_safe(item_type, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
        raise _malformed_protocol()
    if item_type == "message":
        return _copy_message_item(item, budget)
    return _copy_typed_object(budget, item_type)


def _copy_incomplete_details(
    raw: Any, budget: _OpenAIExtractionBudget
) -> dict[str, Any] | None:
    if raw is _OPENAI_TRANSPORT_MISSING or raw is None:
        budget.charge_null()
        return None
    budget.charge_container()
    reason = _sdk_field(raw, "reason")
    if reason is _OPENAI_TRANSPORT_MISSING:
        return {}
    budget.charge_key("reason")
    if reason is None:
        budget.charge_null()
        return {"reason": None}
    if not _openai_observation_is_safe(reason, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
        return {}
    budget.charge_string(reason)
    return {"reason": reason}


def _copy_error_presence(raw: Any, budget: _OpenAIExtractionBudget) -> bool | None:
    if raw is _OPENAI_TRANSPORT_MISSING or raw is None:
        budget.charge_null()
        return None
    budget.charge_bool()
    return True


def _copy_response_request_id(raw: Any) -> str | None:
    value = _sdk_field(raw, "request_id")
    if value is _OPENAI_TRANSPORT_MISSING and type(raw) is not dict:
        value = _sdk_field(raw, "_request_id")
    return _optional_observation(value)


def _extract_openai_sdk_response(raw: Any) -> dict[str, Any]:
    if raw is None:
        raise _malformed_protocol()
    budget = _OpenAIExtractionBudget()
    budget.charge_container()
    owned: dict[str, Any] = {}
    discriminator = _sdk_field(raw, "object")
    if discriminator is not _OPENAI_TRANSPORT_MISSING:
        if not _openai_observation_is_safe(
            discriminator, max_chars=MAX_OPENAI_OBSERVATION_CHARS
        ):
            raise _malformed_protocol()
        budget.charge_key("object")
        budget.charge_string(discriminator)
        owned["object"] = discriminator
    response_id = _optional_observation(
        _sdk_field(raw, "id"), max_chars=MAX_OPENAI_OBSERVATION_CHARS
    )
    if response_id is not None:
        budget.charge_key("id")
        budget.charge_string(response_id)
        owned["id"] = response_id
    request_id = _copy_response_request_id(raw)
    if request_id is not None:
        budget.charge_key("request_id")
        budget.charge_string(request_id)
        owned["request_id"] = request_id
    model = _optional_observation(
        _sdk_field(raw, "model"), max_chars=MAX_OPENAI_MODEL_ID_CHARS
    )
    if model is not None:
        budget.charge_key("model")
        budget.charge_string(model)
        owned["model"] = model
    status = _sdk_field(raw, "status")
    if status is not _OPENAI_TRANSPORT_MISSING:
        if not _openai_observation_is_safe(status, max_chars=MAX_OPENAI_OBSERVATION_CHARS):
            raise _malformed_protocol()
        budget.charge_key("status")
        budget.charge_string(status)
        owned["status"] = status
    output = _sdk_field(raw, "output")
    if output is not _OPENAI_TRANSPORT_MISSING:
        output = _require_extractable_list(output, budget)
        budget.charge_key("output")
        budget.charge_container()
        owned_output = []
        for item in output:
            owned_output.append(_copy_output_item(item, budget))
        owned["output"] = owned_output
    budget.charge_key("incomplete_details")
    owned["incomplete_details"] = _copy_incomplete_details(
        _sdk_field(raw, "incomplete_details"), budget
    )
    budget.charge_key("error")
    owned["error"] = _copy_error_presence(_sdk_field(raw, "error"), budget)
    usage = _copy_openai_usage(_sdk_field(raw, "usage"), budget)
    if usage is not None:
        budget.charge_key("usage")
        owned["usage"] = usage
    bounded = _own_plain_provider_json(owned, depth=0, items=[0])
    if type(bounded) is not dict:
        raise _malformed_protocol()
    try:
        encoded = canonical_json(bounded).encode("utf-8")
    except Exception:
        raise _malformed_protocol() from None
    if len(encoded) > MAX_OPENAI_RAW_EVIDENCE_BYTES:
        raise _malformed_protocol()
    return bounded


def _malformed_transport_failure() -> _OpenAITransportFailure:
    return _OpenAITransportFailure(
        kind=ProviderCallKind.PROVIDER_ERROR,
        category=ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
        http_status=None,
        request_id=None,
        error_type=None,
        error_code=None,
        param=None,
    )


def _closed_unknown_transport_failure() -> _OpenAITransportFailure:
    return _OpenAITransportFailure(
        kind=ProviderCallKind.TRANSPORT_ERROR,
        category=ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
        http_status=None,
        request_id=None,
        error_type=None,
        error_code=None,
        param=None,
    )


def _import_openai_sdk() -> Any:
    try:
        import openai
    except BaseException:
        return None
    return openai


def _transport_failure(
    kind: ProviderCallKind,
    category: ProviderErrorCategory,
    *,
    http_status: int | None,
    request_id: str | None,
    error_type: str | None,
    error_code: str | None,
    param: str | None,
) -> _OpenAITransportFailure:
    return _OpenAITransportFailure(
        kind=kind,
        category=category,
        http_status=http_status,
        request_id=request_id,
        error_type=error_type,
        error_code=error_code,
        param=param,
    )


def _classify_openai_429(
    *,
    http_status: int | None,
    request_id: str | None,
    error_type: str | None,
    error_code: str | None,
    param: str | None,
) -> _OpenAITransportFailure:
    if error_code == _OPENAI_429_QUOTA_CODE:
        category = ProviderErrorCategory.QUOTA_EXHAUSTED
    elif error_code == _OPENAI_429_RATE_LIMIT_CODE:
        if error_type == _OPENAI_429_QUOTA_CODE:
            category = ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE
        else:
            category = ProviderErrorCategory.RATE_LIMIT
    else:
        category = ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE
    return _transport_failure(
        ProviderCallKind.PROVIDER_ERROR,
        category,
        http_status=http_status,
        request_id=request_id,
        error_type=error_type,
        error_code=error_code,
        param=param,
    )


def _normalize_openai_sdk_exception(exc: BaseException) -> _OpenAITransportFailure:
    failure = None
    try:
        http_status = _safe_http_status(_sdk_field(exc, "status_code"))
        request_id = _optional_observation(_sdk_field(exc, "request_id"))
        error_type = _optional_observation(_sdk_field(exc, "type"))
        error_code = _optional_observation(_sdk_field(exc, "code"))
        param = _optional_observation(_sdk_field(exc, "param"))
        openai = _import_openai_sdk()
        if openai is None:
            failure = None
        elif isinstance(exc, getattr(openai, "AuthenticationError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "PermissionDeniedError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.PERMISSION,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "BadRequestError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.INVALID_REQUEST,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "UnprocessableEntityError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.INVALID_REQUEST,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "NotFoundError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.MODEL_UNAVAILABLE,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "ConflictError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "RateLimitError", ())):
            failure = _classify_openai_429(
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "InternalServerError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "APIResponseValidationError", ())):
            failure = _transport_failure(
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "APITimeoutError", ())):
            failure = _transport_failure(
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "APIConnectionError", ())):
            failure = _transport_failure(
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
        elif isinstance(exc, getattr(openai, "APIStatusError", ())):
            if http_status is not None and 500 <= http_status <= 599:
                failure = _transport_failure(
                    ProviderCallKind.PROVIDER_ERROR,
                    ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
                    http_status=http_status,
                    request_id=request_id,
                    error_type=error_type,
                    error_code=error_code,
                    param=param,
                )
            elif http_status == 429:
                failure = _classify_openai_429(
                    http_status=http_status,
                    request_id=request_id,
                    error_type=error_type,
                    error_code=error_code,
                    param=param,
                )
            else:
                failure = _transport_failure(
                    ProviderCallKind.PROVIDER_ERROR,
                    ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                    http_status=http_status,
                    request_id=request_id,
                    error_type=error_type,
                    error_code=error_code,
                    param=param,
                )
        else:
            failure = _transport_failure(
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                http_status=http_status,
                request_id=request_id,
                error_type=error_type,
                error_code=error_code,
                param=param,
            )
    except BaseException:
        failure = None
    finally:
        exc = None
    if failure is None:
        return _closed_unknown_transport_failure()
    return failure


def _perform_openai_responses_transport(
    translated_request: dict[str, Any],
    runtime_credential: RuntimeSecret,
    residual_timeout_seconds: int | float,
    *,
    client_factory: Callable[..., Any] | None = None,
) -> _OpenAITransportResult:
    owned_translated_request = None
    residual_timeout = None
    client = None
    raw_response = None
    try:
        owned_translated_request = _validate_openai_transport_request(translated_request)
        residual_timeout = _validate_openai_residual_timeout(residual_timeout_seconds)
        client = build_openai_client(
            runtime_credential, client_factory=client_factory
        )
        try:
            raw_response = client.responses.create(
                **owned_translated_request,
                timeout=residual_timeout,
            )
        except Exception as caught:
            try:
                failure = _normalize_openai_sdk_exception(caught)
            except BaseException:
                failure = _closed_unknown_transport_failure()
            caught = None
            return failure
        try:
            extracted = _extract_openai_sdk_response(raw_response)
        except _OpenAITranslationReject:
            return _malformed_transport_failure()
        except Exception:
            return _malformed_transport_failure()
        return _OpenAITransportSuccess(response=extracted)
    finally:
        raw_response = None
        client = None
        runtime_credential = None
        client_factory = None
        owned_translated_request = None
        residual_timeout = None
        translated_request = None


_OPENAI_TRANSPORT_FAILURE_PAIRS = frozenset(
    {
        (
            ProviderCallKind.PROVIDER_ERROR,
            ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
        ),
        (ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.PERMISSION),
        (ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.MODEL_UNAVAILABLE),
        (ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.INVALID_REQUEST),
        (ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.RATE_LIMIT),
        (
            ProviderCallKind.PROVIDER_ERROR,
            ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
        ),
        (
            ProviderCallKind.PROVIDER_ERROR,
            ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
        ),
        (ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.QUOTA_EXHAUSTED),
        (
            ProviderCallKind.PROVIDER_ERROR,
            ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
        ),
        (
            ProviderCallKind.TRANSPORT_ERROR,
            ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
        ),
        (
            ProviderCallKind.TRANSPORT_ERROR,
            ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
        ),
        (
            ProviderCallKind.TRANSPORT_ERROR,
            ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
        ),
    }
)


def _openai_transport_error_message(category: ProviderErrorCategory) -> str:
    if category is ProviderErrorCategory.AUTHENTICATION_CONFIGURATION:
        return OPENAI_AUTH_MESSAGE
    if category is ProviderErrorCategory.PERMISSION:
        return OPENAI_PERMISSION_MESSAGE
    if category is ProviderErrorCategory.MODEL_UNAVAILABLE:
        return OPENAI_MODEL_UNAVAILABLE_MESSAGE
    if category is ProviderErrorCategory.INVALID_REQUEST:
        return OPENAI_INVALID_REQUEST_MESSAGE
    if category is ProviderErrorCategory.TRANSPORT_CONNECTIVITY:
        return OPENAI_CONNECTIVITY_MESSAGE
    if category is ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT:
        return OPENAI_TIMEOUT_MESSAGE
    if category is ProviderErrorCategory.RATE_LIMIT:
        return OPENAI_RATE_LIMIT_MESSAGE
    if category is ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL:
        return OPENAI_OVERLOAD_MESSAGE
    if category is ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL:
        return OPENAI_MALFORMED_MESSAGE
    if category is ProviderErrorCategory.QUOTA_EXHAUSTED:
        return OPENAI_QUOTA_MESSAGE
    if category is ProviderErrorCategory.POLICY_REFUSAL:
        return OPENAI_REFUSAL_MESSAGE
    if category is ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT:
        return OPENAI_INCOMPLETE_MESSAGE
    return OPENAI_UNKNOWN_FAILURE_MESSAGE


def _emit_openai_transport_failure_outcome(
    request: LiveInvocationRequest,
    kind: ProviderCallKind,
    category: ProviderErrorCategory,
    http_status: int | None,
    request_id: str | None,
):
    observations = _base_identity_observations(request, None)
    observations["provider_response_id"] = unavailable(
        UnavailableReason.NO_RESPONSE_RECEIVED
    )
    observations["provider_response_status"] = unavailable_int(
        UnavailableReason.NO_RESPONSE_RECEIVED
    )
    if request_id is None:
        observations["provider_request_id"] = unavailable(UnavailableReason.NOT_EXPOSED)
    else:
        observations["provider_request_id"] = observed_str(request_id)
    if http_status is None:
        http_obs = unavailable_int(UnavailableReason.NOT_EXPOSED)
    else:
        http_obs = observed_int(http_status)
    return build_provider_call_outcome(
        kind=kind,
        finish_reason=unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
        raw_output=unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
        structured_output=unavailable_structured(UnavailableReason.NO_RESPONSE_RECEIVED),
        error=NeutralError(
            category=category,
            sanitized_message=_openai_transport_error_message(category),
            http_status=http_obs,
        ),
        stage_output=None,
        **observations,
    )


def _openai_transport_failure_outcome(request: Any, failure: Any):
    """Translate a classified transport failure into a validated non-success outcome.

    Provider-local classification fields that must not cross the worker boundary
    (`error_type`, `error_code`, `param`) are discarded here. Kind/category pairs
    and bounded observations are independently re-validated even when the caller
    hands this converter a hostile or manually constructed failure object.
    """
    kind = None
    category = None
    raw_http_status = None
    raw_request_id = None
    try:
        if type(failure) is not _OpenAITransportFailure:
            raise ProtocolError(OPENAI_TRANSPORT_RESULT_INVALID)
        kind = failure.kind
        category = failure.category
        raw_http_status = failure.http_status
        raw_request_id = failure.request_id
    finally:
        failure = None
    if type(kind) is not ProviderCallKind or type(category) is not ProviderErrorCategory:
        raise ProtocolError(OPENAI_TRANSPORT_RESULT_INVALID)
    if (kind, category) not in _OPENAI_TRANSPORT_FAILURE_PAIRS:
        raise ProtocolError(OPENAI_TRANSPORT_RESULT_INVALID)
    http_status = _safe_http_status(raw_http_status)
    raw_http_status = None
    request_id = _optional_observation(raw_request_id)
    raw_request_id = None
    try:
        return _emit_openai_transport_failure_outcome(
            request, kind, category, http_status, request_id
        )
    except (LiveContractError, ProtocolError, Exception):
        raise ProtocolError(OPENAI_TRANSPORT_RESULT_INVALID) from None


def openai_responses_skeleton(
    options: Mapping[str, Any],
    provider_treatment_config: Mapping[str, Any],
    request: Any,
) -> Any:
    """Registered OpenAI live adapter. One runner-authorized attempt, no retry."""
    secret = acquire_child_openai_runtime_secret()
    translated = None
    transport_result = None
    owned_response = None
    outcome = None
    closed_failure = None
    try:
        _require_empty_openai_options(options)
        translated = build_openai_responses_request(request, provider_treatment_config)
        transport_result = _perform_openai_responses_transport(
            translated,
            secret,
            request.attempt_timeout_seconds,
        )
        result_type = type(transport_result)
        if result_type is _OpenAITransportSuccess:
            owned_response = transport_result.response
            outcome = translate_openai_responses_result(request, owned_response)
        elif result_type is _OpenAITransportFailure:
            outcome = _openai_transport_failure_outcome(request, transport_result)
        else:
            closed_failure = OPENAI_TRANSPORT_RESULT_INVALID
    except (ProtocolError, InfrastructureError, GovernanceViolation):
        raise
    except Exception:
        closed_failure = OPENAI_TRANSPORT_RESULT_INVALID
    finally:
        secret = None
        translated = None
        transport_result = None
        owned_response = None
        options = None
        provider_treatment_config = None
        request = None
    if closed_failure is not None:
        raise ProtocolError(closed_failure)
    if outcome is None:
        raise ProtocolError(OPENAI_TRANSPORT_RESULT_INVALID)
    return outcome
