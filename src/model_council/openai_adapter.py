"""Provider-local OpenAI Responses adapter.

The official OpenAI SDK is imported only inside the default client factory.
No SDK object, credential, or provider-local handle may cross the worker JSON
boundary. Tranche 4 adds pure request/response translation from synthetic
provider-shaped fixtures. The registered production entrypoint remains
fail-closed before SDK client construction or provider invocation.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import Any, Callable

from .errors import InfrastructureError, ProtocolError
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


def _default_openai_client_factory(*, api_key: str) -> Any:
    from openai import OpenAI

    return OpenAI(api_key=api_key)


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
            client = factory(api_key=api_key)
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


def openai_responses_skeleton(
    options: Mapping[str, Any],
    provider_treatment_config: Mapping[str, Any],
    request: Any,
) -> Any:
    """Fail-closed OpenAI live adapter. Transport remains deferred."""
    del request
    secret = acquire_child_openai_runtime_secret()
    try:
        _require_empty_openai_options(options)
        validate_openai_provider_treatment(provider_treatment_config)
        raise ProtocolError(OPENAI_TRANSLATION_NOT_IMPLEMENTED)
    finally:
        secret = None
