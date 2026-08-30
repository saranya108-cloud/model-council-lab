"""Provider-local OpenAI Responses adapter skeleton.

The official OpenAI SDK is imported only inside the default client factory.
No SDK object, credential, or provider-local handle may cross the worker JSON
boundary. Tranche 3 registers a fail-closed skeleton: it does not construct a
Responses request, open a network path, or invoke the client factory.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from typing import Any, Callable

from .errors import InfrastructureError, ProtocolError
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
OPENAI_SECRET_NOT_SERIALIZABLE = "openai runtime secret cannot be serialized"
OPENAI_SECRET_NOT_COPYABLE = "openai runtime secret cannot be copied"

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
    return normalized


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
    """Fail-closed OpenAI live adapter. Translation is deferred to Tranche 4."""
    del request
    secret = acquire_child_openai_runtime_secret()
    try:
        _require_empty_openai_options(options)
        validate_openai_provider_treatment(provider_treatment_config)
        raise ProtocolError(OPENAI_TRANSLATION_NOT_IMPLEMENTED)
    finally:
        secret = None
