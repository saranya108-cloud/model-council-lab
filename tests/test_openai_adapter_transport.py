"""Tranche 5A/5B: provider-local one-call OpenAI Responses transport and activation.

Deterministic offline/fake behavior only. No real provider calls, credentials,
or dependency installation. Optional SDK HTTP proofs run in a subprocess and
accept the established absence path. Production activation is exercised through
the real worker via a disposable python_executable wrapper.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import os
import subprocess
import sys
import textwrap
import types
import unittest
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import patch

import helpers  # noqa: F401 - installs src on sys.path

from model_council.adapters import LIVE_REGISTRY, REGISTRY
from model_council.errors import InfrastructureError, ProtocolError
from model_council.evaluator import EvaluationConfig, ExternalEvaluator
from model_council.executor import SubprocessAdapter
from model_council.live_contract import (
    NeutralProviderFailure,
    ProviderCallKind,
    ProviderErrorCategory,
    UnavailableReason,
    dumps_provider_call_outcome,
)
from model_council.openai_adapter import (
    MAX_OPENAI_OBSERVATION_CHARS,
    MAX_OPENAI_PROVIDER_JSON_ITEMS,
    MAX_OPENAI_RAW_EVIDENCE_BYTES,
    MAX_OPENAI_USAGE_TOKENS,
    OPENAI_AUTH_MESSAGE,
    OPENAI_CLIENT_INIT_FAILURE,
    OPENAI_CONNECTIVITY_MESSAGE,
    OPENAI_INVALID_REQUEST_MESSAGE,
    OPENAI_MALFORMED_MESSAGE,
    OPENAI_OVERLOAD_MESSAGE,
    OPENAI_PERMISSION_MESSAGE,
    OPENAI_QUOTA_MESSAGE,
    OPENAI_RATE_LIMIT_MESSAGE,
    OPENAI_TIMEOUT_MESSAGE,
    OPENAI_TRANSPORT_REQUEST_INVALID,
    OPENAI_TRANSPORT_RESULT_INVALID,
    OPENAI_TRANSPORT_TIMEOUT_INVALID,
    OPENAI_UNKNOWN_FAILURE_MESSAGE,
    RuntimeSecret,
    _OpenAIExtractionBudget,
    _OpenAITransportFailure,
    _OpenAITransportSuccess,
    _canonical_json_string_body_bytes,
    _default_openai_client_factory,
    _openai_transport_failure_outcome,
    _perform_openai_responses_transport,
    build_openai_responses_request,
    openai_responses_skeleton,
)
from model_council.retry_policy import is_retry_candidate
from model_council.runner import ExperimentRunner
from model_council.security import canonical_json, deep_freeze
from helpers import FAKE_IDENTITY, TempRoot, make_spec, make_task
from test_live_contract import make_request
from test_openai_adapter_skeleton import (
    _CHILD_KEY,
    _HOST_KEY,
    _assert_openai_parent_graph_closed,
    _failure_graph_blobs,
    _install_offline_openai_python,
    _isolated_environ,
    _live_envelope,
    _openai_adapter,
    _read_offline_calls,
    _run_worker,
)
from test_openai_adapter_translation import (
    CONFIGURED,
    REQUESTED_ALIAS,
    _CLOSED_TREATMENT,
    _completed_fixture,
    _solver_envelope,
    _solver_request,
    _usage_fixture,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
_FAKE_CREDENTIAL = "mcl-test-openai-runtime-credential-not-real"
_OPENAI_KIND = "openai_responses"
_OPENAI_SDK_VERSION = "2.54.0"
_TIMEOUT = 3.25

_OPENAI_SDK_TRANSPORT_PROBE = r'''
import importlib.metadata
import importlib.util
import json

if importlib.util.find_spec("openai") is None:
    print(json.dumps({"sdk": "absent"}, sort_keys=True))
    raise SystemExit(0)

import httpx
import openai
from openai import OpenAI

from model_council.live_contract import ProviderCallKind, ProviderErrorCategory
from model_council.openai_adapter import (
    RuntimeSecret,
    _OpenAITransportFailure,
    _OpenAITransportSuccess,
    _perform_openai_responses_transport,
    build_openai_responses_request,
)
from test_openai_adapter_translation import _solver_request

EXPECTED_VERSION = "2.54.0"
assert importlib.metadata.version("openai") == EXPECTED_VERSION
approved = build_openai_responses_request(_solver_request(), {})
secret = RuntimeSecret("not-a-real-openai-key")
report = {"sdk": EXPECTED_VERSION, "cases": {}}


def run_case(name, handler):
    attempts = {"count": 0}

    def wrapped(http_request):
        attempts["count"] += 1
        assert http_request.url.host == "network-denied.invalid"
        return handler(http_request)

    seen = {}

    def factory(*, api_key, max_retries):
        seen["api_key"] = api_key
        seen["max_retries"] = max_retries
        return OpenAI(
            api_key=api_key,
            base_url="https://network-denied.invalid/v1",
            max_retries=0,
            http_client=httpx.Client(transport=httpx.MockTransport(wrapped)),
        )

    result = _perform_openai_responses_transport(
        approved, RuntimeSecret("not-a-real-openai-key"), 3.25, client_factory=factory
    )
    payload = {
        "attempts": attempts["count"],
        "max_retries": seen["max_retries"],
        "success": isinstance(result, _OpenAITransportSuccess),
    }
    if isinstance(result, _OpenAITransportFailure):
        payload["kind"] = result.kind.value
        payload["category"] = result.category.value
        payload["http_status"] = result.http_status
        payload["error_code"] = result.error_code
    elif isinstance(result, _OpenAITransportSuccess):
        payload["kind"] = "success"
        payload["status"] = result.response.get("status")
        payload["model"] = result.response.get("model")
    report["cases"][name] = payload
    return result, attempts["count"]


def success_handler(http_request):
    timeout = dict(http_request.extensions["timeout"])
    report["success_timeout"] = timeout
    return httpx.Response(
        200,
        headers={"content-type": "application/json", "x-request-id": "req_offline"},
        json={
            "id": "resp_offline",
            "object": "response",
            "created_at": 0.0,
            "status": "completed",
            "error": None,
            "incomplete_details": None,
            "model": approved["model"],
            "output": [
                {
                    "id": "msg_offline",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "ok", "annotations": []}],
                }
            ],
            "usage": {
                "input_tokens": 1,
                "output_tokens": 2,
                "total_tokens": 3,
            },
        },
    )


def json_error(status, code, error_type, extra_headers=None):
    headers = {"content-type": "application/json", "x-request-id": "req_err"}
    if extra_headers:
        headers.update(extra_headers)

    def handler(http_request):
        return httpx.Response(
            status,
            headers=headers,
            json={
                "error": {
                    "message": "synthetic",
                    "type": error_type,
                    "code": code,
                    "param": "model",
                }
            },
        )

    return handler


def raise_connect(http_request):
    raise httpx.ConnectError("synthetic-connect", request=http_request)


def raise_timeout(http_request):
    raise httpx.ReadTimeout("synthetic-timeout", request=http_request)


run_case("success", success_handler)
run_case("rate_limit", json_error(429, "rate_limit_exceeded", "rate_limit_error", {"retry-after": "7"}))
run_case("quota", json_error(429, "insufficient_quota", "insufficient_quota"))
run_case("ambiguous_429", json_error(429, None, "rate_limit_error", {"retry-after": "9"}))
run_case("internal", json_error(500, "server_error", "server_error"))
run_case("connection", raise_connect)
run_case("timeout", raise_timeout)
print(json.dumps(report, sort_keys=True))
'''


def _assert_secret_absent(test: unittest.TestCase, *blobs) -> None:
    digest = hashlib.sha256(_FAKE_CREDENTIAL.encode("utf-8")).hexdigest()
    for blob in blobs:
        if blob is None:
            continue
        if isinstance(blob, bytes):
            text = blob.decode("utf-8", "replace")
        elif isinstance(blob, str):
            text = blob
        else:
            text = json.dumps(blob, default=str)
        if _FAKE_CREDENTIAL in text:
            test.fail("synthetic runtime credential leaked into inspected output")
        if digest in text:
            test.fail("digest of synthetic runtime credential leaked into inspected output")


def _offline_success_config(**response_overrides):
    return {
        "mode": "success",
        "response": _completed_fixture(
            _solver_envelope(), usage=_usage_fixture(), **response_overrides
        ),
    }


def _offline_error_config(cls, **fields):
    payload = {"class": cls, "message": fields.pop("message", "synthetic")}
    payload.update(fields)
    return {"mode": "error", "error": payload}


def _assert_contained_failure(
    test,
    outcome,
    *,
    kind,
    category,
    message,
    http_status=None,
    request_id=None,
):
    test.assertEqual(outcome.kind, kind)
    test.assertIsNotNone(outcome.error)
    test.assertEqual(outcome.error.category, category)
    test.assertEqual(outcome.error.sanitized_message, message)
    test.assertIsNone(outcome.stage_output)
    test.assertEqual(outcome.adapter_internal_retry_count, 0)
    test.assertEqual(dict(outcome.provider_metadata.value), {})
    test.assertIsNone(outcome.error.provider_retry_hint.value)
    test.assertIsNone(outcome.error.retry_after_seconds.value)
    if http_status is None:
        test.assertIsNone(outcome.error.http_status.value)
    else:
        test.assertEqual(outcome.error.http_status.value, http_status)
    if request_id is None:
        test.assertIsNone(outcome.provider_request_id.value)
    else:
        test.assertEqual(outcome.provider_request_id.value, request_id)
    encoded = dumps_provider_call_outcome(outcome)
    lowered = encoded.lower()
    for marker in (
        "error_type",
        "error_code",
        '"param"',
        "retry-after",
        "traceback",
        "authorization:",
        "bearer ",
        "insufficient_quota",
        "rate_limit_exceeded",
    ):
        test.assertNotIn(marker, lowered)
    _assert_secret_absent(test, encoded, outcome.to_dict())


def _invoke_offline_live(test, config, *, request=None, treatment=None, timeout=None):
    live_request = request or _solver_request()
    if timeout is not None:
        live_request = _solver_request(attempt_timeout_seconds=timeout)
    with TempRoot() as root:
        python, calls = _install_offline_openai_python(root, config)
        adapter = _openai_adapter(
            python_executable=python,
            provider_treatment_config=treatment or {},
        )
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            try:
                outcome = adapter.invoke_live(live_request)
                failure = None
            except NeutralProviderFailure as exc:
                outcome = exc.outcome
                failure = exc
        records = _read_offline_calls(calls)
        last = adapter.last_request
        _assert_secret_absent(
            test,
            json.dumps(last) if last is not None else None,
            [record for record in records],
        )
        return outcome, failure, records, last


def _closed_request(treatment=None):
    return build_openai_responses_request(_solver_request(), treatment or {})


def _plain_fields(failure: _OpenAITransportFailure) -> dict:
    return {
        "kind": failure.kind,
        "category": failure.category,
        "http_status": failure.http_status,
        "request_id": failure.request_id,
        "error_type": failure.error_type,
        "error_code": failure.error_code,
        "param": failure.param,
    }


class _FakeResponses:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class _FakeClient:
    def __init__(self, responses):
        self.responses = responses


class _FakeAPIError(Exception):
    pass


class _FakeAPIStatusError(_FakeAPIError):
    pass


class _FakeAuthenticationError(_FakeAPIStatusError):
    pass


class _FakePermissionDeniedError(_FakeAPIStatusError):
    pass


class _FakeBadRequestError(_FakeAPIStatusError):
    pass


class _FakeUnprocessableEntityError(_FakeAPIStatusError):
    pass


class _FakeNotFoundError(_FakeAPIStatusError):
    pass


class _FakeConflictError(_FakeAPIStatusError):
    pass


class _FakeRateLimitError(_FakeAPIStatusError):
    pass


class _FakeInternalServerError(_FakeAPIStatusError):
    pass


class _FakeAPIResponseValidationError(_FakeAPIError):
    pass


class _FakeAPIConnectionError(_FakeAPIError):
    pass


class _FakeAPITimeoutError(_FakeAPIConnectionError):
    pass


class _FakeOpenAI:
    APIError = _FakeAPIError
    APIStatusError = _FakeAPIStatusError
    AuthenticationError = _FakeAuthenticationError
    PermissionDeniedError = _FakePermissionDeniedError
    BadRequestError = _FakeBadRequestError
    UnprocessableEntityError = _FakeUnprocessableEntityError
    NotFoundError = _FakeNotFoundError
    ConflictError = _FakeConflictError
    RateLimitError = _FakeRateLimitError
    InternalServerError = _FakeInternalServerError
    APIResponseValidationError = _FakeAPIResponseValidationError
    APIConnectionError = _FakeAPIConnectionError
    APITimeoutError = _FakeAPITimeoutError


def _sdk_error(
    cls,
    *,
    message="synthetic",
    status=None,
    request_id=None,
    error_type=None,
    code=None,
    param=None,
):
    exc = cls(message)
    if status is not None:
        exc.status_code = status
    if request_id is not None:
        exc.request_id = request_id
    if error_type is not None:
        exc.type = error_type
    if code is not None:
        exc.code = code
    if param is not None:
        exc.param = param
    return exc


def _invoke(
    *,
    request=None,
    timeout=_TIMEOUT,
    secret=None,
    response=None,
    error=None,
    factory=None,
    openai_module=_FakeOpenAI,
):
    if request is None:
        request = _closed_request()
    if secret is None:
        secret = RuntimeSecret(_FAKE_CREDENTIAL)
    responses = _FakeResponses(result=response, error=error)
    seen = {"responses": responses, "factory_calls": []}

    def default_factory(*, api_key, max_retries):
        seen["factory_calls"].append({"api_key": api_key, "max_retries": max_retries})
        return _FakeClient(responses)

    chosen = factory if factory is not None else default_factory
    with patch(
        "model_council.openai_adapter._import_openai_sdk",
        return_value=openai_module,
    ):
        result = _perform_openai_responses_transport(
            request, secret, timeout, client_factory=chosen
        )
    return result, seen


def _success_response(**overrides):
    message = overrides.pop("message", None)
    reasoning = overrides.pop("reasoning", None)
    tool = overrides.pop("tool", None)
    output = overrides.pop("output", None)
    if output is None:
        items = []
        if reasoning is not None:
            items.append(reasoning)
        if tool is not None:
            items.append(tool)
        items.append(
            message
            or types.SimpleNamespace(
                type="message",
                status="completed",
                role="assistant",
                content=[types.SimpleNamespace(type="output_text", text='{"ok":true}')],
            )
        )
        output = items
    payload = dict(
        object="response",
        id="resp_1",
        request_id="req_1",
        model="gpt-5.6-sol-observed",
        status="completed",
        output=output,
        incomplete_details=None,
        error=None,
        usage=types.SimpleNamespace(
            input_tokens=11,
            output_tokens=22,
            total_tokens=33,
            input_tokens_details=types.SimpleNamespace(cached_tokens=2),
            output_tokens_details=types.SimpleNamespace(reasoning_tokens=4),
        ),
    )
    payload.update(overrides)
    return types.SimpleNamespace(**payload)


class _HostileHeaders:
    def get(self, key, default=None):
        raise AssertionError(f"header {key!r} accessed")

    def __getitem__(self, key):
        raise AssertionError(f"header {key!r} accessed")


class _HostileHTTPResponse:
    headers = _HostileHeaders()

    def json(self):
        raise AssertionError("response body accessed")

    def text(self):
        raise AssertionError("response text accessed")


class _HostileRateLimit(_FakeRateLimitError):
    def __init__(self):
        super().__init__(
            f"Authorization: Bearer {_FAKE_CREDENTIAL}\ntraceback at leak.py"
        )
        self.status_code = 429
        self.request_id = "req_hostile"
        self.type = "rate_limit_error"
        self.code = "rate_limit_exceeded"
        self.param = "model"
        self.response = _HostileHTTPResponse()
        self.body = {"error": {"message": _FAKE_CREDENTIAL, "code": "rate_limit_exceeded"}}
        self.__cause__ = RuntimeError("cause " + _FAKE_CREDENTIAL)
        self.__context__ = RuntimeError("context " + _FAKE_CREDENTIAL)

    def __repr__(self):
        return f"HostileRateLimit({_FAKE_CREDENTIAL})"


class _ExplodingMapping(Mapping):
    def __iter__(self):
        raise RuntimeError(_FAKE_CREDENTIAL)

    def __getitem__(self, key):
        raise RuntimeError(_FAKE_CREDENTIAL)

    def __len__(self):
        return 1


class _SecretBearingMapping(Mapping):
    def __iter__(self):
        yield "Authorization"
        yield "api_key"
        yield "input"

    def __getitem__(self, key):
        return _FAKE_CREDENTIAL

    def __len__(self):
        return 3

    def __repr__(self):
        return f"SecretBearingMapping({_FAKE_CREDENTIAL})"


class _SecretNonJson:
    def __init__(self):
        self.credential = _FAKE_CREDENTIAL

    def __repr__(self):
        return f"SecretNonJson({_FAKE_CREDENTIAL})"


class _HostileObservationError(_FakeAPIStatusError):
    def __init__(self):
        super().__init__("Authorization: Bearer " + _FAKE_CREDENTIAL)
        self.client = types.SimpleNamespace(
            api_key=_FAKE_CREDENTIAL,
            _api_key=_FAKE_CREDENTIAL,
        )
        self.response = _HostileHTTPResponse()
        self.body = {"error": {"message": _FAKE_CREDENTIAL, "code": "rate_limit_exceeded"}}
        self.__cause__ = RuntimeError("cause " + _FAKE_CREDENTIAL)
        self.__context__ = RuntimeError("context " + _FAKE_CREDENTIAL)

    @property
    def status_code(self):
        raise RuntimeError("status_code getter " + _FAKE_CREDENTIAL)

    @property
    def request_id(self):
        raise RuntimeError("request_id getter " + _FAKE_CREDENTIAL)

    @property
    def type(self):
        raise RuntimeError("type getter " + _FAKE_CREDENTIAL)

    @property
    def code(self):
        raise RuntimeError("code getter " + _FAKE_CREDENTIAL)

    @property
    def param(self):
        raise RuntimeError("param getter " + _FAKE_CREDENTIAL)

    def __repr__(self):
        return f"HostileObservationError({_FAKE_CREDENTIAL})"


class _CountedReasoning:
    def __init__(self, counter):
        self._counter = counter

    @property
    def type(self):
        self._counter["n"] += 1
        return "reasoning"


class _CountedOutputText:
    def __init__(self, counter, text, index):
        self._counter = counter
        self._text = text
        self._index = index

    def _touch(self):
        self._counter["n"] += 1
        self._counter["ids"].add(self._index)

    @property
    def type(self):
        self._touch()
        return "output_text"

    @property
    def text(self):
        self._touch()
        return self._text


def _single_hostile_observation_error(field, boom):
    class _Err(_FakeAPIStatusError):
        def __init__(self):
            super().__init__("Authorization: Bearer " + _FAKE_CREDENTIAL)
            self.client = types.SimpleNamespace(
                api_key=_FAKE_CREDENTIAL,
                _api_key=_FAKE_CREDENTIAL,
            )
            self.response = _HostileHTTPResponse()
            self.body = {"error": {"message": _FAKE_CREDENTIAL}}

        @property
        def status_code(self):
            if field == "status_code":
                raise boom
            return 429

        @property
        def request_id(self):
            if field == "request_id":
                raise boom
            return "req_ok"

        @property
        def type(self):
            if field == "type":
                raise boom
            return "rate_limit_error"

        @property
        def code(self):
            if field == "code":
                raise boom
            return "rate_limit_exceeded"

        @property
        def param(self):
            if field == "param":
                raise boom
            return "model"

        def __repr__(self):
            return f"SingleHostile({field},{_FAKE_CREDENTIAL})"

    return _Err()


class _HostileClassLookupSDK:
    def __getattr__(self, name):
        raise KeyboardInterrupt()


class _RaisingInstancecheck(type):
    def __instancecheck__(cls, instance):
        raise KeyboardInterrupt()


class _RaisingSDKError(metaclass=_RaisingInstancecheck):
    pass


class _HostileIsinstanceSDK:
    APIError = _RaisingSDKError
    APIStatusError = _RaisingSDKError
    AuthenticationError = _RaisingSDKError
    PermissionDeniedError = _RaisingSDKError
    BadRequestError = _RaisingSDKError
    UnprocessableEntityError = _RaisingSDKError
    NotFoundError = _RaisingSDKError
    ConflictError = _RaisingSDKError
    RateLimitError = _RaisingSDKError
    InternalServerError = _RaisingSDKError
    APIResponseValidationError = _RaisingSDKError
    APIConnectionError = _RaisingSDKError
    APITimeoutError = _RaisingSDKError


def _assert_closed_unknown(test, result, seen):
    test.assertIsInstance(result, _OpenAITransportFailure)
    test.assertEqual(len(seen["responses"].calls), 1)
    test.assertEqual(result.kind, ProviderCallKind.TRANSPORT_ERROR)
    test.assertEqual(result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)
    test.assertIsNone(result.http_status)
    test.assertIsNone(result.request_id)
    test.assertIsNone(result.error_type)
    test.assertIsNone(result.error_code)
    test.assertIsNone(result.param)
    blob = repr(result) + json.dumps(_plain_fields(result), default=str)
    _assert_secret_absent(test, blob, *_failure_graph_blobs(result))
    test.assertNotIn("traceback", blob.lower())
    test.assertFalse(hasattr(result, "client"))
    test.assertFalse(hasattr(result, "response"))
    test.assertFalse(hasattr(result, "body"))
    test.assertIsNone(getattr(result, "__cause__", None))
    test.assertIsNone(getattr(result, "__context__", None))


class _HostileResponse:
    object = "response"
    id = "resp_hostile"
    request_id = "req_hostile"
    model = "gpt-5.6-sol-observed"
    status = "completed"
    incomplete_details = None
    error = None
    usage = types.SimpleNamespace(
        input_tokens=1,
        output_tokens=1,
        total_tokens=2,
    )

    @property
    def output_text(self):
        raise AssertionError("computed output_text accessed")

    def model_dump(self, *args, **kwargs):
        raise AssertionError("model_dump accessed")

    def model_dump_json(self, *args, **kwargs):
        raise AssertionError("model_dump_json accessed")

    @property
    def __dict__(self):
        raise AssertionError("__dict__ accessed")

    @property
    def created_at(self):
        raise AssertionError("created_at accessed")

    @property
    def metadata(self):
        raise AssertionError("metadata accessed")

    @property
    def output(self):
        return [
            _HostileReasoning(),
            _HostileTool(),
            types.SimpleNamespace(
                type="message",
                status="completed",
                role="assistant",
                content=[types.SimpleNamespace(type="output_text", text="ok")],
            ),
        ]


class _HostileReasoning:
    type = "reasoning"

    @property
    def summary(self):
        raise AssertionError("reasoning contents accessed")

    @property
    def content(self):
        raise AssertionError("reasoning contents accessed")

    @property
    def encrypted_content(self):
        raise AssertionError("reasoning contents accessed")


class _HostileTool:
    type = "function_call"

    @property
    def arguments(self):
        raise AssertionError("tool arguments accessed")

    @property
    def output(self):
        raise AssertionError("tool results accessed")

    @property
    def result(self):
        raise AssertionError("tool results accessed")


class TestOpenAITransportClosedInput(unittest.TestCase):
    def test_accepted_builder_output_reaches_create_once(self):
        live_request = _solver_request(max_output_tokens=137)
        request = build_openai_responses_request(live_request, _CLOSED_TREATMENT)
        result, seen = _invoke(request=request, response=_success_response())
        self.assertIsInstance(result, _OpenAITransportSuccess)
        calls = seen["responses"].calls
        self.assertEqual(len(calls), 1)
        sent = dict(calls[0])
        timeout = sent.pop("timeout")
        self.assertEqual(timeout, _TIMEOUT)
        self.assertEqual(sent, request)
        self.assertEqual(sent["max_output_tokens"], 137)

    def test_extra_and_forbidden_keys_are_rejected_before_factory(self):
        cases = (
            ("timeout", 1),
            ("max_retries", 3),
            ("retry", True),
            ("retry_after", 7),
            ("previous_response_id", "resp_1"),
            ("conversation", "conv_1"),
            ("user", "user-1"),
            ("service_tier", "flex"),
            ("temperature", 0),
            ("top_p", 1),
            ("metadata", {"run": "x"}),
        )
        for key, value in cases:
            with self.subTest(key=key):
                request = dict(_closed_request())
                request[key] = value
                called = []

                def factory(*, api_key, max_retries):
                    called.append(True)
                    raise AssertionError("factory must not run")

                with self.assertRaises(ProtocolError) as ctx:
                    _invoke(request=request, factory=factory)
                self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_REQUEST_INVALID)
                self.assertEqual(called, [])

    def test_malformed_output_ceilings_are_rejected_before_factory(self):
        for value in (None, True, False, 0, -1, 1.0, "16", [], {}):
            with self.subTest(value=repr(value)):
                request = dict(_closed_request())
                request["max_output_tokens"] = value
                called = []

                def factory(*, api_key, max_retries):
                    called.append(True)
                    raise AssertionError("factory must not run")

                with self.assertRaises(ProtocolError) as ctx:
                    _invoke(request=request, factory=factory)
                self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_REQUEST_INVALID)
                self.assertEqual(called, [])

    def test_request_without_output_ceiling_preserves_omission(self):
        request = dict(_closed_request())
        request.pop("max_output_tokens", None)
        result, seen = _invoke(request=request, response=_success_response())
        self.assertIsInstance(result, _OpenAITransportSuccess)
        self.assertEqual(len(seen["responses"].calls), 1)
        self.assertNotIn("max_output_tokens", seen["responses"].calls[0])

    def test_missing_required_key_is_rejected_before_factory(self):
        request = dict(_closed_request())
        del request["model"]
        called = []

        def factory(*, api_key, max_retries):
            called.append(True)
            raise AssertionError("factory must not run")

        with self.assertRaises(ProtocolError) as ctx:
            _invoke(request=request, factory=factory)
        self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_REQUEST_INVALID)
        self.assertEqual(called, [])

    def test_adversarial_and_non_json_requests_are_rejected_before_factory(self):
        closed = _closed_request()
        invalid = dict(closed)
        invalid["input"] = object()
        cases = (
            _ExplodingMapping(),
            invalid,
            [],
            "request",
            None,
        )
        for request in cases:
            with self.subTest(request=type(request).__name__):
                called = []

                def factory(*, api_key, max_retries):
                    called.append(True)
                    raise AssertionError("factory must not run")

                with self.assertRaises(ProtocolError) as ctx:
                    try:
                        _perform_openai_responses_transport(
                            request,
                            RuntimeSecret(_FAKE_CREDENTIAL),
                            _TIMEOUT,
                            client_factory=factory,
                        )
                    except Exception as exc:
                        _assert_secret_absent(self, str(exc), repr(exc))
                        raise
                self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_REQUEST_INVALID)
                self.assertEqual(called, [])

    def test_secret_bearing_mapping_is_rejected_without_traversal_or_chain(self):
        called = []

        def factory(*, api_key, max_retries):
            called.append(True)
            raise AssertionError("factory must not run")

        with self.assertRaises(ProtocolError) as ctx:
            _perform_openai_responses_transport(
                _SecretBearingMapping(),
                RuntimeSecret(_FAKE_CREDENTIAL),
                _TIMEOUT,
                client_factory=factory,
            )
        exc = ctx.exception
        self.assertEqual(str(exc), OPENAI_TRANSPORT_REQUEST_INVALID)
        self.assertEqual(called, [])
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        _assert_secret_absent(self, str(exc), repr(exc), *_failure_graph_blobs(exc))

    def test_secret_bearing_non_json_dict_is_rejected_without_chain(self):
        request = dict(_closed_request())
        request["input"] = _SecretNonJson()
        called = []

        def factory(*, api_key, max_retries):
            called.append(True)
            raise AssertionError("factory must not run")

        with self.assertRaises(ProtocolError) as ctx:
            _perform_openai_responses_transport(
                request,
                RuntimeSecret(_FAKE_CREDENTIAL),
                _TIMEOUT,
                client_factory=factory,
            )
        exc = ctx.exception
        self.assertEqual(str(exc), OPENAI_TRANSPORT_REQUEST_INVALID)
        self.assertEqual(called, [])
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        _assert_secret_absent(self, str(exc), repr(exc), *_failure_graph_blobs(exc))


class TestOpenAITransportTimeout(unittest.TestCase):
    def test_invalid_residual_timeouts_are_rejected_before_factory(self):
        cases = (
            True,
            False,
            "1.5",
            0,
            0.0,
            -1,
            -0.01,
            float("nan"),
            float("inf"),
            float("-inf"),
            math.nan,
        )
        for value in cases:
            with self.subTest(value=repr(value)):
                called = []

                def factory(*, api_key, max_retries):
                    called.append(True)
                    raise AssertionError("factory must not run")

                with self.assertRaises(ProtocolError) as ctx:
                    _invoke(timeout=value, factory=factory, response=_success_response())
                self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_TIMEOUT_INVALID)
                self.assertEqual(called, [])

    def test_finite_positive_timeouts_are_passed_unchanged(self):
        cases = (0.001, _TIMEOUT, 12, 3600.0)
        for value in cases:
            with self.subTest(value=value):
                result, seen = _invoke(
                    timeout=value, response=_success_response()
                )
                self.assertIsInstance(result, _OpenAITransportSuccess)
                self.assertEqual(len(seen["responses"].calls), 1)
                passed = seen["responses"].calls[0]["timeout"]
                self.assertEqual(passed, value)
                self.assertIs(passed, value)


class TestOpenAITransportClientConfiguration(unittest.TestCase):
    def test_injected_factory_receives_credential_once_and_zero_retries(self):
        result, seen = _invoke(response=_success_response())
        self.assertIsInstance(result, _OpenAITransportSuccess)
        self.assertEqual(
            seen["factory_calls"],
            [{"api_key": _FAKE_CREDENTIAL, "max_retries": 0}],
        )

    def test_default_factory_rejects_nonzero_retries_without_importing_sdk(self):
        self.assertNotIn("openai", sys.modules)
        with self.assertRaises(InfrastructureError) as ctx:
            _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=2)
        self.assertEqual(str(ctx.exception), OPENAI_CLIENT_INIT_FAILURE)
        self.assertNotIn("openai", sys.modules)
        with self.assertRaises(InfrastructureError):
            _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=True)
        self.assertNotIn("openai", sys.modules)

    def test_non_secret_credential_fails_before_create(self):
        called = []

        def factory(*, api_key, max_retries):
            called.append(True)
            raise AssertionError("factory must not run")

        with self.assertRaises(InfrastructureError) as ctx:
            _perform_openai_responses_transport(
                _closed_request(),
                "not-a-secret",
                _TIMEOUT,
                client_factory=factory,
            )
        self.assertEqual(str(ctx.exception), OPENAI_CLIENT_INIT_FAILURE)
        self.assertEqual(called, [])


class TestOpenAITransportExactlyOneCall(unittest.TestCase):
    def test_success_and_failures_perform_exactly_one_create(self):
        cases = (
            ("success", _success_response(), None, _OpenAITransportSuccess, None),
            (
                "rate_limit",
                None,
                _sdk_error(
                    _FakeRateLimitError,
                    status=429,
                    error_type="rate_limit_error",
                    code="rate_limit_exceeded",
                ),
                _OpenAITransportFailure,
                ProviderErrorCategory.RATE_LIMIT,
            ),
            (
                "quota",
                None,
                _sdk_error(
                    _FakeRateLimitError,
                    status=429,
                    error_type="insufficient_quota",
                    code="insufficient_quota",
                ),
                _OpenAITransportFailure,
                ProviderErrorCategory.QUOTA_EXHAUSTED,
            ),
            (
                "ambiguous_429",
                None,
                _sdk_error(
                    _FakeRateLimitError,
                    status=429,
                    error_type="rate_limit_error",
                    code=None,
                ),
                _OpenAITransportFailure,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
            ),
            (
                "internal",
                None,
                _sdk_error(_FakeInternalServerError, status=500),
                _OpenAITransportFailure,
                ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
            ),
            (
                "connection",
                None,
                _sdk_error(_FakeAPIConnectionError),
                _OpenAITransportFailure,
                ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
            ),
            (
                "timeout",
                None,
                _sdk_error(_FakeAPITimeoutError),
                _OpenAITransportFailure,
                ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
            ),
        )
        for name, response, error, result_type, category in cases:
            with self.subTest(name=name):
                with patch("time.sleep", side_effect=AssertionError("sleep")):
                    result, seen = _invoke(response=response, error=error)
                self.assertIsInstance(result, result_type)
                self.assertEqual(len(seen["responses"].calls), 1)
                if category is not None:
                    self.assertEqual(result.category, category)
                    self.assertEqual(result.kind, result.kind)


class TestOpenAITransportNoRetry(unittest.TestCase):
    def test_sleep_backoff_and_retry_after_are_not_used(self):
        err = _HostileRateLimit()
        with patch("time.sleep", side_effect=AssertionError("sleep")):
            result, seen = _invoke(error=err)
        self.assertIsInstance(result, _OpenAITransportFailure)
        self.assertEqual(result.category, ProviderErrorCategory.RATE_LIMIT)
        self.assertEqual(len(seen["responses"].calls), 1)
        blob = repr(result) + json.dumps(_plain_fields(result))
        self.assertNotIn("retry-after", blob.lower())
        self.assertNotIn("Retry-After", blob)
        _assert_secret_absent(self, blob, result.request_id, result.error_code)

    def test_transport_source_has_no_retry_loop_or_helper(self):
        from model_council import openai_adapter as openai_mod

        source = inspect.getsource(openai_mod._perform_openai_responses_transport)
        tree = ast.parse(textwrap.dedent(source))
        creates = 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
                self.fail("transport seam contains a retry loop")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "_perform_openai_responses_transport":
                    self.fail("transport seam recurses")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"sleep", "backoff"}:
                    self.fail("transport seam sleeps or backs off")
                if node.func.attr == "create":
                    target = node.func.value
                    if isinstance(target, ast.Attribute) and target.attr == "responses":
                        creates += 1
        self.assertEqual(creates, 1)
        lowered = source.lower()
        self.assertNotIn("retry-after", lowered)
        self.assertNotIn("retry_after", lowered)
        self.assertNotIn("backoff", lowered)
        self.assertNotIn("time.sleep", source)
        normalize_src = inspect.getsource(openai_mod._normalize_openai_sdk_exception)
        self.assertNotIn("retry-after", normalize_src.lower())
        self.assertNotIn("headers", normalize_src)


class TestOpenAITransportExtraction(unittest.TestCase):
    def test_successful_extraction_copies_approved_facts_only(self):
        incomplete = types.SimpleNamespace(reason="max_output_tokens")
        result, _ = _invoke(
            response=_success_response(incomplete_details=incomplete, status="incomplete")
        )
        self.assertIsInstance(result, _OpenAITransportSuccess)
        owned = result.response
        json.dumps(owned)
        self.assertEqual(owned["object"], "response")
        self.assertEqual(owned["id"], "resp_1")
        self.assertEqual(owned["request_id"], "req_1")
        self.assertEqual(owned["model"], "gpt-5.6-sol-observed")
        self.assertEqual(owned["status"], "incomplete")
        self.assertEqual(owned["incomplete_details"], {"reason": "max_output_tokens"})
        self.assertIsNone(owned["error"])
        self.assertEqual(
            owned["usage"],
            {
                "input_tokens": 11,
                "output_tokens": 22,
                "total_tokens": 33,
                "input_tokens_details": {"cached_tokens": 2},
                "output_tokens_details": {"reasoning_tokens": 4},
            },
        )
        message = owned["output"][-1]
        self.assertEqual(message["type"], "message")
        self.assertEqual(message["status"], "completed")
        self.assertEqual(message["role"], "assistant")
        self.assertEqual(message["content"][0]["type"], "output_text")
        self.assertNotIn("output_text", owned)
        self.assertNotIn("created_at", owned)
        self.assertNotIn("metadata", owned)

    def test_request_id_fallback_and_error_presence(self):
        response = _success_response()
        delattr(response, "request_id")
        response._request_id = "req_private"
        response.error = object()
        result, _ = _invoke(response=response)
        self.assertEqual(result.response["request_id"], "req_private")
        self.assertIs(result.response["error"], True)

    def test_computed_output_text_and_forbidden_surfaces_are_not_accessed(self):
        result, _ = _invoke(response=_HostileResponse())
        self.assertIsInstance(result, _OpenAITransportSuccess)
        types_seen = [item["type"] for item in result.response["output"]]
        self.assertEqual(types_seen, ["reasoning", "function_call", "message"])
        self.assertEqual(result.response["output"][0], {"type": "reasoning"})
        self.assertEqual(result.response["output"][1], {"type": "function_call"})
        blob = canonical_json(result.response)
        self.assertNotIn("arguments", blob)
        self.assertNotIn("summary", blob)
        self.assertNotIn("encrypted_content", blob)


class TestOpenAITransport429Policy(unittest.TestCase):
    def test_code_and_type_adversaries(self):
        cases = (
            ("insufficient_quota", "insufficient_quota", ProviderErrorCategory.QUOTA_EXHAUSTED),
            ("rate_limit_exceeded", "rate_limit_error", ProviderErrorCategory.RATE_LIMIT),
            (None, "rate_limit_error", ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            ("not_a_real_code", "rate_limit_error", ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            ("n" * 257, "rate_limit_error", ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            ("sk-not-a-secret-code", "rate_limit_error", ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            ("rate_limit_exceeded", "insufficient_quota", ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            ("rate_limit_exceeded", None, ProviderErrorCategory.RATE_LIMIT),
        )
        for code, error_type, category in cases:
            with self.subTest(code=code, error_type=error_type):
                err = _sdk_error(
                    _FakeRateLimitError,
                    status=429,
                    error_type=error_type,
                    code=code,
                    request_id="req_429",
                )
                result, seen = _invoke(error=err)
                self.assertEqual(len(seen["responses"].calls), 1)
                self.assertEqual(result.kind, ProviderCallKind.PROVIDER_ERROR)
                self.assertEqual(result.category, category)
                self.assertEqual(result.http_status, 429)

    def test_type_alone_never_authorizes_rate_limit(self):
        err = _sdk_error(
            _FakeRateLimitError,
            status=429,
            error_type="rate_limit_exceeded",
        )
        result, _ = _invoke(error=err)
        self.assertEqual(result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)

    def test_status_error_429_uses_the_same_policy(self):
        err = _sdk_error(
            _FakeAPIStatusError,
            status=429,
            error_type="rate_limit_error",
            code="rate_limit_exceeded",
        )
        result, _ = _invoke(error=err)
        self.assertEqual(result.category, ProviderErrorCategory.RATE_LIMIT)


class TestOpenAITransportExceptionMapping(unittest.TestCase):
    def test_specific_sdk_classes_map_to_closed_categories(self):
        cases = (
            (_FakeAuthenticationError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.AUTHENTICATION_CONFIGURATION),
            (_FakePermissionDeniedError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.PERMISSION),
            (_FakeBadRequestError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.INVALID_REQUEST),
            (_FakeUnprocessableEntityError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.INVALID_REQUEST),
            (_FakeNotFoundError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.MODEL_UNAVAILABLE),
            (_FakeConflictError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE),
            (_FakeInternalServerError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL),
            (_FakeAPIResponseValidationError, ProviderCallKind.PROVIDER_ERROR, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL),
            (_FakeAPITimeoutError, ProviderCallKind.TRANSPORT_ERROR, ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT),
            (_FakeAPIConnectionError, ProviderCallKind.TRANSPORT_ERROR, ProviderErrorCategory.TRANSPORT_CONNECTIVITY),
        )
        for cls, kind, category in cases:
            with self.subTest(cls=cls.__name__):
                result, seen = _invoke(error=_sdk_error(cls, status=400))
                self.assertEqual(len(seen["responses"].calls), 1)
                self.assertEqual(result.kind, kind)
                self.assertEqual(result.category, category)

    def test_other_status_and_generic_exceptions(self):
        five = _sdk_error(_FakeAPIStatusError, status=503)
        other = _sdk_error(_FakeAPIStatusError, status=418)
        generic = RuntimeError("boom " + _FAKE_CREDENTIAL)
        five_result, _ = _invoke(error=five)
        other_result, _ = _invoke(error=other)
        generic_result, _ = _invoke(error=generic)
        self.assertEqual(five_result.category, ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL)
        self.assertEqual(other_result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)
        self.assertEqual(other_result.kind, ProviderCallKind.PROVIDER_ERROR)
        self.assertEqual(generic_result.kind, ProviderCallKind.TRANSPORT_ERROR)
        self.assertEqual(generic_result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)
        _assert_secret_absent(self, repr(generic_result), json.dumps(_plain_fields(generic_result)))


class TestOpenAITransportContainment(unittest.TestCase):
    def test_secret_bearing_exception_surfaces_are_not_retained(self):
        result, _ = _invoke(error=_HostileRateLimit())
        blob = repr(result) + json.dumps(_plain_fields(result))
        _assert_secret_absent(self, blob)
        self.assertNotIn("traceback", blob.lower())
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("Bearer", blob)
        self.assertEqual(result.error_code, "rate_limit_exceeded")
        self.assertEqual(result.request_id, "req_hostile")

    def test_failure_repr_only_includes_sanitized_fields(self):
        result, _ = _invoke(
            error=_sdk_error(
                _FakeBadRequestError,
                message="Authorization: Bearer " + _FAKE_CREDENTIAL,
                status=400,
                request_id="req_bad",
                error_type="invalid_request_error",
                code="invalid_value",
                param="model",
            )
        )
        rendered = repr(result)
        _assert_secret_absent(self, rendered)
        self.assertIn("req_bad", rendered)
        self.assertIn("invalid_value", rendered)
        self.assertNotIn("synthetic", rendered)

    def test_hostile_observation_getters_fail_closed_without_escaping(self):
        err = _HostileObservationError()
        result, seen = _invoke(error=err)
        self.assertIsInstance(result, _OpenAITransportFailure)
        self.assertEqual(len(seen["responses"].calls), 1)
        self.assertEqual(result.kind, ProviderCallKind.TRANSPORT_ERROR)
        self.assertEqual(result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)
        self.assertIsNone(result.http_status)
        self.assertIsNone(result.request_id)
        self.assertIsNone(result.error_type)
        self.assertIsNone(result.error_code)
        self.assertIsNone(result.param)
        blob = repr(result) + json.dumps(_plain_fields(result), default=str)
        _assert_secret_absent(self, blob)
        self.assertNotIn("traceback", blob.lower())
        self.assertNotIn("Authorization", blob)
        self.assertNotIn("Bearer", blob)
        self.assertFalse(hasattr(result, "client"))
        self.assertFalse(hasattr(result, "response"))
        self.assertFalse(hasattr(result, "body"))
        self.assertIsNone(getattr(result, "__cause__", None))
        self.assertIsNone(getattr(result, "__context__", None))
        _assert_secret_absent(self, *_failure_graph_blobs(result))

    def test_sdk_import_failure_discards_populated_observations(self):
        err = _sdk_error(
            _FakeRateLimitError,
            status=429,
            request_id="req_import",
            error_type="rate_limit_error",
            code="rate_limit_exceeded",
            param="model",
        )
        result, seen = _invoke(error=err, openai_module=None)
        _assert_closed_unknown(self, result, seen)

    def test_each_observation_getter_independently_fails_closed(self):
        for field in ("status_code", "request_id", "type", "code", "param"):
            with self.subTest(field=field):
                boom = RuntimeError("hostile " + field + " " + _FAKE_CREDENTIAL)
                result, seen = _invoke(error=_single_hostile_observation_error(field, boom))
                _assert_closed_unknown(self, result, seen)

    def test_baseexception_getter_fails_closed_without_escaping(self):
        err = _single_hostile_observation_error("status_code", KeyboardInterrupt())
        result, seen = _invoke(error=err)
        _assert_closed_unknown(self, result, seen)

    def test_sdk_class_lookup_baseexception_fails_closed(self):
        err = _sdk_error(
            _FakeRateLimitError,
            status=429,
            request_id="req_lookup",
            error_type="rate_limit_error",
            code="rate_limit_exceeded",
            param="model",
        )
        result, seen = _invoke(error=err, openai_module=_HostileClassLookupSDK())
        _assert_closed_unknown(self, result, seen)

    def test_sdk_isinstance_baseexception_fails_closed(self):
        err = _sdk_error(
            _FakeRateLimitError,
            status=429,
            request_id="req_isinstance",
            error_type="rate_limit_error",
            code="rate_limit_exceeded",
            param="model",
        )
        result, seen = _invoke(error=err, openai_module=_HostileIsinstanceSDK)
        _assert_closed_unknown(self, result, seen)


class TestOpenAITransportBounds(unittest.TestCase):
    def test_observation_bound_accepts_256_and_drops_257(self):
        safe = "n" * MAX_OPENAI_OBSERVATION_CHARS
        over = "n" * (MAX_OPENAI_OBSERVATION_CHARS + 1)
        accepted, _ = _invoke(
            response=_success_response(id=safe, request_id=safe, model=safe)
        )
        self.assertEqual(accepted.response["id"], safe)
        self.assertEqual(accepted.response["request_id"], safe)
        self.assertEqual(accepted.response["model"], safe)
        dropped, _ = _invoke(
            response=_success_response(id=over, request_id=over, model=over)
        )
        self.assertNotIn("id", dropped.response)
        self.assertNotIn("request_id", dropped.response)
        self.assertNotIn("model", dropped.response)
        blob = canonical_json(dropped.response)
        self.assertNotIn(over, blob)

    def test_status_codes_and_bool_status_are_filtered(self):
        valid, _ = _invoke(error=_sdk_error(_FakeInternalServerError, status=500))
        self.assertEqual(valid.http_status, 500)
        for status in (True, False, 99, 600, "429"):
            with self.subTest(status=status):
                result, _ = _invoke(
                    error=_sdk_error(_FakeInternalServerError, status=status)
                )
                self.assertIsNone(result.http_status)

    def test_usage_ceiling_and_raw_evidence_byte_limit(self):
        ok_usage = types.SimpleNamespace(
            input_tokens=MAX_OPENAI_USAGE_TOKENS,
            output_tokens=0,
            total_tokens=MAX_OPENAI_USAGE_TOKENS,
        )
        ok, _ = _invoke(response=_success_response(usage=ok_usage))
        self.assertEqual(ok.response["usage"]["input_tokens"], MAX_OPENAI_USAGE_TOKENS)
        bad_usage = types.SimpleNamespace(
            input_tokens=MAX_OPENAI_USAGE_TOKENS + 1,
            output_tokens=0,
            total_tokens=0,
        )
        malformed, _ = _invoke(response=_success_response(usage=bad_usage))
        self.assertEqual(
            malformed.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        huge = "x" * (MAX_OPENAI_RAW_EVIDENCE_BYTES + 1)
        huge_message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=[types.SimpleNamespace(type="output_text", text=huge)],
        )
        overflow, _ = _invoke(response=_success_response(message=huge_message))
        self.assertEqual(
            overflow.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )

    def test_provider_json_item_limit_fail_closes(self):
        items = [types.SimpleNamespace(type="reasoning") for _ in range(2000)]
        items.append(
            types.SimpleNamespace(
                type="message",
                status="completed",
                role="assistant",
                content=[types.SimpleNamespace(type="output_text", text="ok")],
            )
        )
        result, _ = _invoke(response=_success_response(output=items))
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )

    def test_oversized_output_stops_before_touching_all_items(self):
        counter = {"n": 0}
        n_items = MAX_OPENAI_PROVIDER_JSON_ITEMS + 64
        items = [_CountedReasoning(counter) for _ in range(n_items)]
        result, _ = _invoke(response=_success_response(output=items))
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertLessEqual(counter["n"], MAX_OPENAI_PROVIDER_JSON_ITEMS)
        self.assertLess(counter["n"], n_items)

    def test_oversized_message_content_stops_before_touching_all_parts(self):
        counter = {"n": 0, "ids": set()}
        n_parts = MAX_OPENAI_PROVIDER_JSON_ITEMS + 32
        parts = [
            _CountedOutputText(counter, "ok", index) for index in range(n_parts)
        ]
        message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=parts,
        )
        result, _ = _invoke(response=_success_response(message=message))
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertLessEqual(counter["n"], MAX_OPENAI_PROVIDER_JSON_ITEMS * 2)
        self.assertLessEqual(len(counter["ids"]), MAX_OPENAI_PROVIDER_JSON_ITEMS)
        self.assertLess(len(counter["ids"]), n_parts)

    def test_aggregate_byte_overflow_rejects_before_full_materialization(self):
        chunk_size = 50_000
        chunk = "n" * chunk_size
        n_parts = (MAX_OPENAI_RAW_EVIDENCE_BYTES // chunk_size) + 8
        counter = {"n": 0, "ids": set()}
        parts = [
            _CountedOutputText(counter, chunk, index) for index in range(n_parts)
        ]
        message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=parts,
        )
        result, _ = _invoke(response=_success_response(message=message))
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertLess(len(counter["ids"]), n_parts)
        self.assertLess(counter["n"], n_parts * 2)
        self.assertLessEqual(
            len(counter["ids"]) * chunk_size,
            MAX_OPENAI_RAW_EVIDENCE_BYTES + chunk_size,
        )

    def _assert_malformed_before_owned_walker(self, *, response, counter, n_source):
        walked = {"n": 0}
        serialized = {"n": 0}

        def _walk_spy(*args, **kwargs):
            walked["n"] += 1
            raise AssertionError("owned-json walker reached before incremental reject")

        from model_council import openai_adapter as openai_mod

        real_extract = openai_mod._extract_openai_sdk_response

        def _extract_spy(raw):
            def _canon_spy(*args, **kwargs):
                serialized["n"] += 1
                raise AssertionError(
                    "final canonical serialization reached before incremental reject"
                )

            with patch(
                "model_council.openai_adapter.canonical_json",
                side_effect=_canon_spy,
            ):
                return real_extract(raw)

        with patch(
            "model_council.openai_adapter._own_plain_provider_json",
            side_effect=_walk_spy,
        ), patch(
            "model_council.openai_adapter._extract_openai_sdk_response",
            side_effect=_extract_spy,
        ):
            result, _ = _invoke(response=response)
        self.assertEqual(walked["n"], 0)
        self.assertEqual(serialized["n"], 0)
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertLess(counter["n"], n_source * 3)
        self.assertLess(len(counter.get("ids", set()) or {0}), n_source)
        return result

    def test_owned_node_overflow_stops_before_all_reasoning_items(self):
        counter = {"n": 0}
        n_items = 600
        items = [_CountedReasoning(counter) for _ in range(n_items)]
        self._assert_malformed_before_owned_walker(
            response=_success_response(output=items),
            counter=counter,
            n_source=n_items,
        )
        self.assertLess(counter["n"], n_items)
        self.assertLessEqual(counter["n"], MAX_OPENAI_PROVIDER_JSON_ITEMS)

    def test_owned_node_overflow_stops_before_all_content_parts(self):
        counter = {"n": 0, "ids": set()}
        n_parts = 400
        parts = [_CountedOutputText(counter, "ok", index) for index in range(n_parts)]
        message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=parts,
        )
        self._assert_malformed_before_owned_walker(
            response=_success_response(message=message),
            counter=counter,
            n_source=n_parts,
        )
        self.assertLess(len(counter["ids"]), n_parts)

    def test_json_overhead_overflow_rejects_before_canonical_serialization(self):
        counter = {"n": 0, "ids": set()}
        n_parts = 300
        chunk = "n" * 3310
        parts = [
            _CountedOutputText(counter, chunk, index) for index in range(n_parts)
        ]
        message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=parts,
        )
        self._assert_malformed_before_owned_walker(
            response=_success_response(message=message),
            counter=counter,
            n_source=n_parts,
        )
        self.assertLess(len(counter["ids"]), n_parts)
        self.assertLessEqual(len(counter["ids"]) * 3310, MAX_OPENAI_RAW_EVIDENCE_BYTES)

    def test_shared_output_and_content_item_budget(self):
        reasoning_counter = {"n": 0}
        content_counter = {"n": 0, "ids": set()}
        items = [_CountedReasoning(reasoning_counter) for _ in range(350)]
        items.append(
            types.SimpleNamespace(
                type="message",
                status="completed",
                role="assistant",
                content=[
                    _CountedOutputText(content_counter, "ok", index)
                    for index in range(350)
                ],
            )
        )
        walked = {"n": 0}

        def _spy(*args, **kwargs):
            walked["n"] += 1
            raise AssertionError("owned-json walker reached")

        with patch(
            "model_council.openai_adapter._own_plain_provider_json",
            side_effect=_spy,
        ):
            result, _ = _invoke(response=_success_response(output=items))
        self.assertEqual(walked["n"], 0)
        self.assertEqual(
            result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL
        )
        self.assertLessEqual(reasoning_counter["n"], 350)
        self.assertLess(len(content_counter["ids"]), 350)

    def test_astral_unicode_overflow_rejects_before_all_content_parts(self):
        counter = {"n": 0, "ids": set()}
        n_parts = 100
        chunk = "\U0001F600" * 1000
        parts = [
            _CountedOutputText(counter, chunk, index) for index in range(n_parts)
        ]
        message = types.SimpleNamespace(
            type="message",
            status="completed",
            role="assistant",
            content=parts,
        )
        self._assert_malformed_before_owned_walker(
            response=_success_response(message=message),
            counter=counter,
            n_source=n_parts,
        )
        self.assertLess(len(counter["ids"]), n_parts)
        self.assertLess(counter["n"], n_parts * 2)
        self.assertLessEqual(len(counter["ids"]), 90)


class TestOpenAITransportCanonicalStringAccounting(unittest.TestCase):
    def _assert_payload_dominates_canonical(self, value):
        encoded = canonical_json(value).encode("utf-8")
        self.assertEqual(2 + _canonical_json_string_body_bytes(value), len(encoded))
        budget = _OpenAIExtractionBudget()
        budget.charge_json_string_payload(value)
        self.assertGreaterEqual(budget.nbytes, len(encoded))

    def test_quote_backslash_control_bmp_and_astral_dominate_canonical_json(self):
        cases = (
            "",
            "plain ascii",
            'quote " here',
            "back\\slash",
            "tab\tand nl\n",
            "\x08\x0c\x0d",
            "\x00\x01\x1f",
            "\x7f",
            "caf\u00e9",
            "\u4e2d\u6587",
            "\U0001F600",
            "\U0001F600" * 8,
        )
        for value in cases:
            with self.subTest(value=repr(value)):
                self._assert_payload_dominates_canonical(value)

    def test_astral_payload_is_twelve_ascii_bytes_per_code_point(self):
        value = "\U0001F600" * 1000
        self.assertEqual(_canonical_json_string_body_bytes(value), 12_000)
        encoded = canonical_json(value).encode("utf-8")
        self.assertEqual(len(encoded), 12_002)
        budget = _OpenAIExtractionBudget()
        budget.charge_json_string_payload(value)
        self.assertEqual(budget.nbytes, 12_002)


class TestOpenAITransportSerialization(unittest.TestCase):
    def test_success_and_failure_results_are_owned_primitives(self):
        success, _ = _invoke(response=_success_response())
        failure, _ = _invoke(
            error=_sdk_error(
                _FakeRateLimitError,
                status=429,
                code="rate_limit_exceeded",
                error_type="rate_limit_error",
            )
        )
        json.dumps(success.response)
        json.dumps(_plain_fields(failure))
        self.assertNotIsInstance(success.response, types.SimpleNamespace)
        for item in success.response["output"]:
            self.assertIs(type(item), dict)


class TestOpenAIProductionActivation(unittest.TestCase):
    def test_registry_identity_is_the_production_entrypoint(self):
        self.assertNotIn(_OPENAI_KIND, REGISTRY)
        self.assertIs(LIVE_REGISTRY[_OPENAI_KIND], openai_responses_skeleton)

    def test_runner_authorized_output_ceiling_reaches_sdk_call(self):
        with TempRoot() as root:
            python, calls = _install_offline_openai_python(
                root, _offline_success_config()
            )
            adapter = _openai_adapter(python_executable=python)
            runner = ExperimentRunner(
                adapter,
                ExternalEvaluator(EvaluationConfig()),
                runs_root=Path(root) / "runs",
            )
            with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
                runner.execute(
                    make_spec(
                        "provider-output-ceiling",
                        "A",
                        max_output_tokens_per_stage=137,
                    ),
                    make_task(),
                )
            records = _read_offline_calls(calls)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["max_output_tokens"], 137)

    def test_real_worker_success_path_uses_configured_model_and_one_sdk_call(self):
        request = _solver_request()
        outcome, failure, records, last = _invoke_offline_live(
            self, _offline_success_config()
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(dict(outcome.stage_output), _solver_envelope())
        self.assertEqual(outcome.configured_identity, CONFIGURED)
        self.assertEqual(outcome.requested_identity, REQUESTED_ALIAS)
        self.assertEqual(outcome.adapter_internal_retry_count, 0)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["max_retries"], 0)
        self.assertEqual(record["model"], CONFIGURED.model_id)
        self.assertNotEqual(record["model"], REQUESTED_ALIAS.model_id)
        self.assertEqual(record["max_output_tokens"], request.max_output_tokens)
        self.assertEqual(record["instructions"], request.role_instruction)
        self.assertEqual(
            record["input"],
            canonical_json({"stage_inputs": dict(request.stage_inputs)}),
        )
        self.assertIs(record["store"], False)
        self.assertIs(record["stream"], False)
        self.assertIs(record["background"], False)
        self.assertEqual(record["tools"], [])
        self.assertEqual(record["tool_choice"], "none")
        self.assertIs(record["parallel_tool_calls"], False)
        self.assertEqual(record["truncation"], "disabled")
        self.assertEqual(record["timeout"], request.attempt_timeout_seconds)
        self.assertNotIn("reasoning", record)
        self.assertEqual(last["adapter"]["options"], {})
        encoded = dumps_provider_call_outcome(outcome)
        _assert_secret_absent(self, encoded, last)

    def test_treatment_is_isolated_from_model_visible_payload(self):
        request = _solver_request()
        outcome, failure, records, _last = _invoke_offline_live(
            self, _offline_success_config(), treatment=_CLOSED_TREATMENT
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["reasoning"], {"effort": "high", "summary": "concise"})
        self.assertEqual(record["text"]["verbosity"], "low")
        visible = record["instructions"] + record["input"]
        for leaked in (
            "reasoning",
            "verbosity",
            "effort",
            REQUESTED_ALIAS.model_id,
            "OPENAI_API_KEY",
            "MCL_OPENAI_API_KEY",
        ):
            self.assertNotIn(leaked, visible)
        self.assertEqual(record["instructions"], request.role_instruction)
        self.assertEqual(
            record["input"],
            canonical_json({"stage_inputs": dict(request.stage_inputs)}),
        )

    def test_timeout_is_propagated_exactly_and_not_defaulted(self):
        outcome, failure, records, _last = _invoke_offline_live(
            self, _offline_success_config(), timeout=3.25
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(records[0]["timeout"], 3.25)
        self.assertEqual(records[0]["max_retries"], 0)

    def test_malformed_refusal_incomplete_and_tool_responses_are_translated(self):
        cases = (
            (
                "malformed",
                _completed_fixture("{not json", output_text="{not json"),
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
            ),
            (
                "refusal",
                {
                    "id": "resp_ref",
                    "object": "response",
                    "status": "completed",
                    "model": "gpt-5.6-sol-observed",
                    "output": [
                        {
                            "id": "msg_1",
                            "type": "message",
                            "status": "completed",
                            "role": "assistant",
                            "content": [
                                {
                                    "type": "refusal",
                                    "refusal": "I cannot help with that.",
                                }
                            ],
                        }
                    ],
                    "error": None,
                    "incomplete_details": None,
                },
                ProviderErrorCategory.POLICY_REFUSAL,
            ),
            (
                "incomplete",
                _completed_fixture(
                    _solver_envelope(),
                    status="incomplete",
                    incomplete_details={"reason": "max_output_tokens"},
                ),
                ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
            ),
            (
                "tool",
                {
                    "id": "resp_tool",
                    "object": "response",
                    "status": "completed",
                    "model": "gpt-5.6-sol-observed",
                    "output": [
                        {
                            "id": "fc_1",
                            "type": "function_call",
                            "call_id": "call_1",
                            "name": "run_shell",
                            "arguments": "{}",
                        }
                    ],
                    "error": None,
                    "incomplete_details": None,
                },
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
            ),
        )
        for name, response, category in cases:
            with self.subTest(name=name):
                outcome, failure, records, _last = _invoke_offline_live(
                    self, {"mode": "success", "response": response}
                )
                self.assertIsNotNone(failure)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["max_retries"], 0)
                self.assertEqual(outcome.error.category, category)
                self.assertIsNone(outcome.stage_output)
                self.assertEqual(outcome.adapter_internal_retry_count, 0)
                encoded = dumps_provider_call_outcome(outcome)
                self.assertNotIn("run_shell", encoded)
                _assert_secret_absent(self, encoded)

    def test_classified_transport_failures_preserve_kind_category_and_bounded_evidence(self):
        cases = (
            (
                "authentication",
                _offline_error_config(
                    "AuthenticationError",
                    status=401,
                    request_id="req_auth",
                    message="Authorization: Bearer " + _FAKE_CREDENTIAL,
                    attach_raw=True,
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
                OPENAI_AUTH_MESSAGE,
                401,
                "req_auth",
                False,
            ),
            (
                "permission",
                _offline_error_config(
                    "PermissionDeniedError", status=403, request_id="req_perm"
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.PERMISSION,
                OPENAI_PERMISSION_MESSAGE,
                403,
                "req_perm",
                False,
            ),
            (
                "quota",
                _offline_error_config(
                    "RateLimitError",
                    status=429,
                    code="insufficient_quota",
                    type="insufficient_quota",
                    request_id="req_quota",
                    param="model",
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.QUOTA_EXHAUSTED,
                OPENAI_QUOTA_MESSAGE,
                429,
                "req_quota",
                False,
            ),
            (
                "rate_limit",
                _offline_error_config(
                    "RateLimitError",
                    status=429,
                    code="rate_limit_exceeded",
                    type="rate_limit_error",
                    request_id="req_rl",
                    param="model",
                    message="retry-after: 7",
                    attach_raw=True,
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.RATE_LIMIT,
                OPENAI_RATE_LIMIT_MESSAGE,
                429,
                "req_rl",
                True,
            ),
            (
                "ambiguous_429",
                _offline_error_config(
                    "RateLimitError",
                    status=429,
                    type="rate_limit_error",
                    request_id="req_amb",
                    message="retry-after: 9",
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                OPENAI_UNKNOWN_FAILURE_MESSAGE,
                429,
                "req_amb",
                False,
            ),
            (
                "connectivity",
                _offline_error_config("APIConnectionError"),
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
                OPENAI_CONNECTIVITY_MESSAGE,
                None,
                None,
                True,
            ),
            (
                "timeout",
                _offline_error_config("APITimeoutError"),
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT,
                OPENAI_TIMEOUT_MESSAGE,
                None,
                None,
                True,
            ),
            (
                "overload",
                _offline_error_config(
                    "InternalServerError", status=500, request_id="req_5xx"
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL,
                OPENAI_OVERLOAD_MESSAGE,
                500,
                "req_5xx",
                True,
            ),
            (
                "validation",
                _offline_error_config("APIResponseValidationError", status=200),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL,
                OPENAI_MALFORMED_MESSAGE,
                200,
                None,
                False,
            ),
            (
                "generic",
                _offline_error_config("APIError", message="traceback at leak.py"),
                ProviderCallKind.TRANSPORT_ERROR,
                ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
                OPENAI_UNKNOWN_FAILURE_MESSAGE,
                None,
                None,
                False,
            ),
            (
                "invalid_request",
                _offline_error_config(
                    "BadRequestError", status=400, request_id="req_bad"
                ),
                ProviderCallKind.PROVIDER_ERROR,
                ProviderErrorCategory.INVALID_REQUEST,
                OPENAI_INVALID_REQUEST_MESSAGE,
                400,
                "req_bad",
                False,
            ),
        )
        for (
            name,
            config,
            kind,
            category,
            message,
            status,
            request_id,
            retryable,
        ) in cases:
            with self.subTest(name=name):
                outcome, failure, records, _last = _invoke_offline_live(self, config)
                self.assertIsNotNone(failure)
                self.assertEqual(failure.error.category, category)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["max_retries"], 0)
                _assert_contained_failure(
                    self,
                    outcome,
                    kind=kind,
                    category=category,
                    message=message,
                    http_status=status,
                    request_id=request_id,
                )
                self.assertEqual(is_retry_candidate(outcome.error.category), retryable)

    def test_unsafe_observation_strings_are_dropped_from_failure_outcome(self):
        outcome, failure, records, _last = _invoke_offline_live(
            self,
            _offline_error_config(
                "AuthenticationError",
                status=401,
                request_id="Authorization: Bearer " + _FAKE_CREDENTIAL,
                type="invalid_api_key",
                code="sk-not-real",
                param="api_key",
                message="secret credential traceback",
                attach_raw=True,
            ),
        )
        self.assertIsNotNone(failure)
        self.assertEqual(len(records), 1)
        self.assertIsNone(outcome.provider_request_id.value)
        encoded = dumps_provider_call_outcome(outcome)
        _assert_secret_absent(self, encoded, *_failure_graph_blobs(failure))
        self.assertNotIn("sk-not-real", encoded)
        self.assertNotIn("invalid_api_key", encoded)
        self.assertEqual(outcome.error.sanitized_message, OPENAI_AUTH_MESSAGE)

    def test_unexpected_transport_result_and_exception_fail_closed(self):
        request = _solver_request()
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=object(),
            ):
                with self.assertRaises(ProtocolError) as ctx:
                    openai_responses_skeleton({}, deep_freeze({}), request)
        self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_RESULT_INVALID)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                side_effect=RuntimeError(
                    "Authorization: Bearer " + _FAKE_CREDENTIAL
                ),
            ):
                with self.assertRaises(ProtocolError) as ctx:
                    openai_responses_skeleton({}, deep_freeze({}), request)
        self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_RESULT_INVALID)
        self.assertIsNone(ctx.exception.__cause__)
        _assert_secret_absent(self, str(ctx.exception), *_failure_graph_blobs(ctx.exception))

    def test_pretransport_failure_makes_zero_sdk_calls(self):
        with TempRoot() as root:
            python, calls = _install_offline_openai_python(root, _offline_success_config())
            adapter = _openai_adapter(
                python_executable=python, options={"timeout": 1}
            )
            with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
                with self.assertRaises(InfrastructureError):
                    adapter.invoke_live(_solver_request())
            self.assertEqual(_read_offline_calls(calls), [])

    def test_runner_owns_retry_decisions_for_retryable_and_nonretryable_failures(self):
        cases = (
            (
                "nonretryable_quota",
                _offline_error_config(
                    "RateLimitError",
                    status=429,
                    code="insufficient_quota",
                    type="insufficient_quota",
                ),
                1,
                "infrastructure_failure",
            ),
            (
                "nonretryable_ambiguous_429",
                _offline_error_config(
                    "RateLimitError", status=429, type="rate_limit_error"
                ),
                1,
                "infrastructure_failure",
            ),
            (
                "retryable_rate_limit",
                _offline_error_config(
                    "RateLimitError",
                    status=429,
                    code="rate_limit_exceeded",
                    type="rate_limit_error",
                ),
                3,
                "retry_exhausted",
            ),
        )
        for name, config, expected_calls, status in cases:
            with self.subTest(name=name):
                with TempRoot() as root:
                    python, calls = _install_offline_openai_python(root, config)
                    adapter = SubprocessAdapter(
                        FAKE_IDENTITY,
                        kind=_OPENAI_KIND,
                        python_executable=python,
                    )
                    counted = []
                    original = adapter.invoke_live

                    def wrapped(live_request):
                        counted.append(live_request.attempt_timeout_seconds)
                        return original(live_request)

                    adapter.invoke_live = wrapped
                    runner = ExperimentRunner(
                        adapter,
                        ExternalEvaluator(EvaluationConfig()),
                        runs_root=Path(root) / "runs",
                    )
                    with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
                        result = runner.execute(
                            make_spec(f"oa-{name}", "A", max_stage_retries=2),
                            make_task(),
                        )
                    self.assertEqual(result.status, status)
                    self.assertEqual(len(counted), expected_calls)
                    self.assertEqual(len(_read_offline_calls(calls)), expected_calls)
                    blob = json.dumps(adapter.last_request)
                    _assert_secret_absent(self, blob, str(result))

    def test_adapter_source_does_not_own_retry_policy_or_sleep(self):
        from model_council import openai_adapter as openai_mod

        source = inspect.getsource(openai_mod)
        self.assertNotIn("is_retry_candidate", source)
        self.assertNotIn("retry_policy", source)
        self.assertNotIn("time.sleep", source)
        skeleton = inspect.getsource(openai_mod.openai_responses_skeleton)
        self.assertIn("acquire_child_openai_runtime_secret", skeleton)
        self.assertIn("build_openai_responses_request", skeleton)
        self.assertIn("_perform_openai_responses_transport", skeleton)
        self.assertIn("translate_openai_responses_result", skeleton)
        self.assertIn("_openai_transport_failure_outcome", skeleton)
        self.assertIn("request.attempt_timeout_seconds", skeleton)
        self.assertNotIn("client_factory=", skeleton)

    def test_registered_worker_path_returns_outcome_envelope(self):
        payload = _live_envelope(
            kind=_OPENAI_KIND,
            options={},
            treatment={},
            request=_solver_request(),
        )
        fixture = _completed_fixture(_solver_envelope(), usage=_usage_fixture())

        class _Client:
            def __init__(self):
                self.responses = types.SimpleNamespace(create=self.create)
                self.calls = []

            def create(self, **kwargs):
                self.calls.append(kwargs)
                return fixture

        client = _Client()

        def factory(*, api_key, max_retries):
            self.assertEqual(max_retries, 0)
            self.assertEqual(api_key, _FAKE_CREDENTIAL)
            return client

        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._default_openai_client_factory",
                side_effect=factory,
            ):
                with patch("socket.socket", side_effect=AssertionError("network")):
                    code, parsed = _run_worker(payload)
        self.assertEqual(code, 0)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["outcome"]["kind"], ProviderCallKind.SUCCESS.value)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0]["timeout"], _solver_request().attempt_timeout_seconds)
        self.assertNotIn(_CHILD_KEY, os.environ)
        _assert_secret_absent(self, parsed)


def _manual_transport_failure(
    *,
    kind=ProviderCallKind.PROVIDER_ERROR,
    category=ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
    http_status=401,
    request_id="req_manual",
    error_type=None,
    error_code=None,
    param=None,
):
    return _OpenAITransportFailure(
        kind=kind,
        category=category,
        http_status=http_status,
        request_id=request_id,
        error_type=error_type,
        error_code=error_code,
        param=param,
    )


class TestOpenAITransportFailureConversionBoundary(unittest.TestCase):
    def _convert(self, failure):
        return _openai_transport_failure_outcome(_solver_request(), failure)

    def test_unsafe_credential_like_request_id_becomes_unavailable(self):
        unsafe = "Authorization: Bearer " + _FAKE_CREDENTIAL
        outcome = self._convert(
            _manual_transport_failure(http_status=401, request_id=unsafe)
        )
        _assert_contained_failure(
            self,
            outcome,
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
            message=OPENAI_AUTH_MESSAGE,
            http_status=401,
            request_id=None,
        )
        encoded = dumps_provider_call_outcome(outcome)
        self.assertNotIn(unsafe, encoded)
        self.assertNotIn("authorization", encoded.lower())
        _assert_secret_absent(self, encoded, outcome.to_dict())

    def test_overlong_request_id_becomes_unavailable(self):
        overlong = "n" * (MAX_OPENAI_OBSERVATION_CHARS + 1)
        outcome = self._convert(
            _manual_transport_failure(http_status=401, request_id=overlong)
        )
        _assert_contained_failure(
            self,
            outcome,
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
            message=OPENAI_AUTH_MESSAGE,
            http_status=401,
            request_id=None,
        )
        encoded = dumps_provider_call_outcome(outcome)
        self.assertNotIn(overlong, encoded)

    def test_invalid_kind_category_pair_fails_closed(self):
        failure = _manual_transport_failure(
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
            http_status=503,
            request_id="req_incoherent",
        )
        with self.assertRaises(ProtocolError) as ctx:
            self._convert(failure)
        self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_RESULT_INVALID)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_valid_http_status_survives_invalid_request_id(self):
        unsafe = "Authorization: Bearer " + _FAKE_CREDENTIAL
        outcome = self._convert(
            _manual_transport_failure(http_status=429, request_id=unsafe)
        )
        _assert_contained_failure(
            self,
            outcome,
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
            message=OPENAI_AUTH_MESSAGE,
            http_status=429,
            request_id=None,
        )
        self.assertNotIn(unsafe, dumps_provider_call_outcome(outcome))

    def test_valid_request_id_survives_invalid_http_status(self):
        outcome = self._convert(
            _manual_transport_failure(http_status=99, request_id="req_independent")
        )
        _assert_contained_failure(
            self,
            outcome,
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.AUTHENTICATION_CONFIGURATION,
            message=OPENAI_AUTH_MESSAGE,
            http_status=None,
            request_id="req_independent",
        )

    def test_hostile_failure_cannot_cross_worker_protocol(self):
        unsafe = "Authorization: Bearer " + _FAKE_CREDENTIAL
        failure = _manual_transport_failure(
            http_status=401,
            request_id=unsafe,
            error_type="invalid_api_key",
            error_code="sk-not-real",
            param="api_key",
        )
        payload = _live_envelope(
            kind=_OPENAI_KIND,
            options={},
            treatment={},
            request=_solver_request(),
        )
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=failure,
            ):
                with patch("socket.socket", side_effect=AssertionError("network")):
                    code, parsed = _run_worker(payload)
        self.assertEqual(code, 0)
        self.assertTrue(parsed["ok"])
        encoded = json.dumps(parsed)
        self.assertNotIn(unsafe, encoded)
        self.assertNotIn(_FAKE_CREDENTIAL, encoded)
        self.assertIsNone(parsed["outcome"]["provider_request_id"]["value"])
        self.assertEqual(parsed["outcome"]["error"]["http_status"]["value"], 401)
        self.assertEqual(
            parsed["outcome"]["kind"], ProviderCallKind.PROVIDER_ERROR.value
        )
        self.assertNotIn("sk-not-real", encoded)
        self.assertNotIn("invalid_api_key", encoded)

    def test_malformed_failure_fails_closed(self):
        cases = (
            object(),
            _manual_transport_failure(kind="provider_error"),
            _manual_transport_failure(
                kind=ProviderCallKind.SUCCESS,
                category=ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
            ),
            _manual_transport_failure(category="authentication_configuration"),
        )
        for failure in cases:
            with self.subTest(failure=repr(failure)[:80]):
                with self.assertRaises(ProtocolError) as ctx:
                    self._convert(failure)
                self.assertEqual(str(ctx.exception), OPENAI_TRANSPORT_RESULT_INVALID)
                self.assertIsNone(ctx.exception.__cause__)
                self.assertIsNone(ctx.exception.__context__)

    def test_incoherent_pair_cannot_cross_worker_as_valid_outcome(self):
        failure = _manual_transport_failure(
            kind=ProviderCallKind.PROVIDER_ERROR,
            category=ProviderErrorCategory.TRANSPORT_CONNECTIVITY,
            http_status=503,
            request_id="req_incoherent",
        )
        payload = _live_envelope(
            kind=_OPENAI_KIND,
            options={},
            treatment={},
            request=_solver_request(),
        )
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=failure,
            ):
                code, parsed = _run_worker(payload)
        self.assertEqual(code, 0)
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["error_class"], "ProtocolError")
        self.assertEqual(parsed["message"], OPENAI_TRANSPORT_RESULT_INVALID)
        encoded = json.dumps(parsed)
        self.assertNotIn("transport_connectivity", encoded)
        self.assertNotIn("req_incoherent", encoded)


class TestOpenAIProviderStdioIsolation(unittest.TestCase):
    _F08_CANARY = "MCL-F08-CANARY"

    def _invoke_leaky(self, *, leaky_getter=False, print_text=None, print_stream="stdout"):
        config = _offline_success_config()
        if leaky_getter:
            config["leaky_getter"] = True
        if print_text is not None:
            config["print_text"] = print_text
        config["print_stream"] = print_stream
        return _invoke_offline_live(self, config)

    def _invoke_hostile_stdio(
        self,
        *,
        print_target,
        print_text=None,
        leaky_getter=True,
        error=None,
    ):
        if error is None:
            config = _offline_success_config()
        else:
            config = _offline_error_config(error)
        config["print_target"] = print_target
        if print_text is not None:
            config["print_text"] = print_text
        if leaky_getter:
            config["leaky_getter"] = True
        try:
            outcome, failure, records, last = _invoke_offline_live(self, config)
            return outcome, failure, records, last, None
        except Exception as caught:
            return None, None, None, None, caught

    def _assert_hostile_stdio_contained(self, exc, outcome, failure, last, records, canary):
        if exc is not None:
            _assert_openai_parent_graph_closed(self, exc)
            _assert_secret_absent(self, str(exc), repr(exc), *_failure_graph_blobs(exc))
            self.assertNotIn(canary, str(exc))
            self.assertNotIn(canary, repr(exc))
            self.fail("hostile provider stdio corrupted the trusted protocol channel")
        encoded = dumps_provider_call_outcome(outcome)
        self.assertNotIn(canary, encoded)
        _assert_secret_absent(self, encoded, last, records)
        if failure is not None:
            _assert_secret_absent(self, *_failure_graph_blobs(failure))
            self.assertNotIn(canary, str(failure))

    def test_leaky_stdout_getter_cannot_contaminate_protocol_or_parent_graph(self):
        try:
            outcome, failure, records, last = self._invoke_leaky(leaky_getter=True)
            exc = None
        except Exception as caught:
            outcome, failure, records, last = None, None, None, None
            exc = caught
        if exc is not None:
            _assert_openai_parent_graph_closed(self, exc)
            _assert_secret_absent(self, str(exc), repr(exc), *_failure_graph_blobs(exc))
            self.fail("leaky provider stdout should not break the trusted protocol")
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(len(records), 1)
        encoded = dumps_provider_call_outcome(outcome)
        _assert_secret_absent(self, encoded, last, records)
        self.assertNotIn(_FAKE_CREDENTIAL, encoded)

    def test_leaky_stderr_getter_cannot_contaminate_protocol_or_parent_graph(self):
        try:
            outcome, failure, records, last = self._invoke_leaky(
                leaky_getter=True, print_stream="stderr"
            )
            exc = None
        except Exception as caught:
            outcome, failure, records, last = None, None, None, None
            exc = caught
        if exc is not None:
            _assert_openai_parent_graph_closed(self, exc)
            _assert_secret_absent(self, str(exc), repr(exc), *_failure_graph_blobs(exc))
            self.fail("leaky provider stderr should not break the trusted protocol")
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        encoded = dumps_provider_call_outcome(outcome)
        _assert_secret_absent(self, encoded, last, records)

    def test_provider_stdout_noise_does_not_prefix_protocol(self):
        outcome, failure, records, last = self._invoke_leaky(
            print_text="provider-local stdout noise"
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(len(records), 1)
        encoded = dumps_provider_call_outcome(outcome)
        self.assertNotIn("provider-local stdout noise", encoded)
        _assert_secret_absent(self, encoded, last)

    def test_provider_stderr_noise_does_not_prefix_protocol(self):
        outcome, failure, records, last = self._invoke_leaky(
            print_text="provider-local stderr noise", print_stream="stderr"
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        encoded = dumps_provider_call_outcome(outcome)
        self.assertNotIn("provider-local stderr noise", encoded)
        _assert_secret_absent(self, encoded, last)

    def test_successful_worker_path_still_emits_one_json_protocol_payload(self):
        outcome, failure, records, last = _invoke_offline_live(
            self, _offline_success_config()
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(len(records), 1)
        encoded = dumps_provider_call_outcome(outcome)
        json.loads(encoded)
        _assert_secret_absent(self, encoded, last)

    def test_sys_dunder_stdout_cannot_corrupt_trusted_protocol(self):
        canary = self._F08_CANARY
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="__stdout__", print_text=canary
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_fd1_write_cannot_corrupt_trusted_protocol(self):
        canary = self._F08_CANARY
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd1", print_text=canary
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_sys_dunder_stderr_cannot_corrupt_trusted_protocol(self):
        canary = self._F08_CANARY
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="__stderr__", print_text=canary
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_fd2_write_cannot_corrupt_trusted_protocol(self):
        canary = self._F08_CANARY
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd2", print_text=canary
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_credential_on_fd1_cannot_enter_parent_protocol_or_exception_graph(self):
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd1"
        )
        self._assert_hostile_stdio_contained(
            exc, outcome, failure, last, records, _FAKE_CREDENTIAL
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_credential_on_dunder_stdout_cannot_enter_parent_graph(self):
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="__stdout__"
        )
        self._assert_hostile_stdio_contained(
            exc, outcome, failure, last, records, _FAKE_CREDENTIAL
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_credential_on_dunder_stderr_cannot_enter_parent_graph(self):
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="__stderr__"
        )
        self._assert_hostile_stdio_contained(
            exc, outcome, failure, last, records, _FAKE_CREDENTIAL
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_credential_on_fd2_cannot_enter_parent_protocol_or_exception_graph(self):
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd2"
        )
        self._assert_hostile_stdio_contained(
            exc, outcome, failure, last, records, _FAKE_CREDENTIAL
        )
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)

    def test_descriptor_noise_before_during_after_success_remains_one_envelope(self):
        canary = self._F08_CANARY + "-noise"
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd1", print_text=canary, leaky_getter=True
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        self.assertEqual(len(records), 1)
        encoded = dumps_provider_call_outcome(outcome)
        json.loads(encoded)

    def test_descriptor_noise_then_provider_error_still_crosses(self):
        canary = self._F08_CANARY + "-fail"
        outcome, failure, records, last, exc = self._invoke_hostile_stdio(
            print_target="fd1",
            print_text=canary,
            leaky_getter=False,
            error="APIConnectionError",
        )
        self._assert_hostile_stdio_contained(exc, outcome, failure, last, records, canary)
        self.assertIsNotNone(failure)
        self.assertEqual(outcome.kind, ProviderCallKind.TRANSPORT_ERROR)
        self.assertEqual(
            outcome.error.category, ProviderErrorCategory.TRANSPORT_CONNECTIVITY
        )
        self.assertEqual(len(records), 1)


class TestOpenAITransportOptionalSDK(unittest.TestCase):
    def test_installed_sdk_makes_exactly_one_http_attempt_per_case(self):
        env = {
            "PYTHONPATH": os.pathsep.join(
                (str(REPO_ROOT / "src"), str(REPO_ROOT / "tests"))
            )
        }
        completed = subprocess.run(
            [sys.executable, "-B", "-c", _OPENAI_SDK_TRANSPORT_PROBE],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "offline OpenAI transport subprocess failed:\n" + completed.stderr[:2000],
        )
        report = json.loads(completed.stdout)
        if report == {"sdk": "absent"}:
            return
        self.assertEqual(report["sdk"], _OPENAI_SDK_VERSION)
        cases = report["cases"]
        expected = {
            "success": {"kind": "success", "attempts": 1},
            "rate_limit": {
                "kind": ProviderCallKind.PROVIDER_ERROR.value,
                "category": ProviderErrorCategory.RATE_LIMIT.value,
                "attempts": 1,
            },
            "quota": {
                "kind": ProviderCallKind.PROVIDER_ERROR.value,
                "category": ProviderErrorCategory.QUOTA_EXHAUSTED.value,
                "attempts": 1,
            },
            "ambiguous_429": {
                "kind": ProviderCallKind.PROVIDER_ERROR.value,
                "category": ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE.value,
                "attempts": 1,
            },
            "internal": {
                "kind": ProviderCallKind.PROVIDER_ERROR.value,
                "category": ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL.value,
                "attempts": 1,
            },
            "connection": {
                "kind": ProviderCallKind.TRANSPORT_ERROR.value,
                "category": ProviderErrorCategory.TRANSPORT_CONNECTIVITY.value,
                "attempts": 1,
            },
            "timeout": {
                "kind": ProviderCallKind.TRANSPORT_ERROR.value,
                "category": ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT.value,
                "attempts": 1,
            },
        }
        for name, want in expected.items():
            got = cases[name]
            self.assertEqual(got["attempts"], 1, name)
            self.assertEqual(got["max_retries"], 0, name)
            self.assertEqual(got["kind"], want["kind"], name)
            if "category" in want:
                self.assertEqual(got["category"], want["category"], name)
        self.assertEqual(
            report["success_timeout"],
            {"connect": 3.25, "read": 3.25, "write": 3.25, "pool": 3.25},
        )


if __name__ == "__main__":
    unittest.main()
