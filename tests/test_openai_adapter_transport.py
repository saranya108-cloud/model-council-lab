"""Tranche 5A: dormant provider-local one-call OpenAI Responses transport seam.

Deterministic offline/fake behavior only. No real provider calls, credentials,
or dependency installation. Optional SDK HTTP proofs run in a subprocess and
accept the established absence path.
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
from model_council.live_contract import ProviderCallKind, ProviderErrorCategory
from model_council.openai_adapter import (
    MAX_OPENAI_OBSERVATION_CHARS,
    MAX_OPENAI_PROVIDER_JSON_ITEMS,
    MAX_OPENAI_RAW_EVIDENCE_BYTES,
    MAX_OPENAI_USAGE_TOKENS,
    OPENAI_CLIENT_INIT_FAILURE,
    OPENAI_TRANSLATION_NOT_IMPLEMENTED,
    OPENAI_TRANSPORT_REQUEST_INVALID,
    OPENAI_TRANSPORT_TIMEOUT_INVALID,
    RuntimeSecret,
    _OpenAIExtractionBudget,
    _OpenAITransportFailure,
    _OpenAITransportSuccess,
    _canonical_json_string_body_bytes,
    _default_openai_client_factory,
    _perform_openai_responses_transport,
    build_openai_responses_request,
    openai_responses_skeleton,
)
from model_council.security import canonical_json, deep_freeze
from test_live_contract import make_request
from test_openai_adapter_skeleton import (
    _CHILD_KEY,
    _HOST_KEY,
    _failure_graph_blobs,
    _isolated_environ,
    _live_envelope,
    _run_worker,
)
from test_openai_adapter_translation import _CLOSED_TREATMENT, _solver_request

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
        request = _closed_request(_CLOSED_TREATMENT)
        result, seen = _invoke(request=request, response=_success_response())
        self.assertIsInstance(result, _OpenAITransportSuccess)
        calls = seen["responses"].calls
        self.assertEqual(len(calls), 1)
        sent = dict(calls[0])
        timeout = sent.pop("timeout")
        self.assertEqual(timeout, _TIMEOUT)
        self.assertEqual(sent, request)

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
            ("max_output_tokens", 16),
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


class TestOpenAITransportDormancy(unittest.TestCase):
    def test_registry_identity_and_direct_entrypoint_remain_dormant(self):
        self.assertNotIn(_OPENAI_KIND, REGISTRY)
        self.assertIs(LIVE_REGISTRY[_OPENAI_KIND], openai_responses_skeleton)
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport"
            ) as transport:
                with patch("model_council.openai_adapter.build_openai_client") as factory:
                    with patch(
                        "socket.socket",
                        side_effect=AssertionError("network path opened"),
                    ):
                        with self.assertRaises(ProtocolError) as ctx:
                            openai_responses_skeleton(
                                {}, deep_freeze({}), make_request()
                            )
            factory.assert_not_called()
            transport.assert_not_called()
        self.assertEqual(str(ctx.exception), OPENAI_TRANSLATION_NOT_IMPLEMENTED)

    def test_worker_registered_invocation_fails_before_transport(self):
        payload = _live_envelope(kind=_OPENAI_KIND, options={}, treatment={})
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport"
            ) as transport:
                with patch("model_council.openai_adapter.build_openai_client") as factory:
                    code, parsed = _run_worker(payload)
        self.assertEqual(code, 0)
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["error_class"], "ProtocolError")
        self.assertIn("translation is not implemented", parsed["message"])
        factory.assert_not_called()
        transport.assert_not_called()


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
