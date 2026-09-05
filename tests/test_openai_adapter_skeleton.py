"""Tranche 3: OpenAI adapter skeleton, worker treatment visibility, credential boundary."""

from __future__ import annotations

import ast
import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import threading
import types
import unittest
from contextlib import contextmanager
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch
import copy
import pickle

from helpers import FAKE_IDENTITY, TempRoot, make_runner, make_spec, make_task
from model_council import EvaluationConfig, ExperimentRunner, ExternalEvaluator
from model_council.adapters import LIVE_REGISTRY, REGISTRY
from model_council.errors import InfrastructureError, ProtocolError
from model_council.executor import SubprocessAdapter
from model_council.protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from model_council.security import (
    canonical_json,
    deep_freeze,
    normalize_provider_treatment_config,
)
from model_council.types import GovernanceViolation, StageTimeout
from model_council import worker as worker_mod
from model_council.worker import main as worker_main
from test_live_contract import make_request
from test_provider_treatment_config import REASONING_SHAPED, RUNTIME_SHAPED

REPO_ROOT = Path(__file__).resolve().parents[1]
_FAKE_CREDENTIAL = "mcl-test-openai-runtime-credential-not-real"
_HOST_KEY = "OPENAI_API_KEY"
_CHILD_KEY = "MCL_OPENAI_API_KEY"
_PROTOCOL_FD_KEY = "MCL_WORKER_PROTOCOL_FD"
_OPENAI_KIND = "openai_responses"
_OPENAI_SDK_VERSION = "2.54.0"
_AMBIENT_SECRET_ENV = {
    "HOME": "/tmp/mcl-test-home",
    "HTTP_PROXY": "http://127.0.0.1:9",
    "HTTPS_PROXY": "https://127.0.0.1:9",
    "ALL_PROXY": "socks5://127.0.0.1:9",
    "http_proxy": "http://127.0.0.1:9",
    "https_proxy": "https://127.0.0.1:9",
    "GIT_ASKPASS": "secret-askpass",
    "GH_TOKEN": "gh-not-real",
    "GITHUB_TOKEN": "github-not-real",
    "AWS_SECRET_ACCESS_KEY": "aws-not-real",
    "AWS_SESSION_TOKEN": "aws-session-not-real",
    "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/mcl-fake-gcp.json",
    "ANTHROPIC_API_KEY": "anthropic-not-real",
    "OTEL_EXPORTER_OTLP_HEADERS": "api-key=otel-not-real",
    "OTEL_RESOURCE_ATTRIBUTES": "service.name=mcl-test",
    "DEBUG": "1",
    "PYTHONDEBUG": "1",
}

_OPENAI_SDK_COMPATIBILITY_PROBE = r'''
import importlib.metadata
import importlib.util
import inspect
import json

if importlib.util.find_spec("openai") is None:
    print(json.dumps({"sdk": "absent"}, sort_keys=True))
    raise SystemExit(0)

import httpx
import openai
from openai import OpenAI
from openai.types.responses import (
    Response,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)
from openai.types.responses.response import IncompleteDetails

from model_council.live_contract import ProviderCallKind
from model_council.openai_adapter import (
    build_openai_responses_request,
    translate_openai_responses_result,
)
from model_council.security import canonical_json
from test_openai_adapter_translation import _solver_envelope, _solver_request

EXPECTED_VERSION = "2.54.0"
assert importlib.metadata.version("openai") == EXPECTED_VERSION
assert openai.__version__ == EXPECTED_VERSION

constructor = inspect.signature(OpenAI)
assert {"api_key", "timeout", "max_retries", "http_client"} <= set(
    constructor.parameters
)
assert constructor.parameters["max_retries"].default == 2
assert openai.DEFAULT_MAX_RETRIES == 2
assert openai.DEFAULT_TIMEOUT.as_dict() == {
    "connect": 5.0,
    "read": 600,
    "write": 600,
    "pool": 600,
}

required_status_errors = (
    openai.BadRequestError,
    openai.AuthenticationError,
    openai.PermissionDeniedError,
    openai.NotFoundError,
    openai.ConflictError,
    openai.UnprocessableEntityError,
    openai.RateLimitError,
    openai.InternalServerError,
)
assert all(issubclass(cls, openai.APIStatusError) for cls in required_status_errors)
assert issubclass(openai.APITimeoutError, openai.APIConnectionError)
assert issubclass(openai.APIConnectionError, openai.APIError)

request = _solver_request()
envelope = _solver_envelope()
approved = build_openai_responses_request(request, {})
expected_keys = {
    "background",
    "input",
    "instructions",
    "max_output_tokens",
    "model",
    "parallel_tool_calls",
    "store",
    "stream",
    "text",
    "tool_choice",
    "tools",
    "truncation",
}
assert set(approved) == expected_keys
assert approved["max_output_tokens"] == request.max_output_tokens

success_attempts = 0
captured_body = None
captured_timeout = None

def success_handler(http_request):
    global success_attempts, captured_body, captured_timeout
    assert http_request.url.host == "network-denied.invalid"
    assert http_request.url.path == "/v1/responses"
    success_attempts += 1
    captured_body = json.loads(http_request.content)
    captured_timeout = dict(http_request.extensions["timeout"])
    output_text = canonical_json(envelope)
    return httpx.Response(
        200,
        headers={"content-type": "application/json", "x-request-id": "req_offline"},
        json={
            "id": "resp_offline",
            "object": "response",
            "created_at": 0.0,
            "status": "completed",
            "background": False,
            "error": None,
            "incomplete_details": None,
            "instructions": approved["instructions"],
            "max_output_tokens": approved["max_output_tokens"],
            "max_tool_calls": None,
            "model": approved["model"],
            "output": [
                {
                    "id": "msg_offline",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "annotations": [],
                            "logprobs": [],
                            "text": output_text,
                        }
                    ],
                }
            ],
            "parallel_tool_calls": False,
            "previous_response_id": None,
            "prompt_cache_key": None,
            "reasoning": {"effort": None, "summary": None},
            "safety_identifier": None,
            "service_tier": "default",
            "store": False,
            "temperature": None,
            "text": {"format": {"type": "text"}, "verbosity": "medium"},
            "tool_choice": "none",
            "tools": [],
            "top_logprobs": 0,
            "top_p": 1.0,
            "truncation": "disabled",
            "usage": {
                "input_tokens": 11,
                "input_tokens_details": {"cached_tokens": 2},
                "output_tokens": 22,
                "output_tokens_details": {"reasoning_tokens": 4},
                "total_tokens": 33,
            },
            "metadata": {},
        },
    )

client = OpenAI(
    api_key="not-a-real-openai-key",
    base_url="https://network-denied.invalid/v1",
    timeout=httpx.Timeout(7.0),
    max_retries=0,
    http_client=httpx.Client(transport=httpx.MockTransport(success_handler)),
)
create = inspect.signature(client.responses.create)
assert expected_keys | {"timeout"} <= set(create.parameters)
response = client.responses.create(**approved, timeout=3.25)
assert success_attempts == 1
assert captured_body == approved
assert captured_timeout == {
    "connect": 3.25,
    "read": 3.25,
    "write": 3.25,
    "pool": 3.25,
}
assert isinstance(response, Response)
assert response.object == "response"
assert response.status == "completed"
assert response.id == "resp_offline"
assert response.model == approved["model"]
assert response.output_text == canonical_json(envelope)
assert isinstance(response.output[0], ResponseOutputMessage)
assert response.output[0].type == "message"
assert response.output[0].status == "completed"
assert isinstance(response.output[0].content[0], ResponseOutputText)
assert response.output[0].content[0].type == "output_text"
assert ResponseOutputRefusal(type="refusal", refusal="synthetic").type == "refusal"
assert IncompleteDetails(reason="max_output_tokens").reason == "max_output_tokens"
assert response.usage.input_tokens == 11
assert response.usage.input_tokens_details.cached_tokens == 2
assert response.usage.output_tokens == 22
assert response.usage.output_tokens_details.reasoning_tokens == 4
assert response.usage.total_tokens == 33

plain = response.model_dump(mode="json")
assert "output_text" not in plain
plain["output_text"] = response.output_text
outcome = translate_openai_responses_result(request, plain)
assert outcome.kind == ProviderCallKind.SUCCESS
assert dict(outcome.stage_output) == envelope
assert outcome.adapter_internal_retry_count == 0

retry_attempts = 0

def rate_limit_handler(http_request):
    global retry_attempts
    assert http_request.url.host == "network-denied.invalid"
    retry_attempts += 1
    return httpx.Response(
        429,
        headers={
            "content-type": "application/json",
            "retry-after": "7",
            "x-request-id": "req_rate_limit",
        },
        json={
            "error": {
                "message": "synthetic",
                "type": "rate_limit_error",
                "code": "rate_limit_exceeded",
                "param": "model",
            }
        },
    )

retry_client = OpenAI(
    api_key="not-a-real-openai-key",
    base_url="https://network-denied.invalid/v1",
    max_retries=0,
    http_client=httpx.Client(transport=httpx.MockTransport(rate_limit_handler)),
)
try:
    retry_client.responses.create(**approved)
except openai.RateLimitError as exc:
    assert exc.status_code == 429
    assert exc.request_id == "req_rate_limit"
    assert exc.type == "rate_limit_error"
    assert exc.code == "rate_limit_exceeded"
    assert exc.param == "model"
    assert exc.response.headers.get("retry-after") == "7"
else:
    raise AssertionError("synthetic rate limit did not raise RateLimitError")
assert retry_attempts == 1

print(
    json.dumps(
        {
            "request_keys": sorted(captured_body),
            "retry_attempts": retry_attempts,
            "sdk": EXPECTED_VERSION,
            "success_attempts": success_attempts,
            "translation": outcome.kind.value,
        },
        sort_keys=True,
    )
)
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


@contextmanager
def _isolated_environ(**updates):
    filtered = {key: os.environ[key] for key in os.environ if key != _HOST_KEY}
    filtered.update(updates)
    with patch.dict(os.environ, filtered, clear=True):
        yield


def _durable_text(run_dir: Path) -> str:
    parts = []
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _run_worker(payload):
    adapter = payload.get("adapter") if isinstance(payload, dict) else None
    kind = adapter.get("kind") if isinstance(adapter, dict) else None
    if kind == _OPENAI_KIND:
        code, parsed, _stdout_text = _run_openai_worker_with_protocol_fd(payload)
        return code, parsed
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = worker_main()
    raw = stdout.getvalue()
    parsed = json.loads(raw) if raw.startswith("{") else raw
    return code, parsed


def _close_fd(fd):
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _run_openai_worker_with_protocol_fd(payload):
    """In-process OpenAI worker using the same inherited-pipe protocol channel as the executor."""
    protocol_r, protocol_w = os.pipe()
    os.set_inheritable(protocol_r, False)
    os.set_inheritable(protocol_w, True)
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    saved_dunder_out = sys.__stdout__
    saved_dunder_err = sys.__stderr__
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    claimed = False
    try:
        with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
            with patch.dict(os.environ, {_PROTOCOL_FD_KEY: str(protocol_w)}, clear=False):
                code = worker_main()
        proto = worker_mod._protocol_out
        if proto is not None and proto is not stdout and proto is not saved_stdout:
            claimed = True
            try:
                proto.flush()
            except Exception:
                pass
            try:
                proto.close()
            except Exception:
                pass
        worker_mod._protocol_out = None
        worker_mod._discarded_stdio = None
        chunks = []
        if claimed:
            while True:
                chunk = os.read(protocol_r, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        protocol_raw = b"".join(chunks).decode("utf-8") if chunks else ""
        stdout_text = stdout.getvalue()
        parsed = json.loads(protocol_raw) if protocol_raw.startswith("{") else protocol_raw
        return code, parsed, stdout_text
    finally:
        worker_mod._protocol_out = None
        worker_mod._discarded_stdio = None
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        _close_fd(saved_out)
        _close_fd(saved_err)
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
        sys.__stdout__ = saved_dunder_out
        sys.__stderr__ = saved_dunder_err
        _close_fd(protocol_r)
        if not claimed:
            _close_fd(protocol_w)


def _live_envelope(kind="live_stub", options=None, request=None, treatment=None, **overrides):
    live_request = request or make_request()
    payload = {
        "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
        "execution_profile": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
        "adapter": {
            "kind": kind,
            "options": dict(options or {}),
        },
        "provider_treatment_config": {} if treatment is None else treatment,
        "live_invocation_request": live_request.to_dict(),
    }
    payload.update(overrides)
    return payload


def _openai_adapter(**kwargs):
    return SubprocessAdapter(FAKE_IDENTITY, kind=_OPENAI_KIND, **kwargs)


_OFFLINE_OPENAI_WRAPPER = r'''
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve()
_CONFIG = json.loads(_HERE.with_name(_HERE.name + ".json").read_text())
_CALLS = _HERE.with_name(_HERE.name + ".calls.jsonl")


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


class _FakeSDK:
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


_ERROR_TYPES = {
    "AuthenticationError": _FakeAuthenticationError,
    "PermissionDeniedError": _FakePermissionDeniedError,
    "BadRequestError": _FakeBadRequestError,
    "UnprocessableEntityError": _FakeUnprocessableEntityError,
    "NotFoundError": _FakeNotFoundError,
    "ConflictError": _FakeConflictError,
    "RateLimitError": _FakeRateLimitError,
    "InternalServerError": _FakeInternalServerError,
    "APIResponseValidationError": _FakeAPIResponseValidationError,
    "APIConnectionError": _FakeAPIConnectionError,
    "APITimeoutError": _FakeAPITimeoutError,
    "APIStatusError": _FakeAPIStatusError,
    "APIError": _FakeAPIError,
    "Exception": Exception,
    "RuntimeError": RuntimeError,
}


def _raise_configured_error(spec):
    cls = _ERROR_TYPES[spec["class"]]
    exc = cls(spec.get("message") or "synthetic")
    status = spec.get("status")
    if status is not None:
        exc.status_code = status
    for field in ("request_id", "type", "code", "param"):
        if spec.get(field) is not None:
            setattr(exc, field, spec[field])
    if spec.get("attach_raw"):
        exc.body = {"error": {"message": spec.get("message") or "synthetic"}}
        exc.response = object()
    raise exc


def _emit_stdio_canary(text, target):
    payload = text if type(text) is str else str(text)
    encoded = payload.encode("utf-8")
    if target == "__stdout__":
        print(payload, file=sys.__stdout__, flush=True)
        return
    if target == "__stderr__":
        print(payload, file=sys.__stderr__, flush=True)
        return
    if target == "fd1":
        os.write(1, encoded)
        return
    if target == "fd2":
        os.write(2, encoded)
        return
    if target in ("stderr", "__stderr__"):
        print(payload, file=sys.stderr, flush=True)
        return
    print(payload, flush=True)


class _LeakAttr:
    def __init__(self, name):
        self.name = name

    def __get__(self, obj, owner):
        if obj is None:
            return self
        obj._emit()
        payload = object.__getattribute__(obj, "_payload")
        if isinstance(payload, dict) and self.name in payload:
            return payload[self.name]
        raise AttributeError(self.name)


class _LeakySDKResponse:
    object = _LeakAttr("object")
    id = _LeakAttr("id")
    request_id = _LeakAttr("request_id")
    _request_id = _LeakAttr("_request_id")
    model = _LeakAttr("model")
    status = _LeakAttr("status")
    output = _LeakAttr("output")
    incomplete_details = _LeakAttr("incomplete_details")
    error = _LeakAttr("error")
    usage = _LeakAttr("usage")

    def __init__(self, payload, leak, stream):
        object.__setattr__(self, "_payload", payload)
        object.__setattr__(self, "_leak", leak)
        object.__setattr__(self, "_stream", stream)

    def _emit(self):
        leak = object.__getattribute__(self, "_leak")
        stream = object.__getattribute__(self, "_stream")
        _emit_stdio_canary(leak, stream)


class _FakeResponses:
    def __init__(self, max_retries, credential=None):
        self.max_retries = max_retries
        self.credential = credential

    def create(self, **kwargs):
        record = {
            "timeout": kwargs.get("timeout"),
            "model": kwargs.get("model"),
            "instructions": kwargs.get("instructions"),
            "input": kwargs.get("input"),
            "max_output_tokens": kwargs.get("max_output_tokens"),
            "store": kwargs.get("store"),
            "stream": kwargs.get("stream"),
            "background": kwargs.get("background"),
            "tools": kwargs.get("tools"),
            "tool_choice": kwargs.get("tool_choice"),
            "parallel_tool_calls": kwargs.get("parallel_tool_calls"),
            "truncation": kwargs.get("truncation"),
            "text": kwargs.get("text"),
            "max_retries": self.max_retries,
            "keys": sorted(kwargs),
        }
        if "reasoning" in kwargs:
            record["reasoning"] = kwargs["reasoning"]
        with _CALLS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        printed = _CONFIG.get("print_text")
        target = _CONFIG.get("print_target") or _CONFIG.get("print_stream", "stdout")
        leak = self.credential if printed is None else printed
        should_emit = (
            printed is not None
            or _CONFIG.get("leaky_getter")
            or _CONFIG.get("print_target")
        )
        if should_emit:
            _emit_stdio_canary(leak, target)
        mode = _CONFIG.get("mode", "success")
        if mode == "error":
            if should_emit:
                _emit_stdio_canary(leak, target)
            _raise_configured_error(_CONFIG["error"])
        if mode == "raise":
            if should_emit:
                _emit_stdio_canary(leak, target)
            raise RuntimeError(_CONFIG.get("message") or "unexpected")
        if should_emit:
            _emit_stdio_canary(leak, target)
        if _CONFIG.get("leaky_getter"):
            return _LeakySDKResponse(_CONFIG["response"], leak, target)
        if should_emit:
            _emit_stdio_canary(leak, target)
        return _CONFIG["response"]


class _FakeClient:
    def __init__(self, max_retries, credential=None):
        self.responses = _FakeResponses(max_retries, credential=credential)


def _factory(*, api_key, max_retries):
    try:
        return _FakeClient(max_retries, credential=api_key)
    finally:
        api_key = None


import model_council.openai_adapter as oa

oa._default_openai_client_factory = _factory
oa._import_openai_sdk = lambda: _FakeSDK

from model_council.worker import main

raise SystemExit(main())
'''


def _install_offline_openai_python(directory, config):
    root = Path(directory)
    executable = root / "mcl-offline-python"
    executable.write_text(
        f"#!{sys.executable}\n" + _OFFLINE_OPENAI_WRAPPER, encoding="utf-8"
    )
    executable.chmod(0o755)
    executable.with_name(executable.name + ".json").write_text(
        json.dumps(config), encoding="utf-8"
    )
    calls = executable.with_name(executable.name + ".calls.jsonl")
    if calls.exists():
        calls.unlink()
    return str(executable), calls


def _read_offline_calls(calls_path):
    if not Path(calls_path).exists():
        return []
    return [
        json.loads(line)
        for line in Path(calls_path).read_text(encoding="utf-8").splitlines()
        if line
    ]


def _completed(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[sys.executable, "-B", "-m", "model_council.worker"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def _capture_run(stdout, returncode=0, stderr=""):
    captured = {}

    def _run(*args, **kwargs):
        captured["env"] = dict(kwargs.get("env") or {})
        captured["input"] = kwargs.get("input")
        return _completed(stdout, returncode=returncode, stderr=stderr)

    return captured, _run


def _is_harness_frame(frame) -> bool:
    path = frame.f_code.co_filename.replace("\\", "/")
    return "/model_council/" in path and "/tests/" not in path


def _local_value_blobs(value):
    from model_council.openai_adapter import RuntimeSecret

    blobs = []
    if value is None:
        return blobs
    if type(value) is RuntimeSecret:
        blobs.append("RuntimeSecret")
        inner = getattr(value, "_value", None)
        if isinstance(inner, str):
            blobs.append(inner)
        return blobs
    if isinstance(value, subprocess.CompletedProcess):
        blobs.extend([value.stdout, value.stderr, value.args])
        return blobs
    if isinstance(value, subprocess.TimeoutExpired):
        blobs.extend(
            [
                getattr(value, "stdout", None),
                getattr(value, "stderr", None),
                getattr(value, "output", None),
            ]
        )
        return blobs
    if isinstance(value, (bytes, bytearray)):
        blobs.append(bytes(value))
        return blobs
    try:
        blobs.append(str(value))
    except Exception:
        blobs.append(object.__repr__(value))
    try:
        blobs.append(repr(value))
    except Exception:
        pass
    return blobs


def _harness_exception_blobs(exc):
    seen = set()
    blobs = []
    stack = [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        blobs.append(str(current))
        blobs.append(repr(current))
        tb = getattr(current, "__traceback__", None)
        while tb is not None:
            if _is_harness_frame(tb.tb_frame):
                for val in tb.tb_frame.f_locals.values():
                    blobs.extend(_local_value_blobs(val))
            tb = tb.tb_next
        stack.append(getattr(current, "__cause__", None))
        stack.append(getattr(current, "__context__", None))
    return blobs


def _is_test_surface_frame(frame) -> bool:
    path = frame.f_code.co_filename.replace("\\", "/")
    if "/tests/" in path:
        return True
    if "/unittest/" in path:
        return True
    name = path.rsplit("/", 1)[-1]
    return name.startswith("unittest")


def _walk_failure_traceback(tb, stack) -> None:
    while tb is not None:
        if not _is_test_surface_frame(tb.tb_frame):
            for val in tb.tb_frame.f_locals.values():
                stack.append(val)
        tb = tb.tb_next


def _failure_graph_blobs(root):
    from model_council.openai_adapter import RuntimeSecret

    seen = set()
    blobs = []
    stack = [root]
    while stack:
        current = stack.pop()
        if current is None:
            continue
        ident = id(current)
        if ident in seen:
            continue
        seen.add(ident)
        if isinstance(current, BaseException):
            blobs.append(str(current))
            blobs.append(repr(current))
            doc = getattr(current, "doc", None)
            if doc is not None:
                blobs.append(doc)
            stack.append(current.__cause__)
            stack.append(current.__context__)
            _walk_failure_traceback(current.__traceback__, stack)
            continue
        if isinstance(current, types.TracebackType):
            _walk_failure_traceback(current, stack)
            continue
        if isinstance(current, (bytes, bytearray, memoryview)):
            blobs.append(bytes(current))
            continue
        if isinstance(current, str):
            blobs.append(current)
            continue
        if isinstance(current, (int, float, bool, complex)):
            continue
        if type(current) is RuntimeSecret:
            blobs.append(str(current))
            blobs.append(repr(current))
            stack.append(getattr(current, "_value", None))
            continue
        if isinstance(current, subprocess.CompletedProcess):
            blobs.extend([current.stdout, current.stderr, current.args])
            continue
        if isinstance(current, Mapping):
            for key, val in current.items():
                stack.append(key)
                stack.append(val)
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            for item in current:
                stack.append(item)
            continue
        if isinstance(
            current,
            (types.ModuleType, types.FunctionType, types.MethodType, types.CodeType, types.FrameType, type),
        ):
            continue
        try:
            blobs.append(str(current))
        except Exception:
            pass
        try:
            blobs.append(repr(current))
        except Exception:
            pass
    return blobs


def _assert_openai_parent_graph_closed(test, exc):
    """Credential-bearing parse streams must not survive on the parent exception."""
    _assert_secret_absent(test, *_failure_graph_blobs(exc), *_harness_exception_blobs(exc))
    test.assertIsNone(exc.__cause__)
    test.assertIsNone(exc.__context__)
    seen = set()
    stack = [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, json.JSONDecodeError):
            test.fail("JSONDecodeError retained in parent exception graph")
        if isinstance(current, subprocess.CompletedProcess):
            test.fail("CompletedProcess retained in parent exception graph")
        if isinstance(current, BaseException):
            doc = getattr(current, "doc", None)
            if isinstance(doc, str):
                _assert_secret_absent(test, doc)
            stack.append(current.__cause__)
            stack.append(current.__context__)
            tb = current.__traceback__
            while tb is not None:
                if _is_harness_frame(tb.tb_frame):
                    for val in tb.tb_frame.f_locals.values():
                        stack.append(val)
                tb = tb.tb_next


class _FalseyMapping(dict):
    def __bool__(self):
        return False


class _PhaseChangingTreatment(Mapping):
    def __init__(self):
        self._passes = 0

    def __iter__(self):
        self._passes += 1
        if self._passes == 1:
            return iter(["harmless"])
        return iter(["store"])

    def __getitem__(self, key):
        if key == "store":
            return False
        return 1

    def __len__(self):
        return 1


class TestOpenAIAdapterSkeleton(unittest.TestCase):
    def test_openai_responses_kind_is_live_only_and_sdk_import_is_lazy(self):
        self.assertNotIn(_OPENAI_KIND, REGISTRY)
        self.assertIn(_OPENAI_KIND, LIVE_REGISTRY)
        self.assertEqual(
            execution_profile_for_kind(_OPENAI_KIND),
            EXECUTION_PROFILE_LIVE_CONTRACT_V1,
        )
        for name in list(sys.modules):
            if name == "openai" or name.startswith("openai."):
                self.fail("openai SDK must not be imported by the test process yet")
        from model_council import adapters as adapters_mod
        from model_council import openai_adapter as openai_mod
        from model_council import worker as worker_mod

        del worker_mod, adapters_mod
        self.assertNotIn("openai", sys.modules)
        tree = ast.parse(Path(openai_mod.__file__).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name, "openai")
                    self.assertFalse(alias.name.startswith("openai."))
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotEqual(node.module, "openai")
                self.assertFalse(node.module.startswith("openai."))

    def test_optional_openai_dependency_is_exactly_pinned(self):
        path = REPO_ROOT / "requirements-openai.txt"
        self.assertTrue(path.is_file())
        dependency_lines = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            dependency_lines.append(stripped)
        self.assertEqual(dependency_lines, ["openai==2.54.0"])
        self.assertFalse((REPO_ROOT / "requirements.txt").exists())
        self.assertFalse((REPO_ROOT / "pyproject.toml").exists())

    def test_installed_openai_sdk_is_offline_compatible(self):
        env = {
            "PYTHONPATH": os.pathsep.join(
                (str(REPO_ROOT / "src"), str(REPO_ROOT / "tests"))
            )
        }
        completed = subprocess.run(
            [sys.executable, "-B", "-c", _OPENAI_SDK_COMPATIBILITY_PROBE],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "offline OpenAI SDK compatibility subprocess failed:\n"
            + completed.stderr[:2000],
        )
        report = json.loads(completed.stdout)
        if report == {"sdk": "absent"}:
            return
        self.assertEqual(
            report,
            {
                "request_keys": [
                    "background",
                    "input",
                    "instructions",
                    "max_output_tokens",
                    "model",
                    "parallel_tool_calls",
                    "store",
                    "stream",
                    "text",
                    "tool_choice",
                    "tools",
                    "truncation",
                ],
                "retry_attempts": 1,
                "sdk": _OPENAI_SDK_VERSION,
                "success_attempts": 1,
                "translation": "success",
            },
        )

    def test_live_worker_requires_explicit_provider_treatment_config(self):
        with TempRoot() as root:
            counter = Path(root) / "counter"
            payload = _live_envelope(
                options={"invocation_counter_path": str(counter)},
                treatment={"reasoning": {"effort": "high"}},
            )
            del payload["provider_treatment_config"]
            payload["adapter"]["options"]["text"] = {"verbosity": "low"}
            code, parsed = _run_worker(payload)
            self.assertEqual(code, 0)
            self.assertFalse(parsed["ok"])
            self.assertEqual(parsed["error_class"], "ProtocolError")
            self.assertFalse(counter.exists())

    def test_live_worker_passes_exact_deep_frozen_treatment(self):
        adapter = SubprocessAdapter(
            FAKE_IDENTITY,
            kind="live_stub",
            provider_treatment_config=RUNTIME_SHAPED,
        )
        expected = adapter.persisted_provider_treatment_config()
        self.assertEqual(expected, RUNTIME_SHAPED)
        captured = {}
        original = LIVE_REGISTRY["live_stub"]

        def spy(options, provider_treatment_config, request):
            captured["treatment"] = provider_treatment_config
            captured["options"] = options
            return original(options, provider_treatment_config, request)

        with patch.dict(LIVE_REGISTRY, {"live_stub": spy}):
            code, parsed = _run_worker(
                _live_envelope(treatment=expected)
            )
        self.assertEqual(code, 0)
        self.assertTrue(parsed["ok"])
        frozen = captured["treatment"]
        self.assertIsInstance(frozen, MappingProxyType)
        self.assertIsInstance(frozen["runtime"], MappingProxyType)
        self.assertIsInstance(frozen["runtime"]["stop"], tuple)
        self.assertEqual(json.loads(canonical_json(frozen)), expected)
        with self.assertRaises(TypeError):
            frozen["injected"] = True
        with patch("model_council.executor.subprocess.run") as mocked:
            mocked.return_value = _completed(
                json.dumps(
                    {
                        "ok": False,
                        "error_class": "ProtocolError",
                        "message": "probe",
                    }
                )
            )
            with self.assertRaises(ProtocolError):
                adapter.invoke_live(make_request())
            sent = json.loads(mocked.call_args.kwargs["input"])
        self.assertEqual(sent["provider_treatment_config"], expected)
        self.assertNotIn("provider_treatment_config", sent["adapter"]["options"])
        self.assertEqual(
            adapter.last_request["provider_treatment_config"],
            adapter.persisted_provider_treatment_config(),
        )

    def test_openai_runtime_options_must_be_empty(self):
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter(options={"timeout": 1})
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError):
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()
            callable_adapter = _openai_adapter(options={"client_factory": object()})
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError):
                    callable_adapter.invoke_live(make_request())
                mocked.assert_not_called()
            empty = _openai_adapter(options={})
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(
                    json.dumps(
                        {
                            "ok": False,
                            "error_class": "ProtocolError",
                            "message": "openai responses translation is not implemented",
                        }
                    )
                )
                with self.assertRaises(ProtocolError):
                    empty.invoke_live(make_request())
                sent = json.loads(mocked.call_args.kwargs["input"])
            self.assertEqual(sent["adapter"]["options"], {})

    def test_openai_skeleton_never_constructs_client_or_opens_network(self):
        from model_council.live_contract import ProviderCallKind
        from model_council.openai_adapter import (
            _OpenAITransportSuccess,
            openai_responses_skeleton,
        )
        from test_openai_adapter_translation import _completed_fixture, _solver_envelope

        fixture = _completed_fixture(_solver_envelope())
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=_OpenAITransportSuccess(response=fixture),
            ) as transport:
                with patch("model_council.openai_adapter.build_openai_client") as factory:
                    with patch(
                        "socket.socket",
                        side_effect=AssertionError("network path opened"),
                    ):
                        with patch(
                            "socket.create_connection",
                            side_effect=AssertionError("network path opened"),
                        ):
                            outcome = openai_responses_skeleton(
                                {}, deep_freeze({}), make_request()
                            )
            factory.assert_not_called()
            transport.assert_called_once()
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        _assert_secret_absent(self, outcome.to_dict())
        self.assertNotIn(_CHILD_KEY, os.environ)

    def test_client_factory_is_provider_local_and_injectable(self):
        from model_council import openai_adapter as openai_mod

        self.assertTrue(hasattr(openai_mod, "build_openai_client"))
        self.assertNotIn("build_openai_client", dir(sys.modules["model_council.worker"]))
        seen = {}

        def factory(*, api_key, max_retries):
            seen["api_key"] = api_key
            seen["max_retries"] = max_retries
            return {"sentinel": True}

        secret = openai_mod.RuntimeSecret(_FAKE_CREDENTIAL)
        _assert_secret_absent(self, repr(secret), str(secret))
        self.assertFalse(hasattr(secret, "to_dict"))
        self.assertFalse(hasattr(secret, "to_json"))
        factory_src = inspect.getsource(openai_mod._default_openai_client_factory)
        builder_src = inspect.getsource(openai_mod.build_openai_client)
        self.assertIn("max_retries=0", factory_src)
        self.assertIn("max_retries=0", builder_src)
        self.assertIn(
            "max_retries",
            inspect.signature(openai_mod._default_openai_client_factory).parameters,
        )
        client = openai_mod.build_openai_client(secret, client_factory=factory)
        self.assertEqual(client, {"sentinel": True})
        self.assertEqual(seen["api_key"], _FAKE_CREDENTIAL)
        self.assertEqual(seen["max_retries"], 0)
        with patch.object(
            openai_mod,
            "_default_openai_client_factory",
            side_effect=AssertionError("default factory must not run"),
        ):
            openai_mod.build_openai_client(secret, client_factory=factory)
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter(options={"client_factory": factory})
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError):
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()

    def test_openai_sdk_object_cannot_cross_worker_protocol(self):
        from model_council.openai_adapter import RuntimeSecret, build_openai_client

        class _FakeSDKClient:
            def __init__(self, api_key):
                self.api_key = api_key

        client = build_openai_client(
            RuntimeSecret(_FAKE_CREDENTIAL),
            client_factory=lambda *, api_key, max_retries: _FakeSDKClient(api_key),
        )
        with self.assertRaises(TypeError):
            json.dumps({"client": client})
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(
                    json.dumps(
                        {
                            "ok": False,
                            "error_class": "ProtocolError",
                            "message": "openai responses translation is not implemented",
                        }
                    )
                )
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
                raw_input = mocked.call_args.kwargs["input"]
            parsed = json.loads(raw_input)
        self.assertEqual(parsed["adapter"]["options"], {})
        self.assertNotIn("client", parsed)
        envelope_text = json.dumps(adapter.last_request)
        _assert_secret_absent(self, raw_input, envelope_text, parsed)

    def test_parent_maps_host_key_to_internal_child_key_only(self):
        ambient = dict(_AMBIENT_SECRET_ENV)
        ambient[_HOST_KEY] = _FAKE_CREDENTIAL
        with _isolated_environ(**ambient):
            adapter = _openai_adapter()
            captured, fake_run = _capture_run(
                json.dumps(
                    {
                        "ok": False,
                        "error_class": "ProtocolError",
                        "message": "openai responses translation is not implemented",
                    }
                )
            )
            with patch("model_council.executor.subprocess.run", side_effect=fake_run):
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
            env = captured["env"]
            self.assertEqual(set(env), {"PATH", "PYTHONPATH", _CHILD_KEY, _PROTOCOL_FD_KEY})
            self.assertTrue(env[_PROTOCOL_FD_KEY].isdigit())
            self.assertGreaterEqual(int(env[_PROTOCOL_FD_KEY]), 3)
            self.assertEqual(env[_CHILD_KEY], _FAKE_CREDENTIAL)
            self.assertNotIn(_HOST_KEY, env)
            self.assertNotIn(_CHILD_KEY, adapter.last_request)
            self.assertNotIn(_CHILD_KEY, json.dumps(adapter.last_request))

    def test_runtime_secret_is_absent_from_serialized_envelope_and_last_request(self):
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter(provider_treatment_config=REASONING_SHAPED)
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(
                    json.dumps(
                        {
                            "ok": False,
                            "error_class": "ProtocolError",
                            "message": "openai responses translation is not implemented",
                        }
                    )
                )
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
                raw_input = mocked.call_args.kwargs["input"]
            last = adapter.last_request
        _assert_secret_absent(
            self,
            raw_input,
            json.dumps(last),
            last,
            adapter.persisted_provider_treatment_config(),
        )
        self.assertNotIn(_HOST_KEY, json.dumps(last))
        self.assertNotIn(_CHILD_KEY, json.dumps(last))
        self.assertEqual(last["adapter"]["options"], {})
        self.assertEqual(last["provider_treatment_config"], REASONING_SHAPED)

    def test_missing_runtime_credential_fails_before_spawn(self):
        with _isolated_environ():
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError) as ctx:
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()
            _assert_secret_absent(self, str(ctx.exception))
            self.assertIn("missing", str(ctx.exception).lower())

    def test_empty_runtime_credential_fails_before_spawn(self):
        with _isolated_environ(**{_HOST_KEY: ""}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError) as ctx:
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()
            _assert_secret_absent(self, str(ctx.exception))

    def test_whitespace_control_and_oversized_credentials_fail_closed(self):
        from model_council.openai_adapter import validate_openai_runtime_credential

        cases = (
            "   ",
            " leading",
            "trailing ",
            "has\nnewline",
            "has\ttab",
            "has\rcr",
            "A" * 4097,
        )
        for value in cases:
            with self.subTest(kind="environ", size=len(value)):
                with _isolated_environ(**{_HOST_KEY: value}):
                    adapter = _openai_adapter()
                    with patch("model_council.executor.subprocess.run") as mocked:
                        with self.assertRaises(InfrastructureError) as ctx:
                            adapter.invoke_live(make_request())
                        mocked.assert_not_called()
                    message = str(ctx.exception)
                    if value:
                        self.assertNotIn(value, message)
                    self.assertIn("malformed", message.lower())
        # NUL cannot be stored in the process environment; validate it directly.
        with self.assertRaises(InfrastructureError) as ctx:
            validate_openai_runtime_credential("has\x00nul")
        self.assertIn("malformed", str(ctx.exception).lower())
        self.assertNotIn("has", str(ctx.exception))

    def test_child_consumes_and_removes_internal_credential_before_adapter_body(self):
        from model_council.live_contract import ProviderCallKind
        from model_council.openai_adapter import (
            _OpenAITransportSuccess,
            openai_responses_skeleton,
        )
        from test_openai_adapter_translation import _completed_fixture, _solver_envelope

        fixture = _completed_fixture(_solver_envelope())
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with patch(
                "model_council.openai_adapter._perform_openai_responses_transport",
                return_value=_OpenAITransportSuccess(response=fixture),
            ):
                outcome = openai_responses_skeleton(
                    {}, deep_freeze({}), make_request()
                )
            self.assertNotIn(_CHILD_KEY, os.environ)
        self.assertEqual(outcome.kind, ProviderCallKind.SUCCESS)
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with self.assertRaises(InfrastructureError):
                openai_responses_skeleton({"not": "empty"}, deep_freeze({}), make_request())
            self.assertNotIn(_CHILD_KEY, os.environ)

    def test_unrelated_ambient_secrets_proxies_and_telemetry_are_not_inherited(self):
        ambient = dict(_AMBIENT_SECRET_ENV)
        ambient[_HOST_KEY] = _FAKE_CREDENTIAL
        with _isolated_environ(**ambient):
            adapter = _openai_adapter()
            captured, fake_run = _capture_run(
                json.dumps(
                    {
                        "ok": False,
                        "error_class": "ProtocolError",
                        "message": "openai responses translation is not implemented",
                    }
                )
            )
            with patch("model_council.executor.subprocess.run", side_effect=fake_run):
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
            env = captured["env"]
            self.assertEqual(set(env), {"PATH", "PYTHONPATH", _CHILD_KEY, _PROTOCOL_FD_KEY})
            self.assertTrue(env[_PROTOCOL_FD_KEY].isdigit())
            self.assertGreaterEqual(int(env[_PROTOCOL_FD_KEY]), 3)
            for name in _AMBIENT_SECRET_ENV:
                self.assertNotIn(name, env)
            self.assertNotIn(_HOST_KEY, env)

    def test_openai_treatment_rejects_existing_secret_like_keys(self):
        from model_council.openai_adapter import openai_responses_skeleton

        cases = (
            {"api_key": "x"},
            {"openai_api_key": "x"},
            {"Authorization": "Bearer x"},
            {"headers": {"accept": "json"}},
            {"credentials": {"token": "x"}},
        )
        for config in cases:
            with self.subTest(keys=tuple(config)):
                with self.assertRaises(GovernanceViolation):
                    SubprocessAdapter(
                        FAKE_IDENTITY,
                        kind=_OPENAI_KIND,
                        provider_treatment_config=config,
                    )
                with self.assertRaises(GovernanceViolation):
                    normalize_provider_treatment_config(config)
                with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
                    with self.assertRaises(GovernanceViolation):
                        openai_responses_skeleton(
                            {},
                            deep_freeze(config),
                            make_request(),
                        )
                    self.assertNotIn(_CHILD_KEY, os.environ)

    def test_openai_treatment_rejects_stateful_conversation_controls(self):
        from model_council.openai_adapter import openai_responses_skeleton

        cases = (
            {"previous_response_id": "resp_1"},
            {"conversation": "conv_1"},
            {"conversation_id": "conv_1"},
            {"thread": "th_1"},
            {"thread_id": "th_1"},
            {"background": False},
            {"store": False},
            {"runtime": {"store": True}},
            {"nested": [{"thread_id": "th_nested"}]},
        )
        for config in cases:
            with self.subTest(config_keys=str(sorted(config))):
                with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
                    with self.assertRaises(InfrastructureError) as ctx:
                        openai_responses_skeleton(
                            {},
                            deep_freeze(config),
                            make_request(),
                        )
                    self.assertNotIn(_CHILD_KEY, os.environ)
                message = str(ctx.exception).lower()
                self.assertTrue(
                    "stateful" in message or "conversation" in message or "store" in message
                )

    def test_secret_bearing_client_factory_exception_is_replaced_without_chain(self):
        from model_council.openai_adapter import RuntimeSecret, build_openai_client

        def exploding_factory(*, api_key, max_retries):
            raise RuntimeError(
                f"sdk failed api_key={api_key} Authorization: Bearer {api_key}"
            )

        with self.assertRaises(InfrastructureError) as ctx:
            build_openai_client(
                RuntimeSecret(_FAKE_CREDENTIAL),
                client_factory=exploding_factory,
            )
        exc = ctx.exception
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        _assert_secret_absent(self, str(exc), repr(exc))
        self.assertNotIn("Authorization", str(exc))
        self.assertNotIn("Bearer", str(exc))
        self.assertNotIn("RuntimeError", str(exc))
        self.assertIn("initialization", str(exc).lower())

    def test_secret_bearing_worker_stream_is_neither_returned_nor_digested(self):
        stderr_body = f"leak:{_FAKE_CREDENTIAL}\n"
        digest = hashlib.sha256(stderr_body.encode("utf-8")).hexdigest()
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed("", returncode=1, stderr=stderr_body)
                with self.assertRaises(InfrastructureError) as ctx:
                    adapter.invoke_live(make_request())
            message = str(ctx.exception)
        _assert_secret_absent(self, message)
        self.assertNotIn("stderr_sha256", message)
        self.assertNotIn(digest, message)
        self.assertIn("stderr_bytes", message)
        self.assertIn("suppressed", message.lower())
        self.assertIn("exit 1", message)

    def test_fake_secret_absent_from_worker_response_invocation_metadata_artifacts_and_terminal_report(self):
        with TempRoot() as root:
            python, _calls = _install_offline_openai_python(
                root,
                {
                    "mode": "error",
                    "error": {
                        "class": "AuthenticationError",
                        "status": 401,
                        "request_id": "req_auth",
                        "message": "Authorization: Bearer " + _FAKE_CREDENTIAL,
                        "attach_raw": True,
                    },
                },
            )
            adapter = SubprocessAdapter(
                FAKE_IDENTITY,
                kind=_OPENAI_KIND,
                python_executable=python,
            )
            runs_root = Path(root) / "runs"
            runner = ExperimentRunner(
                adapter,
                ExternalEvaluator(EvaluationConfig()),
                runs_root=runs_root,
            )
            with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
                result = runner.execute(make_spec("oa-secret-absent", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            run_dir = runs_root / "oa-secret-absent"
            blob = _durable_text(run_dir)
            last = runner.adapter.last_request
            _assert_secret_absent(
                self,
                blob,
                json.dumps(last) if last is not None else None,
                result.metadata,
                getattr(result, "error", None),
                str(result),
            )
            terminal = json.loads((run_dir / "run_result.json").read_text())
            _assert_secret_absent(self, terminal)
            self.assertNotIn(_HOST_KEY, json.dumps(last))
            self.assertNotIn(_CHILD_KEY, json.dumps(last))
            self.assertEqual(last["adapter"]["options"], {})
            self.assertIn("provider_treatment_config", last)

    def test_existing_fake_and_live_stub_paths_remain_unchanged(self):
        live_params = inspect.signature(LIVE_REGISTRY["live_stub"]).parameters
        self.assertEqual(len(live_params), 3)
        fake_params = inspect.signature(REGISTRY["fake"]).parameters
        self.assertEqual(len(fake_params), 5)
        with TempRoot() as root:
            fake_runner, _ = make_runner(root, kind="fake")
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(
                    json.dumps(
                        {
                            "ok": True,
                            "execution_profile": "pre_live_legacy",
                            "response": {
                                "text": "ok",
                                "artifacts": {},
                                "identity_used": FAKE_IDENTITY.to_dict(),
                                "tokens_in": 1,
                                "tokens_out": 1,
                                "tool_uses": 0,
                            },
                        }
                    )
                )
                fake_runner.adapter.invoke(
                    role_instruction="role:solver x",
                    stage_inputs={"task": "t"},
                    budget=make_spec("x").resource_limits,
                    seed=0,
                )
                fake_env = mocked.call_args.kwargs["env"]
            self.assertEqual(set(fake_env), {"PATH", "PYTHONPATH"})
            self.assertNotIn(_CHILD_KEY, fake_env)
            self.assertNotIn("provider_treatment_config", fake_runner.adapter.last_request)
        with TempRoot() as root:
            live_runner, runs_root = make_runner(root, kind="live_stub")
            result = live_runner.execute(make_spec("oa-live-stub-still", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            last = live_runner.adapter.last_request
            self.assertIn("provider_treatment_config", last)
            self.assertEqual(
                last["provider_treatment_config"],
                live_runner.adapter.persisted_provider_treatment_config(),
            )
            self.assertNotIn("provider_treatment_config", last["adapter"]["options"])
        with TempRoot() as root:
            crash, runs_root = make_runner(
                root, kind="crash_worker", options={"stderr_canary": "crash-canary"}
            )
            result = crash.execute(make_spec("oa-crash-diag", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            payload = json.loads((runs_root / "oa-crash-diag" / "run_result.json").read_text())
            self.assertIn("stderr_sha256", payload["error"])
            self.assertIn("stderr_bytes", payload["error"])
        self.assertEqual(HARNESS_PROTOCOL_VERSION, "m1-dev-harness-v13")
        self.assertNotIn("openai", sys.modules)


class TestOpenAIAdapterSkeletonRemediation(unittest.TestCase):
    def _assert_harness_graph_secret_free(self, exc, *, require_no_completed=False):
        from model_council.openai_adapter import RuntimeSecret

        _assert_secret_absent(self, *_harness_exception_blobs(exc))
        tb = exc.__traceback__
        while tb is not None:
            if _is_harness_frame(tb.tb_frame):
                for val in tb.tb_frame.f_locals.values():
                    if type(val) is RuntimeSecret:
                        self.fail("RuntimeSecret remained in harness traceback locals")
                    if require_no_completed and isinstance(val, subprocess.CompletedProcess):
                        self.fail("CompletedProcess remained in harness traceback locals")
            tb = tb.tb_next

    def _assert_failure_graph_secret_free(self, exc):
        _assert_secret_absent(self, *_failure_graph_blobs(exc))

    def test_exactly_4096_utf8_bytes_are_accepted(self):
        from model_council.openai_adapter import validate_openai_runtime_credential

        credential = "A" * 4096
        self.assertEqual(len(credential.encode("utf-8")), 4096)
        self.assertEqual(validate_openai_runtime_credential(credential), credential)
        with _isolated_environ(**{_HOST_KEY: credential}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(
                    json.dumps(
                        {
                            "ok": False,
                            "error_class": "ProtocolError",
                            "message": "openai responses translation is not implemented",
                        }
                    )
                )
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
                mocked.assert_called()

    def test_more_than_4096_utf8_bytes_are_rejected(self):
        from model_council.openai_adapter import validate_openai_runtime_credential

        oversized = "é" * 2049
        self.assertGreater(len(oversized.encode("utf-8")), 4096)
        with self.assertRaises(InfrastructureError) as ctx:
            validate_openai_runtime_credential(oversized)
        self.assertIn("malformed", str(ctx.exception).lower())
        with _isolated_environ(**{_HOST_KEY: oversized}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError):
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()

    def test_printable_non_ascii_credential_is_accepted(self):
        from model_council.openai_adapter import validate_openai_runtime_credential

        credential = "mcl-åßé-密钥"
        self.assertEqual(validate_openai_runtime_credential(credential), credential)
        with _isolated_environ(**{_HOST_KEY: credential}):
            adapter = _openai_adapter()
            captured, fake_run = _capture_run(
                json.dumps(
                    {
                        "ok": False,
                        "error_class": "ProtocolError",
                        "message": "openai responses translation is not implemented",
                    }
                )
            )
            with patch("model_council.executor.subprocess.run", side_effect=fake_run):
                with self.assertRaises(ProtocolError):
                    adapter.invoke_live(make_request())
            self.assertEqual(captured["env"][_CHILD_KEY], credential)

    def test_malformed_parent_credential_traceback_locals_are_secret_free(self):
        malformed = _FAKE_CREDENTIAL + " "
        with _isolated_environ(**{_HOST_KEY: malformed}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError) as ctx:
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()
        self._assert_harness_graph_secret_free(ctx.exception)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_malformed_child_acquisition_traceback_locals_are_secret_free(self):
        from model_council.openai_adapter import acquire_child_openai_runtime_secret

        malformed = _FAKE_CREDENTIAL + "\n"
        with _isolated_environ(**{_CHILD_KEY: malformed}):
            with self.assertRaises(InfrastructureError) as ctx:
                acquire_child_openai_runtime_secret()
            self.assertNotIn(_CHILD_KEY, os.environ)
        self._assert_harness_graph_secret_free(ctx.exception)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_client_factory_secret_bearing_failure_graph_is_sanitized(self):
        from model_council.openai_adapter import RuntimeSecret, build_openai_client

        def exploding_factory(*, api_key, max_retries):
            cause = RuntimeError("nested " + api_key)
            raise RuntimeError("sdk failed Authorization: Bearer " + api_key) from cause

        with self.assertRaises(InfrastructureError) as ctx:
            build_openai_client(
                RuntimeSecret(_FAKE_CREDENTIAL),
                client_factory=exploding_factory,
            )
        exc = ctx.exception
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        self._assert_harness_graph_secret_free(exc)
        self.assertIn("initialization", str(exc).lower())

    def test_runtime_secret_pickle_dumps_fails_safely(self):
        from model_council.openai_adapter import RuntimeSecret

        secret = RuntimeSecret(_FAKE_CREDENTIAL)
        with self.assertRaises(InfrastructureError) as ctx:
            pickle.dumps(secret)
        _assert_secret_absent(self, str(ctx.exception), repr(ctx.exception))
        self.assertIn("serialized", str(ctx.exception).lower())
        self._assert_failure_graph_secret_free(ctx.exception)
        if getattr(secret, "_value", None) == _FAKE_CREDENTIAL:
            self.fail("pickle rejection left the raw credential on the wrapper")

    def test_runtime_secret_copy_fails_safely(self):
        from model_council.openai_adapter import RuntimeSecret

        secret = RuntimeSecret(_FAKE_CREDENTIAL)
        with self.assertRaises(InfrastructureError) as ctx:
            copy.copy(secret)
        _assert_secret_absent(self, str(ctx.exception), repr(ctx.exception))
        self.assertIn("copied", str(ctx.exception).lower())
        self._assert_failure_graph_secret_free(ctx.exception)
        if getattr(secret, "_value", None) == _FAKE_CREDENTIAL:
            self.fail("copy rejection left the raw credential on the wrapper")

    def test_runtime_secret_deepcopy_fails_safely(self):
        from model_council.openai_adapter import RuntimeSecret

        secret = RuntimeSecret(_FAKE_CREDENTIAL)
        with self.assertRaises(InfrastructureError) as ctx:
            copy.deepcopy(secret)
        _assert_secret_absent(self, str(ctx.exception), repr(ctx.exception))
        self.assertIn("copied", str(ctx.exception).lower())
        self._assert_failure_graph_secret_free(ctx.exception)
        if getattr(secret, "_value", None) == _FAKE_CREDENTIAL:
            self.fail("deepcopy rejection left the raw credential on the wrapper")

    def test_runtime_secret_direct_hooks_discard_raw_value_before_rejecting(self):
        from model_council.openai_adapter import RuntimeSecret

        cases = (
            ("reduce", lambda secret: secret.__reduce__()),
            ("reduce_ex", lambda secret: secret.__reduce_ex__(pickle.HIGHEST_PROTOCOL)),
            ("getstate", lambda secret: secret.__getstate__()),
            ("setstate", lambda secret: secret.__setstate__({})),
            ("getnewargs", lambda secret: secret.__getnewargs__()),
            ("getnewargs_ex", lambda secret: secret.__getnewargs_ex__()),
            ("copy", lambda secret: secret.__copy__()),
            ("deepcopy", lambda secret: secret.__deepcopy__({})),
        )
        for name, action in cases:
            with self.subTest(hook=name):
                secret = RuntimeSecret(_FAKE_CREDENTIAL)
                with self.assertRaises(InfrastructureError) as ctx:
                    action(secret)
                self._assert_failure_graph_secret_free(ctx.exception)
                if getattr(secret, "_value", None) == _FAKE_CREDENTIAL:
                    self.fail("hook rejection left the raw credential on the wrapper")

    def test_fresh_runtime_secret_still_reaches_client_factory_exactly_once(self):
        from model_council.openai_adapter import RuntimeSecret, build_openai_client

        consumed = RuntimeSecret(_FAKE_CREDENTIAL)
        with self.assertRaises(InfrastructureError):
            pickle.dumps(consumed)
        if getattr(consumed, "_value", None) == _FAKE_CREDENTIAL:
            self.fail("consumed RuntimeSecret still retained the raw credential")
        seen = []

        def factory(*, api_key, max_retries):
            self.assertEqual(max_retries, 0)
            seen.append(api_key)
            return {"sentinel": True}

        client = build_openai_client(
            RuntimeSecret(_FAKE_CREDENTIAL),
            client_factory=factory,
        )
        self.assertEqual(client, {"sentinel": True})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0], _FAKE_CREDENTIAL)

    def test_openai_spawn_oserror_does_not_retain_credential_in_failure_graph(self):
        missing_python = os.path.join(
            os.sep, "nonexistent", "mcl-openai-python-not-real-executable"
        )
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter(python_executable=missing_python)
            with self.assertRaises(InfrastructureError) as ctx:
                adapter.invoke_live(make_request())
        exc = ctx.exception
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        self.assertIn("failed to spawn adapter process", str(exc))
        self._assert_failure_graph_secret_free(exc)

    def test_timeout_exception_does_not_retain_secret_bearing_output(self):
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()

            def boom(*args, **kwargs):
                raise subprocess.TimeoutExpired(
                    cmd=[sys.executable],
                    timeout=1,
                    output=_FAKE_CREDENTIAL,
                    stderr=_FAKE_CREDENTIAL,
                )

            with patch("model_council.executor.subprocess.run", side_effect=boom):
                with self.assertRaises(StageTimeout) as ctx:
                    adapter.invoke_live(make_request())
        exc = ctx.exception
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        self._assert_harness_graph_secret_free(exc)
        _assert_secret_absent(self, str(exc), repr(exc))

    def test_nonzero_openai_worker_exit_releases_completed_process_buffers(self):
        stdout_body = "out:" + _FAKE_CREDENTIAL
        stderr_body = "err:" + _FAKE_CREDENTIAL
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(stdout_body, returncode=7, stderr=stderr_body)
                with self.assertRaises(InfrastructureError) as ctx:
                    adapter.invoke_live(make_request())
        exc = ctx.exception
        self._assert_harness_graph_secret_free(exc, require_no_completed=True)
        self.assertNotIn("stderr_sha256", str(exc))
        self.assertIn("stderr_bytes", str(exc))
        self.assertIn("suppressed", str(exc).lower())

    def test_falsey_nonempty_options_are_rejected_on_parent_path(self):
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter(options=_FalseyMapping({"timeout": 1}))
            self.assertFalse(bool(_FalseyMapping({"timeout": 1})))
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(InfrastructureError):
                    adapter.invoke_live(make_request())
                mocked.assert_not_called()

    def test_falsey_nonempty_options_are_rejected_on_direct_skeleton(self):
        from model_council.openai_adapter import (
            OPENAI_OPTIONS_MUST_BE_EMPTY,
            openai_responses_skeleton,
        )

        options = _FalseyMapping({"client_factory": object()})
        self.assertFalse(bool(options))
        with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
            with self.assertRaises(InfrastructureError) as ctx:
                openai_responses_skeleton(options, {}, make_request())
            self.assertNotIn(_CHILD_KEY, os.environ)
        self.assertEqual(str(ctx.exception), OPENAI_OPTIONS_MUST_BE_EMPTY)

    def test_phase_changing_treatment_cannot_bypass_stateless_rejection(self):
        from model_council.openai_adapter import validate_openai_provider_treatment

        mapping = _PhaseChangingTreatment()
        try:
            result = validate_openai_provider_treatment(mapping)
        except InfrastructureError:
            return
        serialized = json.dumps(result)
        self.assertNotIn("store", serialized)
        self.assertNotIn("thread_id", serialized)
        self.assertNotIn("previous_response_id", serialized)

    def test_recursive_prohibited_controls_remain_rejected_in_nested_structures(self):
        from model_council.openai_adapter import openai_responses_skeleton

        cases = (
            {"outer": {"inner": {"Store": False}}},
            {"items": [{"thread-id": "x"}]},
            {"a": [{"b": {"previous_response_id": "r"}}]},
            {"runtime": [{"conversation": "c"}, {"ok": 1}]},
        )
        for config in cases:
            with self.subTest(config=str(sorted(config))):
                with _isolated_environ(**{_CHILD_KEY: _FAKE_CREDENTIAL}):
                    with self.assertRaises(InfrastructureError) as ctx:
                        openai_responses_skeleton({}, config, make_request())
                    self.assertNotIn(_CHILD_KEY, os.environ)
                message = str(ctx.exception).lower()
                self.assertTrue(
                    "stateful" in message or "conversation" in message or "store" in message
                )

    def test_malformed_openai_worker_stdout_does_not_retain_secret_streams(self):
        garbage = "Authorization: Bearer " + _FAKE_CREDENTIAL + "\n{not-json"
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.subprocess.run") as mocked:
                mocked.return_value = _completed(garbage, returncode=0, stderr=garbage)
                with self.assertRaises(ProtocolError) as ctx:
                    adapter.invoke_live(make_request())
        exc = ctx.exception
        self.assertIn("not valid JSON", str(exc))
        _assert_openai_parent_graph_closed(self, exc)
        self._assert_harness_graph_secret_free(exc, require_no_completed=True)
        self._assert_failure_graph_secret_free(exc)
        self.assertNotIn(_FAKE_CREDENTIAL, str(exc))
        self.assertNotIn("Authorization", str(exc))

    def test_assertion_helpers_do_not_interpolate_synthetic_credential(self):
        with self.assertRaises(AssertionError) as ctx:
            _assert_secret_absent(self, "prefix-" + _FAKE_CREDENTIAL)
        if _FAKE_CREDENTIAL in str(ctx.exception):
            self.fail("assertion helper interpolated the synthetic credential")


def _openai_fail_closed_payload():
    return _live_envelope(kind=_OPENAI_KIND, options={}, treatment={})


def _run_openai_worker_captured_stdout(payload, *, protocol_fd=None):
    invoked = []

    def spy(*args, **kwargs):
        invoked.append(True)
        raise AssertionError("openai adapter must not run without a dedicated protocol channel")

    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    saved_out = os.dup(1)
    saved_err = os.dup(2)
    saved_stdout = sys.stdout
    saved_stderr = sys.stderr
    saved_dunder_out = sys.__stdout__
    saved_dunder_err = sys.__stderr__
    try:
        with _isolated_environ():
            os.environ.pop(_PROTOCOL_FD_KEY, None)
            if protocol_fd is not None:
                os.environ[_PROTOCOL_FD_KEY] = protocol_fd
            with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
                with patch.dict(LIVE_REGISTRY, {_OPENAI_KIND: spy}):
                    code = worker_main()
        return code, stdout.getvalue(), invoked
    finally:
        worker_mod._protocol_out = None
        worker_mod._discarded_stdio = None
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        _close_fd(saved_out)
        _close_fd(saved_err)
        sys.stdout = saved_stdout
        sys.stderr = saved_stderr
        sys.__stdout__ = saved_dunder_out
        sys.__stderr__ = saved_dunder_err


class TestOpenAIWorkerProtocolFdFailClosed(unittest.TestCase):
    def _assert_fail_closed(self, code, stdout_text, invoked, *, banned=None):
        self.assertNotEqual(code, 0)
        self.assertEqual(invoked, [])
        stripped = stdout_text.lstrip()
        self.assertFalse(stripped.startswith("{"))
        self.assertNotIn('"ok"', stdout_text)
        self.assertNotIn("error_class", stdout_text)
        if banned:
            self.assertNotIn(banned, stdout_text)

    def test_missing_protocol_fd_fails_closed_without_stdout_fallback(self):
        code, stdout_text, invoked = _run_openai_worker_captured_stdout(
            _openai_fail_closed_payload()
        )
        self._assert_fail_closed(code, stdout_text, invoked)
        self.assertNotIn(_PROTOCOL_FD_KEY, stdout_text)

    def test_non_integer_protocol_fd_fails_closed_without_adapter(self):
        malformed = "not-an-fd"
        code, stdout_text, invoked = _run_openai_worker_captured_stdout(
            _openai_fail_closed_payload(),
            protocol_fd=malformed,
        )
        self._assert_fail_closed(code, stdout_text, invoked, banned=malformed)

    def test_invalid_low_protocol_fd_fails_closed_without_adapter(self):
        for value in ("0", "1", "2"):
            with self.subTest(fd=value):
                code, stdout_text, invoked = _run_openai_worker_captured_stdout(
                    _openai_fail_closed_payload(),
                    protocol_fd=value,
                )
                self._assert_fail_closed(code, stdout_text, invoked, banned=value)

    def test_out_of_range_protocol_fd_fails_closed_without_adapter(self):
        overflow_fd = str(2**63)
        code, stdout_text, invoked = _run_openai_worker_captured_stdout(
            _openai_fail_closed_payload(),
            protocol_fd=overflow_fd,
        )
        self._assert_fail_closed(code, stdout_text, invoked, banned=overflow_fd)

    def test_closed_protocol_fd_fails_closed_without_adapter(self):
        payload = _openai_fail_closed_payload()
        invoked = []

        def spy(*args, **kwargs):
            invoked.append(True)
            raise AssertionError("openai adapter must not run without a dedicated protocol channel")

        stdin = io.StringIO(json.dumps(payload))
        stdout = io.StringIO()
        saved_out = os.dup(1)
        saved_err = os.dup(2)
        saved_stdout = sys.stdout
        saved_stderr = sys.stderr
        saved_dunder_out = sys.__stdout__
        saved_dunder_err = sys.__stderr__
        try:
            with _isolated_environ():
                os.environ.pop(_PROTOCOL_FD_KEY, None)
                read_fd, write_fd = os.pipe()
                os.close(read_fd)
                closed_value = str(write_fd)
                os.environ[_PROTOCOL_FD_KEY] = closed_value
                os.close(write_fd)
                with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
                    with patch.dict(LIVE_REGISTRY, {_OPENAI_KIND: spy}):
                        code = worker_main()
            self._assert_fail_closed(code, stdout.getvalue(), invoked, banned=closed_value)
        finally:
            worker_mod._protocol_out = None
            worker_mod._discarded_stdio = None
            os.dup2(saved_out, 1)
            os.dup2(saved_err, 2)
            _close_fd(saved_out)
            _close_fd(saved_err)
            sys.stdout = saved_stdout
            sys.stderr = saved_stderr
            sys.__stdout__ = saved_dunder_out
            sys.__stderr__ = saved_dunder_err

    def test_valid_protocol_fd_still_invokes_adapter_on_dedicated_channel(self):
        payload = _openai_fail_closed_payload()
        invoked = []
        original = LIVE_REGISTRY["live_stub"]

        def spy(options, provider_treatment_config, request):
            invoked.append(True)
            return original(options, provider_treatment_config, request)

        with patch.dict(LIVE_REGISTRY, {_OPENAI_KIND: spy}):
            code, parsed, stdout_text = _run_openai_worker_with_protocol_fd(payload)
        self.assertEqual(code, 0)
        self.assertTrue(parsed["ok"])
        self.assertEqual(invoked, [True])
        self.assertEqual(stdout_text, "")
        self.assertEqual(parsed["execution_profile"], EXECUTION_PROFILE_LIVE_CONTRACT_V1)

    def test_live_stub_without_protocol_fd_still_uses_stdout(self):
        payload = _live_envelope(kind="live_stub", treatment={})
        self.assertNotEqual(payload["adapter"]["kind"], _OPENAI_KIND)
        with _isolated_environ():
            os.environ.pop(_PROTOCOL_FD_KEY, None)
            code, parsed = _run_worker(payload)
        self.assertEqual(code, 0)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["execution_profile"], EXECUTION_PROFILE_LIVE_CONTRACT_V1)


class TestOpenAIProtocolReaderStartFailure(unittest.TestCase):
    def test_reader_start_failure_does_not_join_unstarted_thread_or_leak_fds(self):
        joined = []
        created = []
        start_error = RuntimeError("synthetic protocol reader start failure")
        real_pipe = os.pipe

        def tracking_pipe():
            pair = real_pipe()
            created.extend(pair)
            return pair

        class _FailingReaderThread(threading.Thread):
            def start(self):
                raise start_error

            def join(self, timeout=None):
                joined.append(timeout)
                return super().join(timeout)

        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.os.pipe", tracking_pipe):
                with patch("model_council.executor.threading.Thread", _FailingReaderThread):
                    with patch("model_council.executor.subprocess.run") as mocked:
                        with self.assertRaises(RuntimeError) as ctx:
                            adapter.invoke_live(make_request())
                        mocked.assert_not_called()
        self.assertIs(ctx.exception, start_error)
        self.assertIsNone(ctx.exception.__context__)
        self.assertEqual(joined, [])
        self.assertEqual(len(created), 2)
        for fd in created:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_reader_start_oserror_preserves_spawn_failure_without_join(self):
        joined = []
        created = []
        real_pipe = os.pipe

        def tracking_pipe():
            pair = real_pipe()
            created.extend(pair)
            return pair

        class _FailingReaderThread(threading.Thread):
            def start(self):
                raise OSError("synthetic protocol reader start oserror")

            def join(self, timeout=None):
                joined.append(timeout)
                return super().join(timeout)

        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.os.pipe", tracking_pipe):
                with patch("model_council.executor.threading.Thread", _FailingReaderThread):
                    with patch("model_council.executor.subprocess.run") as mocked:
                        with self.assertRaises(InfrastructureError) as ctx:
                            adapter.invoke_live(make_request())
                        mocked.assert_not_called()
        self.assertIn("failed to spawn adapter process", str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)
        self.assertEqual(joined, [])
        self.assertEqual(len(created), 2)
        for fd in created:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_reader_thread_starts_and_joins_on_normal_spawn(self):
        started = []
        joined = []

        class _TrackingThread(threading.Thread):
            def start(self):
                started.append(True)
                return super().start()

            def join(self, timeout=None):
                joined.append(timeout)
                return super().join(timeout)

        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            adapter = _openai_adapter()
            with patch("model_council.executor.threading.Thread", _TrackingThread):
                with patch("model_council.executor.subprocess.run") as mocked:
                    mocked.return_value = _completed('{"ok": true}', returncode=0)
                    with self.assertRaises(ProtocolError):
                        adapter.invoke_live(make_request())
                    mocked.assert_called_once()
        self.assertEqual(started, [True])
        self.assertTrue(joined)


if __name__ == "__main__":
    unittest.main()
