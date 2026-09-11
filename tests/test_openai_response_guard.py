"""F6b Checkpoint 1: bounded OpenAI response bodies and owned-client cleanup.

All HTTP and worker integration is offline.  SDK cases use OpenAI 2.54.0,
HTTPX 0.28.1, synthetic credentials, and MockTransport without real sockets.
"""

from __future__ import annotations

import gc
import importlib.metadata
import json
import os
import subprocess
import sys
import textwrap
import types
import unittest
import weakref
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import helpers  # noqa: F401 - installs src and tests on sys.path
import httpx

from helpers import FAKE_IDENTITY, make_spec, make_task
from model_council.artifacts import ArtifactStore
from model_council.errors import InfrastructureError, ProtocolError
from model_council.evaluator import EvaluationConfig, ExternalEvaluator
from model_council.executor import SubprocessAdapter
from model_council.live_contract import ProviderCallKind, ProviderErrorCategory
from model_council.openai_adapter import (
    RuntimeSecret,
    _OpenAITransportFailure,
    _OpenAITransportSuccess,
    _default_openai_client_factory,
    _normalize_openai_sdk_exception,
    _perform_openai_responses_transport,
    build_openai_client,
    build_openai_responses_request,
)
from test_attempt_lifecycle_dispatch import synthetic_writer
from test_openai_adapter_skeleton import _isolated_environ
from test_openai_adapter_translation import (
    _completed_fixture,
    _solver_envelope,
    _solver_request,
    _usage_fixture,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
_FAKE_CREDENTIAL = "mcl-f6b-synthetic-key-not-real"
_HOST_KEY = "OPENAI_API_KEY"


class CountingSyncByteStream(httpx.SyncByteStream):
    def __init__(self, chunks, *, close_error=None):
        self.chunks = tuple(chunks)
        self.requested = 0
        self.close_calls = 0
        self.close_error = close_error

    def __iter__(self):
        for chunk in self.chunks:
            self.requested += 1
            yield chunk

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


def _guard_symbols():
    from model_council.openai_response_guard import (
        MAX_OPENAI_HTTP_BODY_BYTES,
        _OpenAIResponseBoundaryError,
        _bounded_body_chunks,
        _build_bounded_openai_http_client,
    )

    return (
        MAX_OPENAI_HTTP_BODY_BYTES,
        _OpenAIResponseBoundaryError,
        _bounded_body_chunks,
        _build_bounded_openai_http_client,
    )


def _guarded_get(chunks, *, headers=None, close_error=None, buffered=False):
    limit, boundary_error, _, builder = _guard_symbols()
    del limit, boundary_error
    stream = CountingSyncByteStream(chunks, close_error=close_error)
    attempts = []

    def handler(request):
        attempts.append(request)
        if buffered:
            return httpx.Response(200, headers=headers, content=b"".join(chunks))
        return httpx.Response(200, headers=headers, stream=stream)

    client = builder(transport=httpx.MockTransport(handler))
    try:
        response = client.get("https://offline.invalid/body")
        return response, stream, attempts
    finally:
        client.close()


class TestBoundedBodyChunks(unittest.TestCase):
    def test_exact_byte_boundaries_for_one_large_chunk(self):
        limit, boundary_error, bounded, _ = _guard_symbols()
        for size, accepted in (
            (7_999_999, True),
            (8_000_000, True),
            (8_000_001, False),
        ):
            with self.subTest(size=size):
                chunks = [b"x" * size]
                if accepted:
                    result = list(bounded(chunks))
                    self.assertEqual(result, chunks)
                else:
                    with self.assertRaises(boundary_error) as caught:
                        list(bounded(chunks))
                    self.assertEqual(str(caught.exception), "openai response body rejected")
                    self.assertEqual(limit, 8_000_000)

    def test_multiple_chunks_and_final_one_byte_overflow(self):
        limit, boundary_error, bounded, _ = _guard_symbols()
        sentinel_requests = []

        def source():
            for chunk in (b"a" * (limit - 1), b"b", b"c", b"sentinel"):
                sentinel_requests.append(len(sentinel_requests))
                yield chunk

        iterator = bounded(source())
        self.assertEqual(next(iterator), b"a" * (limit - 1))
        self.assertEqual(next(iterator), b"b")
        with self.assertRaises(boundary_error):
            next(iterator)
        self.assertEqual(len(sentinel_requests), 3)

    def test_crossing_chunk_is_never_partially_yielded_or_drained(self):
        limit, boundary_error, bounded, _ = _guard_symbols()
        source = CountingSyncByteStream(
            (b"a" * (limit - 2), b"crossing", b"never-requested")
        )
        iterator = bounded(source)
        self.assertEqual(next(iterator), b"a" * (limit - 2))
        with self.assertRaises(boundary_error):
            next(iterator)
        self.assertEqual(source.requested, 2)

    def test_empty_exact_bytes_chunks_are_allowed(self):
        _, _, bounded, _ = _guard_symbols()
        chunks = [b"", b"a", b"", b"bc", b""]
        self.assertEqual(list(bounded(chunks)), chunks)

    def test_non_exact_bytes_chunk_is_rejected(self):
        _, boundary_error, bounded, _ = _guard_symbols()
        for value in (bytearray(b"x"), memoryview(b"x"), "x", 1, None):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(boundary_error) as caught:
                    list(bounded([value]))
                self.assertEqual(str(caught.exception), "openai response body rejected")


class TestGuardedHttpClient(unittest.TestCase):
    def test_actual_bytes_are_authoritative_for_content_length(self):
        limit, boundary_error, _, _ = _guard_symbols()
        cases = (
            ("missing", {}, (b"ok",), True),
            ("understated", {"content-length": "1"}, (b"x" * limit, b"y"), False),
            ("overstated", {"content-length": str(limit + 1)}, (b"ok",), True),
        )
        for name, headers, chunks, accepted in cases:
            with self.subTest(name=name):
                if accepted:
                    response, stream, attempts = _guarded_get(chunks, headers=headers)
                    self.assertEqual(response.content, b"".join(chunks))
                    self.assertEqual(stream.requested, len(chunks))
                    self.assertEqual(len(attempts), 1)
                else:
                    with self.assertRaises(boundary_error):
                        _guarded_get(chunks, headers=headers)

    def test_encoding_policy_accepts_absent_or_normalized_identity(self):
        for headers in ({}, {"content-encoding": "  IdEnTiTy  "}):
            with self.subTest(headers=headers):
                response, stream, attempts = _guarded_get((b"body",), headers=headers)
                self.assertEqual(response.content, b"body")
                self.assertEqual(stream.requested, 1)
                self.assertEqual(len(attempts), 1)

    def test_encoding_policy_rejects_all_prohibited_forms_before_iteration(self):
        _, boundary_error, _, builder = _guard_symbols()
        values = tuple(
            [(b"content-encoding", value)]
            for value in (b"gzip", b"deflate", b"br", b"zstd", b"rot13", b"", b"gzip, identity")
        ) + (
            [(b"content-encoding", b"identity"), (b"content-encoding", b"identity")],
        )
        for raw_headers in values:
            with self.subTest(raw_headers=raw_headers):
                stream = CountingSyncByteStream((b"must-not-read",))

                def handler(request):
                    return httpx.Response(200, headers=raw_headers, stream=stream)

                client = builder(transport=httpx.MockTransport(handler))
                try:
                    with patch.object(
                        httpx.Response,
                        "_get_content_decoder",
                        side_effect=AssertionError("decoder accessed"),
                    ) as decoder:
                        with self.assertRaises(boundary_error):
                            client.get("https://offline.invalid/encoding")
                    decoder.assert_not_called()
                    self.assertEqual(stream.requested, 0)
                    self.assertEqual(stream.close_calls, 1)
                finally:
                    client.close()

    def test_request_sends_identity_accept_encoding_and_preserves_defaults(self):
        _, _, _, builder = _guard_symbols()
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, stream=CountingSyncByteStream((b"ok",)))

        client = builder(transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(client.get("https://offline.invalid").content, b"ok")
        finally:
            client.close()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].headers["accept-encoding"], "identity")
        self.assertIn("accept", seen[0].headers)
        self.assertIn("user-agent", seen[0].headers)

    def test_stream_close_is_forwarded_once_on_completion_and_rejection(self):
        limit, boundary_error, _, _ = _guard_symbols()
        response, completed, _ = _guarded_get((b"one", b"two"))
        self.assertEqual(response.content, b"onetwo")
        self.assertEqual(completed.close_calls, 1)
        rejected = CountingSyncByteStream((b"x" * limit, b"overflow", b"sentinel"))

        def handler(request):
            return httpx.Response(200, stream=rejected)

        builder = _guard_symbols()[3]
        client = builder(transport=httpx.MockTransport(handler))
        try:
            with self.assertRaises(boundary_error):
                client.get("https://offline.invalid")
        finally:
            client.close()
        self.assertEqual(rejected.requested, 2)
        self.assertEqual(rejected.close_calls, 1)

    def test_stream_close_failure_propagates_without_second_close(self):
        error = RuntimeError("stream close sentinel")
        stream = CountingSyncByteStream((b"ok",), close_error=error)
        _, _, _, builder = _guard_symbols()

        def handler(request):
            return httpx.Response(200, stream=stream)

        client = builder(transport=httpx.MockTransport(handler))
        try:
            with self.assertRaises(RuntimeError) as caught:
                client.get("https://offline.invalid")
            self.assertIs(caught.exception, error)
        finally:
            client.close()
        self.assertEqual(stream.close_calls, 1)

    def test_buffered_response_detection_only_small_usable_oversized_rejected(self):
        """Buffered fixtures provide detection coverage, not early interception proof."""
        limit, boundary_error, _, _ = _guard_symbols()
        small, _, _ = _guarded_get((b"buffered",), buffered=True)
        self.assertEqual(small.content, b"buffered")
        with self.assertRaises(boundary_error):
            _guarded_get((b"x" * (limit + 1),), buffered=True)


class _FakeResponses:
    def __init__(self, trace, *, result=None, error=None):
        self.trace = trace
        self.result = result
        self.error = error
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            self.trace.append("sdk exception")
            raise self.error
        self.trace.append("sdk return")
        return self.result


class _FakeClient:
    def __init__(self, responses, trace=None, close_error=None):
        self.responses = responses
        self.trace = trace if trace is not None else []
        self.close_error = close_error
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.trace.append("close")
        if self.close_error is not None:
            raise self.close_error


def _owned(client):
    from model_council.openai_adapter import _OwnedOpenAIClient

    return _OwnedOpenAIClient(client)


def _transport_request():
    return build_openai_responses_request(_solver_request(), {})


def _transport_call(client_or_carrier, *, lifecycle=None):
    if lifecycle is not None:
        return _perform_openai_responses_transport(
            _transport_request(),
            RuntimeSecret(_FAKE_CREDENTIAL),
            3.25,
            client_factory=lambda **kwargs: client_or_carrier,
            lifecycle=lifecycle,
        )
    with synthetic_writer(_solver_request()) as writer:
        return _perform_openai_responses_transport(
            _transport_request(),
            RuntimeSecret(_FAKE_CREDENTIAL),
            3.25,
            client_factory=lambda **kwargs: client_or_carrier,
            lifecycle=writer,
        )


class TestClientOwnership(unittest.TestCase):
    def test_build_dispatcher_returns_injected_dictionary_unchanged(self):
        value = {"close": "still borrowed"}
        built = build_openai_client(
            RuntimeSecret(_FAKE_CREDENTIAL), client_factory=lambda **kwargs: value
        )
        self.assertIs(built, value)

    def test_borrowed_client_without_close_works(self):
        trace = []
        responses = _FakeResponses(
            trace,
            result=_completed_fixture(_solver_envelope(), usage=_usage_fixture()),
        )
        client = types.SimpleNamespace(responses=responses)
        result = _transport_call(client)
        self.assertIsInstance(result, _OpenAITransportSuccess)
        self.assertEqual(len(responses.calls), 1)

    def test_borrowed_close_trap_is_never_inspected_or_closed(self):
        trace = []
        responses = _FakeResponses(
            trace,
            result=_completed_fixture(_solver_envelope(), usage=_usage_fixture()),
        )

        class Borrowed:
            def __init__(self, response_api):
                self.responses = response_api

            def __getattribute__(self, name):
                if name == "close":
                    raise AssertionError("borrowed close inspected")
                return object.__getattribute__(self, name)

        result = _transport_call(Borrowed(responses))
        self.assertIsInstance(result, _OpenAITransportSuccess)

    def test_patched_default_factory_raw_client_remains_borrowed(self):
        trace = []
        client = _FakeClient(
            _FakeResponses(
                trace,
                result=_completed_fixture(_solver_envelope(), usage=_usage_fixture()),
            ),
            trace,
        )
        with patch(
            "model_council.openai_adapter._default_openai_client_factory",
            return_value=client,
        ):
            with synthetic_writer(_solver_request()) as writer:
                result = _perform_openai_responses_transport(
                    _transport_request(),
                    RuntimeSecret(_FAKE_CREDENTIAL),
                    3.25,
                    lifecycle=writer,
                )
        self.assertIsInstance(result, _OpenAITransportSuccess)
        self.assertEqual(client.close_calls, 0)

    def test_ownership_carrier_transfers_once_and_has_fixed_repr(self):
        from model_council.openai_adapter import _OwnedOpenAIClient

        client = object()
        carrier = _OwnedOpenAIClient(client)
        self.assertEqual(repr(carrier), "_OwnedOpenAIClient(REDACTED)")
        self.assertIs(carrier._take(), client)
        with self.assertRaises(InfrastructureError):
            carrier._take()

    def test_consumed_carrier_reuse_fails_before_sdk_dispatch(self):
        trace = []
        responses = _FakeResponses(trace, result={})
        carrier = _owned(_FakeClient(responses, trace))
        carrier._take()
        with self.assertRaises(InfrastructureError):
            _transport_call(carrier)
        self.assertEqual(responses.calls, [])

    def test_carrier_has_no_destructor_or_automatic_gc_cleanup(self):
        from model_council.openai_adapter import _OwnedOpenAIClient

        trace = []
        client = _FakeClient(types.SimpleNamespace(), trace)
        carrier = _OwnedOpenAIClient(client)
        self.assertNotIn("__del__", _OwnedOpenAIClient.__dict__)
        reference = weakref.ref(client)
        del client
        del carrier
        gc.collect()
        self.assertEqual(trace, [])
        self.assertIsNone(reference())

    def test_two_real_production_constructions_are_distinct_owned_clients(self):
        from model_council.openai_adapter import _OwnedOpenAIClient
        from model_council.openai_response_guard import _build_bounded_openai_http_client

        transports = []

        def builder():
            transport = httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"{}")
            )
            transports.append(transport)
            return _build_bounded_openai_http_client(transport=transport)

        with patch("model_council.openai_adapter._build_bounded_openai_http_client", side_effect=builder):
            first = _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
            second = _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertIs(type(first), _OwnedOpenAIClient)
        self.assertIs(type(second), _OwnedOpenAIClient)
        first_client = first._take()
        second_client = second._take()
        self.assertIsNot(first_client, second_client)
        first_client.close()
        second_client.close()
        self.assertEqual(len(transports), 2)


class _CloseProbe:
    def __init__(self, *, close_error=None):
        self.close_calls = 0
        self.close_error = close_error

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class TestProductionConstruction(unittest.TestCase):
    def test_http_client_construction_failure_makes_zero_sdk_calls(self):
        sdk_calls = []
        with patch(
            "model_council.openai_adapter._build_bounded_openai_http_client",
            side_effect=RuntimeError("builder secret"),
        ), patch("openai.OpenAI", side_effect=lambda **kwargs: sdk_calls.append(kwargs)):
            with self.assertRaises(InfrastructureError) as caught:
                _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertEqual(str(caught.exception), "openai client initialization failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertEqual(sdk_calls, [])

    def test_sdk_construction_failure_closes_http_once_and_sanitizes(self):
        http_client = _CloseProbe()
        with patch(
            "model_council.openai_adapter._build_bounded_openai_http_client",
            return_value=http_client,
        ), patch("openai.OpenAI", side_effect=RuntimeError("sdk secret")):
            with self.assertRaises(InfrastructureError) as caught:
                _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertEqual(http_client.close_calls, 1)
        self.assertEqual(str(caught.exception), "openai client initialization failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_sdk_construction_and_cleanup_failure_keep_primary_fixed(self):
        cleanup = RuntimeError("cleanup secret")
        http_client = _CloseProbe(close_error=cleanup)
        with patch(
            "model_council.openai_adapter._build_bounded_openai_http_client",
            return_value=http_client,
        ), patch("openai.OpenAI", side_effect=RuntimeError("sdk secret")):
            with self.assertRaises(InfrastructureError) as caught:
                _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertEqual(http_client.close_calls, 1)
        self.assertEqual(str(caught.exception), "openai client initialization failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_successful_construction_does_not_close_early_and_passes_literal_retry(self):
        http_client = _CloseProbe()
        sdk_client = _CloseProbe()
        seen = []

        def construct(**kwargs):
            seen.append(kwargs)
            return sdk_client

        with patch(
            "model_council.openai_adapter._build_bounded_openai_http_client",
            return_value=http_client,
        ), patch("openai.OpenAI", side_effect=construct):
            carrier = _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertEqual(http_client.close_calls, 0)
        self.assertEqual(sdk_client.close_calls, 0)
        self.assertEqual(seen[0]["max_retries"], 0)
        self.assertIs(seen[0]["http_client"], http_client)
        self.assertIs(carrier._take(), sdk_client)

    def test_handoff_failure_closes_sdk_once_without_separate_http_close(self):
        http_client = _CloseProbe()
        sdk_client = _CloseProbe()
        with patch(
            "model_council.openai_adapter._build_bounded_openai_http_client",
            return_value=http_client,
        ), patch("openai.OpenAI", return_value=sdk_client), patch(
            "model_council.openai_adapter._OwnedOpenAIClient",
            side_effect=RuntimeError("handoff secret"),
        ):
            with self.assertRaises(InfrastructureError) as caught:
                _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
        self.assertEqual(str(caught.exception), "openai client initialization failed")
        self.assertEqual(sdk_client.close_calls, 1)
        self.assertEqual(http_client.close_calls, 0)
        self.assertIsNone(caught.exception.__context__)

    def test_construction_control_exceptions_are_fresh_after_cleanup(self):
        for original, expected_type, expected_args in (
            (KeyboardInterrupt("secret"), KeyboardInterrupt, ()),
            (SystemExit("secret"), SystemExit, (1,)),
        ):
            with self.subTest(kind=expected_type.__name__):
                http_client = _CloseProbe()
                with patch(
                    "model_council.openai_adapter._build_bounded_openai_http_client",
                    return_value=http_client,
                ), patch("openai.OpenAI", side_effect=original):
                    with self.assertRaises(expected_type) as caught:
                        _default_openai_client_factory(api_key=_FAKE_CREDENTIAL, max_retries=0)
                self.assertEqual(caught.exception.args, expected_args)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(http_client.close_calls, 1)


class _TraceLifecycle:
    def __init__(self, delegate, trace, fail_event=None, failure=None):
        self.delegate = delegate
        self.trace = trace
        self.fail_event = fail_event
        self.failure = failure

    def append(self, event, data=None):
        if event == "sdk_return_observed":
            self.trace.append("sdk return observation")
        elif event == "sdk_exception_observed":
            self.trace.append("sdk exception observation")
        elif event == "sdk_call_boundary":
            self.trace.append("sdk call boundary")
        if event == self.fail_event:
            raise self.failure
        return self.delegate.append(event, data)


class TestTransportCleanupOrdering(unittest.TestCase):
    def _with_writer(self, callback):
        with synthetic_writer(_solver_request()) as writer:
            return callback(writer)

    def test_success_orders_observation_extraction_close_return(self):
        trace = []
        responses = _FakeResponses(
            trace,
            result=_completed_fixture(_solver_envelope(), usage=_usage_fixture()),
        )
        client = _FakeClient(responses, trace)

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace)
            from model_council import openai_adapter as adapter

            original = adapter._extract_openai_sdk_response

            def extract(raw):
                trace.append("extraction")
                return original(raw)

            with patch.object(adapter, "_extract_openai_sdk_response", side_effect=extract):
                result = _transport_call(_owned(client), lifecycle=lifecycle)
            trace.append("transport return")
            return result

        result = self._with_writer(run)
        self.assertIsInstance(result, _OpenAITransportSuccess)
        self.assertEqual(
            trace,
            ["sdk call boundary", "sdk return", "sdk return observation", "extraction", "close", "transport return"],
        )
        self.assertEqual(client.close_calls, 1)

    def test_sdk_failure_orders_observation_normalization_close_return(self):
        trace = []
        responses = _FakeResponses(trace, error=RuntimeError("sdk failure"))
        client = _FakeClient(responses, trace)

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace)
            from model_council import openai_adapter as adapter

            original = adapter._normalize_openai_sdk_exception

            def normalize(raw):
                trace.append("normalization")
                return original(raw)

            with patch.object(adapter, "_normalize_openai_sdk_exception", side_effect=normalize):
                result = _transport_call(_owned(client), lifecycle=lifecycle)
            trace.append("transport return")
            return result

        result = self._with_writer(run)
        self.assertIsInstance(result, _OpenAITransportFailure)
        self.assertEqual(
            trace,
            ["sdk call boundary", "sdk exception", "sdk exception observation", "normalization", "close", "transport return"],
        )

    def test_extraction_rejection_orders_observation_rejection_close_result(self):
        trace = []
        responses = _FakeResponses(trace, result=object())
        client = _FakeClient(responses, trace)

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace)
            from model_council import openai_adapter as adapter

            def reject(raw):
                trace.append("extraction rejection")
                raise ValueError("synthetic extraction rejection")

            with patch.object(adapter, "_extract_openai_sdk_response", side_effect=reject):
                result = _transport_call(_owned(client), lifecycle=lifecycle)
            trace.append("malformed result")
            return result

        result = self._with_writer(run)
        self.assertEqual(result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL)
        self.assertEqual(
            trace,
            ["sdk call boundary", "sdk return", "sdk return observation", "extraction rejection", "close", "malformed result"],
        )

    def test_lifecycle_failure_after_acquisition_closes_without_sdk_call(self):
        trace = []
        responses = _FakeResponses(trace, result={})
        client = _FakeClient(responses, trace)
        failure = ProtocolError("boundary failure")

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace, "sdk_call_boundary", failure)
            with self.assertRaises(ProtocolError) as caught:
                _transport_call(_owned(client), lifecycle=lifecycle)
            self.assertIs(caught.exception, failure)

        self._with_writer(run)
        self.assertEqual(responses.calls, [])
        self.assertEqual(client.close_calls, 1)

    def test_missing_lifecycle_after_acquisition_closes_without_sdk_call(self):
        trace = []
        responses = _FakeResponses(trace, result={})
        client = _FakeClient(responses, trace)
        with self.assertRaises(ProtocolError) as caught:
            _perform_openai_responses_transport(
                _transport_request(),
                RuntimeSecret(_FAKE_CREDENTIAL),
                3.25,
                client_factory=lambda **kwargs: _owned(client),
                lifecycle=None,
            )
        self.assertEqual(
            str(caught.exception),
            "OpenAI SDK dispatch requires attempt lifecycle authorization",
        )
        self.assertEqual(responses.calls, [])
        self.assertEqual(client.close_calls, 1)

    def test_sdk_observation_append_failure_is_preserved_and_closed_once(self):
        trace = []
        responses = _FakeResponses(trace, error=RuntimeError("provider secret"))
        client = _FakeClient(responses, trace, close_error=RuntimeError("cleanup secret"))
        failure = ProtocolError("append failure")

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace, "sdk_exception_observed", failure)
            with self.assertRaises(ProtocolError) as caught:
                _transport_call(_owned(client), lifecycle=lifecycle)
            self.assertIs(caught.exception, failure)

        self._with_writer(run)
        self.assertEqual(client.close_calls, 1)
        self.assertEqual(len(responses.calls), 1)

    def test_pending_success_or_normalized_failure_is_vetoed_by_close_failure(self):
        cases = (
            _FakeResponses([], result=_completed_fixture(_solver_envelope(), usage=_usage_fixture())),
            _FakeResponses([], error=RuntimeError("sdk failure")),
        )
        for responses in cases:
            with self.subTest(error=responses.error is not None):
                client = _FakeClient(responses, close_error=RuntimeError("cleanup secret"))
                with self.assertRaises(InfrastructureError) as caught:
                    _transport_call(_owned(client))
                self.assertEqual(str(caught.exception), "openai client cleanup failed")
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(client.close_calls, 1)
                self.assertEqual(len(responses.calls), 1)

    def test_existing_boundary_exception_survives_cleanup_failure(self):
        trace = []
        responses = _FakeResponses(trace, result={})
        primary = ProtocolError("primary")
        client = _FakeClient(responses, trace, close_error=RuntimeError("cleanup secret"))

        def run(writer):
            lifecycle = _TraceLifecycle(writer, trace, "sdk_call_boundary", primary)
            with self.assertRaises(ProtocolError) as caught:
                _transport_call(_owned(client), lifecycle=lifecycle)
            self.assertIs(caught.exception, primary)

        self._with_writer(run)
        self.assertEqual(client.close_calls, 1)

    def test_cleanup_control_exception_does_not_replace_escaping_primary(self):
        for cleanup_error in (KeyboardInterrupt("secret"), SystemExit("secret")):
            with self.subTest(kind=type(cleanup_error).__name__):
                trace = []
                responses = _FakeResponses(trace, result={})
                primary = ProtocolError("primary")
                client = _FakeClient(responses, trace, close_error=cleanup_error)

                def run(writer):
                    lifecycle = _TraceLifecycle(
                        writer, trace, "sdk_call_boundary", primary
                    )
                    with self.assertRaises(ProtocolError) as caught:
                        _transport_call(_owned(client), lifecycle=lifecycle)
                    self.assertIs(caught.exception, primary)

                self._with_writer(run)
                self.assertEqual(client.close_calls, 1)
                self.assertEqual(responses.calls, [])

    def test_close_control_exceptions_are_fresh_without_primary(self):
        for close_error, expected, args in (
            (KeyboardInterrupt("secret"), KeyboardInterrupt, ()),
            (SystemExit("secret"), SystemExit, (1,)),
        ):
            with self.subTest(kind=expected.__name__):
                responses = _FakeResponses(
                    [], result=_completed_fixture(_solver_envelope(), usage=_usage_fixture())
                )
                client = _FakeClient(responses, close_error=close_error)
                with self.assertRaises(expected) as caught:
                    _transport_call(_owned(client))
                self.assertEqual(caught.exception.args, args)
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(client.close_calls, 1)

    def test_sensitive_cleanup_exception_graph_is_not_reachable(self):
        secret = "cleanup-graph-secret-sentinel"
        cause = RuntimeError(secret)
        cleanup = RuntimeError("outer cleanup")
        cleanup.__cause__ = cause
        responses = _FakeResponses(
            [], result=_completed_fixture(_solver_envelope(), usage=_usage_fixture())
        )
        client = _FakeClient(responses, close_error=cleanup)
        with self.assertRaises(InfrastructureError) as caught:
            _transport_call(_owned(client))
        self.assertEqual(str(caught.exception), "openai client cleanup failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)
        self.assertNotIn(secret, repr(caught.exception))


class TestGuardFailureMapping(unittest.TestCase):
    def test_direct_and_immediate_cause_guard_errors_map_to_malformed(self):
        _, boundary_error, _, _ = _guard_symbols()
        direct = boundary_error()
        caught_immediate = None
        try:
            try:
                raise boundary_error()
            except boundary_error as cause:
                raise RuntimeError("wrapper") from cause
        except RuntimeError as caught:
            caught_immediate = caught
        for value in (direct, caught_immediate):
            with self.subTest(kind=type(value).__name__):
                result = _normalize_openai_sdk_exception(value)
                self.assertEqual(result.kind, ProviderCallKind.PROVIDER_ERROR)
                self.assertEqual(result.category, ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL)
                self.assertIsNone(result.http_status)
                self.assertIsNone(result.request_id)
                self.assertIsNone(result.error_type)
                self.assertIsNone(result.error_code)
                self.assertIsNone(result.param)

    def test_unrelated_and_deeper_cause_guard_errors_are_not_special(self):
        _, boundary_error, _, _ = _guard_symbols()
        unrelated = RuntimeError("openai response body rejected")
        caught_deeper = None
        try:
            try:
                try:
                    raise boundary_error()
                except boundary_error as deepest:
                    raise ValueError("middle") from deepest
            except ValueError as middle:
                raise RuntimeError("outer") from middle
        except RuntimeError as caught:
            caught_deeper = caught
        for value in (unrelated, caught_deeper):
            with self.subTest(value=str(value)):
                result = _normalize_openai_sdk_exception(value)
                self.assertEqual(result.kind, ProviderCallKind.TRANSPORT_ERROR)
                self.assertEqual(result.category, ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE)

    def test_hostile_unrelated_cause_accessor_preserves_fail_closed_mapping(self):
        class HostileCause(RuntimeError):
            def __getattribute__(self, name):
                if name == "__cause__":
                    raise KeyboardInterrupt("provider-controlled cause trap")
                return super().__getattribute__(name)

        result = _normalize_openai_sdk_exception(HostileCause("synthetic"))
        self.assertEqual(result.kind, ProviderCallKind.TRANSPORT_ERROR)
        self.assertEqual(
            result.category,
            ProviderErrorCategory.UNKNOWN_SANITIZED_FAILURE,
        )


_SDK_PROBE = r'''
import importlib.metadata
import json
import types
from unittest.mock import patch

import httpx
import openai

from model_council.live_contract import ProviderCallKind, ProviderErrorCategory
from model_council.openai_adapter import (
    RuntimeSecret,
    _perform_openai_responses_transport,
    build_openai_responses_request,
)
from model_council.openai_response_guard import (
    MAX_OPENAI_HTTP_BODY_BYTES,
    _build_bounded_openai_http_client,
)
from test_attempt_lifecycle_dispatch import synthetic_writer
from test_openai_adapter_translation import _solver_request

assert importlib.metadata.version("openai") == "2.54.0"
assert importlib.metadata.version("httpx") == "0.28.1"
approved = build_openai_responses_request(_solver_request(), {})
report = {"versions": [openai.__version__, httpx.__version__], "cases": {}}


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.requested = 0
        self.close_calls = 0
    def __iter__(self):
        for chunk in self.chunks:
            self.requested += 1
            yield chunk
    def close(self):
        self.close_calls += 1


def success_body():
    envelope = {"text":"ok","artifacts":{"candidate":"ok","evidence":"proof"},"structured":None}
    return json.dumps({
        "id":"resp_offline","object":"response","created_at":0.0,"status":"completed",
        "error":None,"incomplete_details":None,"model":approved["model"],
        "output":[{"id":"msg","type":"message","status":"completed","role":"assistant",
                   "content":[{"type":"output_text","text":json.dumps(envelope,separators=(",",":")),"annotations":[]}]}],
        "usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3},
    }, separators=(",", ":")).encode()


def run_case(name, status, chunks=None, headers=None, raised=None):
    attempts = []
    stream = Stream(chunks or ())
    seen_request = {}
    def handler(request):
        attempts.append(1)
        seen_request["json"] = json.loads(request.content)
        seen_request["timeout"] = dict(request.extensions["timeout"])
        seen_request["accept_encoding"] = request.headers["accept-encoding"]
        if raised is not None:
            raise raised(request=request)
        return httpx.Response(status, headers=headers or {"content-type":"application/json"}, stream=stream)
    transport = httpx.MockTransport(handler)
    def builder():
        return _build_bounded_openai_http_client(transport=transport)
    with patch("model_council.openai_adapter._build_bounded_openai_http_client", side_effect=builder):
        with synthetic_writer(_solver_request()) as writer:
            result = _perform_openai_responses_transport(
                approved, RuntimeSecret("synthetic-not-real"), 3.25, lifecycle=writer
            )
            events = [event["event"] for event in writer.events()]
    item = {
        "attempts": len(attempts), "requested": stream.requested, "stream_close": stream.close_calls,
        "kind": "success" if result.__class__.__name__.endswith("Success") else result.kind.value,
        "category": None if result.__class__.__name__.endswith("Success") else result.category.value,
        "events": events, "request": seen_request,
    }
    if result.__class__.__name__.endswith("Success"):
        item["model"] = result.response["model"]
        item["usage"] = result.response["usage"]
    report["cases"][name] = item


body = success_body()
run_case("success", 200, [body[:17], b"", body[17:]])
for status in (200, 400, 429, 500):
    run_case("overflow_" + str(status), status, [b"x" * MAX_OPENAI_HTTP_BODY_BYTES, b"z", b"sentinel"])
run_case("encoding", 200, [body], {"content-type":"application/json", "content-encoding":"gzip"})
errors = {
    "auth": (401, {"error":{"message":"x","type":"invalid_request_error","code":"invalid_api_key","param":None}}),
    "quota": (429, {"error":{"message":"x","type":"insufficient_quota","code":"insufficient_quota","param":None}}),
    "rate": (429, {"error":{"message":"x","type":"rate_limit_error","code":"rate_limit_exceeded","param":None}}),
    "overload": (500, {"error":{"message":"x","type":"server_error","code":"server_error","param":None}}),
}
for name, (status, payload) in errors.items():
    run_case(name, status, [json.dumps(payload).encode()])
run_case("timeout", 200, raised=lambda *, request: httpx.ReadTimeout("synthetic", request=request))
run_case("connectivity", 200, raised=lambda *, request: httpx.ConnectError("synthetic", request=request))
print(json.dumps(report, sort_keys=True))
'''


class TestInstalledSDKCompatibility(unittest.TestCase):
    def test_guard_and_adapter_imports_remain_lazy(self):
        probe = textwrap.dedent(
            """
            import json, sys
            import model_council.openai_response_guard
            guard = [name for name in sys.modules if name == 'openai' or name.startswith('openai.') or name == 'httpx' or name.startswith('httpx.')]
            import model_council.openai_adapter
            adapter = [name for name in sys.modules if name == 'openai' or name.startswith('openai.') or name == 'httpx' or name.startswith('httpx.')]
            print(json.dumps({'guard': guard, 'adapter': adapter}))
            """
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT / "src")
        completed = subprocess.run(
            [sys.executable, "-B", "-c", probe],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {"guard": [], "adapter": []})

    def test_installed_sdk_streaming_guard_and_compatibility_matrix(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join((str(REPO_ROOT / "src"), str(REPO_ROOT / "tests")))
        completed = subprocess.run(
            [sys.executable, "-B", "-c", _SDK_PROBE],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=45,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["versions"], ["2.54.0", "0.28.1"])
        success = report["cases"]["success"]
        self.assertEqual(success["attempts"], 1)
        self.assertEqual(success["kind"], "success")
        self.assertEqual(success["model"], _transport_request()["model"])
        self.assertEqual(success["usage"]["total_tokens"], 3)
        self.assertEqual(success["request"]["json"], _transport_request())
        self.assertEqual(success["request"]["accept_encoding"], "identity")
        self.assertEqual(success["request"]["timeout"], {"connect": 3.25, "read": 3.25, "write": 3.25, "pool": 3.25})
        self.assertFalse(success["request"]["json"]["stream"])
        self.assertEqual(success["stream_close"], 1)
        for status in (200, 400, 429, 500):
            item = report["cases"]["overflow_" + str(status)]
            self.assertEqual(item["attempts"], 1)
            self.assertEqual(item["requested"], 2)
            self.assertEqual(item["stream_close"], 1)
            self.assertEqual(item["kind"], ProviderCallKind.PROVIDER_ERROR.value)
            self.assertEqual(item["category"], ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL.value)
        encoding = report["cases"]["encoding"]
        self.assertEqual(encoding["attempts"], 1)
        self.assertEqual(encoding["requested"], 0)
        self.assertEqual(encoding["category"], ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL.value)
        categories = {
            "auth": ProviderErrorCategory.AUTHENTICATION_CONFIGURATION.value,
            "quota": ProviderErrorCategory.QUOTA_EXHAUSTED.value,
            "rate": ProviderErrorCategory.RATE_LIMIT.value,
            "overload": ProviderErrorCategory.PROVIDER_OVERLOAD_INTERNAL.value,
            "timeout": ProviderErrorCategory.TRANSPORT_PROVIDER_TIMEOUT.value,
            "connectivity": ProviderErrorCategory.TRANSPORT_CONNECTIVITY.value,
        }
        for name, category in categories.items():
            self.assertEqual(report["cases"][name]["attempts"], 1)
            self.assertEqual(report["cases"][name]["category"], category)


_WORKER_WRAPPER = r'''
import json
import os
import sys
import time
from pathlib import Path

import httpx

sys.dont_write_bytecode = True
here = Path(__file__).resolve()
config = json.loads(here.with_name(here.name + ".json").read_text())
markers = here.with_name(here.name + ".markers.jsonl")


def mark(value):
    with markers.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


class ResponseStream(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
    def __iter__(self):
        for index, chunk in enumerate(self.chunks):
            mark({"stream_chunk": index})
            yield chunk
    def close(self):
        mark({"response_stream_close": True})


class ControlledTransport(httpx.BaseTransport):
    def handle_request(self, request):
        mark({"http_attempt": 1, "accept_encoding": request.headers.get("accept-encoding")})
        mode = config["mode"]
        request_json = json.loads(request.content)
        envelope = {"text":"ok","artifacts":{"candidate":"ok","evidence":"proof"},"structured":None}
        payload = {
            "id":"resp_worker","object":"response","created_at":0.0,"status":"completed",
            "error":None,"incomplete_details":None,"model":request_json["model"],
            "output":[{"id":"msg","type":"message","status":"completed","role":"assistant",
                       "content":[{"type":"output_text","text":json.dumps(envelope,separators=(",",":")),"annotations":[]}]}],
            "usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3},
        }
        headers = {"content-type":"application/json"}
        status = 200
        chunks = [json.dumps(payload, separators=(",", ":")).encode()]
        if mode == "overflow":
            chunks = [b"x" * 8000000, b"z", b"sentinel"]
        elif mode == "encoding":
            headers["content-encoding"] = "gzip"
        elif mode == "sdk_exception":
            status = 500
            chunks = [json.dumps({"error":{"message":"synthetic","type":"server_error","code":"server_error"}}).encode()]
        return httpx.Response(status, headers=headers, stream=ResponseStream(chunks))
    def close(self):
        mark({"owned_client_close_entered": True})
        mode = config["close"]
        if mode == "failure":
            raise RuntimeError("cleanup-secret-sentinel")
        if mode == "block":
            while True:
                time.sleep(0.05)
        mark({"owned_client_close_returned": True})


import model_council.openai_adapter as adapter
from model_council.openai_response_guard import _build_bounded_openai_http_client

adapter._build_bounded_openai_http_client = lambda: _build_bounded_openai_http_client(transport=ControlledTransport())
from model_council.worker import main
raise SystemExit(main())
'''


def _install_worker_wrapper(root, config):
    executable = Path(root) / "f6b-worker-python"
    executable.write_text(f"#!{sys.executable}\n" + _WORKER_WRAPPER, encoding="utf-8")
    executable.chmod(0o755)
    executable.with_name(executable.name + ".json").write_text(json.dumps(config), encoding="utf-8")
    return executable, executable.with_name(executable.name + ".markers.jsonl")


def _read_markers(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestRealWorkerOfflineIntegration(unittest.TestCase):
    def _run(self, mode, close, *, timeout=2.0):
        root_context = TemporaryDirectory()
        self.addCleanup(root_context.cleanup)
        root = Path(root_context.name)
        executable, markers = _install_worker_wrapper(root, {"mode": mode, "close": close})
        runs = root / "runs"
        adapter = SubprocessAdapter(
            FAKE_IDENTITY,
            kind="openai_responses",
            python_executable=str(executable),
        )
        runner = __import__("model_council.runner", fromlist=["ExperimentRunner"]).ExperimentRunner(
            adapter, ExternalEvaluator(EvaluationConfig()), runs_root=runs
        )
        run_id = "f6b-" + mode.replace("_", "-") + "-" + close
        with _isolated_environ(**{_HOST_KEY: _FAKE_CREDENTIAL}):
            result = runner.execute(
                make_spec(run_id, "A", max_stage_retries=0, stage_timeout_seconds=timeout),
                make_task(),
            )
        journal_path = runs / run_id / "attempt-lifecycle/solver/attempt-0001/journal.jsonl"
        from model_council.attempt_lifecycle import AttemptJournal

        snapshot = AttemptJournal(journal_path).inspect(require_closed=True)
        report = ArtifactStore.verify_terminal_run(runs, run_id)
        return result, snapshot, report, _read_markers(markers), runs / run_id

    def test_body_overflow_and_encoding_publish_malformed_only_after_close(self):
        for mode in ("overflow", "encoding"):
            with self.subTest(mode=mode):
                result, snapshot, report, markers, run = self._run(mode, "success")
                self.assertEqual(result.status, "infrastructure_failure")
                self.assertEqual(report["terminal_status"], "infrastructure_failure")
                self.assertTrue(report["terminal_verified"])
                self.assertEqual(
                    [event["event"] for event in snapshot["events"]],
                    ["attempt_prepared", "dispatch_permitted", "sdk_call_boundary", "sdk_exception_observed", "outcome_observed"],
                )
                self.assertEqual(snapshot["closure"]["reason"], "returned")
                self.assertEqual(snapshot["outcome"]["kind"], ProviderCallKind.PROVIDER_ERROR.value)
                self.assertEqual(
                    snapshot["outcome"]["error"]["category"],
                    ProviderErrorCategory.MALFORMED_PROVIDER_PROTOCOL.value,
                )
                self.assertTrue(any("owned_client_close_returned" in item for item in markers))
                self.assertEqual(sum("http_attempt" in item for item in markers), 1)
                if mode == "overflow":
                    self.assertEqual(
                        [item["stream_chunk"] for item in markers if "stream_chunk" in item],
                        [0, 1],
                    )
                persisted = b"".join(
                    path.read_bytes()
                    for path in run.rglob("*")
                    if path.is_file()
                )
                self.assertNotIn(b"sentinel", persisted)
                self.assertNotIn(_FAKE_CREDENTIAL.encode(), persisted)
                self.assertFalse((run / "seals/solver.json").exists())
                self.assertFalse((run / "evaluation.json").exists())
                self.assertIsNone(result.final_candidate_ref)

    def test_close_failure_after_sdk_return_or_exception_vetoes_outcome(self):
        expected_observation = {
            "success": "sdk_return_observed",
            "sdk_exception": "sdk_exception_observed",
        }
        for mode in ("success", "sdk_exception"):
            with self.subTest(mode=mode):
                result, snapshot, report, markers, run = self._run(mode, "failure")
                self.assertEqual(result.status, "infrastructure_failure")
                self.assertEqual(report["terminal_status"], "infrastructure_failure")
                self.assertEqual(snapshot["closure"]["reason"], "returned")
                self.assertIsNone(snapshot["outcome"])
                self.assertEqual(snapshot["retry_safety"], "indeterminate")
                self.assertEqual(snapshot["events"][-1]["event"], expected_observation[mode])
                self.assertEqual(sum("owned_client_close_entered" in item for item in markers), 1)
                self.assertFalse(any("owned_client_close_returned" in item for item in markers))
                self.assertFalse((run / "seals/solver.json").exists())
                self.assertFalse((run / "evaluation.json").exists())

    def test_blocking_close_is_terminated_by_existing_parent_deadline(self):
        result, snapshot, report, markers, run = self._run("success", "block", timeout=2.0)
        self.assertIn(result.status, {"infrastructure_failure", "retry_exhausted"})
        self.assertEqual(report["terminal_status"], result.status)
        self.assertTrue(report["terminal_verified"])
        self.assertEqual(snapshot["events"][-1]["event"], "sdk_return_observed")
        self.assertIsNone(snapshot["outcome"])
        self.assertEqual(snapshot["retry_safety"], "indeterminate")
        self.assertEqual(sum("owned_client_close_entered" in item for item in markers), 1)
        self.assertFalse(any("owned_client_close_returned" in item for item in markers))
        self.assertFalse((run / "seals/solver.json").exists())
        self.assertFalse((run / "evaluation.json").exists())


if __name__ == "__main__":
    unittest.main()
