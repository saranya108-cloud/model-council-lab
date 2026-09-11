"""Pre-materialization byte boundary for synchronous OpenAI HTTP responses.

This module intentionally imports only the Python standard library.  HTTPX and
the OpenAI SDK remain lazy dependencies of the client builder.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator


MAX_OPENAI_HTTP_BODY_BYTES = 8_000_000
_BOUNDARY_MESSAGE = "openai response body rejected"


class _OpenAIResponseBoundaryError(Exception):
    def __init__(self) -> None:
        super().__init__(_BOUNDARY_MESSAGE)


def _bounded_body_chunks(source: Iterable[bytes]) -> Iterator[bytes]:
    """Yield complete raw chunks while the aggregate byte count stays bounded."""
    remaining = MAX_OPENAI_HTTP_BODY_BYTES
    for chunk in source:
        if type(chunk) is not bytes or len(chunk) > remaining:
            raise _OpenAIResponseBoundaryError()
        remaining -= len(chunk)
        yield chunk


def _build_bounded_openai_http_client(*, transport=None):
    """Build the production HTTP client with an early synchronous body guard.

    ``transport`` is a trusted offline-test seam.  Production callers do not
    expose or populate it.
    """
    import httpx
    from openai import DefaultHttpxClient

    class _BoundedSyncByteStream(httpx.SyncByteStream):
        __slots__ = ("_closed", "_source")

        def __init__(self, source) -> None:
            self._source = source
            self._closed = False

        def __iter__(self):
            yield from _bounded_body_chunks(self._source)

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            source = self._source
            self._source = None
            source.close()

    def enforce_response_boundary(response) -> None:
        encodings = response.headers.get_list("content-encoding")
        if encodings:
            if (
                len(encodings) != 1
                or "," in encodings[0]
                or encodings[0].strip().casefold() != "identity"
            ):
                raise _OpenAIResponseBoundaryError()

        # ``content=`` and ``json=`` test responses may already have been read
        # before MockTransport returns them.  Length checking detects overflow
        # in that fixture shape, but cannot demonstrate early interception.
        if hasattr(response, "_content"):
            if len(response.content) > MAX_OPENAI_HTTP_BODY_BYTES:
                raise _OpenAIResponseBoundaryError()
            return

        response.stream = _BoundedSyncByteStream(response.stream)

    options = {
        "headers": {"Accept-Encoding": "identity"},
        "event_hooks": {"response": [enforce_response_boundary]},
    }
    if transport is not None:
        options["transport"] = transport
    return DefaultHttpxClient(**options)
