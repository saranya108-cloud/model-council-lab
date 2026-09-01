"""Bounded, credential-safe error summaries for worker/parent persistence.

Unexpected child failures must never copy traceback, exception repr, headers,
credentials, environment, or provider request bodies into durable run records.
"""

from __future__ import annotations

from .security import sha256_bytes

MAX_SANITIZED_ERROR_CHARS = 256
WORKER_SANITIZED_FAILURE = "worker aborted with a sanitized infrastructure failure"
WORKER_CRASH_SUMMARY = "worker process crashed"
INTERRUPTED_INFRASTRUCTURE_MESSAGE = "run aborted by a sanitized infrastructure interrupt"
INTERRUPTED_EVALUATION_MESSAGE = "evaluation aborted by a sanitized infrastructure interrupt"

_SECRET_MARKERS = (
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "bearer ",
    "sk-",
    "cookie",
    "set-cookie",
    "secret",
    "password",
    "credential",
    "traceback",
    "stacktrace",
    "stack_trace",
    "x-api-key",
    "access_token",
    "refresh_token",
    "private_key",
    "request_id",
    "x-request-id",
)


def contains_secret_marker(text: str | None) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _SECRET_MARKERS)


def sanitize_error_text(text: str | None, *, fallback: str) -> str:
    """Return a bounded printable summary, or fallback if it looks unsafe."""
    if type(text) is not str or not text.strip():
        return fallback
    if contains_secret_marker(text):
        return fallback
    cleaned = "".join(ch if ch.isprintable() or ch in "\n\t" else "?" for ch in text)
    cleaned = cleaned.strip()
    if not cleaned:
        return fallback
    if len(cleaned) > MAX_SANITIZED_ERROR_CHARS:
        cleaned = cleaned[:MAX_SANITIZED_ERROR_CHARS]
    return cleaned


def exception_type_name(exc: BaseException) -> str:
    return type(exc).__name__


def sanitize_exception(exc: BaseException, *, fallback: str) -> str:
    """Summarize an exception without repr() or nested cause/object dumps."""
    name = exception_type_name(exc)
    message = sanitize_error_text(str(exc), fallback="")
    if not message:
        return name
    summary = f"{name}: {message}"
    if len(summary) > MAX_SANITIZED_ERROR_CHARS:
        return summary[:MAX_SANITIZED_ERROR_CHARS]
    return summary


def suppressed_stream_meta(text: str | None) -> dict[str, object]:
    """Record length/digest of a suppressed diagnostic stream, never its body."""
    data = b"" if text is None else str(text).encode("utf-8", "replace")
    return {
        "bytes": len(data),
        "sha256": sha256_bytes(data) if data else None,
        "suppressed": True,
    }
