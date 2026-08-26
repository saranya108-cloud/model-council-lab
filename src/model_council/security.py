"""Security primitives: identifier policy, path containment, hashing, freezing."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import GovernanceViolation

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Provider treatment configuration is opaque bounded JSON, not credentials
# and not an unbounded options bag. Limits are structural only.
MAX_PROVIDER_TREATMENT_CONFIG_BYTES = 16_384
MAX_PROVIDER_TREATMENT_CONFIG_DEPTH = 8
MAX_PROVIDER_TREATMENT_CONFIG_ITEMS = 64
MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES = 4_096

_SECRET_LIKE_KEY_EXACT = frozenset(
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
        "credential",
        "credentials",
        "bearer",
        "private_key",
        "auth_token",
        "api_token",
        "oauth_token",
        "id_token",
        "session_token",
        "request_headers",
        "default_headers",
        "http_headers",
        "token",
    }
)
_SECRET_LIKE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "password",
    "credential",
    "private_key",
    "access_token",
    "refresh_token",
    "secret",
    "bearer",
)


def safe_identifier(value: Any, label: str = "identifier") -> str:
    """Restrictive identifier grammar; rejects traversal, separators, dot-names."""
    if not isinstance(value, str) or not value:
        raise GovernanceViolation(f"{label} must be a non-empty string")
    if value in (".", ".."):
        raise GovernanceViolation(f"{label} {value!r} is not a safe identifier")
    if not SAFE_IDENTIFIER_RE.match(value):
        raise GovernanceViolation(
            f"{label} {value!r} violates the safe-identifier policy "
            f"([A-Za-z0-9][A-Za-z0-9._-]*, no path separators or traversal)"
        )
    return value


def contained_path(base: Path, candidate: Path) -> Path:
    """Resolve candidate and prove it stays inside base; else raise."""
    base_resolved = Path(base).resolve()
    candidate_resolved = Path(candidate).resolve()
    if not candidate_resolved.is_relative_to(base_resolved):
        raise GovernanceViolation(
            f"path {candidate!r} escapes permitted namespace {base_resolved}"
        )
    return candidate_resolved


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def digest_json(obj: Any) -> str:
    return sha256_bytes(
        json.dumps(_plain(obj), sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def deep_freeze(obj: Any) -> Any:
    """Recursively freeze mappings, lists, tuples, and sets.

    After freezing, no mutation of the caller-owned input structure can affect
    the frozen copy: every container level is copied into an immutable form.
    """
    if isinstance(obj, dict):
        return MappingProxyType({k: deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return tuple(deep_freeze(v) for v in obj)
    if isinstance(obj, tuple):
        return tuple(deep_freeze(v) for v in obj)
    if isinstance(obj, set):
        return frozenset(deep_freeze(v) for v in obj)
    if isinstance(obj, frozenset):
        return frozenset(deep_freeze(v) for v in obj)
    return obj


def _plain(obj: Any) -> Any:
    if isinstance(obj, MappingProxyType):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        values = [_plain(v) for v in obj]
        # Python cannot order unlike native types (for example ``1`` and
        # ``"one"``).  Canonicalization must not depend on that comparison;
        # use a type-tagged JSON representation as the deterministic key.
        return sorted(values, key=_stable_sort_key)
    return obj


def _stable_sort_key(value: Any) -> tuple[str, str]:
    """Return a deterministic, type-stable key for canonical set members."""
    return (
        type(value).__name__,
        json.dumps(value, sort_keys=True, separators=(",", ":")),
    )


def canonical_json(obj: Any) -> str:
    return json.dumps(_plain(obj), sort_keys=True, separators=(",", ":"))


def normalize_provider_treatment_config(
    value: Any, *, label: str = "provider_treatment_config"
) -> dict:
    """Copy opaque JSON-compatible treatment config; reject secrets and junk.

    Neutral code does not interpret provider-specific key meanings. This only
    enforces generic JSON types, nesting/size bounds, and secret-like key names.
    """
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise GovernanceViolation(f"{label} must be a JSON object")
    normalized = _normalize_json_object(value, label, depth=0)
    encoded = canonical_json(normalized).encode("utf-8")
    if len(encoded) > MAX_PROVIDER_TREATMENT_CONFIG_BYTES:
        raise GovernanceViolation(
            f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_BYTES}-byte bound"
        )
    return normalized


def _classify_secret_like_key(key: str) -> str:
    """Normalize separators for secret classification only; do not persist this form."""
    collapsed = re.sub(r"[-.\s]+", "_", key.strip().lower())
    return re.sub(r"_+", "_", collapsed).strip("_")


def _reject_secret_like_key(key: Any, label: str) -> str:
    if type(key) is not str or not key:
        raise GovernanceViolation(f"{label} keys must be non-empty strings")
    if key.lower().startswith("x-"):
        raise GovernanceViolation(f"{label} contains forbidden field {key!r}")
    normalized = _classify_secret_like_key(key)
    if normalized in _SECRET_LIKE_KEY_EXACT:
        raise GovernanceViolation(f"{label} contains forbidden field {key!r}")
    for fragment in _SECRET_LIKE_KEY_FRAGMENTS:
        if fragment in normalized:
            raise GovernanceViolation(f"{label} contains forbidden field {key!r}")
    return key


def _normalize_json_object(value: Mapping, label: str, *, depth: int) -> dict:
    if depth > MAX_PROVIDER_TREATMENT_CONFIG_DEPTH:
        raise GovernanceViolation(
            f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_DEPTH}-level nesting bound"
        )
    data = dict(value)
    if len(data) > MAX_PROVIDER_TREATMENT_CONFIG_ITEMS:
        raise GovernanceViolation(
            f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_ITEMS}-item bound"
        )
    normalized = {}
    for key, item in data.items():
        _reject_secret_like_key(key, label)
        normalized[key] = _normalize_json_value(item, f"{label}.{key}", depth=depth + 1)
    return normalized


def _normalize_json_value(value: Any, label: str, *, depth: int) -> Any:
    if depth > MAX_PROVIDER_TREATMENT_CONFIG_DEPTH:
        raise GovernanceViolation(
            f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_DEPTH}-level nesting bound"
        )
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise GovernanceViolation(f"{label} must be a finite JSON number")
        return value
    if type(value) is str:
        if len(value.encode("utf-8")) > MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES:
            raise GovernanceViolation(
                f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES}-byte string bound"
            )
        return value
    if type(value) is list:
        if len(value) > MAX_PROVIDER_TREATMENT_CONFIG_ITEMS:
            raise GovernanceViolation(
                f"{label} exceeds the {MAX_PROVIDER_TREATMENT_CONFIG_ITEMS}-item bound"
            )
        return [
            _normalize_json_value(item, f"{label}[{index}]", depth=depth + 1)
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        return _normalize_json_object(value, label, depth=depth)
    raise GovernanceViolation(f"{label} is not a JSON value ({type(value).__name__})")


def source_revision(repo_root: Path | None = None) -> dict:
    """Best-effort read-only Git provenance. Never hashes repository contents.

    Returns {"source_revision": <HEAD or None>, "working_tree_dirty": bool|None,
    "git_available": bool}. This metadata records WHICH source state produced a
    run; the treatment hash proves the declared configuration only — it does
    not cryptographically cover the source tree.
    """
    import subprocess

    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    info = {
        "source_revision": None,
        "working_tree_dirty": None,
        "git_available": False,
        "uncommitted_implementation": None,
    }
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10
        )
        if head.returncode != 0:
            return info
        info["git_available"] = True
        info["source_revision"] = head.stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=10
        )
        dirty = bool(status.stdout.strip())
        info["working_tree_dirty"] = dirty
        info["uncommitted_implementation"] = dirty
        return info
    except (OSError, subprocess.SubprocessError):
        return info
