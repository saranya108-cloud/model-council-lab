"""Security primitives: identifier policy, path containment, hashing, freezing."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import GovernanceViolation

SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


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
