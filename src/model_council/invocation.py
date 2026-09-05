"""Canonical invocation evidence: untrusted, runner-owned, not stage artifacts.

Compatibility: pre-live fake adapters do not return ProviderCallOutcome.
Records still persist runner evidence plus a narrow adapter-evidence envelope
with `compatibility: pre_live_fake_adapter`. Live outcomes, when present, are
stored via their already-sanitized contract dict.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .live_contract import (
    LIVE_CONTRACT_VERSION,
    MAX_RAW_EVIDENCE_BYTES,
    NeutralError,
    ProviderCallOutcome,
    build_live_invocation_request,
)
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    SUPPORTED_EXECUTION_PROFILES,
)
from .security import canonical_json, digest_json, sha256_bytes
from .types import AdapterIdentity, GovernanceViolation, IntegrityViolation, ResourceLimits

MAX_RAW_EVIDENCE_CHARS = MAX_RAW_EVIDENCE_BYTES  # historical alias; ceiling is bytes
INVOCATION_ROOT = "invocations"
INVOCATION_FILENAME = "invocation.json"
RAW_OUTPUT_FILENAME = "raw-output.txt"
TRUNCATION_HEADER_PREFIX = "[m1-raw-evidence: truncated"
MINIMAL_TRUNCATION_MARKER = "[truncated]\n"
_FULL_TRUNCATION_HEADER_RE = re.compile(
    rb"^\[m1-raw-evidence: truncated observed_bytes=([0-9]+)\]\n"
)
_MINIMAL_TRUNCATION_BYTES = MINIMAL_TRUNCATION_MARKER.encode("ascii")

KIND_MODEL_ARTIFACT = "model_artifact"
KIND_INVOCATION_METADATA = "invocation_metadata"
KIND_UNTRUSTED_RAW_OUTPUT = "untrusted_raw_output"
MANIFEST_KINDS = frozenset(
    {KIND_MODEL_ARTIFACT, KIND_INVOCATION_METADATA, KIND_UNTRUSTED_RAW_OUTPUT}
)

RETRY_DECISIONS = frozenset({"promote", "retry", "stop"})
RETRY_RATIONALES = frozenset(
    {
        "stage_succeeded",
        "retry_candidate_remaining",
        "retry_budget_exhausted",
        "provider_nonretryable",
        "failed_budget",
        "failed_contract",
        "identity_mismatch",
        "identity_policy_rejected",
        "stage_timeout",
        "model_failure",
        "infrastructure_failure",
    }
)
VERDICTS = frozenset({"not_evaluated", "passed", "failed"})
FAILURE_CLASSES = frozenset(
    {
        None,
        "timeout",
        "model",
        "provider",
        "budget",
        "contract",
        "governance",
        "infrastructure",
    }
)

_RECORD_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "condition",
        "role",
        "attempt",
        "requested_identity",
        "configured_identity",
        "stage_timeout_seconds",
        "attempt_timeout_seconds",
        "input_content_digest",
        "treatment_digest",
        "usage_estimated",
        "cumulative_tokens_in",
        "projected_tokens_in",
        "consumed_tokens_in",
        "invocation_began",
        "harness_observed_latency_seconds",
        "retry_decision",
        "retry_rationale",
        "contract_verdict",
        "identity_verdict",
        "failure_class",
        "adapter_evidence",
        "raw_output",
        "promoted_artifact_refs",
    }
)

INVOCATION_SCHEMA = "m1-invocation-record-v2"

_FORBIDDEN_KEY_MARKERS = (
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "secret",
    "password",
    "credential",
    "traceback",
    "header",
    "bearer",
    "private_key",
    "access_token",
)


def attempt_dirname(attempt: int) -> str:
    if type(attempt) is not int or isinstance(attempt, bool) or attempt < 1:
        raise GovernanceViolation(f"attempt must be a positive integer, got {attempt!r}")
    return f"attempt-{attempt:04d}"


def invocation_ref(role: str, attempt: int, filename: str) -> str:
    return f"{INVOCATION_ROOT}/{role}/{attempt_dirname(attempt)}/{filename}"


def _truncate_utf8_prefix(text: str, max_bytes: int) -> tuple[str, int, bool]:
    """Return (prefix, observed_utf8_bytes, truncated) without splitting a code point."""
    data = text.encode("utf-8")
    observed = len(data)
    if observed <= max_bytes:
        return text, observed, False
    clipped = data[:max_bytes]
    while clipped:
        try:
            return clipped.decode("utf-8"), observed, True
        except UnicodeDecodeError:
            clipped = clipped[:-1]
    return "", observed, True


def _full_truncation_header(observed: int) -> str:
    return f"{TRUNCATION_HEADER_PREFIX} observed_bytes={observed}]\n"


def _fit_truncated_raw(text: str, observed: int, limit: int) -> tuple[str, str]:
    """Return (stored_text, label) whose UTF-8 size is <= limit."""
    header = _full_truncation_header(observed)
    header_bytes = len(header.encode("utf-8"))
    if header_bytes <= limit:
        payload, _, _ = _truncate_utf8_prefix(text, limit - header_bytes)
        stored = header + payload
        return stored, header.strip()
    marker = MINIMAL_TRUNCATION_MARKER
    marker_bytes = len(marker.encode("utf-8"))
    if marker_bytes <= limit:
        payload, _, _ = _truncate_utf8_prefix(text, limit - marker_bytes)
        stored = marker + payload
        return stored, marker.strip()
    clipped = marker.encode("ascii")[:limit].decode("ascii")
    return clipped, clipped.strip() or "truncated"


def classify_stored_raw_evidence(data: bytes) -> dict[str, Any]:
    """Classify a persisted raw-evidence file using the writer’s canonical forms.

    Forms:
      * ``full`` — ``[m1-raw-evidence: truncated observed_bytes=N]\\n`` plus payload
      * ``minimal`` — ``[truncated]\\n`` plus optional payload
      * ``clipped_minimal`` — a non-empty proper prefix of ``[truncated]\\n``
        used when N is smaller than the minimal marker
      * ``untruncated`` — complete payload with no truncation marker
    """
    if type(data) is not bytes:
        raise IntegrityViolation("raw evidence must be verified as bytes")
    stored_bytes = len(data)
    match = _FULL_TRUNCATION_HEADER_RE.match(data)
    if match:
        return {
            "form": "full",
            "truncated": True,
            "observed_bytes": int(match.group(1)),
            "stored_bytes": stored_bytes,
            "label": data[: match.end()].decode("ascii").strip(),
        }
    if data.startswith(_MINIMAL_TRUNCATION_BYTES):
        return {
            "form": "minimal",
            "truncated": True,
            "observed_bytes": None,
            "stored_bytes": stored_bytes,
            "label": MINIMAL_TRUNCATION_MARKER.strip(),
        }
    if (
        stored_bytes > 0
        and stored_bytes < len(_MINIMAL_TRUNCATION_BYTES)
        and data == _MINIMAL_TRUNCATION_BYTES[:stored_bytes]
    ):
        return {
            "form": "clipped_minimal",
            "truncated": True,
            "observed_bytes": None,
            "stored_bytes": stored_bytes,
            "label": data.decode("ascii").strip() or "truncated",
        }
    return {
        "form": "untruncated",
        "truncated": False,
        "observed_bytes": None,
        "stored_bytes": stored_bytes,
        "label": None,
    }


def verify_raw_evidence_truncation(
    data: bytes,
    *,
    truncated: Any,
    stored_bytes: Any,
    observed_bytes: Any,
) -> None:
    """Classify stored bytes first, then require metadata to match.

    The truncated boolean does not choose which checks run. Canonical
    truncated forms cannot be relabeled complete, and non-canonical bytes
    cannot be labeled truncated.
    """
    if truncated is None or type(truncated) is not bool:
        raise IntegrityViolation("raw evidence truncation metadata is missing or invalid")
    if type(stored_bytes) is not int or isinstance(stored_bytes, bool) or stored_bytes < 0:
        raise IntegrityViolation("raw evidence stored_bytes metadata is missing or invalid")
    if stored_bytes != len(data):
        raise IntegrityViolation("raw evidence stored_bytes does not match the persisted file")
    view = classify_stored_raw_evidence(data)
    if view["truncated"] is not truncated:
        raise IntegrityViolation(
            "raw evidence truncation metadata does not match the stored representation"
        )
    if truncated:
        if type(observed_bytes) is not int or isinstance(observed_bytes, bool) or observed_bytes < stored_bytes:
            raise IntegrityViolation("truncated raw evidence observed_bytes is missing or incoherent")
        if view["form"] == "full" and view["observed_bytes"] != observed_bytes:
            raise IntegrityViolation("truncated raw evidence observed_bytes does not match the marker")
    else:
        if type(observed_bytes) is not int or isinstance(observed_bytes, bool):
            raise IntegrityViolation("complete raw evidence is missing observed_bytes")
        if observed_bytes != stored_bytes:
            raise IntegrityViolation("complete raw evidence observed_bytes must equal stored_bytes")


def bound_raw_evidence(text: str | None, *, limit: int = MAX_RAW_EVIDENCE_BYTES) -> dict[str, Any]:
    """Return stored text plus byte metadata. Never claims a digest of unread bytes.

    `limit` is the complete persisted-file ceiling, including any truncation
    marker. The stored file/string is always <= N UTF-8 bytes.
    """
    if text is None:
        return {
            "present": False,
            "truncated": False,
            "stored_text": None,
            "stored_bytes": 0,
            "observed_bytes": None,
            "sha256_complete": None,
            "label": None,
        }
    if type(text) is not str:
        raise GovernanceViolation("raw evidence text must be a string or None")
    if limit <= 0:
        raise GovernanceViolation("raw evidence limit must be positive")
    payload, observed, truncated = _truncate_utf8_prefix(text, limit)
    complete_digest = sha256_bytes(text.encode("utf-8"))
    if truncated:
        stored_text, label = _fit_truncated_raw(text, observed, limit)
    else:
        stored_text = payload
        label = None
    stored_bytes = len(stored_text.encode("utf-8"))
    if stored_bytes > limit:
        raise GovernanceViolation("raw evidence retained-byte ceiling exceeded")
    return {
        "present": True,
        "truncated": truncated,
        "stored_text": stored_text,
        "stored_bytes": stored_bytes,
        "observed_bytes": observed,
        "sha256_complete": complete_digest,
        "label": label,
    }


def raw_text_from_untrusted_response(response: Mapping[str, Any] | None) -> str | None:
    """Compatibility: fake adapters return a response dict, not ProviderCallOutcome.

    Only model-produced fields are captured. Identity, usage, and protocol
    metadata belong in the invocation record, not this untrusted blob.
    """
    if response is None:
        return None
    if not isinstance(response, Mapping):
        raise GovernanceViolation("untrusted response must be a mapping or None")
    payload = {
        key: response[key]
        for key in ("text", "artifacts", "structured")
        if key in response
    }
    if not payload:
        return None
    return canonical_json(payload)


def treatment_digest_for_attempt(
    *,
    condition: str,
    role: str,
    role_instruction: str,
    stage_inputs: Mapping[str, str],
    requested_identity: AdapterIdentity,
    configured_identity: AdapterIdentity,
    seed: int,
    resource_limits: ResourceLimits,
    execution_profile: str,
    adapter_kind: str,
    adapter_config_digest: str,
    live_contract_version: str = LIVE_CONTRACT_VERSION,
    harness_protocol_version: str = HARNESS_PROTOCOL_VERSION,
    provider_treatment_config: Mapping[str, Any] | None = None,
    provider_identity_policy: Mapping[str, Any] | None = None,
) -> tuple[str, str]:
    """Return (input_content_digest, treatment_digest).

    Remaining timeout, attempt number, timestamps, and retry decisions are not
    treatment. Declared ResourceLimits, including stage timeout and retry
    allowance, are treatment.
    """
    request = build_live_invocation_request(
        condition=condition,
        role=role,
        role_instruction=role_instruction,
        stage_inputs=stage_inputs,
        requested_identity=requested_identity,
        configured_identity=configured_identity,
        seed=seed,
        max_output_tokens=resource_limits.max_output_tokens_per_stage,
        max_tool_calls=resource_limits.max_tool_calls_per_stage,
        attempt_timeout_seconds=float(resource_limits.stage_timeout_seconds),
    )
    payload = {
        "harness_protocol_version": harness_protocol_version,
        "live_contract_version": live_contract_version,
        "execution_profile": execution_profile,
        "condition": condition,
        "role": role,
        "role_instruction": role_instruction,
        "input_content_digest": request.input_content_digest,
        "output_contract": dict(request.output_contract),
        "requested_identity": requested_identity.to_dict(),
        "configured_identity": configured_identity.to_dict(),
        "resource_limits": resource_limits.to_dict(),
        "seed": seed,
        "adapter_kind": adapter_kind,
        "adapter_config_digest": adapter_config_digest,
        "provider_treatment_config": dict(provider_treatment_config or {}),
    }
    if provider_identity_policy is not None:
        payload["provider_identity_policy"] = dict(provider_identity_policy)
    return request.input_content_digest, digest_json(payload)


def build_invocation_record(
    *,
    run_id: str,
    condition: str,
    role: str,
    attempt: int,
    requested_identity: AdapterIdentity,
    configured_identity: AdapterIdentity,
    stage_timeout_seconds: float,
    attempt_timeout_seconds: float,
    input_content_digest: str,
    treatment_digest: str,
    tokens_in: int,
    tokens_out: int,
    cumulative_tokens_in: int,
    retry_decision: str,
    retry_rationale: str,
    contract_verdict: str,
    identity_verdict: str,
    failure_class: str | None,
    promoted_artifact_refs: tuple[str, ...] | list[str] = (),
    raw_output_meta: Mapping[str, Any] | None = None,
    identity_used: Mapping[str, Any] | None = None,
    reported_usage: Mapping[str, Any] | None = None,
    neutral_error: NeutralError | None = None,
    provider_outcome: ProviderCallOutcome | None = None,
    execution_profile: str,
    invocation_began: bool = False,
    projected_tokens_in: int | None = None,
    consumed_tokens_in: int | None = None,
    harness_observed_latency_seconds: float | None = None,
) -> dict[str, Any]:
    if retry_decision not in RETRY_DECISIONS:
        raise GovernanceViolation(f"invalid retry_decision {retry_decision!r}")
    if retry_rationale not in RETRY_RATIONALES:
        raise GovernanceViolation(f"invalid retry_rationale {retry_rationale!r}")
    if contract_verdict not in VERDICTS or identity_verdict not in VERDICTS:
        raise GovernanceViolation("invalid validation verdict")
    if failure_class not in FAILURE_CLASSES:
        raise GovernanceViolation(f"invalid failure_class {failure_class!r}")
    refs = [str(item) for item in promoted_artifact_refs]
    for ref in refs:
        if ".." in ref or ref.startswith("/") or "\\" in ref:
            raise GovernanceViolation(f"promoted artifact ref is not harness-owned: {ref!r}")
    raw_meta = dict(raw_output_meta or {})
    raw_view = {
        "present": bool(raw_meta.get("present")),
        "truncated": bool(raw_meta.get("truncated", False)),
        "ref": invocation_ref(role, attempt, RAW_OUTPUT_FILENAME) if raw_meta.get("present") else None,
        "stored_bytes": raw_meta.get("stored_bytes", 0),
        "observed_bytes": raw_meta.get("observed_bytes"),
        "sha256_stored": raw_meta.get("sha256_stored"),
        "sha256_complete": raw_meta.get("sha256_complete"),
        "truncation_label": raw_meta.get("label"),
    }
    if invocation_began is not True and invocation_began is not False:
        raise GovernanceViolation("invocation_began must be a boolean")
    projected = int(tokens_in if projected_tokens_in is None else projected_tokens_in)
    consumed = int((tokens_in if invocation_began else 0) if consumed_tokens_in is None else consumed_tokens_in)
    if consumed < 0 or projected < 0:
        raise GovernanceViolation("token accounting must be non-negative")
    if not invocation_began and consumed != 0:
        raise GovernanceViolation("consumed input must be zero when invocation did not begin")
    latency = harness_observed_latency_seconds
    if latency is not None:
        latency = float(latency)
        if latency < 0:
            raise GovernanceViolation("harness_observed_latency_seconds must be non-negative")
    if execution_profile not in SUPPORTED_EXECUTION_PROFILES:
        raise GovernanceViolation(f"unknown execution profile {execution_profile!r}")
    if execution_profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
        if identity_used is not None or reported_usage is not None:
            raise GovernanceViolation(
                "live-contract evidence must not use the legacy identity_used/reported_usage route"
            )
        adapter_evidence = {
            "compatibility": "live_contract",
            "provider_call_outcome": None if provider_outcome is None else provider_outcome.to_dict(),
        }
    elif execution_profile == EXECUTION_PROFILE_PRE_LIVE_LEGACY:
        if provider_outcome is not None:
            raise GovernanceViolation(
                "legacy compatibility evidence must not carry a ProviderCallOutcome"
            )
        adapter_evidence = {
            "compatibility": "pre_live_fake_adapter",
            "provider_call_outcome": None,
            "identity_used": None if identity_used is None else dict(identity_used),
            "reported_usage": None if reported_usage is None else dict(reported_usage),
            "neutral_error": None if neutral_error is None else neutral_error.to_dict(),
            "adapter_internal_retry_count": 0,
        }
    else:
        raise GovernanceViolation(f"unsupported execution profile {execution_profile!r}")
    record = {
        "schema": INVOCATION_SCHEMA,
        "run_id": run_id,
        "condition": condition,
        "role": role,
        "attempt": attempt,
        "requested_identity": requested_identity.to_dict(),
        "configured_identity": configured_identity.to_dict(),
        "stage_timeout_seconds": float(stage_timeout_seconds),
        "attempt_timeout_seconds": float(attempt_timeout_seconds),
        "input_content_digest": input_content_digest,
        "treatment_digest": treatment_digest,
        "usage_estimated": {"tokens_in": int(tokens_in), "tokens_out": int(tokens_out)},
        "cumulative_tokens_in": int(cumulative_tokens_in),
        "projected_tokens_in": projected,
        "consumed_tokens_in": consumed,
        "invocation_began": invocation_began,
        "harness_observed_latency_seconds": latency,
        "retry_decision": retry_decision,
        "retry_rationale": retry_rationale,
        "contract_verdict": contract_verdict,
        "identity_verdict": identity_verdict,
        "failure_class": failure_class,
        "adapter_evidence": adapter_evidence,
        "raw_output": raw_view,
        "promoted_artifact_refs": refs,
    }
    _reject_secret_keys(record, "invocation record")
    extra = set(record) - _RECORD_FIELDS
    if extra:
        raise GovernanceViolation(f"invocation record has unexpected fields: {sorted(extra)}")
    return record


def serialize_invocation_record(record: Mapping[str, Any]) -> str:
    _reject_secret_keys(record, "invocation record")
    missing = _RECORD_FIELDS - set(record)
    if missing:
        raise GovernanceViolation(f"invocation record missing fields: {sorted(missing)}")
    extra = set(record) - _RECORD_FIELDS
    if extra:
        raise GovernanceViolation(f"invocation record has unexpected fields: {sorted(extra)}")
    return canonical_json(dict(record))


def _reject_secret_keys(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is not str:
                raise GovernanceViolation(f"{label} keys must be strings")
            normalized = key.strip().lower().replace("-", "_")
            if key.lower().startswith("x-"):
                raise GovernanceViolation(f"{label} contains forbidden field {key!r}")
            for marker in _FORBIDDEN_KEY_MARKERS:
                if marker in normalized:
                    raise GovernanceViolation(f"{label} contains forbidden field {key!r}")
            _reject_secret_keys(item, f"{label}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{label}[{index}]")
