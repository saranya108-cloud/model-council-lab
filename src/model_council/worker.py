"""Adapter worker: the ONLY supported execution context for model adapters.

Reads a JSON request from stdin, validates the harness protocol handshake,
invokes a registered adapter for the runner-selected execution profile, and
writes a JSON response to stdout. It holds no references to the Runner,
Evaluator, ArtifactStore, hidden checks, or preserved artifacts.
"""

from __future__ import annotations

import json
import sys

from .adapters import LIVE_REGISTRY, REGISTRY, _identity_used, _role_from_instruction
from .live_contract import (
    LiveContractError,
    NeutralProviderFailure,
    ProviderCallOutcome,
    parse_live_invocation_request,
    parse_provider_call_outcome,
)
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from .sanitize import WORKER_SANITIZED_FAILURE
from .types import ModelFailure, ProtocolError


def _fail(error_class: str, message: str) -> int:
    json.dump({"ok": False, "error_class": error_class, "message": message}, sys.stdout)
    return 0


def _validate_harness_protocol(request: object) -> str | None:
    if not isinstance(request, dict):
        return "worker request must be a JSON object"
    version = request.get("harness_protocol_version")
    if version is None:
        return "missing harness protocol version"
    if type(version) is not str or not version:
        return f"malformed harness protocol version: {version!r}"
    if version != HARNESS_PROTOCOL_VERSION:
        return f"unsupported harness protocol version: {version!r}"
    return None


def main() -> int:
    try:
        return _main()
    except Exception:
        return _fail("InfrastructureError", WORKER_SANITIZED_FAILURE)


def _main() -> int:
    request = json.load(sys.stdin)
    protocol_error = _validate_harness_protocol(request)
    if protocol_error:
        return _fail("ProtocolError", protocol_error)

    adapter_spec = request.get("adapter")
    if not isinstance(adapter_spec, dict) or "kind" not in adapter_spec:
        return _fail("ProtocolError", "worker request missing adapter.kind")
    kind = adapter_spec["kind"]

    if kind == "raw_garbage":
        # Adversarial protocol probe: exit 0 with non-JSON stdout.
        sys.stdout.write("###this is not json###")
        return 0

    sent_profile = request.get("execution_profile")
    try:
        expected_profile = execution_profile_for_kind(kind)
    except ProtocolError as exc:
        return _fail("ProtocolError", str(exc))
    if type(sent_profile) is not str or sent_profile != expected_profile:
        return _fail(
            "ProtocolError",
            (
                f"execution profile mismatch: runner sent {sent_profile!r}, "
                f"worker expects {expected_profile!r} for kind {kind!r}"
            ),
        )

    options = dict(adapter_spec.get("options") or {})
    if expected_profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
        return _run_live(kind, options, request)
    if expected_profile == EXECUTION_PROFILE_PRE_LIVE_LEGACY:
        return _run_legacy(kind, options, request)
    return _fail("ProtocolError", f"unsupported execution profile {expected_profile!r}")


def _run_live(kind: str, options: dict, request: dict) -> int:
    if kind not in LIVE_REGISTRY:
        return _fail("ProtocolError", f"kind {kind!r} is not a registered live-contract adapter")
    try:
        live_request = parse_live_invocation_request(request.get("live_invocation_request"))
    except LiveContractError as exc:
        return _fail("ProtocolError", f"invalid live invocation request: {exc}")
    try:
        result = LIVE_REGISTRY[kind](options, live_request)
    except ModelFailure:
        return _fail(
            "ProtocolError",
            "live adapter raised ModelFailure; live kinds cannot use the legacy failure route",
        )
    except NeutralProviderFailure:
        return _fail(
            "ProtocolError",
            "live adapter raised NeutralProviderFailure; return a ProviderCallOutcome instead",
        )
    except Exception:
        return _fail("ProtocolError", WORKER_SANITIZED_FAILURE)
    if not isinstance(result, ProviderCallOutcome):
        return _fail(
            "ProtocolError",
            "live adapter must return a ProviderCallOutcome; legacy response envelopes are rejected",
        )
    try:
        parsed = parse_provider_call_outcome(result.to_dict())
    except LiveContractError as exc:
        return _fail("ProtocolError", f"live adapter returned an invalid ProviderCallOutcome: {exc}")
    json.dump(
        {
            "ok": True,
            "execution_profile": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
            "outcome": parsed.to_dict(),
        },
        sys.stdout,
    )
    return 0


def _run_legacy(kind: str, options: dict, request: dict) -> int:
    if kind not in REGISTRY:
        json.dump(
            {"ok": False, "error_class": "UnknownAdapter", "message": f"unknown adapter kind {kind!r}"},
            sys.stdout,
        )
        return 0
    try:
        response = REGISTRY[kind](
            options,
            request["role_instruction"],
            dict(request["stage_inputs"]),
            dict(request["budget"]),
            int(request["seed"]),
        )
    except ModelFailure as exc:
        json.dump(
            {"ok": False, "error_class": "ModelFailure", "message": str(exc)}, sys.stdout
        )
        return 0
    except NeutralProviderFailure as exc:
        json.dump(
            {
                "ok": False,
                "error_class": "NeutralProviderFailure",
                "message": str(exc),
                "error": exc.error.to_dict(),
            },
            sys.stdout,
        )
        return 0
    except Exception:
        return _fail("InfrastructureError", WORKER_SANITIZED_FAILURE)

    identity_used = _identity_used(options)
    if kind == "drift":
        wrong_from_role = options.get("wrong_identity_from_role")
        if wrong_from_role and _role_from_instruction(request["role_instruction"]) == wrong_from_role:
            override = options.get("identity_override") or {
                "provider": "drift-provider",
                "model_id": "drift-model",
            }
            merged = dict(identity_used)
            merged.update({k: str(v) for k, v in override.items()})
            identity_used = merged

    response["identity_used"] = identity_used
    json.dump(
        {
            "ok": True,
            "execution_profile": EXECUTION_PROFILE_PRE_LIVE_LEGACY,
            "response": response,
        },
        sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
