"""Adapter worker: the ONLY supported execution context for model adapters.

Reads a JSON request from stdin, invokes a registered adapter with serialized
data only, and writes a JSON response to stdout. It holds no references to the
Runner, Evaluator, ArtifactStore, hidden checks, or preserved artifacts.

Per the Human Chair trust decision, adapter implementations are trusted
project code; this process provides timeout/protocol isolation, not an OS
sandbox. Every response echoes the identity actually resolved for the
invocation; the parent verifies it against the frozen RunSpec expectation.
"""

from __future__ import annotations

import json
import sys

from .adapters import REGISTRY, _identity_used, _role_from_instruction
from .types import ModelFailure


def main() -> int:
    request = json.load(sys.stdin)
    adapter_spec = request["adapter"]
    kind = adapter_spec["kind"]

    if kind == "raw_garbage":
        # Adversarial protocol probe: exit 0 with non-JSON stdout.
        sys.stdout.write("###this is not json###")
        return 0

    if kind not in REGISTRY:
        json.dump(
            {"ok": False, "error_class": "UnknownAdapter", "message": f"unknown adapter kind {kind!r}"},
            sys.stdout,
        )
        return 0

    options = dict(adapter_spec.get("options") or {})
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
    json.dump({"ok": True, "response": response}, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
