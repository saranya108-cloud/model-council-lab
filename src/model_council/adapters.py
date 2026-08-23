"""Child-side adapter implementations.

This module is imported ONLY by the worker subprocess. It must never import
runner, evaluator, or artifacts: the adapter's execution context receives only
serialized data and holds no references to harness internals.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Mapping

from .types import ModelFailure


def _digest(model_id: str, role: str, stage_inputs: Mapping[str, str], seed: int) -> str:
    payload = json.dumps(
        {
            "model": model_id,
            "role": role,
            "inputs": dict(sorted(stage_inputs.items())),
            "seed": seed,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _usage(role_instruction: str, stage_inputs: Mapping[str, str], text: str) -> tuple[int, int]:
    tokens_in = len(role_instruction.split()) + len(
        " ".join(stage_inputs.values()).split()
    )
    return tokens_in, len(text.split())


def _role_from_instruction(role_instruction: str) -> str:
    for token in role_instruction.split():
        if token.startswith("role:"):
            return token[len("role:"):]
    raise ValueError(f"role instruction missing 'role:<name>' marker: {role_instruction!r}")


def _identity_used(options: Mapping[str, Any]) -> dict[str, str]:
    """The identity actually resolved for this invocation.

    Trusted adapter code resolves its own configuration; the parent compares
    this against the frozen RunSpec expectation after every stage.
    """
    override = options.get("identity_override")
    if isinstance(override, dict):
        return {
            "provider": str(override.get("provider", "fake-provider")),
            "model_id": str(override.get("model_id", options["model_id"])),
            "model_version": str(override.get("model_version", "v1")),
            "adapter_name": str(override.get("adapter_name", "fake")),
            "adapter_version": str(override.get("adapter_version", "v0")),
        }
    return {
        "provider": "fake-provider",
        "model_id": str(options["model_id"]),
        "model_version": "v1",
        "adapter_name": "fake",
        "adapter_version": "v0",
    }


def fake_generate(
    options: Mapping[str, Any],
    role_instruction: str,
    stage_inputs: Mapping[str, Any],
    budget: Mapping[str, Any],
    seed: int,
) -> dict[str, Any]:
    """Deterministic development model. Seed always comes from the stage call."""
    model_id = str(options["model_id"])
    role = _role_from_instruction(role_instruction)
    # Each stage invocation is a fresh process, so failure injection must be a
    # pure function of (seed): "fail_if_seed_lt" fails deterministically for
    # lower seeds only, enabling transient-failure semantics across processes.
    fail_threshold = options.get("fail_if_seed_lt")
    if fail_threshold is not None and seed < int(fail_threshold):
        raise ModelFailure(f"simulated failure for role={role} seed={seed}")
    digest = _digest(model_id, role, stage_inputs, seed)
    task_text = stage_inputs.get("task", "")
    prohibited = " # MODIFIED_HIDDEN_TESTS" if options.get("inject_prohibited_content") else ""
    fix_body = f"PROPOSED_FIX[{digest}]{prohibited}\n{task_text.strip()}"

    artifacts: dict[str, str] = {}
    structured: dict[str, Any] | None = None

    if role == "solver":
        artifacts = {
            "candidate": f"# Candidate (solver)\n{fix_body}",
            "evidence": (
                f"# Evidence (solver)\n- claim: defect located in scoped files\n"
                f"- basis: visible tests and bug report [{digest}]"
            ),
        }
    elif role == "draft":
        artifacts = {"draft": f"# Draft\n{fix_body}"}
    elif role == "self_review":
        artifacts = {
            "self_review": (
                "# Self-review of draft\n- FINDING [S1]: verify edge cases in scope\n"
                "- SUFFICIENCY: sufficient"
            )
        }
    elif role == "verifier":
        prior = stage_inputs.get("solver_candidate", "")
        findings = [
            {
                "finding_id": "V1",
                "description": "confirm fix addresses reported behavior",
                "material": True,
            }
        ]
        if options.get("verifier_extra_finding"):
            findings.append(
                {
                    "finding_id": "V2",
                    "description": "second material finding",
                    "material": True,
                }
            )
        malformed = options.get("malformed_verifier")
        if malformed == "no_description":
            findings[0]["description"] = ""
        elif malformed == "duplicate_id":
            findings.append(dict(findings[0]))
        elif malformed == "findings_scalar":
            findings = 42
        elif malformed == "material_string":
            findings[0]["material"] = "true"
        findings_lines = [
            f"- FINDING [V1]: confirm fix addresses reported behavior "
            f"(prior candidate present: {str(bool(prior)).lower()})"
        ]
        if options.get("verifier_extra_finding"):
            findings_lines.append("- FINDING [V2]: second material finding")
        findings_lines += [
            "- FALSIFICATION ATTEMPT: checked against bug report conditions",
            "- SUFFICIENCY: evidence sufficient",
        ]
        artifacts = {
            "findings": "# Independent verification\n" + "\n".join(findings_lines)
        }
        if malformed == "structured_scalar":
            structured = 42
        else:
            structured = {"findings": findings, "sufficiency": "sufficient"}
    elif role in ("revise", "reviser"):
        findings_text = (
            stage_inputs.get("verifier_findings") or stage_inputs.get("self_review") or ""
        )
        base = stage_inputs.get("solver_candidate") or stage_inputs.get("draft") or fix_body
        dispositions: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for line in findings_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- FINDING"):
                fid = "V1" if "[V1]" in stripped else ("V2" if "[V2]" in stripped else "S1")
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)
                dispositions.append(
                    {
                        "finding_id": fid,
                        "decision": "accept",
                        "rationale": "addressed in revision",
                    }
                )
        mode = options.get("disposition_mode", "ok")
        if mode == "missing":
            dispositions = []
        elif mode == "unknown_id":
            dispositions.append(
                {"finding_id": "VX", "decision": "accept", "rationale": "phantom"}
            )
        elif mode == "duplicate" and dispositions:
            dispositions.append(dict(dispositions[0]))
        elif mode == "no_rationale":
            if dispositions:
                dispositions[0]["rationale"] = "   "
        elif mode == "bad_decision":
            # F12 regression fixture: an otherwise well-formed disposition
            # whose decision value is invalid. Dispositions are NOT cleared.
            if dispositions:
                dispositions[0]["decision"] = "partially"
        disposition_block = "\n".join(
            f"- {d['decision'].upper()}: {d['finding_id']} — {d['rationale']}"
            for d in dispositions
        ) or "- no material findings to disposition"
        artifacts = {
            "final_candidate": (
                f"# Final candidate ({role})\n{base}\n"
                f"REVISION_APPLIED[{digest}]\n\n# Dispositions\n{disposition_block}"
            )
        }
        structured = {"dispositions": dispositions}
    else:
        raise ValueError(f"unknown role: {role}")

    text = "\n\n".join(artifacts.values())
    tokens_in, tokens_out = _usage(role_instruction, stage_inputs, text)
    if options.get("over_input_budget_words"):
        tokens_in += int(options["over_input_budget_words"])
    if options.get("over_output_budget_words"):
        tokens_out += int(options["over_output_budget_words"])
    tool_uses = int(options.get("tool_uses", 0))
    return {
        "text": text,
        "artifacts": artifacts,
        "structured": structured,
        "model_metadata": {
            "adapter_kind": "fake",
            "deterministic_digest": digest,
        },
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "cost_units": 0.0,
        "tool_uses": tool_uses,
    }


def introspect_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    """Adversarial probe: report everything reachable from the child context."""
    import sys

    found_objects: list[str] = []
    frame = sys._getframe()
    while frame is not None:
        for scope_name, scope in (("globals", frame.f_globals), ("locals", frame.f_locals)):
            for name in ("runner", "evaluator", "store", "_config", "evaluation_config"):
                obj = scope.get(name)
                if obj is not None:
                    found_objects.append(f"{scope_name}:{name}={type(obj).__name__}")
        frame = frame.f_back
    evaluator_config_markers = [
        v
        for v in json.dumps(dict(stage_inputs)).split()
        if v.startswith("SECRET")
    ]
    return {
        "text": "introspection report",
        "artifacts": {},
        "structured": {
            "found_objects": sorted(set(found_objects)),
            "evaluator_secret_markers_found": evaluator_config_markers,
            "cwd_entries": __import__("os").listdir("."),
        },
        "model_metadata": {"adapter_kind": "introspect"},
        "tokens_in": 1,
        "tokens_out": 1,
        "cost_units": 0.0,
        "tool_uses": 0,
    }


def tamper_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    """Adversarial probe: try to reach and mutate preserved run artifacts."""
    import os

    guesses = [
        "runs",
        "../runs",
        "../../runs",
        os.path.join(os.getcwd(), "runs"),
    ]
    attempted = []
    mutated = []
    for guess in guesses:
        attempted.append(guess)
        if os.path.exists(guess):
            for root, _, files in os.walk(guess):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        with open(path, "a", encoding="utf-8") as handle:
                            handle.write("TAMPERED\n")
                        mutated.append(path)
                    except OSError:
                        pass
    return {
        "text": "tamper report",
        "artifacts": {},
        "structured": {"attempted_paths": attempted, "mutated_paths": mutated},
        "model_metadata": {"adapter_kind": "tamper"},
        "tokens_in": 1,
        "tokens_out": 1,
        "cost_units": 0.0,
        "tool_uses": 0,
    }


def sleep_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    time.sleep(float(options.get("seconds", 30)))
    return {
        "text": "too late",
        "artifacts": {},
        "structured": None,
        "model_metadata": {},
        "tokens_in": 1,
        "tokens_out": 1,
        "cost_units": 0.0,
        "tool_uses": 0,
    }


def rogue_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    """Adversarial: emits an unauthorized extra artifact from the solver stage."""
    response = fake_generate(options, role_instruction, stage_inputs, budget, seed)
    role = _role_from_instruction(role_instruction)
    if role == "solver":
        response["artifacts"]["rogue"] = "unauthorized write attempt"
    return response


def crash_worker_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    """Adversarial: worker dies without any protocol response."""
    import os
    import signal

    os.kill(os.getpid(), signal.SIGKILL)
    raise AssertionError("unreachable")


def bad_usage_generate(options, role_instruction, stage_inputs, budget, seed) -> dict:
    """Adversarial: returns a structurally invalid usage metric."""
    response = fake_generate(options, role_instruction, stage_inputs, budget, seed)
    field = options.get("bad_usage_field", "tokens_in")
    mode = options.get("bad_usage_mode", "negative")
    value = {"negative": -5, "boolean": True, "string": "many", "none": None}[mode]
    response[field] = value
    return response


REGISTRY = {
    "fake": fake_generate,
    "introspect": introspect_generate,
    "tamper": tamper_generate,
    "sleep": sleep_generate,
    "rogue": rogue_generate,
    "crash_worker": crash_worker_generate,
    "drift": fake_generate,
    "bad_usage": bad_usage_generate,
}
