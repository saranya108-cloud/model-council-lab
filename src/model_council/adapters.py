"""Child-side adapter implementations.

This module is imported ONLY by the worker subprocess. It must never import
runner, evaluator, or artifacts: the adapter's execution context receives only
serialized data and holds no references to harness internals.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

from .live_contract import (
    CallTiming,
    FinishReason,
    LiveInvocationRequest,
    NeutralError,
    NeutralProviderFailure,
    ObservedInt,
    ObservedNumber,
    ObservedStr,
    ProviderCallKind,
    ProviderErrorCategory,
    UnavailableReason,
    UntrustedStructured,
    build_provider_call_outcome,
    empty_provider_metadata,
    observed_identity,
    observed_int,
    observed_provider_metadata,
    observed_str,
    observed_structured,
    unavailable,
    unavailable_identity,
    unavailable_int,
    unavailable_metrics,
    unavailable_number,
    unavailable_structured,
    ProviderUsage,
)
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


def _next_fake_invocation_count(options: Mapping[str, Any]) -> int | None:
    """Test-harness-only counter. Lives in adapter options, not treatment."""
    raw_path = options.get("invocation_counter_path")
    if raw_path is None:
        return None
    path = Path(str(raw_path))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        current = int(path.read_text(encoding="utf-8").strip() or "0")
    except FileNotFoundError:
        current = 0
    except ValueError:
        current = 0
    current += 1
    path.write_text(str(current), encoding="utf-8")
    return current


def _neutral_failure_from_options(options: Mapping[str, Any]) -> NeutralProviderFailure | None:
    raw_category = options.get("neutral_error_category")
    if raw_category is None:
        return None
    try:
        category = ProviderErrorCategory(str(raw_category))
    except ValueError as exc:
        raise ValueError(f"unknown neutral_error_category {raw_category!r}") from exc
    hint_raw = options.get("provider_retry_hint")
    if hint_raw is None:
        hint = ObservedStr(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        hint = ObservedStr(value=str(hint_raw), unavailable_reason=None)
    retry_after_raw = options.get("retry_after_seconds")
    if retry_after_raw is None:
        retry_after = ObservedNumber(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        retry_after = ObservedNumber(value=float(retry_after_raw), unavailable_reason=None)
    http_raw = options.get("neutral_http_status")
    if http_raw is None:
        http_status = ObservedInt(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        http_status = ObservedInt(value=int(http_raw), unavailable_reason=None)
    return NeutralProviderFailure(
        NeutralError(
            category=category,
            sanitized_message=f"simulated {category.value}",
            http_status=http_status,
            provider_retry_hint=hint,
            retry_after_seconds=retry_after,
        )
    )


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
    # Invocation count is test-adapter state on disk, not a model-visible
    # treatment parameter. Production adapters never receive this counter.
    invocation_count = _next_fake_invocation_count(options)
    fail_before = options.get("fail_before_call_count")
    if (
        invocation_count is not None
        and fail_before is not None
        and invocation_count < int(fail_before)
    ):
        injected = _neutral_failure_from_options(options)
        if injected is not None:
            raise injected
        raise ModelFailure(
            f"simulated failure for role={role} invocation={invocation_count}"
        )
    if fail_before is None:
        injected = _neutral_failure_from_options(options)
        if injected is not None:
            raise injected
    # Static seed predicate: fails or succeeds independently of attempt number.
    fail_threshold = options.get("fail_if_seed_lt")
    if fail_threshold is not None and seed < int(fail_threshold):
        raise ModelFailure(f"simulated failure for role={role} seed={seed}")
    raise_message = options.get("raise_message")
    if raise_message is not None:
        cause_text = options.get("raise_cause")
        if cause_text is not None:
            try:
                raise RuntimeError(str(cause_text))
            except RuntimeError as cause:
                raise RuntimeError(str(raise_message)) from cause
        raise RuntimeError(str(raise_message))
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
            structured = {"findings": findings}
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
        # Condition C reviser receives verifier_findings; Condition B does not
        # advertise or require C dispositions.
        if "verifier_findings" in stage_inputs:
            structured = {"dispositions": dispositions}
        else:
            structured = None
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
    import sys

    canary = options.get("stderr_canary")
    if canary:
        sys.stderr.write(str(canary))
        sys.stderr.flush()
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


def _live_stub_usage():
    reason = UnavailableReason.NOT_EXPOSED
    return ProviderUsage(
        input_tokens=unavailable_int(reason),
        cached_input_tokens=unavailable_int(reason),
        cache_write_tokens=unavailable_int(reason),
        output_tokens=unavailable_int(reason),
        reasoning_tokens=unavailable_int(reason),
        total_tokens=unavailable_int(reason),
        extra=unavailable_metrics(UnavailableReason.NOT_APPLICABLE),
    )


def _live_stub_provider_metadata(options: Mapping[str, Any]) -> UntrustedStructured:
    unavailable_raw = options.get("provider_metadata_unavailable")
    if unavailable_raw is not None:
        return unavailable_structured(str(unavailable_raw))
    raw = options.get("provider_metadata")
    if raw is None:
        return empty_provider_metadata()
    if not isinstance(raw, Mapping):
        raise ValueError("live stub provider_metadata option must be a JSON object")
    return observed_provider_metadata(dict(raw))


def _live_stub_error(
    options: Mapping[str, Any], category: ProviderErrorCategory
) -> NeutralError:
    hint_raw = options.get("provider_retry_hint")
    if hint_raw is None:
        hint = ObservedStr(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        hint = ObservedStr(value=str(hint_raw), unavailable_reason=None)
    retry_after_raw = options.get("retry_after_seconds")
    if retry_after_raw is None:
        retry_after = ObservedNumber(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        retry_after = ObservedNumber(value=float(retry_after_raw), unavailable_reason=None)
    http_raw = options.get("neutral_http_status")
    if http_raw is None:
        http_status = ObservedInt(value=None, unavailable_reason=UnavailableReason.NOT_EXPOSED)
    else:
        http_status = ObservedInt(value=int(http_raw), unavailable_reason=None)
    return NeutralError(
        category=category,
        sanitized_message=f"simulated {category.value}",
        http_status=http_status,
        provider_retry_hint=hint,
        retry_after_seconds=retry_after,
    )


def _live_stub_error_observations(options: Mapping[str, Any], category: ProviderErrorCategory):
    retain = bool(options.get("retain_observational_evidence"))
    if category in (
        ProviderErrorCategory.POLICY_REFUSAL,
        ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT,
    ):
        retain = True
    if not retain:
        return {
            "provider_response_id": unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
            "provider_request_id": unavailable(UnavailableReason.NOT_EXPOSED),
            "provider_response_status": unavailable_int(UnavailableReason.NO_RESPONSE_RECEIVED),
            "finish_reason": unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
            "raw_output": unavailable(UnavailableReason.NO_RESPONSE_RECEIVED),
            "structured_output": unavailable_structured(UnavailableReason.NO_RESPONSE_RECEIVED),
        }
    finish_raw = options.get("finish_reason")
    if finish_raw is None:
        if category is ProviderErrorCategory.POLICY_REFUSAL:
            finish_raw = FinishReason.CONTENT_FILTER.value
        elif category is ProviderErrorCategory.INCOMPLETE_PROVIDER_RESULT:
            finish_raw = FinishReason.INCOMPLETE.value
        else:
            finish_raw = FinishReason.ERROR.value
    raw_output = options.get("raw_output")
    if raw_output is None:
        raw_output = f"simulated {category.value}"
    structured = options.get("structured_output")
    status = options.get("provider_response_status", 200)
    response_id = options.get("provider_response_id", "live-stub-resp")
    return {
        "provider_response_id": observed_str(str(response_id)),
        "provider_request_id": unavailable(UnavailableReason.NOT_EXPOSED),
        "provider_response_status": observed_int(int(status)),
        "finish_reason": ObservedStr(value=str(finish_raw), unavailable_reason=None),
        "raw_output": ObservedStr(value=str(raw_output), unavailable_reason=None),
        "structured_output": (
            unavailable_structured(UnavailableReason.NOT_APPLICABLE)
            if structured is None
            else observed_structured(structured)
        ),
    }


def _live_stub_stage_payload(request: LiveInvocationRequest, options: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic stage bytes for the live-protocol stub. Not a provider."""
    role = request.role
    stage_inputs = dict(request.stage_inputs)
    digest = _digest(request.configured_identity.model_id, role, stage_inputs, request.seed)
    task_text = stage_inputs.get("task", "")
    fix_body = f"PROPOSED_FIX[{digest}]\n{task_text.strip()}"
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
        findings = [
            {
                "finding_id": "V1",
                "description": "confirm fix addresses reported behavior",
                "material": True,
            }
        ]
        if options.get("extra_nested_key"):
            findings[0]["unexpected"] = "extra"
        artifacts = {
            "findings": (
                "# Independent verification\n"
                "- FINDING [V1]: confirm fix addresses reported behavior\n"
                "- SUFFICIENCY: evidence sufficient"
            )
        }
        structured = {"findings": findings}
    elif role == "reviser":
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
        artifacts = {
            "final_candidate": (
                f"# Final candidate (reviser)\n{base}\nREVISION_APPLIED[{digest}]"
            )
        }
        if request.condition == "C":
            structured = {"dispositions": dispositions}
        else:
            structured = None
    else:
        raise ValueError(f"unknown role: {role}")
    if options.get("extra_artifact"):
        artifacts[str(options["extra_artifact"])] = "unauthorized extra artifact"
    text = "\n\n".join(artifacts.values())
    return {"text": text, "artifacts": artifacts, "structured": structured}


def live_stub_generate(options: Mapping[str, Any], request: LiveInvocationRequest):
    """Live-contract test stub. Returns ProviderCallOutcome, never a legacy dict.

    Test hooks live in trusted adapter options, not in the experimental treatment.
    """
    _next_fake_invocation_count(options)
    if options.get("raise_model_failure"):
        raise ModelFailure("live stub must not use legacy ModelFailure")
    if options.get("return_legacy_response"):
        # Intentionally wrong: worker must reject this as a protocol failure.
        return {
            "text": "legacy shape",
            "artifacts": {"candidate": "x", "evidence": "y"},
            "identity_used": request.configured_identity.to_dict(),
            "tokens_in": 1,
            "tokens_out": 1,
            "tool_uses": 0,
        }
    error_category = options.get("neutral_error_category")
    if error_category is not None:
        category = ProviderErrorCategory(str(error_category))
        error = _live_stub_error(options, category)
        observations = _live_stub_error_observations(options, category)
        return build_provider_call_outcome(
            kind=ProviderCallKind.PROVIDER_ERROR,
            requested_identity=request.requested_identity,
            configured_identity=request.configured_identity,
            provider_resolved_identity=unavailable_identity(UnavailableReason.NOT_EXPOSED),
            invocation_returned_identity=observed_identity(
                model_id=request.configured_identity.model_id
            ),
            provider_snapshot_identity=unavailable(UnavailableReason.NOT_EXPOSED),
            tool_use_count=0,
            usage=_live_stub_usage(),
            timing=CallTiming(
                provider_processing_ms=unavailable_number(UnavailableReason.NOT_EXPOSED),
            ),
            adapter_internal_retry_count=0,
            error=error,
            stage_output=None,
            provider_metadata=_live_stub_provider_metadata(options),
            **observations,
        )
    payload = _live_stub_stage_payload(request, options)
    raw_value = payload["text"]
    structured = payload["structured"]
    configured = request.configured_identity
    return build_provider_call_outcome(
        kind=ProviderCallKind.SUCCESS,
        requested_identity=request.requested_identity,
        configured_identity=configured,
        provider_resolved_identity=unavailable_identity(UnavailableReason.NOT_EXPOSED),
        invocation_returned_identity=observed_identity(
            provider=configured.provider,
            model_id=configured.model_id,
            model_version=configured.model_version,
        ),
        provider_snapshot_identity=unavailable(UnavailableReason.NOT_EXPOSED),
        provider_response_id=observed_str("live-stub-resp"),
        provider_request_id=unavailable(UnavailableReason.NOT_EXPOSED),
        provider_response_status=observed_int(200),
        finish_reason=ObservedStr(value=FinishReason.COMPLETED.value, unavailable_reason=None),
        raw_output=ObservedStr(value=raw_value, unavailable_reason=None),
        structured_output=(
            unavailable_structured(UnavailableReason.NOT_APPLICABLE)
            if structured is None
            else observed_structured(structured)
        ),
        tool_use_count=int(options.get("tool_uses", 0)),
        usage=_live_stub_usage(),
        timing=CallTiming(
            provider_processing_ms=unavailable_number(UnavailableReason.NOT_EXPOSED),
        ),
        adapter_internal_retry_count=0,
        error=None,
        stage_output=payload,
        provider_metadata=_live_stub_provider_metadata(options),
    )


# Legacy deterministic adapters. Live kinds must not appear here.
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

# Live-contract adapters. Invoked only after worker handshake validation.
LIVE_REGISTRY = {
    "live_stub": live_stub_generate,
}

_overlap = set(REGISTRY) & set(LIVE_REGISTRY)
if _overlap:
    raise RuntimeError(f"adapter kind registered in both execution profiles: {sorted(_overlap)}")
