"""Role definitions, stage sequences, and context-isolation policy.

The ContextPolicy is the structural enforcement of role isolation: the runner
constructs each stage's inputs exclusively from the allowed keys below, and any
attempt to supply extra keys raises GovernanceViolation.
"""

from __future__ import annotations

from .types import Condition, GovernanceViolation

ROLE_SOLVER = "solver"
ROLE_VERIFIER = "verifier"
ROLE_REVISER = "reviser"
ROLE_DRAFT = "draft"
ROLE_SELF_REVIEW = "self_review"

CONTEXT_POLICY_VERSION = "ctx-policy-v1"

# Roles whose responses are governed by a structured output contract.
CONTRACT_ROLES = frozenset({ROLE_VERIFIER, ROLE_REVISER})

CONDITION_STAGES: dict[Condition, tuple[str, ...]] = {
    Condition.A: (ROLE_SOLVER,),
    Condition.B: (ROLE_DRAFT, ROLE_SELF_REVIEW, ROLE_REVISER),
    Condition.C: (ROLE_SOLVER, ROLE_VERIFIER, ROLE_REVISER),
}

PRIMARY_ARTIFACT: dict[str, str] = {
    ROLE_SOLVER: "candidate",
    ROLE_VERIFIER: "findings",
    ROLE_REVISER: "final_candidate",
    ROLE_DRAFT: "draft",
    ROLE_SELF_REVIEW: "self_review",
}

EXTRA_ARTIFACTS: dict[str, tuple[str, ...]] = {
    ROLE_SOLVER: ("evidence",),
}

# Exact artifact contract for every stage.  The runner validates this before
# persistence, and ArtifactStore uses it when sealing and re-verifying stages.
EXPECTED_ARTIFACTS: dict[str, frozenset[str]] = {
    role: frozenset({PRIMARY_ARTIFACT[role], *EXTRA_ARTIFACTS.get(role, ())})
    for role in PRIMARY_ARTIFACT
}

STAGE_OUTPUT_KEYS: dict[str, dict[str, str]] = {
    # artifact name -> context key made available to later stages
    ROLE_SOLVER: {"candidate": "solver_candidate", "evidence": "solver_evidence"},
    ROLE_VERIFIER: {"findings": "verifier_findings"},
    ROLE_REVISER: {"final_candidate": "final_candidate"},
    ROLE_DRAFT: {"draft": "draft"},
    ROLE_SELF_REVIEW: {"self_review": "self_review"},
}

ALLOWED_INPUT_KEYS: dict[tuple[Condition, str], frozenset[str]] = {
    # Condition A
    (Condition.A, ROLE_SOLVER): frozenset({"task"}),
    # Condition B: one agent identity across all three stages; serial refinement.
    (Condition.B, ROLE_DRAFT): frozenset({"task"}),
    (Condition.B, ROLE_SELF_REVIEW): frozenset({"task", "draft"}),
    (Condition.B, ROLE_REVISER): frozenset({"task", "draft", "self_review"}),
    # Condition C: independent verifier sees candidate + evidence, never raw traces.
    (Condition.C, ROLE_SOLVER): frozenset({"task"}),
    (Condition.C, ROLE_VERIFIER): frozenset({"task", "solver_candidate", "solver_evidence"}),
    (Condition.C, ROLE_REVISER): frozenset({"task", "solver_candidate", "verifier_findings"}),
}

WORKFLOW_NOTES: dict[Condition, str] = {
    Condition.A: "single-call reference; not call-matched to B or C",
    Condition.B: "serial self-refinement by one model identity (draft -> self-review -> revise); controls serial refinement only, not independent best-of-N sampling",
    Condition.C: "homogeneous role-separated council (solver -> independent verifier -> reviser); separate isolated stage invocations of one model lineage",
}

ROLE_INSTRUCTIONS: dict[str, str] = {
    ROLE_SOLVER: (
        "role:solver You are the Solver. Own the initial technical solution for the "
        "reported defect. Produce a scoped candidate fix and concise evidence supporting "
        "it. Stay within the in-scope files. You cannot approve your own work."
    ),
    ROLE_VERIFIER: (
        "role:verifier You are the Independent Verifier. Inspect the task and the "
        "candidate solution without access to hidden tests or evaluator internals. "
        "Attempt to falsify the solver's claims. Report concrete findings and state "
        "whether the evidence is sufficient. You cannot rewrite the solution or decide "
        "the final implementation."
    ),
    ROLE_REVISER: (
        "role:reviser You are the Reviser. Respond to every material finding with an "
        "explicit accept/reject disposition and rationale, then produce the final "
        "candidate submitted for external evaluation. You cannot suppress findings or "
        "modify evaluation infrastructure."
    ),
    ROLE_DRAFT: (
        "role:draft Single generalist agent producing an initial draft repair for the "
        "reported defect within scope."
    ),
    ROLE_SELF_REVIEW: (
        "role:self_review Same single generalist agent reviewing its own draft for "
        "defects before revision. This is serial self-refinement, not independent review."
    ),
}


def validate_context(condition: Condition, role: str, provided_keys: frozenset[str]) -> None:
    allowed = ALLOWED_INPUT_KEYS.get((condition, role))
    if allowed is None:
        raise GovernanceViolation(f"no context policy defined for condition={condition} role={role}")
    disallowed = provided_keys - allowed
    if disallowed:
        raise GovernanceViolation(
            f"stage {role} under condition {condition.value} received keys outside its policy: "
            f"{sorted(disallowed)}; allowed={sorted(allowed)}"
        )


def validate_stage_sequence(condition: Condition, executed: tuple[str, ...]) -> None:
    expected = CONDITION_STAGES[condition]
    if executed != expected[: len(executed)]:
        raise GovernanceViolation(
            f"invalid stage order for condition {condition.value}: executed={executed}, "
            f"expected_prefix={expected[: len(executed)]}, full={expected}"
        )
