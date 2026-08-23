# Decision 0002 — MVP Experimental Design and Council Governance

## Status

Accepted pending Human Chair approval

## Supersedes

This decision supersedes the experimental workflow and baseline definitions in [Decision 0001](0001-mvp-scope.md).

Decision 0001 remains part of project history. Where Decision 0001 conflicts with Decision 0002 — specifically its Coordinator → Specialist → Reviewer → Synthesizer workflow, its council-vs-single-model baseline definition, and its implication that those components suffice to test the core hypothesis — **Decision 0002 governs**.

Decision 0001's governing principle (measurement before infrastructure; every component earns its place experimentally) is reaffirmed and strengthened by this decision, not overturned.

## Decision

The first Model Council experiment will use controlled conditions designed to separately distinguish:

- **additional inference** (H1)
- **role-separated collaboration** (H2 — tested as the complete role-separated workflow bundle)
- **model diversity** (H3)

Initial architecture (per [Architecture Proposal v0.3](../architecture-proposal-v0.3.md)):

- Deterministic **Experiment Runner** (software, not an agent) enforcing governance
- **Solver**
- **Independent Verifier**
- **Reviser**
- **External Evaluator**
- **Human Chair**

## Experimental Conditions

| Condition | Workflow |
|---|---|
| A | Single-call reference: one model, one final candidate |
| B | Single-agent Draft → Self-review → Revise (same lineage/version throughout) |
| C | Homogeneous Solver → Independent Verifier → Reviser (isolated instances of the same model) |
| D | Heterogeneous Solver → Independent Verifier → Reviser, with homogeneous controls per participating model and counterbalanced role assignments |

Key comparisons and constraints:

- **C vs. B** is the primary H2 comparison.
- **D vs. corresponding homogeneous controls** is the H3 comparison.
- **D does not depend on H2 being positive.**
- Resource matching for the primary comparison is invocation-count and stage-budget matched; actual tokens, cost, and wall-clock time are reported as outcomes.

## Governance

**Authority follows role, not confidence, verbosity, or model prestige.**

| Role | Owns | Key prohibitions |
|---|---|---|
| Solver | Initial solution, patch/artifact, supporting evidence | Cannot approve own work; cannot touch tests/config/evaluator |
| Independent Verifier | Inspection, falsification attempts, defect/risk findings, evidence-quality calls | Cannot rewrite the solution silently or decide implementation |
| Reviser | Response to findings; final submitted artifact | Must address every material finding; cannot suppress dissent |
| Experiment Runner | Condition assignment, ordering, budgets, timeouts, context isolation, artifact preservation | Deterministic software; judges nothing about correctness |
| External Evaluator | Hidden-test execution, success determination, metrics | Outside council context; criteria not agent-modifiable |
| Human Chair | Commits, pushes, publication, spending, credentials, permissions, destructive actions, governance changes | Delegates routine technical disputes to role authority |

Technical enforcement (write boundaries, permissions, process isolation) must back prompt-level charters wherever practical.

Disagreement outside any defined authority is recorded as unresolved dissent. No autonomous debate loops in M1.

## Evaluation

**Primary:**
- Hidden-test task success (per the v0.3 §9 definition).

**Secondary:**
- Regression failures
- Prohibited modifications
- Token usage
- Cost
- Latency
- Retries/failures
- Human intervention
- Reproducibility across repeated trials

## Result Interpretation

Three categories, per preregistered statistical rules:

- **Positive** — improvement exceeds a preregistered minimum effect size.
- **Negative** — no practically meaningful advantage under a predefined equivalence/non-inferiority framework where appropriate.
- **Inconclusive** — uncertainty too wide to distinguish benefit from no benefit or harm.

"Failure to win" is not falsification. Underpowered non-results are Inconclusive, and are reported honestly as such.

## Deferred

Remain deferred until experiments justify them:

- Dynamic routing / learned capability scoring
- Generalized messaging / message bus
- Long-term memory
- Autonomous debate loops
- Voting / confidence aggregation
- Model-role automation

Each returns only via a future decision record citing evidence.

## Human Chair Decisions Still Required

These are open. No answers are invented here.

1. Sample size / number of trials per condition (power or sensitivity analysis).
2. Minimum effect size worth detecting.
3. Statistical decision framework per comparison (superiority/equivalence/non-inferiority; interval method).
4. Initial models/lineages for Condition D (and thus the homogeneous controls required alongside).
5. Per-run budget ceiling.
6. Whether best-of-N sampling is funded as an exploratory control condition.
7. Preregistration location (in-repo immutable file vs. external timestamped record).
8. Invalid-run adjudication details (who rules on edge cases, under what recorded procedure).
9. Initial benchmark task population (source, inclusion/exclusion, size, difficulty distribution).
