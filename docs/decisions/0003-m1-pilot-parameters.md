# Decision 0003 — M1 Pilot Parameters

## Status

Accepted by Human Chair

## Relationship to Prior Decisions

- [Decision 0002](0002-mvp-experiment-design.md) continues to govern the Model Council experimental architecture and council governance.
- Decision 0003 records the Human Chair's initial operating parameters for the M1 exploratory pilot.
- Decision 0003 does not replace the A/B/C/D architecture defined by Decision 0002.
- A formal M1 preregistration will later freeze exact tasks, prompts, model identifiers, budgets, evaluator versions, randomization, and other execution details before held-out evaluation begins.

---

## 1. Pilot Purpose

M1 is an **exploratory pilot**, not a definitive statistical demonstration that Model Councils outperform individual models.

Its immediate goals are to:

- verify that the experimental harness works
- determine whether the role-separated council workflow produces a practically interesting signal
- measure operational cost and complexity
- estimate variance for later experiment design
- identify whether a larger powered study is justified

Results from M1 must not be generalized beyond the defined task population.

## 2. Benchmark Domain

The initial benchmark domain is:

**Python code repair**

A valid task begins from a frozen repository snapshot containing a known behavioral defect. The agent receives:

- a written bug report
- permitted repository context
- permitted tools

and must produce a scoped repair.

The repair must:

- correct the specified behavior
- pass hidden task-specific tests
- introduce no new regression failures
- leave documented pre-existing failures unchanged
- not modify prohibited evaluation infrastructure
- remain within task scope

Excluded from M1:

- new feature development
- broad refactoring
- documentation-only changes
- formatting/lint-only tasks
- dependency-upgrade tasks
- tasks requiring external accounts or APIs
- flaky or nondeterministic defects
- giant repository-wide rewrites
- tasks without objective evaluation
- tasks previously exposed during model or prompt development

## 3. Pilot Size

Initial target:

- approximately **12 held-out repair tasks**
- across approximately **3–4 small or medium Python repositories**
- roughly **2–4 defects per repository**

Target difficulty distribution:

- approximately 4 easy
- approximately 4 medium
- approximately 4 hard

This is a pilot target, not a powered confirmatory sample size. If task construction reveals that a different exact count is needed for quality or balance, the Human Chair must approve the change before held-out execution.

## 4. Task Construction

Prefer realistic defects rather than only trivial synthetic mutations. The task pool may include:

- realistic seeded defects
- defects emerging from AI-generated repositories
- carefully selected historical bugs where reproducibility and contamination controls are adequate

AI-generated repositories may be used as a source of realistic bugs. However:

- each repair task must be isolated and independently evaluable
- the entire buggy repository must not automatically be treated as one task
- each defect needs defined expected behavior
- each defect needs hidden evaluation coverage
- frozen starting snapshots must be preserved

Development tasks and held-out evaluation tasks must remain completely separate. Any task inspected during harness development or prompt tuning is permanently excluded from the held-out evaluation set.

## 5. Tests and Evaluation

Each repair task should have:

### Visible tests
Available to agents during the repair process.

### Hidden task-specific tests
Unavailable to agents and executed only by the External Evaluator.

### Regression tests
Used to ensure unrelated behavior remains intact.

The primary outcome remains the hidden-test task-success definition established by [Architecture v0.3](../architecture-proposal-v0.3.md) and Decision 0002.

## 6. Initial Trial Count

For the exploratory pilot:

- Conditions A, B, and C will each run on every held-out task.
- Initial target: one primary run per task per condition.

With 12 tasks, this yields approximately:

- 12 A runs
- 12 B runs
- 12 C runs
- **36 core pilot runs**

Additionally:

- select a small subset of approximately 3 tasks in advance
- repeat those runs once to obtain an early indication of run-to-run variance

The repeated subset must be selected before examining held-out results. This pilot sample must not be presented as statistically powered for broad superiority claims.

## 7. Practically Interesting Pilot Effect

For M1, a **practically interesting pilot signal** is defined as approximately:

**2 additional successful repairs out of 12 tasks**

— roughly a 16.7 percentage-point difference. This is:

- a practical decision threshold for whether further study is justified
- not a formal proof of superiority
- not a claim that smaller effects are zero

Pilot interpretation:

### Positive pilot signal
C exceeds B by at least approximately 2 successful tasks, without a clearly disproportionate operational or cost penalty.

### Adverse pilot signal
C trails B by at least approximately 2 successful tasks.

### Inconclusive
The observed difference falls between those thresholds or uncertainty prevents a useful interpretation.

[Architecture v0.3](../architecture-proposal-v0.3.md)'s broader Positive / Negative / Inconclusive statistical framework is preserved. A later confirmatory study must perform formal sample-size and power/sensitivity analysis.

## 8. Resource Matching

For the primary B-vs-C comparison, use the Architecture v0.3 principle:

**invocation-count and stage-budget matched**

B and C should have:

- the same number of model stages
- equivalent maximum input budgets per stage
- equivalent maximum output budgets per stage
- equivalent tool access
- equivalent execution limits
- equivalent retry rules
- the same frozen repository snapshot

Actual token usage, cached-token usage, dollar cost, latency, and tool usage must be recorded separately as outcomes. Condition A remains the single-call reference and is not call-matched to B or C.

Initial working resource ceilings may be established during development runs and must be frozen in the preregistration before held-out evaluation.

## 9. Invalid Runs, Retries, and Human Intervention

Initial operating principles:

- Agent modification of hidden tests or evaluator infrastructure is prohibited and counts against the assigned condition according to the preregistered invalid-run policy.
- Unrecovered timeout counts as failure.
- Infrastructure failure clearly external to agent behavior may receive one standardized infrastructure retry.
- Model/API failure uses the same predefined retry policy across comparable conditions.
- Substantive human assistance after a run begins does not count as an unassisted success.
- Assisted outcomes may be recorded separately.
- No discretionary post-hoc exclusions based on whether a result is inconvenient.
- Known pre-existing test failures may remain, but no new regression failures are permitted.
- Flaky tasks should be detected and removed before the held-out benchmark is frozen.

Exact invalid-run adjudication rules remain to be finalized in the M1 preregistration.

## 10. Formal H3 Model Pool

The initial planned known-lineage model pool for the formal heterogeneous Model Council experiment is:

| Model | Lineage |
|---|---|
| SOL | OpenAI |
| GLM 5.2 | Zhipu AI |
| Kimi K2.7 Coder | Moonshot AI |
| DeepSeek | DeepSeek |

Exact provider endpoints and model/version identifiers must be frozen in the preregistration before formal evaluation.

Models must not be permanently assigned roles based on reputation or assumed strengths. For the H3 diversity experiment:

- models must be rotated or counterbalanced across Solver, Verifier, and Reviser roles
- homogeneous council controls are required for each participating model
- heterogeneous councils must be compared against appropriate homogeneous controls
- role assignment schedules must be preregistered

This prevents the project from confusing model strength, role fit, lineage diversity, and council structure.

## 11. Ox Alpha Status

**Ox Alpha — provenance unknown / exploratory**

Ox Alpha may participate in:

- architecture work
- implementation development
- exploratory council runs
- non-preregistered research comparisons

Ox Alpha should not currently be used as evidence for a known-lineage diversity claim because its provenance has not been confirmed.

Ox may later become eligible for the formal H3 pool if:

- provenance becomes sufficiently established
- reproducible access is available
- the Human Chair approves its inclusion

No speculation about Ox Alpha's origin is recorded here.

## 12. Best-of-N Control

Best-of-N sampling is **not required for the core M1 pilot**. It may later be run as an exploratory control if:

- budget permits
- initial results justify it
- the Human Chair approves

Condition B must not be claimed to already control independent best-of-N sampling.

## 13. Preregistration

The formal M1 preregistration will be stored in the repository at:

```
experiments/m1/preregistration.md
```

It must be committed before any held-out evaluation runs begin. The preregistration should freeze at minimum:

- held-out task manifest
- task snapshots
- development/evaluation split
- prompt versions
- model/provider/version identifiers
- experimental conditions
- role assignments
- resource budgets
- retry rules
- invalid-run rules
- evaluator version
- hidden-test snapshots
- condition order/randomization
- repeated-task subset
- primary and secondary outcomes
- result interpretation rules

Git history serves as the timestamped project record for this pilot.

## 14. Still Deferred Until Preregistration

The following exact execution parameters remain to be frozen after development work provides the necessary information. These are preregistration details, not unresolved architecture questions:

- exact held-out task list
- exact repository set
- exact stage token ceilings
- exact wall-clock limits
- exact tool-call ceilings
- exact provider/model identifiers
- exact randomization schedule
- exact invalid-run adjudication edge cases
- exact repeated-task subset

## 15. Human Chair Decision

The Human Chair approves this small-first approach. The project prefers:

**a small interpretable pilot that produces trustworthy evidence**

over:

**a large expensive benchmark designed before the harness has demonstrated basic reliability.**

Complexity should continue to be earned through evidence.
