# SOL Validation Review — Architecture Proposal v0.2

**Reviewer:** Sol

**Version:** 0.2

**Date:** 2026-08-23

**Review type:** Validation of independent-review incorporation and remaining experimental confounders

**Overall assessment:** Needs revision before implementation

## Executive judgment

Ox substantially and faithfully incorporated the independent review's main architectural recommendations. The central design is now falsifiable and materially stronger than v0.1.

However, several causal confounders remain. Most importantly, “compute-matched” is not operationally defined, Condition D cannot isolate model diversity from model strength and role assignment, and the negative-result protocol mistakes “no demonstrated win” for falsification.

This validation applies to the current draft of [Architecture Proposal v0.2](../architecture-proposal-v0.2.md). It validates the experimental design, not experimental results; no experiment data yet exists to verify.

## 1. Incorporation fidelity

| Independent-review recommendation | v0.2 status | Assessment |
|---|---|---|
| Separate extra inference, council structure, and diversity | Adopted | Faithful |
| Use A/B/C/D experimental conditions | Adopted | Faithful in structure |
| Compare C versus B, not merely C versus A | Adopted | Faithful |
| Replace coordinator pipeline with Solver → Verifier → Reviser | Adopted | Faithful |
| Use deterministic non-agent experiment control | Adopted | Faithful |
| Freeze tasks, prompts, versions, and run specifications | Adopted | Faithful |
| Isolate the evaluator and hidden tests | Adopted | Faithful |
| Use objective M1 outcomes rather than LLM judging | Adopted | Faithful |
| Fix role assignments during the pilot | Adopted | Faithful for A–C |
| Counterbalance assignments when testing specialization/diversity | Deferred | Material gap for D |
| Operationalize equivalent budgets and information access | Partially adopted | Not sufficiently defined |
| Revise the accepted MVP decision | Not adopted in v0.2 | Repository governance remained inconsistent at the time of review |

Ox accurately acknowledges the original causal problem, separates the hypotheses, introduces the recommended conditions, and adopts the smaller workflow.

The research-governance and objective-evaluation sections are also faithful and unusually strong for an early proposal.

## 2. Remaining confounders

### 2.1 High: Condition D does not isolate model diversity

Condition D uses different model lineages while Condition C uses one model lineage. Any D-versus-C difference could result from:

- One model simply being stronger.
- A model being particularly well suited to its assigned role.
- Different context windows or tool-use reliability.
- Different price, latency, or output-token behavior.
- Diversity itself.

Fixed assignment is insufficient. Counterbalancing is currently deferred, but it is essential to H3 rather than a later refinement.

For a credible H3 test:

- Run homogeneous councils for every participating model.
- Run heterogeneous councils using the same model set.
- Rotate or counterbalance models across Solver, Verifier, and Reviser.
- Compare heterogeneous performance against the corresponding homogeneous controls.
- Match or explicitly model token, cost, tool, and context-window differences.

H3 is also incorrectly made dependent on H2 succeeding. A heterogeneous council could improve outcomes even when a homogeneous council does not. Skipping D after a null H2 result would leave the project's diversity thesis untested and introduce outcome-dependent experiment selection.

### 2.2 High: “Compute-matched” is not operationally defined

The proposal says all conditions share identical token and call budgets, but Condition A has one call while B and C have three stages. That statement cannot be interpreted literally without more detail.

For B versus C, matching must specify:

- Number of model invocations.
- Maximum and actual input/output tokens per stage.
- Whether cached tokens count.
- Tool-call and execution-time limits.
- Retry budgets.
- Context included at each handoff.
- Whether equality means tokens, cost, wall time, or invocation count.

Condition A should be described as a single-call reference, not as call-matched. B and C should be the strictly compute-matched comparison.

### 2.3 High: Condition B does not fully control repeated sampling

v0.2 says B controls repeated sampling, but Draft → Self-review → Revise is serial self-refinement, not independent repeated sampling.

C changes several things simultaneously:

- Role prompts.
- Agent identity or conversational continuity.
- Context isolation.
- Information-handoff format.
- Reviewer independence.

Therefore C-versus-B tests the entire workflow bundle, not role specialization alone.

Either:

- Reframe H2 as testing the complete role-separated workflow bundle; or
- Add an isolated three-call generalist condition with the same handoffs but without specialized role prompts.

A best-of-N control is not necessarily mandatory for the pilot, but v0.2 should not claim B already controls that mechanism.

### 2.4 High: The negative-result protocol uses invalid falsification logic

The proposal says hypotheses are falsified when gains do not exceed noise or one condition does not beat another.

Failure to demonstrate superiority is not evidence of equivalence or no effect. An underpowered experiment can produce the same result.

The preregistration must define:

- A minimum effect size worth detecting.
- A superiority, equivalence, or non-inferiority framework.
- Confidence intervals or another uncertainty procedure.
- How repeated trials nested within tasks are handled.
- “Positive,” “negative,” and “inconclusive” outcomes separately.

A wide interval spanning benefit and harm must be reported as inconclusive, not falsification.

### 2.5 Medium: Prompt-development effort can confound conditions

v0.2 correctly separates prompt-development tasks from held-out evaluation, but it does not control how prompts are developed.

If council roles receive more iteration or human optimization than the generalist baseline, C may win because its prompts were better tuned.

The protocol should predefine:

- Separate development and held-out task sets.
- Equal prompt-development budgets across conditions.
- A stopping rule for prompt revisions.
- Who selects the final prompts.
- Whether selection is blinded to held-out outcomes.

### 2.6 Medium: The task population is underdefined

“Code repair” is too broad to establish the benchmark population. Results could depend heavily on which languages, repository sizes, test-coverage levels, and defect types are selected.

The experiment specification should define:

- Task source and eligibility rules.
- Inclusion and exclusion criteria.
- Difficulty and repository-size distribution.
- Languages and frameworks.
- Whether tasks are sampled or curated.
- How ceiling and floor tasks are handled.

Without this, task selection remains an experimenter degree of freedom.

### 2.7 Medium: Retries and human intervention are recorded but not causally handled

Retries, invalid runs, and human intervention are logged, but their treatment in the primary outcome remains unresolved. Human rescue could disproportionately improve one condition.

Predefine that:

- Timeouts and unrecovered execution failures count against the assigned condition.
- Retry counts and triggers are identical.
- Human intervention either counts as primary-task failure or is analyzed under a separately labeled assisted outcome.
- Post-randomization exclusions are prohibited except under preregistered invalid-run rules.

The proposal itself acknowledges that invalid-run adjudication is unresolved.

### 2.8 Medium: Task-success scoring needs a precise definition

“Hidden-test task success” is a good primary outcome, but it still needs an operational definition:

- Must all hidden and regression tests pass?
- Is success binary or partially scored?
- Are unchanged existing failures allowed?
- How are flaky tests detected?
- Are test timeouts failures?
- What happens when a patch modifies tests or evaluation infrastructure?

The evaluator version and hidden-test snapshot should be part of the immutable experiment specification.

### 2.9 Medium: Decision 0001 contradicts v0.2

At the time of this review, v0.2 said it was consistent with Decision 0001 but explicitly replaced that decision's accepted workflow.

Decision 0001 still accepted:

```text
Coordinator → Specialist → Reviewer → Synthesizer
```

and the ambiguous single-model baseline.

Before implementation, a new decision record should supersede or amend Decision 0001. Otherwise the repository contains two conflicting authoritative directions.

### 2.10 Low: Role charters do not guarantee control separation

The claim that agents “never compete for control” is stronger than the documented mechanism supports. Prompt-level charters describe expected behavior; they do not enforce it.

The deterministic runner should enforce:

- Which artifact each role may modify.
- Immutable evaluator and experiment files.
- Stage transitions.
- Scope and tool permissions.
- Preservation of the original candidate, critique, and revision as distinct artifacts.

## 3. Required changes before implementation

1. Operationally define compute matching for B versus C.
2. Correct the claim that B controls independent repeated sampling.
3. Reframe H2 as a workflow-bundle test or add an isolation/role-prompt ablation.
4. Redesign D with per-model homogeneous controls and counterbalanced role assignments.
5. Remove H3's logical dependency on a positive H2 result, or explicitly defer H3 without claiming it has been tested.
6. Replace binary “falsified” rules with superiority/equivalence thresholds and an inconclusive category.
7. Define prompt-tuning parity and the benchmark sampling frame.
8. Resolve task-success, retries, intervention, and invalid-run rules before execution.
9. Supersede or amend Decision 0001.

## 4. Final judgment

Ox faithfully incorporated the independent review at the architectural level. v0.2 is no longer a platform-first proposal and now contains the correct basic causal ladder.

It is not yet an implementation-ready experimental protocol. A–C can become credible after compute matching, prompt-development parity, task-selection rules, and statistical decision criteria are made explicit. Condition D requires a more substantial redesign before it can support any claim about model diversity.
