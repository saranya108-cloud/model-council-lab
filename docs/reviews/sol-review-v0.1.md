# Independent Systems Review — Model Council Lab

**Reviewer:** Sol

**Version:** 0.1

**Date:** 2026-08-23

**Review type:** Pre-implementation research-design review

**Disposition:** Revise the MVP experiment design before implementation

## Executive judgment

The project has moved in the right direction by rejecting the infrastructure-heavy v0.1 proposal in favor of a smaller experiment. Dynamic routing, persistent knowledge, workflow engines, and a generalized message bus are correctly deferred.

However, the accepted MVP is not yet sufficient to test the stated hypothesis. A four-agent, four-call council compared only with a one-call model would confound council structure with additional inference, additional context, review opportunities, and potentially stronger model assignments. A positive result could not be attributed to specialization or collaboration.

The MVP should be reframed as a controlled research harness with three initial conditions:

1. A single-call reference.
2. A compute-matched single-agent refinement process.
3. A compute-matched, role-separated council using the same underlying model.

A heterogeneous-model council should then be a fourth condition or immediate follow-up. This separates the effects of extra compute, role structure, and model diversity.

## 1. Architecture assessment

### MVP scope

[Decision 0001](../decisions/0001-mvp-scope.md) is directionally sound. Its principle that every component must earn its place experimentally is appropriate for a research project. The deferrals also respond well to the [adversarial review](../adversarial-review-v0.1.md)'s central criticism that v0.1 described a platform before establishing an effect.

The accepted architecture is nevertheless not quite the smallest causal experiment. For one code-repair task, a learned coordinator is unnecessary: task selection and workflow sequencing can be deterministic experiment-runner functions. Likewise, a separate synthesizer has little to synthesize when there is one proposal and one critique; its real function is revision.

The first council should therefore be:

```text
Solver → Independent Verifier → Reviser
```

This retains the essential interaction—one agent challenging another—while removing an unnecessary planning call and clarifying responsibility for the final answer.

### Correctly deferred

I agree with deferring:

- Dynamic routing and capability learning.
- Multi-provider infrastructure.
- Local/cloud optimization.
- Generalized message protocols and workflow engines.
- Long-term agent memory and knowledge distillation.
- Autonomous debate loops.
- A broad library of domain personas.
- Voting and confidence aggregation.

These components could be valuable later, but none is required to determine whether structured collaboration produces an observable effect.

### Essential elements currently missing

The following are research infrastructure, not product infrastructure, and should exist before the first reported experiment:

- An immutable experiment specification containing condition, task, model identifier, prompt version, parameters, budgets, and termination rules.
- Frozen task snapshots and hidden evaluation tests.
- Isolation between runs and no cross-run agent memory.
- A deterministic condition allocator with randomized or counterbalanced run order.
- Raw artifact preservation: prompts, responses, patches, tool traces, failures, token accounting, and timestamps.
- An evaluator outside the council's context and control.
- Explicit timeout, retry, partial-failure, and invalid-run rules.
- A preregistered primary outcome and analysis method.
- Reproducible model/version identification, with provider changes recorded as experimental discontinuities.

Basic logging alone is insufficient if it cannot reconstruct exactly what treatment each task received.

## 2. Research design

### What hypothesis is actually being tested?

The [README](../../README.md) asks whether specialized agents can outperform one model working alone. That question contains at least three distinct hypotheses:

- **H1 — Additional inference:** Multiple calls improve results over one call.
- **H2 — Council structure:** Independent role-separated calls outperform an equally funded single-agent refinement process.
- **H3 — Model diversity:** Heterogeneous models outperform the same council topology using one model lineage.

The accepted MVP can observe a performance difference, but it cannot currently separate these effects. Its assertion that the chosen components are sufficient to test the core hypothesis is too strong.

### Required experimental conditions

| Condition | Workflow | Purpose |
|---|---|---|
| A: Single-call reference | One model produces a final answer | Measures the simplest deployment |
| B: Single-agent control | Draft → self-review → revise, with one generalist model | Controls for additional calls and revision |
| C: Homogeneous council | Solver → verifier → reviser, using isolated instances of the same model | Tests role separation and independent context |
| D: Heterogeneous council | Same topology and budgets, but preassigned different models | Tests model diversity |

The primary comparison for council structure is **C versus B**, not C versus A. The primary comparison for diversity is **D versus C**. Condition A remains useful as a cost and latency reference.

If the project runs only A and C, the result should be described as “multi-call workflow versus single-call inference,” not evidence that specialization works.

### Baselines

“One model performing the same task with equivalent tools and context” remains ambiguous. “Equivalent” must specify:

- The same starting task and repository snapshot.
- The same available tools and execution limits.
- Equal or separately reported token and call budgets.
- The same model where the causal contrast requires it.
- No privileged hidden-test access.
- Comparable opportunity to revise.
- Identical failure and retry accounting.

A best-of-N or self-refinement control could also be added if affordable. Otherwise the council may merely benefit from repeated sampling.

### Evaluation

Code repair is a good first task category because correctness can be evaluated outside the model. The initial primary outcome should be hidden-test task success, supplemented by regression failures, invalid modifications, cost, latency, and human intervention.

“Quality of output” should either be operationally defined or removed from the primary M1 scorecard. An unblinded LLM judge would weaken an otherwise objective experiment.

Before running the benchmark:

- Freeze tasks, prompts, budgets, and exclusion rules.
- Select sample size using an expected-effect or sensitivity analysis.
- Randomize condition order within tasks.
- Run repeated trials where stochasticity is enabled.
- Report paired effects, uncertainty intervals, and all failures.
- Keep exploratory analyses clearly separate from preregistered outcomes.
- Treat results from one task category as task-specific, not proof of a general council advantage.

## 3. Agent design

The broad roles in the architecture proposal are plausible product roles, but most are premature research variables. The useful initial roles are functional rather than occupational:

- **Solver:** Produces the candidate patch and a concise evidence record.
- **Verifier:** Independently inspects the task, patch, and test evidence; identifies concrete defects and attempted falsifications.
- **Reviser:** Accepts or rejects each criticism and produces the final patch.

The verifier should see the original task and candidate artifact, but not unnecessary chain-of-thought or model identity. This reduces anchoring without pretending stylistic anonymization is reliable.

Roles should be fixed during the first experiment so the treatment is reproducible. Model-to-role assignment should not be chosen dynamically. When specialization is later tested, assignments should be preregistered and counterbalanced or rotated across tasks. Otherwise task difficulty and model strength will be confused with role suitability.

A learned coordinator should be introduced only when tasks genuinely require decomposition and after a fixed non-agent coordinator has established a baseline.

## 4. Additional failure modes

Ox's adversarial review identifies major risks, especially agreement cascades, synthesis errors, evaluation gaming, and cost growth. Additional risks include the following.

### Coordination

- **Lossy handoffs:** A compact proposal or critique may omit evidence needed downstream.
- **Artifact/version mismatch:** The verifier may review a different patch state than the reviser receives.
- **Role collapse:** Identical models may reproduce the same reasoning despite different prompts.
- **Verifier impotence:** A valid criticism may be logged but ignored by the reviser.
- **Synthesis bottleneck:** Final quality may mostly measure the reviser's ability, masking council contribution.
- **Task-boundary errors:** A coordinator's incorrect decomposition can make individually correct subtasks collectively wrong.

### Evaluation

- Hidden-test leakage or benchmark contamination.
- Agents modifying tests or evaluation infrastructure.
- Flaky tests being interpreted as model variance.
- Post-hoc task exclusion or metric selection.
- Reusing tasks during prompt development and then treating them as held out.
- Multiple comparisons producing apparent wins by chance.
- Inability to assign credit when the final answer improves.

### Model bias

- Correlated errors among models trained on similar data.
- Provider-family style bias influencing judges or reviewers.
- Order and position effects in sequential critiques.
- Verbosity being mistaken for rigor.
- Model updates changing results mid-study.
- Persona prompts altering compliance or output style more than reasoning ability.

### Cost and operations

- Repeated transmission of repository context dominating token cost.
- Retry and failed-run costs being omitted.
- Caching changing both price and latency across conditions.
- Human setup and intervention costs being excluded.
- Rate limits or timeouts disproportionately harming council runs.
- Partial runs producing incomparable artifacts.
- Non-reproducible hosted-model versions.

### False confidence

- Several agents repeating one correlated error may look like consensus.
- A dissent record may create an appearance of rigor without improving correctness.
- Confidence scores may be uncalibrated and incomparable across models.
- Successful synthesis may conceal that no agent verified the decisive claim.

## 5. Points of agreement and disagreement

### Points of agreement

- The architecture proposal correctly treats cost and latency as first-class outcomes.
- Ox is correct that routing, generalized messaging, workflow engines, and long-term knowledge are premature.
- Objective code tasks are the appropriate initial domain.
- Run history should preserve disagreement and failure evidence.
- A negative result must be allowed to invalidate the proposed architecture.
- A reviewer/verifier is important because challenge is the council's central proposed mechanism.

### Points of disagreement

- A one-call baseline is not enough, even if well prompted.
- “One provider, three calls, honest numbers” still does not establish a council effect without a compute-matched multi-pass control.
- Single-provider-first is operationally sensible, but it cannot establish the README's model-diversity claim.
- The accepted coordinator is unnecessary for an initially fixed task workflow.
- “Comparable context” should be replaced by explicit budgets and information-access rules.
- Additional experimental controls do not improperly complicate M1; they prevent an uninterpretable result.

## 6. Recommended changes before implementation

1. Rewrite the primary question as separate hypotheses for extra inference, role separation, and model diversity.
2. Replace the single baseline with conditions A–C above; add D before making diversity claims.
3. Replace the coordinator–specialist–reviewer–synthesizer pipeline with solver–verifier–reviser for the first task class.
4. Define the independent evaluator, frozen task suite, hidden tests, and prohibited task/test mutations.
5. Specify exact budgets, model parameters, retry rules, timeouts, and failure accounting.
6. Define one primary outcome and statistical analysis before examining results.
7. Version every prompt, task, model, tool configuration, and artifact.
8. State that M1 is a task-specific pilot unless its sample size supports confirmatory conclusions.

## 7. Proposed MVP architecture

```text
Frozen task manifest
        ↓
Randomized condition allocator
        ↓
Isolated run executor
  ├─ A: single call
  ├─ B: generalist draft → self-review → revise
  └─ C: solver → independent verifier → reviser
        ↓
Artifact and telemetry recorder
        ↓
External hidden-test evaluator
        ↓
Paired analysis: success, regressions, cost, latency, intervention
```

No router, message bus, learned memory, model voting, autonomous debate, or agent-controlled evaluator is needed.

This architecture can produce a falsifiable result. If C does not outperform B under comparable budgets, role-separated councils have not earned further infrastructure. If C wins, condition D can test whether heterogeneous models add value beyond the council structure itself.
