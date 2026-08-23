# Model Council Lab — Architecture Proposal v0.3

> Status: PROPOSED. Supersedes [Architecture Proposal v0.2](architecture-proposal-v0.2.md).
> Integrates SOL's validation review of v0.2 ([SOL Validation Review](reviews/sol-validation-review-v0.2.md)), retaining valid criticism from [Adversarial Review v0.1](adversarial-review-v0.1.md) and [SOL Systems Review v0.1](reviews/sol-review-v0.1.md).
> Companion governance record: [Decision 0002 — MVP Experimental Design and Council Governance](decisions/0002-mvp-experiment-design.md).

---

## Framing

The long-term vision is unchanged — councils of diverse specialized models may outperform single models under explicit roles and authority boundaries. v0.3's contribution is precision: making the initial experiment **causally interpretable** and **operationally defined** so that any result means exactly one thing.

This is a research design document. Every operational rule below exists to prevent a specific way the first experiment could produce an uninterpretable or self-deceiving result.

---

## 1. Research Hypotheses

Three hypotheses remain separate and are tested with distinct comparisons.

### H1 — Additional inference
Does giving a model additional calls and revision opportunities improve results over single-call inference?
- *Test:* Condition B vs. Condition A.

### H2 — Role-separated workflow
Does an independently role-separated workflow outperform an equivalently resourced single-agent refinement workflow?

**Precision requirement:** for M1, H2 tests the **complete role-separated workflow bundle**, not pure "specialization" in isolation. The bundle includes:
- separate agent instances
- independent verifier context
- role-specific prompts
- structured handoffs
- verifier independence
- revision based on external critique

C-vs-B does not isolate every individual component of this bundle; it tests the bundle as a treatment. Decomposing the bundle is future work and requires its own factorial designs.

### H3 — Model diversity
Does a heterogeneous council outperform corresponding homogeneous councils after controlling for model strength, role fit, and resource differences?

**Independence requirement:** H3 must not depend logically on H2 producing a positive result. A homogeneous council may fail while a heterogeneous council succeeds — that pattern is itself informative, and the design must be able to observe it. See §12.

## 2. Experimental Conditions

First benchmark domain: code repair (see §8 for population definition).

### Condition A — Single-call reference
One model receives:
- the frozen task
- the permitted tools
- the task context

and produces one final candidate.

*Purpose:* simple deployment reference; cost baseline; latency baseline; H1 reference.
*A is **not** described as compute-matched to B or C.* It anchors the simplest deployment.

### Condition B — Single-agent refinement control
One generalist model performs:

```
Draft → Self-review → Revise
```

Same model lineage and model version throughout.

*Purpose:* measure the effect of additional inference and revision; serve as the primary control for Condition C.
*Scope limit:* B controls **serial self-refinement only**. It does not control independent repeated sampling (best-of-N). If best-of-N is later funded, it is reported as a separately labeled exploratory condition.

### Condition C — Homogeneous role-separated council
Isolated instances of the same underlying model:

```
Solver → Independent Verifier → Reviser
```

*Purpose:* compare role-separated collaboration against serial self-refinement.
***Primary comparison: C vs. B.*** This tests the role-separated workflow bundle (§1, H2) — nothing stronger.

### Condition D — Heterogeneous council
Same `Solver → Independent Verifier → Reviser` topology, models from different lineages.

To keep H3 unconfounded by model strength or role fit, D requires:
1. homogeneous council controls for every model participating in D;
2. heterogeneous councils using the same participating model set;
3. role rotation or counterbalancing across Solver, Verifier, Reviser;
4. fixed preregistered assignment schedules;
5. paired comparison against corresponding homogeneous controls;
6. explicit accounting for context-window, tool-use, cost, token, and latency differences.

**D is not conditional on C winning.** It may run after the A–C pilot for practical reasons, but it remains an independent experiment required to test H3.

## 3. Resource Matching (Operational Definition)

"Compute-matched" is replaced by explicit rules. For the primary **B-vs-C** comparison, matching is specified across:

| Resource | Rule |
|---|---|
| Model invocations | Matched count per task |
| Input tokens per stage | Maximum cap per stage |
| Output tokens per stage | Maximum cap per stage |
| Cached tokens | Stated whether counted toward budget |
| Tool calls | Limit per stage |
| Execution time | Limit per stage |
| Retries | Identical retry budgets |
| Context at each stage | Enumerated per stage in the experiment spec |
| Repository snapshot | Identical commit/snapshot per task |
| Tool availability | Identical tool set |
| Model/version | Same lineage + version (B and C) |
| Sampling parameters | Temperature/top-p recorded; matched where controllable |

**Primary resource-matching principle: invocation-count and stage-budget matched**, with actual tokens, dollar cost, and wall-clock time reported separately as outcomes rather than enforced as constraints. Dollar cost cannot always be matched exactly across models; pretending otherwise hides real differences.

For Condition D, resource differences between models are **reported and modeled**, not hidden — heterogeneous councils will differ in cost/latency by construction, and those differences are part of the finding.

## 4. Experiment Runner and Enforcement

The Experiment Runner is **deterministic software, not an AI agent**. Governance is technically enforced, not merely prompted. Responsibilities:

- Assign experimental condition (randomized/counterbalanced order).
- Instantiate each stage.
- Enforce stage ordering.
- Enforce timeout and retry limits.
- Provide only allowed context to each role (verifier context isolation included).
- Enforce tool permissions.
- Enforce artifact-write boundaries (each role writes only its designated workspace).
- Prevent mutation of frozen tasks, evaluator files, and hidden tests.
- Preserve each stage's artifact separately and immutably.
- Record failures and human interventions.
- Enforce termination rules.

Role authority is technically constrained wherever practical: filesystem permissions, write-scoped directories, and process isolation back up the charters in §5. Prompt-level rules alone are insufficient where enforcement is cheap.

## 5. Council Governance and Decision Authority

**Principle: authority follows role — not confidence, verbosity, or model prestige.**

### Solver
*Owns:* initial candidate solution; initial patch/artifact; evidence supporting the solution.
*May modify:* only the candidate workspace/artifact allowed for that stage.
*Cannot:* approve its own solution; alter hidden tests; alter experiment configuration; alter evaluator files.

### Independent Verifier
*Owns:* independent inspection; falsification attempts; defect/risk findings; evidence-quality assessment.
*May:* declare evidence insufficient; flag concrete defects; flag regression risks; flag unsupported assumptions.
*Cannot:* silently rewrite the solution; make the final implementation decision; alter evaluation infrastructure; expand task scope.

Sees the original task and candidate artifact; not unnecessary reasoning traces or model identity.

### Reviser
*Owns:* response to each verifier finding; final candidate artifact submitted for external evaluation.
*Must:* explicitly accept or reject each material verifier finding; record rationale; preserve unresolved dissent verbatim.
*Cannot:* suppress verifier findings; alter hidden tests; alter evaluator rules; authorize external consequential actions.

### External Evaluator
*Owns:* hidden-test execution; objective task-success determination; regression detection; metric collection.
*Cannot:* participate in council deliberation; reveal hidden-test details to agents; permit agents to modify evaluation criteria.

### Human Chair
*Owns final authority over consequential actions:* commits; pushes; publication; spending; infrastructure changes; credentials; permissions; destructive actions; changes to experiment governance.

The chair does not arbitrate normal technical disagreements already covered by role authority.

## 6. Conflict Resolution

No unrestricted debate; no majority vote in M1.

- Verifier owns evidence-quality objections.
- Reviser owns the final response to objections.
- External Evaluator owns objective pass/fail results.
- Human Chair owns consequential actions.
- Disagreements outside all defined authorities are recorded as **unresolved dissent** in the run record.
- No autonomous debate loops.
- No agent may expand its own authority by claiming higher confidence.

Preserved as **distinct immutable run artifacts**: original candidate, verifier critique, final revision.

## 7. Prompt Development Parity

Prompt tuning can silently bias one condition. Rules:

- **Separate development-task set** and **held-out evaluation-task set**; development tasks never appear in evaluation.
- **Equal prompt-development effort** across Conditions B and C (formally logged: iterations and revisions; time tracked informally, not instrumented — full instrumentation revisitable later if prompt-tuning bias proves measurable).
- **Fixed prompt-revision budget** per condition, declared before development begins.
- **Stopping rule** for prompt iteration (e.g., budget exhausted or development-set performance plateaus — whichever first).
- **Named owner** selects final prompts.
- **Prohibition:** held-out evaluation outcomes may never be used to tune prompts.
- Prompt versions frozen before evaluation; frozen versions embedded in the immutable experiment specification.

## 8. Task Population

"Code repair" is operationally defined in the experiment manifest:

| Field | Required definition |
|---|---|
| Task source | Named dataset/repository/provenance |
| Inclusion criteria | Explicit |
| Exclusion criteria | Explicit |
| Languages | Enumerated |
| Repository-size range | Min/max |
| Test coverage | Requirements where applicable |
| Defect categories | Taxonomy |
| Difficulty distribution | Declared |
| Sampling vs. curation | Stated method |
| Trivial ceiling tasks | Identified/excluded or analyzed separately |
| Impossible floor tasks | Identified/excluded or analyzed separately |

M1 is a **task-specific pilot**. No claim of general Model Council superiority may be drawn from one narrow task population.

## 9. Task Success Definition

**Primary outcome — a task succeeds only if ALL hold:**
1. All required hidden task-specific tests pass.
2. No new regression tests fail.
3. Pre-existing known failures are unchanged.
4. The submitted patch modifies no prohibited evaluation/test infrastructure.
5. Execution completes within the allowed timeout.

Additional specifications:
- **Flaky tests:** identified during benchmark validation; flaky-test failures trigger a preregistered re-run rule, not silent exclusion.
- **Evaluator timeouts:** recorded as failures of the assigned condition, not invalid runs, unless the timeout stems from harness error (preregistered distinction).
- **Existing failing tests:** catalogued per task snapshot; "unchanged" is the criterion, not "passing."
- **Partial credit:** none for the primary outcome. Secondary metrics may capture partial progress descriptively.
- **Prohibited test modifications:** invalidate the run as a failed primary attempt for the assigned condition (not merely excluded data).

The evaluator version and hidden-test snapshot are components of the immutable experiment specification.

## 10. Retries, Failures, and Human Intervention

Predefined before any run:
- **Identical retry triggers** across conditions.
- **Identical maximum retry counts** where applicable.
- Timeouts and unrecovered execution failures **count against the assigned condition**.
- **Post-randomization exclusions prohibited** except under preregistered invalid-run rules.
- Human rescue/intervention either:
  - counts as a primary-task failure, or
  - is reported separately as an explicitly labeled *assisted outcome*.

Quiet human rescue improving one condition is a protocol violation, and intervention records make it detectable.

## 11. Statistical Decision Rules

Correction to prior language: **failure to show superiority does not automatically falsify a hypothesis.** Absence of evidence under an underpowered design is not evidence of absence. Every comparison yields one of three outcomes:

### Positive
Evidence supports improvement greater than a preregistered minimum effect size.

### Negative
Evidence supports no practically meaningful advantage, under a predefined equivalence/non-inferiority framework where appropriate.

### Inconclusive
Uncertainty remains too wide to distinguish meaningful benefit from no benefit or harm.

Preregistration must specify:
- minimum effect size worth detecting;
- superiority / equivalence / non-inferiority framework per comparison;
- uncertainty interval method;
- handling of repeated trials within tasks (paired structure);
- primary analysis method;
- sample size / sensitivity assumptions.

**Sample size has not yet been decided and will not be fabricated here.** It remains an open Human Chair decision (Decision 0002, §Human Chair Decisions). Until set, M1 results are reported as pilot evidence with explicit uncertainty, not confirmatory claims.

## 12. Condition D Causal Design

A credible diversity test separates four confounds: **model strength, model-role fit, lineage diversity, resource differences.**

Required design elements:
1. Homogeneous council baseline for each participating model (its strength and general capability measured in-role).
2. Heterogeneous council using the same model pool.
3. Counterbalanced role assignments (every model appears in every role across the schedule).
4. Fixed preregistered assignment schedule.
5. Corresponding cost/token/context/tool metadata per assignment.
6. Paired comparison against appropriate homogeneous controls.

**Explicitly insufficient:** a single heterogeneous assignment —

```
Model X → Solver
Model Y → Verifier
Model Z → Reviser
```

— cannot support a diversity claim. Any observed difference could reflect which model landed in which role, raw model strength, or chance. Only counterbalanced, controlled comparisons license H3 conclusions.

## 13. Deferred Features

Retained in the long-term vision, deferred until experiments justify them. Each must earn complexity through evidence:

learned routing · capability matrix · generalized message bus · workflow engine · long-term memory · knowledge distillation · autonomous debate loops · model voting · confidence aggregation · large role libraries · automatic model-role assignment · persistent reputation systems.

Security posture unchanged: read-only defaults, deny-by-default tools, sandboxed execution, budget caps, Human Chair approval for consequential actions.

---

## Changes Incorporated in v0.3

**Adopted from SOL's validation review of v0.2:**
- H2 reframed as testing the complete role-separated workflow bundle, with explicit disclaimer against component-isolation claims.
- H3 decoupled from H2 success; full causal design for Condition D (homogeneous controls, counterbalancing, preregistered schedules).
- "Compute-matched" replaced by an operational resource-matching table with a stated primary principle (invocation-count and stage-budget matched).
- Falsification language corrected to Positive/Negative/Inconclusive outcomes with equivalence/non-inferiority options.
- New sections: Experiment Runner technical enforcement (§4), Prompt Development Parity (§7), Task Population manifest (§8), precise Task Success Definition (§9), Retry/Intervention accounting (§10).
- B's scope limited honestly: controls serial self-refinement, not best-of-N sampling.
- Sample size acknowledged as undecided and routed to the Human Chair rather than fabricated.

**Retained from Ox's adversarial review:**
- Measurement-before-infrastructure; smallest interpretable experiment.
- All platform machinery (routing, bus, workflows, memory, distillation) stays deferred behind evidence.
- Anonymization skepticism → context minimization instead of claimed anonymization.
- Negative-result discipline and honest cost reporting.

**Differences from v0.2:**
- v0.2's "must be able to lose" framing replaced by a statistically coherent three-outcome framework (v0.2 risked equating non-significance with falsification).
- v0.2's D-after-C-wins gating removed; D is now unconditional as H3's experiment.
- Governance moved from prompt-level charters toward technically enforced boundaries via a deterministic runner.
- Added operational definitions v0.2 lacked entirely: prompts parity, task population, success criteria, retry/intervention rules.

**Remaining unresolved questions (Human Chair):** sample size/trials per condition; minimum effect size; statistical framework selection per comparison; initial Condition D model pool; per-run budget ceiling; whether best-of-N is funded as an exploratory control; preregistration location; invalid-run adjudication details; initial benchmark task population. Full list in Decision 0002.

**Recommendations intentionally not adopted:**
- None rejected outright from the validation brief. One deliberate softening: SOL-style strict preregistration formality is applied to comparisons and metrics, but prompt-development logging is effort-parity based rather than fully instrumented (time-tracking tooling would exceed MVP proportionality); this is revisitable if prompt-tuning bias becomes measurable.
