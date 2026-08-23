# Adversarial Review — Architecture Proposal v0.1

> Status: REVIEW. Responds to [Architecture Proposal v0.1](architecture-proposal-v0.1.md). Must be addressed before M1 implementation.

## Verdict

The proposal describes a research platform, not a research project. It front-loads infrastructure for experiments that haven't produced a single data point yet. Roughly half of it should be cut from M1, and several "design principles" are untested assumptions dressed up as decisions.

---

## Over-engineering

### 1. The Router (§3) is premature and circular

The routing score function requires a capability matrix built from evaluated runs. But the evaluation framework doesn't exist until M2. You've designed M3 machinery that depends on M2 outputs while M1 has zero runs. Worse: the diversity bonus term assumes diversity helps — the exact hypothesis you claim to be testing. Building the answer into the objective function is not research.

### 2. Typed message bus with 6 message types (§1) is speculative generality

You have no evidence yet about which interaction patterns matter. Six types, round numbers, confidence fields, anonymization rules — this is a protocol for a system at 10x the current scale. A dict passed between function calls would validate the pipeline-mode experiment just as well. You can't design a communication protocol before you know what agents need to say to each other.

### 3. Declarative DAG workflows are overkill for two modes

Pipeline mode is a straight line; deliberation mode is a fixed loop. Neither needs a workflow engine. Declarative topology definition pays off when you have many topologies to compare — you have two.

### 4. Seven roles defined in detail (§2), none exercised

Output contracts for a financial analyst before the coding specialist can complete one task? Each role adds prompt surface, eval surface, and failure modes. The proposal treats role breadth as a feature; it's actually a cost center with no experimental value until the council-vs-single comparison exists at all.

### 5. Long-term memory and knowledge distillation (§4) solve a problem you don't have

"Distilled facts, verified capability matrix, reusable patterns" — distillation pipelines are notoriously hard and noisy. For an early research repo, append-only run logs already give you everything queryable. This is a component that will be built once, barely used, and rot.

---

## Hidden Assumptions

- **That disagreement is signal.** "Preserve disagreement" assumes critic dissent correlates with error correction. It may correlate with model-specific quirks, verbosity, or sycophancy-in-reverse. Unmeasured.
- **That LLM-as-judge works here.** Judges share lineages and biases with the models being judged; judging councils is even harder than judging single outputs (who grades the synthesized dissent?). The proposal hand-waves this with "judge-lineage diversity."
- **That anonymizing proposals from the skeptic is possible.** Models have recognizable stylistic fingerprints; frontier models can often identify each other's output. Anonymization may be theater.
- **That orchestration overhead is small enough to ignore.** The headline metric compares quality-per-dollar, but context re-statement across agents multiplies token costs non-linearly. If the council loses on cost, is it the topology or the plumbing? The design can't tell you.
- **That roles transfer across models.** "Role ≠ model" assumes a security-checklist persona works equally well pasted onto any model. Persona adherence varies wildly; this assumption is testable but stated as settled.
- **That local models are useful at all in the loop.** Listed throughout, but if local models require heavy prompting to hit role contracts, they may never clear the bar.

---

## Failure Modes Not Addressed

1. **Echo chamber / agreement cascade.** Sequential debate converges to the first confident proposal. Nothing in the design detects or prevents sycophantic convergence — the most common multi-agent failure in practice.
2. **Error compounding through synthesis.** The synthesizer averages over critiques it can't verify. A wrong specialist output plus a weak critique produces confident garbage with a dissent record attached — false authority.
3. **Infinite revise loops.** CHALLENGE → REVISE cycles have no stated convergence criterion or cap beyond budget caps. Budget caps prevent runaway *cost*, not runaway *non-convergence*.
4. **Evaluation gaming.** Agents optimizing toward rubric-based judge scores (especially if prompts reference criteria) will drift toward judge-pleasing output.
5. **Prompt-injection via research content into deliberation.** Marking external content "untrusted" doesn't stop a fetched page from steering the researcher's proposal, which then propagates through the whole council. Containment strategy is named, not designed.
6. **Cost explosion from independent opinions.** "Stakes exceed threshold → independent opinions" means high-stakes tasks trigger N× full-council reruns with no analysis of diminishing returns.

---

## What Must Be Cut From M1

| Cut | Why |
|---|---|
| Message bus (typed protocol) | Function calls suffice for pipeline mode |
| Skeptic + deliberation mode | That's M2's experiment; don't build ahead of data |
| All roles except Coordinator + one Specialist + Synthesizer | Minimum viable council |
| Local/cloud split | Single provider, single model tier first |
| Long-term memory / knowledge distillation | Run logs only |
| Security reviewer role | Tool Gateway deny-by-default covers safety for now |
| Routing score function entirely | Replace with hardcoded config; measure first |

**M1 should shrink to:** config file naming models per role → sequential pipeline → one task class (code tasks, since they're objectively verifiable — no judge needed) → run log → side-by-side comparison vs. single model. That's it. One provider, three calls, honest numbers.

---

## Questions the Proposal Must Answer Before Any Code

1. What is the **baseline**? "Single model" is undefined — same model with a good system prompt? Best single model? The comparison is meaningless until pinned.
2. What decision rule ends a debate round? (Unspecified = infinite loops or arbitrary cutoffs.)
3. Who evaluates the evaluator?
4. If the council loses on every metric, does anything in this architecture survive? If nothing does, the architecture isn't testing the hypothesis — it's committed to it.

---

## Summary Judgment

v0.1 optimizes for looking like a complete system instead of generating the first falsifying measurement. Strip it to the smallest configuration that can produce a number, then let the data justify each component added afterward.
