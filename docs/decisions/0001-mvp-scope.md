# Decision 0001 — MVP Scope

## Status

Accepted

## Decision

The project will begin with the smallest measurable Model Council experiment rather than implementing the full v0.1 architecture immediately.

The goal of the MVP is to determine whether a council workflow provides measurable improvement over a single-model baseline. Every component beyond this scope must earn its place through experimental evidence.

This decision follows the [Adversarial Review v0.1](../adversarial-review-v0.1.md) of [Architecture Proposal v0.1](../architecture-proposal-v0.1.md), which found that v0.1 front-loads infrastructure ahead of data. The team accepts that critique: measurement before infrastructure.

## Accepted for MVP

- Coordinator/planner agent
- One specialist agent
- One reviewer/critic agent
- Final synthesizer
- Basic run logging
- Single task category with objective evaluation where possible (code tasks preferred, since pass/fail is verifiable without an LLM judge)

These components are sufficient to test the core hypothesis: they form a complete council workflow (decompose → execute → challenge → synthesize) with logging to compare against a single-model run on identical tasks. Anything more would confound the comparison or delay the first measurement.

## Deferred Until Evidence Requires Them

- Dynamic model routing
- Learned capability matrix
- Multi-provider orchestration
- Local/cloud optimization
- Typed message bus
- Complex workflow engine
- Long-term memory system
- Knowledge distillation
- Autonomous debate loops
- Expanded agent role library

These are valuable research areas, but each adds cost, complexity, and failure modes before any result exists to justify them. They should be introduced when experimental results demonstrate a concrete need, not speculatively.

## Baseline Definition

**Council workflow:**

```
Coordinator → Specialist → Reviewer → Synthesizer
```

**Single-model baseline:**

One model performing the same task with equivalent tools and context.

Both configurations receive the same task, the same tool access, and comparable context. The purpose of pinning the baseline this way is to isolate whether the *council structure itself* adds value — not whether a multi-call system outperforms a poorly prompted single call.

## Evaluation Criteria

Initial measurements recorded per run:

- Task success/accuracy (objective checks where possible)
- Quality of output
- Cost/token usage
- Latency
- Human intervention required
- Reliability/reproducibility (variance across repeated runs)

If the council wins on quality but loses on cost or latency, that is a valid finding and will be recorded honestly.

## Rationale

The team chose measurement before infrastructure. The project optimizes for discovering what works rather than building a complete framework before evidence exists. A minimal experiment that produces one honest number is worth more than a full platform that has never been validated against a baseline.

## Revisit Conditions

Deferred components may be added when:

- Experiments demonstrate a need for them
- Measurements show improvement attributable to the component
- Complexity is justified by results

Each addition should arrive with its own decision record referencing the experimental evidence that motivates it.
