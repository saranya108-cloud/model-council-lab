# Model Council Lab

Model Council Lab (MCL) is an experimental, evidence-first control plane for
testing whether structured collaboration among AI models improves outcomes.
It coordinates roles, enforces experiment boundaries, and preserves enough
evidence to evaluate a run without trusting the models' own claims.

MCL is not intended to replace a general-purpose agent runtime. Codex, the
OpenAI Agents API, or another qualified runtime may eventually provide
sessions, tools, child execution, and sandboxing beneath an explicit backend
contract. MCL retains authority over council structure, model and provider
identity, budgets, reviewer independence, evidence admission, lifecycle
interpretation, evaluation, and acceptance.

## Research question

The project began with a simple question:

**Can a group of AI agents working under distinct roles outperform a single
model working alone?**

MCL treats that as a set of hypotheses to test, not an assumption:

- Does additional inference and revision improve results?
- Does an independently role-separated workflow outperform equivalently
  resourced self-refinement?
- Does model diversity add value after controlling for model strength, role
  assignment, resources, and chance?

The current M1 design does not assume that a model belongs permanently in a
particular role. A credible diversity experiment requires homogeneous controls,
counterbalanced role assignments, fixed schedules, and explicit accounting for
resource differences.

## Current status

MCL is an active research harness, not a production service and not a completed
benchmark.

Implemented in the M1 development harness:

- Conditions A, B, and C for single-call, self-refinement, and homogeneous
  role-separated workflows
- solver, independent verifier, and reviser context policies
- a deterministic experiment runner and external evaluator boundary
- provider-neutral invocation and outcome contracts
- model/provider identity enforcement and runner-owned retry policy
- per-stage resource ceilings and separate accounting for harness estimates and
  adapter-reported usage
- Protocol v15 attempt journals, stage artifacts, seals, terminal records, and
  completed-run verification
- an OpenAI Responses adapter with bounded worker communication, bounded
  response-body admission, and explicit owned-client cleanup

Accepted milestone evidence records successful Protocol v15 live plumbing
validation for Conditions B and C at the recorded baseline. That validation
establishes the integration and evidence path; it does **not** establish that
councils outperform a single model or generalize across providers and tasks.

Still deferred or unproven:

- held-out M1 task evaluation and statistical conclusions
- Condition D heterogeneous-council experiments
- cross-provider compatibility and native heterogeneous child routing
- a finalized execution-backend admission contract
- production readiness, hostile-code sandboxing, and external evidence
  attestation

## What MCL controls

MCL's durable responsibilities are:

- **Council topology:** which stages exist and in what order
- **Identity:** configured, requested, and observed provider/model identity
- **Authority:** role-specific context, permissions, and write boundaries
- **Budgets:** invocation, token, tool, retry, and deadline ceilings
- **Independence:** especially the verifier's isolation from unnecessary solver
  context
- **Evidence:** canonical inputs, outputs, findings, dispositions, lifecycle
  events, and artifact integrity
- **Acceptance:** terminal verification, external evaluation, unresolved
  dissent, and Human Chair decisions

Execution backends may supply operational capabilities, but their sessions,
traces, usage reports, or success states are not automatically equivalent to
MCL evidence. A backend must be admitted against explicit identity, budget,
permission, cancellation, recovery, closure, and evidence-completeness rules.

## M1 experimental conditions

| Condition | Workflow | Purpose |
| --- | --- | --- |
| A | Single call | Simple deployment and cost/latency reference |
| B | Draft -> self-review -> revise | Measures additional inference and serial refinement |
| C | Solver -> independent verifier -> reviser | Tests the complete role-separated workflow bundle against B |
| D | Heterogeneous role-separated council | Tests diversity with controls and counterbalanced roles; deferred |

Condition C versus B does not isolate every component of collaboration. It
tests the role-separated workflow as a bundle. Condition D is a separate
hypothesis and must not be interpreted without its required controls.

## Safety and evidence model

- Model outputs and model-produced structured data are untrusted.
- M1 adapters are trusted, project-controlled harness code; arbitrary
  third-party or model-supplied Python adapters are out of scope.
- The subprocess boundary enforces invocation protocol and direct-worker
  deadlines, but it is not an operating-system sandbox for hostile adapter
  code.
- Meaningful external actions remain under Human Chair control, including live
  provider calls, credentials, commits, pushes, publication, spending, and
  infrastructure changes.
- Evidence hashes and seals provide local consistency and tamper detection;
  they are not signatures or protection against an attacker who can rewrite
  all trusted local state.
- The presence of a live adapter or canary entry point is not authorization to
  execute it.

## Repository map

```text
src/model_council/       Harness, contracts, lifecycle, adapters, and evaluator
tests/                   Offline unit, contract, lifecycle, and boundary tests
experiments/development/ Development-only tasks and guarded canary entry points
docs/decisions/          Accepted scope, governance, pilot, and trust decisions
docs/reviews/            Review and milestone-closure records
docs/architecture-proposal-v0.3.md
                         Proposed experimental architecture
```

Local run artifacts may exist under `runs/`. They are evidence, not source code,
and are not made canonical merely by being present in a checkout.

## Offline verification

The core harness uses the Python standard library. From the repository root:

```sh
PYTHONPATH=src:tests python3 -B -m unittest discover -s tests -v
```

The OpenAI adapter has a separately pinned optional dependency in
`requirements-openai.txt`. Installing it or running a live provider canary is
outside the ordinary offline workflow and requires explicit authorization.

## Start with these documents

- [Architecture Proposal v0.3](docs/architecture-proposal-v0.3.md) — proposed
  research architecture and causal design
- [Decision 0001](docs/decisions/0001-mvp-scope.md) — MVP scope
- [Decision 0002](docs/decisions/0002-mvp-experiment-design.md) — experimental
  design and council governance
- [Decision 0003](docs/decisions/0003-m1-pilot-parameters.md) — pilot parameters
- [Decision 0004](docs/decisions/0004-m1-adapter-trust-model.md) — adapter and
  artifact trust boundaries
- [Decision 0005](docs/decisions/0005-openai-response-body-bound.md) — OpenAI
  response-body and client-ownership bounds
- [Protocol v15 B/C closure](docs/reviews/protocol-v15-bc-closure.md) — accepted
  live-validation and preservation record
- [Development experiments](experiments/development/README.md) — offline usage,
  artifact layout, and development-only constraints

## Architectural direction

The recommended next architecture step is a bounded **Execution Backend
Admission Contract and Evidence Mapping** decision record. It should define how
backend sessions, turns, model generations, tool calls, child executions,
identity, budgets, permissions, cancellation, recovery, and closure map into
MCL's canonical evidence model before any runtime is treated as a qualified
backend.

This direction is a proposal, not an implemented integration or an accepted
compatibility claim.

## Principles

- Measure capability; do not assume it.
- Preserve disagreement and unresolved evidence.
- Keep role authority explicit and technically enforced where practical.
- Prefer transparent, reproducible workflows over black-box success claims.
- Separate implemented behavior, accepted evidence, proposed architecture, and
  future hypotheses.
- Make every added layer of infrastructure earn its complexity through a
  falsifiable experiment.

## License

Apache License 2.0. See [LICENSE](LICENSE).
