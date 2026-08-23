# Model Council Lab — Architecture Proposal v0.1

> Status: PROPOSED — under review. See [Adversarial Review v0.1](adversarial-review-v0.1.md) before implementation.

**Thesis:** A council of diverse models with explicit roles, adversarial critique, and measurable routing can outperform a single general-purpose model on complex tasks — but only if orchestration overhead, cost, and noise are measured as first-class variables.

---

## 1. Architecture

### Core Components

| Component | Responsibility |
|---|---|
| **Council Kernel** | Central process; owns session state, lifecycle, and termination conditions |
| **Model Registry** | Catalog of available models: capabilities, costs, context limits, latency profiles, local/cloud flag |
| **Role Definitions** | Declarative specs per agent role (system prompt, tools, constraints, output schema) |
| **Router** | Maps tasks → model + role assignments based on capability scores, budget, and policy |
| **Message Bus** | Typed message passing between agents (proposal, critique, vote, artifact) |
| **Tool Gateway** | Single chokepoint for all tool/file/network access; enforces permissions |
| **Memory Store** | Session scratchpad + persistent experiment/decision records |
| **Evaluator** | Scores runs on quality, accuracy, reliability, cost, latency |
| **Human Approval Gate** | Blocks consequential actions pending human sign-off |

### Orchestration Layer

A coordinator-centric topology with two modes:

- **Pipeline mode:** planner → parallel specialists → critic → synthesizer. Deterministic, cheap, good baseline.
- **Deliberation mode:** specialists propose independently → structured debate rounds → skeptic challenges → vote/synthesize. Used for high-stakes or ambiguous decisions.

Orchestration is **declarative workflows** (DAG-like) rather than hardcoded loops, so experiments can compare topologies without rewriting logic.

### Agent Communication

Typed, structured messages over the bus:

```
{ type: proposal | critique | vote | artifact | question,
  from, to, round, payload, confidence, citations }
```

Key rules:

- Agents never talk to each other's internals — only via messages.
- Critiques must reference specific claims in proposals (traceable disagreement).
- The skeptic sees proposals **anonymized by model identity** to reduce authority bias.

### Workflow Lifecycle

```
TASK INTAKE
  → PLAN (coordinator decomposes, routes subtasks)
  → EXECUTE (parallel specialist work)
  → CHALLENGE (skeptic/adversarial review)
  → REVISE (targeted fixes, optional re-debate)
  → SYNTHESIZE (final answer + dissent record)
  → EVALUATE (score the run)
  → RECORD (memory + decision log)
```

Every run ends with a **dissent record**: what agents disagreed on, why, and which position won. This is core research data.

---

## 2. Agent Roles

| Role | Model profile | Output contract |
|---|---|---|
| **Coordinator/Planner** | Strong reasoning, cheap-to-mid tier | Task decomposition, routing plan, budget allocation |
| **Researcher** | Long-context, web/tool access | Sourced findings with citations |
| **Coding Specialist** | Best available code model | Diffs + tests, not prose |
| **Financial Analyst** | Quant/reasoning strong | Structured numbers with assumptions stated |
| **Security Reviewer** | Conservative, checklist-driven | Risk register with severity ratings |
| **Skeptic/Adversarial Critic** | Different lineage than proposers (deliberately) | Specific objections + falsification attempts |
| **Final Synthesizer** | High-quality writer/model | Recommendation + confidence + recorded dissent |

Design principle: **role ≠ model**. Roles are contracts; any registered model can be assigned to a role. This enables the core experiment — "which model is actually best at critique?" — instead of baking assumptions in.

---

## 3. Model Routing

Routing decisions are made by the Router using a scoring function:

```
score(model, task) = w₁·capability_fit + w₂·(−cost) + w₃·(−latency) + w₄·diversity_bonus − penalty(risk)
```

- **Which model handles which task:** capability matrix built empirically — the registry stores observed performance per (model, role, task-type), updated after every evaluated run. Routing improves through measurement, matching the README principle "measure capability, don't assume it."
- **Local vs cloud:** local models for high-volume, low-risk subtasks (drafting, summarization, first-pass code); cloud frontier models for planning, final synthesis, and security review. Policy knobs: privacy (sensitive data stays local), budget cap per run, latency targets.
- **Independent opinions:** triggered when (a) stakes exceed threshold, (b) proposer confidence < threshold, (c) critic flags material uncertainty, or (d) the task type is known-contested (e.g., financial forecasts). Independent opinions always use **different model lineages** to decorrelate errors.

---

## 4. Memory & Knowledge

| Layer | Scope | Content |
|---|---|---|
| **Session memory** | One run | Message history, artifacts, working notes; discarded after run |
| **Long-term knowledge** | Persistent | Distilled facts, verified capability matrix, reusable patterns |
| **Experiment history** | Persistent | Every run: config, topology, models used, prompts, outputs, eval scores — append-only, queryable |
| **Decision records** | Persistent | What was decided, alternatives considered, dissent, human approvals, rationale |

Storage starts simple: local files (JSONL/SQLite) under version control for configs, gitignored for bulky artifacts. No database dependency until scale demands it.

---

## 5. Evaluation

Every run produces a scorecard:

- **Quality:** rubric-based LLM-as-judge (with judge-lineage diversity) + human spot-checks on a sample.
- **Accuracy:** objective tasks get ground-truth checks (tests pass/fail, math verification, citation existence).
- **Reliability:** variance across N repeated runs; consistency of verdicts under prompt perturbation.
- **Autonomy:** fraction of tasks completed without human intervention or retry escalation.
- **Cost:** tokens × price per model, aggregated per run and per outcome.
- **Latency:** wall-clock per phase and end-to-end.

**The headline metric:** council vs. single-model baseline on identical tasks — quality delta per dollar and per second. If the council wins on quality but loses 10× on cost, that's the finding, and the framework should surface it honestly.

---

## 6. Security

- **Read-only defaults.** Agents can read the workspace; writes require role-granted permission.
- **Approval requirements.** Anything outside the repo (network calls beyond whitelisted domains, file deletion, git push, shell execution) requires explicit human approval through the gate.
- **Tool permissions per role.** Researcher gets fetch-only; coding specialist gets write-in-sandbox; security reviewer gets read-only everywhere; nobody gets unrestricted shell.
- **Safeguards:**
  - Tool Gateway denies-by-default; every call logged and attributable to an agent.
  - Sandbox for all code execution.
  - Prompt-injection containment: external content (web pages, fetched docs) is marked untrusted and cannot trigger tools directly.
  - Budget hard-caps per run prevent runaway loops.
  - No secret exposure: credentials live outside agent-visible context.

---

## 7. Roadmap — First Three Milestones

### M1 — Skeleton Council (pipeline mode)

Model Registry + Coordinator + one specialist + Synthesizer, single provider, session memory, basic logging. Deliverable: one task class runs end-to-end council vs. single-model comparison.

### M2 — Deliberation & Evaluation

Add Skeptic role, debate workflow, typed message bus, evaluator scorecards, experiment history. Deliverable: reproducible benchmark comparing pipeline vs. deliberation vs. single-model across ≥2 task types, with cost/quality trade-off data.

### M3 — Intelligent Routing & Local Models

Capability matrix learned from M2 data, router with budget policies, local/cloud split, approval gates and Tool Gateway enforcement. Deliverable: demonstrable case where the router beats fixed assignment on cost-adjusted quality.

---

## Open Questions for Review

1. Should the Skeptic ever see model identities (transparency vs. bias trade-off)?
2. Single-provider-first vs. multi-provider from day one?
3. Is the human gate interactive (CLI prompt) or async (queued approvals)?
