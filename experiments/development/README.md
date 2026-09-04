# M1 Development Experiments

This directory holds **development-only** material for the M1 harness.

Per [Decision 0003 §4](../../docs/decisions/0003-m1-pilot-parameters.md), any task
inspected during harness development or prompt tuning is **permanently excluded**
from the held-out evaluation set. Everything under `tasks/` is development-only
and must never be promoted into the held-out benchmark.

## Trust model (per Human Chair decision)

**Trusted:** adapter implementations and all harness code are project-controlled,
reviewed code. Arbitrary third-party or model-supplied adapter Python is NOT
supported in M1.

**Untrusted:** model outputs — text, structured JSON, tool requests/results.
All model-produced content is validated before it can affect a run.

## What is enforced

- **Path-safe ArtifactStore interface:** run IDs must match
  `[A-Za-z0-9][A-Za-z0-9._-]*` (`.`/`..`/separators rejected); every externally
  influenced path is resolved and proven to stay inside its permitted namespace.
- **Validated stage context:** each stage receives only its policy-permitted
  context keys; extra keys are rejected structurally, not by prompt.
- **Structured model-output contracts (Condition C):** strict JSON-schema-style
  validation of verifier findings and reviser dispositions (exact types; no
  coercions). Violations terminate the run as `failed_contract` without writing
  final artifacts or seals.
- **Resource ceilings with documented accounting:** the runner independently
  estimates input/output usage over the complete original model-visible values
  before JSON transport escaping (a deterministic whitespace-delimited
  approximation) and enforces per-stage ceilings on those estimates. This is
  not provider-tokenizer parity. Child-reported metrics are validated as
  protocol data (required integers, non-negative) but are NOT treated as
  verified provider numbers; both values are recorded separately.
- **Model identity verification:** each invocation returns the identity it
  actually resolved; the runner compares it to the frozen RunSpec expectation
  after every stage. Mismatch/drift terminates the run as `failed_governance`.
- **Immutable experiment configuration:** RunSpec metadata, evaluator config,
  and adapter options are deep-frozen at construction; mappings, sequences,
  and heterogeneous sets use deterministic canonicalization; later caller
  mutation cannot change hashes or behavior.
- **Process-level timeout for the direct adapter child:** an invocation that
  exceeds `stage_timeout_seconds` is terminated.
- **Artifact integrity checking:** append-only SHA-256 manifest, persisted
  seals, exact condition-specific stage/artifact topology checks, authoritative
  parent-side hashes during active runs, re-verification before each downstream
  transition and before evaluation, and a public completed-run verifier
  (`ArtifactStore.verify_completed(runs_root, run_id)`). The verifier requires
  every expected stage seal, manifest record, artifact hash/byte count, and the
  terminal final-candidate reference.
- **Evaluator isolation:** hidden-test configuration never enters any
  model-visible payload.

## What is NOT claimed for M1

- No OS sandboxing against malicious project-controlled adapter Python. The
  subprocess boundary provides timeout/process isolation and a clean protocol,
  not a hostile-code sandbox.
- No protection against a same-user attacker with arbitrary filesystem access:
  an attacker who rewrites artifacts, seals, AND the manifest after completion
  defeats unauthenticated local records. M1 does not provide external
  cryptographic notarization.
- No containment of descendant processes spawned intentionally by trusted
  adapters (adapter implementation rule: do not spawn unmanaged descendants);
  only the direct child is guaranteed terminated on timeout.
- No arbitrary third-party adapters, no Condition D. The development harness
  now contains an activated OpenAI Responses live adapter; SDK/request
  translation and offline transport evidence exist. No real provider response
  has yet been exercised end-to-end. The Checkpoint 7 canary entrypoint is
  development-only and guarded. Implementing the entrypoint does not authorize
  executing it. Any real invocation requires later explicit Human Chair
  authorization. A canary provides plumbing/integration evidence only.

## Terminal-status policy

Once a safe run namespace exists for a supported run specification, ANY later failure produces a terminal
`run_result.json` (`failed_governance`, `failed_budget`, `failed_contract`,
`failed_evaluation`, `retry_exhausted`, `infrastructure_failure`, or
`succeeded`). Failures that prevent establishing a safe namespace at all —
invalid condition/task pairing or an unsafe run ID — raise before any record
exists, by design. Worker crashes and malformed worker protocol/metrics are
classified as `infrastructure_failure` and never consume the preregistered
model retry budget.

## Contents

- `tasks/` — development task specifications (JSON `TaskSpec` documents)

## Running

Standard library only; no packages to install.

```sh
python3 -B -m unittest discover -s tests -v
```

Programmatic Condition C example:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path("src").resolve()))

from model_council import (
    AdapterIdentity, Condition, EvaluationConfig, ExperimentRunner,
    ExternalEvaluator, ResourceLimits, RunSpec, SubprocessAdapter, TaskSpec,
)

IDENTITY = AdapterIdentity(
    provider="fake-provider", model_id="fake-dev-model", model_version="v1",
    adapter_name="fake", adapter_version="v0",
)
task = TaskSpec(
    task_id="dev-001", bug_report="example defect",
    workspace_id="ws-dev-001", allowed_files=("example.py",),
)
spec = RunSpec(
    run_id="demo-c-001", task_id="dev-001", condition=Condition.C,
    model_identifier=IDENTITY.key(), prompt_version="prompts-dev-v0",
    resource_limits=ResourceLimits(), seed=7,
)
runner = ExperimentRunner(
    adapter=SubprocessAdapter(IDENTITY, kind="fake"),
    evaluator=ExternalEvaluator(EvaluationConfig()),
    runs_root=Path("runs"),
)
result = runner.execute(spec, task)
print(result.status, result.evaluation.passed, result.final_candidate_ref)
```

Artifacts land under `runs/<run-id>/`:

```text
runs/<run-id>/
  run_spec.json        # frozen at run creation (immutable)
  manifest.jsonl       # append-only SHA-256 record of every artifact write
  seals/<role>.json    # persisted sealing hashes per completed stage
  solver/              # candidate.md + evidence.md (Condition A/C)
  verifier/            # findings.md (Condition C)
  reviser/             # final_candidate.md
  evaluation.json      # External Evaluator outcome (write-once)
  integrity_check.json # completion-time verification result
  run_result.json      # terminal run summary (write-once, always present once
                       # a safe run namespace exists)
```

The terminal record includes a treatment hash (declared configuration only),
Git source revision / pre-run working-tree dirty flag (which source state
produced the run), and per-stage usage split into harness-estimated vs
adapter-reported.

## What this is not

Pre-experiment development infrastructure only. It does not measure model
intelligence or contain held-out tasks. The development harness now contains
an activated OpenAI Responses live adapter; SDK/request translation and
offline transport evidence exist, but no real provider response has yet been
exercised end-to-end. The Checkpoint 7 canary entrypoint is development-only
and guarded. Implementing the entrypoint does not authorize executing it. Any
real invocation requires later explicit Human Chair authorization. A canary
provides plumbing/integration evidence only. Condition D remains deferred.
