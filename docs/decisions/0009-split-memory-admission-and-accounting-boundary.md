# Decision 0009 — Split Memory Admission and Accounting Boundary

## 1. Status

**Accepted by Human Chair**

Amy, as Human Chair, accepted Decision 0009. This acceptance records the
architecture decision; it does not open Tranche B, admit a provider, authorize
implementation, or authorize execution.

Canonical MCL baseline for this proposal:

- Repository: `/Users/aclab/aclab/model-council-lab`
- Branch: `m1-live-adapter-dev`
- HEAD: `8ee850c1f2f4f5151e8300853ee48fc6ec5ef23c`

Decisions 0004, 0006, 0007, and 0008 and accepted P3-A remain controlling.
This decision adds a resource-admission and accounting boundary for the
intended local open-weight path. It does not weaken their identity,
provider-specific/versioned admission, exactly-one-execution, boundedness,
cleanup, historical-compatibility, or independent-verification requirements.

Current gate disposition:

> **TRANCHE A — ARCHITECTURE ACCEPTED**

> **TRANCHE B REMAINS CLOSED**

---

## 2. Context

The intended platform is the Acer GN100 host `gn100-26db` with an NVIDIA GB10,
driver `580.173.02`, CUDA 13.0, and approximately 121.69 GiB of CUDA-visible
total memory.

The intended model artifact has passed its separately performed artifact gate:

- Repository: `unsloth/GLM-4.7-Flash-GGUF`
- Revision: `46cbdf738df140a74f50a25b9e23cb8b038ad77b`
- File: `GLM-4.7-Flash-Q4_K_M.gguf`
- Exact size: `18,312,339,776` bytes
- SHA-256: `73ba18480e06ccda453a26263c0e2be2bd86294e827b1812ddea2f88bba2d924`

Artifact inspection reported GGUF v3, architecture `deepseek2`, 844 tensors,
47 blocks, 64 experts with 4 used and 1 shared, zero tensor-bounds errors, zero
alignment errors, zero overlaps, and tensor data ending exactly at EOF. It
reported no `split.*` metadata, no MTP / NextN / draft / speculative tensor
names, and an explicit 64-expert dimension in fused expert tensors.

Those facts establish neither runtime admission nor memory safety. Decision
0008 continues to require an execution-bound relationship among independently
observed consumed artifacts, admitted runtime/build identity, the authorized
attempt, execution, cleanup, and terminal verification.

The non-model CUDA baseline reported approximately 170 MiB of NVIDIA
per-process accounting for a CUDA context. A 64 MiB `cudaMalloc` increased that
accounting by exactly 64 MiB, freeing it returned the process to its context
baseline, and `cudaDeviceReset()` removed the compute process. No residual
process remained. This establishes basic allocation and cleanup behavior on the
characterized platform. It does not establish authoritative cgroup attribution
or an admission ceiling.

---

## 3. Tranche A Characterization Evidence

The supplied Tranche A characterization record describes 24 isolated runs:
8 cases with 3 repetitions each. Each run had exactly one intended worker PID
in its dedicated cgroup. All API calls succeeded, all `memory.events` counters
remained zero, each final per-run NVIDIA process query was empty, every
transient unit was removed, and the final global NVIDIA process query was
empty.

Supplied Tranche A evidence SHA-256:

`726cfbf2107f542465169e4ca8704aabc98a9588ef577744c45fff05e45e4c16`

The evidence produced these bounded observations:

1. A 64 MiB CUDA device allocation appeared as exactly +64 MiB in NVIDIA
   per-process accounting.
2. The same allocation did not appear as an equivalent +64 MiB charge in
   cgroup `memory.current`, RSS, or PSS.
3. `cudaHostAlloc` charged approximately 64 MiB to cgroup memory and RSS/PSS,
   and that charge was released after cleanup.
4. cuBLAS initialization showed material cgroup variability: approximately
   +171.81 MiB in one run and approximately +94.74 MiB in two repetitions,
   despite stable PSS.
5. CUDA global free-memory readings were too noisy for precise per-worker
   attribution.

These are characterization observations, not enforcement proof. Zero
`memory.events` under an unconstrained or non-triggering characterization does
not demonstrate an effective `memory.max`. Empty final process queries and
removed units establish the reported successful cleanup observations but do not
prove every required failure path.

The SHA-256 records the supplied evidence identity. A digest written in this
decision is authority/provenance metadata, not a substitute for retaining and
independently measuring the evidence bytes. The Tranche A record must still be
canonically preserved with its acquisition context, commands or equivalent
method, raw observations, case/repetition mapping, timestamps, platform and
software identity, and independently verified digest before it can satisfy the
Tranche B gate.

---

## 4. Decision

MCL shall use a split memory admission and accounting model for the intended
GB10 open-weight worker. Three coordinated controls must pass independently:

1. a host/cgroup budget;
2. a GPU-process/device budget; and
3. a machine safety reserve.

No one control substitutes for another. Unknown, missing, contradictory,
stale, or ambiguously attributed evidence in any required control fails closed.

The host/cgroup and GPU-process ledgers have different semantics and may
overlap on the GB10 unified-memory platform. Their values must not be naively
added into a purported total. Admission instead requires each ledger to satisfy
its own independently defined ceiling and the machine to preserve its separate
safety reserve.

The decision separates:

- **Authority** — frozen budgets, margins, identities, versions, reserve rules,
  worker/cgroup/GPU bindings, and permitted allocation behavior.
- **Observation** — measurements actually obtained from the relevant cgroup,
  exact worker PID, exact GPU UUID, runtime, process, and machine.
- **Enforcement** — mechanisms that prevent or terminate disallowed resource
  use at the boundary they govern.
- **Verification** — independent reconstruction and comparison of authority,
  observation, enforcement, lifecycle, and terminal outcome.

Configured limits, copied expected values, a successful API return, a stored
`within_budget=true` verdict, or a final empty process list cannot replace the
required observations and comparisons.

---

## 5. Host / Cgroup Budget

The primary host-memory authority and enforcement evidence is:

- `memory.current`;
- `memory.peak`;
- `memory.events`;
- a later-authorized `memory.max`; and
- exact membership of the intended worker and only the intended worker set in
  its dedicated cgroup.

This ledger governs memory actually charged to the cgroup, including ordinary
host memory, pinned host memory, and applicable runtime or shared-library pages.

The admitted path must freeze the cgroup identity, applicable hierarchy,
worker-membership rule, host budget, startup reserve treatment, and intended
`memory.max` before the governed execution begins. It must observe and retain
the actual values and relevant event counters for the complete admitted
lifecycle.

`memory.current`, `memory.peak`, and `memory.events` are not interchangeable.
The verifier must preserve and interpret their separate meanings, including
whether a limit was approached, peaked, or enforced and which counter changed.
An observed process exit alone does not identify a host-limit hit.

RSS and PSS are reconciliation and diagnostic evidence. They may help explain
process and shared-page behavior, but they are not host-budget enforcement
authority and cannot override cgroup evidence.

Any extra, missing, migrated, or ambiguously attributed worker process in the
dedicated cgroup invalidates attribution. A cgroup measurement without exact
membership cannot establish the intended worker's host charge.

---

## 6. GPU-Process / Device Budget

The primary device-memory attribution is NVIDIA per-process memory bound to:

- the exact intended worker PID; and
- the exact admitted GPU UUID.

PID-only, device-index-only, aggregate-device, configured-device, or
process-name matching is insufficient. PID reuse, worker replacement, GPU
renumbering, multi-process activity, missing samples, and stale observations
must be detected or remain disqualifying uncertainty.

The admitted allocation path must enforce a preventative allocation-time
ceiling, or an equivalently strong fail-before-overshoot mechanism, for device
memory governed by this ledger. A requested allocation that would exceed the
remaining admitted device budget must fail before the overshooting allocation
becomes live.

Periodic `nvidia-smi` observation is post-allocation observation. It may supply
attribution and reconciliation evidence but is not preventative enforcement and
cannot by itself satisfy the allocation ceiling.

`cudaMemGetInfo` may be retained only as a coarse machine-headroom signal. Its
global free-memory result is not worker attribution, cannot establish one
worker's consumption, and cannot replace exact per-process evidence or the
preventative allocation boundary.

The implementation must define what allocations enter the device budget,
where authority is checked, how concurrent or asynchronous allocations are
serialized or reserved, and how releases return capacity without double
credit. Unknown allocation behavior fails closed.

---

## 7. Machine Safety Reserve

MCL shall preserve explicit system and desktop headroom independently of the
worker budgets.

The safety reserve protects continued host, display, driver, monitoring,
cleanup, and operator control under the admitted workload. It must be frozen as
authority using contemporaneous platform characterization and must not be
silently consumed to enlarge a worker budget.

Admission must fail when required machine headroom is unavailable even if the
host/cgroup and GPU-process ledgers would otherwise pass. Conversely, apparent
global headroom cannot excuse a failed worker ledger.

The reserve calculation must account conservatively for the unified-memory
platform without pretending that cgroup and NVIDIA charges are disjoint. No
single summed number is authoritative unless later evidence and architecture
establish a non-overlapping composition rule.

---

## 8. CUDA / cuBLAS / cuBLASLt Startup Reserve

CUDA, cuBLAS, and cuBLASLt startup overhead shall be a separately measured and
versioned reserve. It is not an informal allowance and is not inferred from the
model-file size.

The reserve characterization must:

1. distinguish cold and warm starts;
2. randomize execution order sufficiently to expose order and cache effects;
3. retain every observation rather than only an average;
4. select a conservative observed upper envelope;
5. add an explicit documented margin with a stated basis; and
6. bind the result to the exact GPU, driver, CUDA, relevant library versions,
   and admitted runtime/build identity.

The lower warm observation cannot replace the higher cold or otherwise
applicable observation. Cold and warm values must not be averaged into a lower
authority. The observed approximately +171.81 MiB and +94.74 MiB cgroup changes
demonstrate variability; they do not allocate a final reserve.

The prior provisional 8 GiB allowance is not authority for this path. It may
remain historical context only. A final startup reserve requires the
characterization and binding above.

A material change in GPU, driver, CUDA, cuBLAS, cuBLASLt, runtime/build,
relevant launch configuration, or observed startup behavior invalidates the
reserve binding until recharacterized or explicitly covered by a previously
admitted closed version set.

---

## 9. Combined-Footprint Admission

Component measurements cannot establish the simultaneous maximum of the
intended worker. Before Tranche B opens, a combined-footprint test must measure
while simultaneously live:

- the CUDA context;
- runtime and shared libraries;
- cuBLAS and cuBLASLt handles;
- pinned host memory;
- a representative device allocation;
- cgroup accounting; and
- NVIDIA per-process accounting.

The test must preserve the exact worker/cgroup/PID/GPU association and the
temporal relationship among allocations and observations. Separately measured
component peaks must not be presented as proof of a simultaneous combined
footprint.

The combined test is characterization evidence. Production admission still
requires frozen budgets, preventative device enforcement, applicable cgroup
enforcement, the machine reserve, lifecycle evidence, and independent terminal
verification.

---

## 10. Admission and Execution Ordering

Run authority must freeze the applicable identities, ledger versions, budgets,
startup reserve, machine reserve, enforcement configuration, and cleanup rules
before worker execution.

The intended order is:

`frozen authority`
→ `dedicated cgroup and exact membership`
→ `worker/PID/GPU binding`
→ `startup and combined-budget admission`
→ `preventative allocation permission`
→ `bounded allocation or execution`
→ `outcome observation`
→ `cleanup and reaping`
→ `terminal verification`

Preparation does not authorize an allocation. Observation after an allocation
does not retroactively authorize it. A passing host ledger does not grant
device capacity, a passing device ledger does not grant host capacity, and
either worker ledger does not grant use of the machine reserve.

The exact provider-specific/versioned admission path required by Decisions
0007 and 0008 must select these semantics consistently in parent authority,
worker permission, runtime enforcement, persisted evidence, and terminal
verification. Unsupported or contradictory selection fails closed without
historical fallback.

---

## 11. Cleanup and Failure Semantics

Timeout, cancellation, allocation failure, host-limit hit, and device-limit hit
must each demonstrate:

- no residual NVIDIA compute process;
- no residual transient worker unit;
- correct worker termination and reaping; and
- no retry, fallback, redispatch, or successor execution.

These properties require fault-specific evidence. Success-path cleanup does not
prove failure-path cleanup, and a final global empty query alone does not prove
the identity, timing, or causal path of the worker that was cleaned up.

Host-limit and device-limit failures must preserve their actual supported
observations. One must not be inferred from the other or manufactured from a
generic worker exit. Ambiguous resource failure remains conservative
uncertainty.

Missing, torn, contradictory, or incomplete resource evidence cannot authorize
allocation, semantic execution, retry, fallback, downstream execution,
promotion, evaluation, or success. Earlier valid observations remain
preserved.

Cleanup is separate from outcome. Normal return does not establish cleanup;
worker reaping does not establish that all owned CUDA, library, pinned-memory,
process, pipe, or transient-unit obligations completed. Required cleanup
failure suppresses any pending successful publication under the admitted
lifecycle.

No resource failure, cleanup ambiguity, or apparent returned capacity grants
permission for a replacement worker or successor semantic execution.

---

## 12. Evidence Lifecycle and Canonical Preservation

Evidence must distinguish and preserve:

### Authority

Frozen host, device, startup, and machine-reserve budgets; exact version and
identity bindings; permitted allocation rules; and enforcement configuration.

### Membership and attribution

Dedicated cgroup identity and hierarchy, complete worker membership, exact PID,
exact GPU UUID, and their lifetimes and associations.

### Observation

Cgroup current/peak/events, NVIDIA per-process memory, diagnostic RSS/PSS,
coarse machine-headroom readings, allocation requests/results, and relevant
timestamps.

### Enforcement

Actual `memory.max` behavior when authorized, preventative device-allocation
decisions, denied requests, and limit-hit observations.

### Outcome

Return, error, timeout, cancellation, limit hit, allocation failure, and any
incomplete-execution observation before normalization.

### Cleanup

Owned-resource release, worker termination/reaping, NVIDIA process absence,
transient-unit removal, communication closure, and remaining uncertainty.

### Verification

Independent reconstruction of authority, attribution, observations,
enforcement, lifecycle, cleanup, and terminal eligibility.

The Tranche A evidence must be retained as immutable or equivalently
integrity-protected canonical evidence with sufficient provenance to reproduce
its meaning. The preserved bytes must be independently measured and compared
with the supplied SHA-256. A copied digest, filename, manifest entry, or stored
match verdict is not that observation.

Any normalization or summary must remain traceable to the retained raw evidence
and must not replace it. Evidence existing only on the characterization host,
in a transient unit, in process memory, or in an uncommitted location does not
satisfy canonical preservation.

---

## 13. Tranche B Opening Gate

Tranche B remains closed until all of the following are satisfied:

1. Amy explicitly accepts Decision 0009 as architecture. The proposed status
   must not be changed to `Accepted by Human Chair` merely because this file is
   created or committed.
2. The Tranche A evidence is canonically preserved with provenance and the
   supplied SHA-256 is independently verified against the preserved bytes.
3. Cold/warm and randomized-order characterization establishes a conservative
   CUDA/cuBLAS/cuBLASLt startup upper envelope plus an explicit documented
   margin, bound to the required hardware/software/runtime identity.
4. A combined-footprint test measures the simultaneously live components and
   both required accounting ledgers named in Section 9.
5. Actual cgroup limits demonstrate intended enforcement and applicable
   `memory.events` behavior.
6. The GPU allocation path demonstrates preventative allocation-time
   enforcement rather than discovering overshoot afterward.
7. Timeout, cancellation, allocation failure, host-limit hit, and device-limit
   hit demonstrate the cleanup and no-successor properties in Section 11.
8. No material accounting ambiguity remains for the intended Tranche B worker.

Every item is conjunctive. Partial evidence, a successful subset, or confidence
in an untested path does not open the tranche. Human acceptance of this
architecture does not itself satisfy the remaining evidence gates or authorize
execution.

---

## 14. Tranche B Scope After Later Authorization

Even after the opening gate passes and a later explicit authorization is
granted, Tranche B may cover only:

- trivial native `sm_121a` compilation;
- cubin/fatbin inspection;
- proof that native cubin exists;
- proof that PTX is absent;
- PTX-JIT-disabled execution of the trivial kernel;
- exact compiler, toolchain, and build evidence; and
- bounded cleanup and evidence preservation.

Tranche B does not authorize:

- opening or loading the GLM GGUF;
- inference;
- model-specific kernels;
- model context creation;
- model tensors;
- production memory admission; or
- implementation of the provider adapter.

The narrow native-code experiment cannot be used as evidence that model
loading, inference, production budgets, or provider admission are safe.

---

## 15. Versioning and Compatibility Boundary

The split-ledger semantics, source-specific authorities, startup reserve,
attribution requirements, enforcement mechanisms, and evidence schema require
an explicit provider-specific/versioned admission and verifier path.

This decision does not allocate a protocol number, schema identifier, event
name, provider kind, runtime API, cgroup layout, or implementation abstraction.
A later implementation proposal must enumerate exact source and test changes,
version selections, compatibility behavior, and migration or rejection rules.

Historical OpenAI, legacy, `live_stub`, and accepted evidence retain their
existing meanings. Decision 0009 must not be retroactively inferred from old
fields or silently inserted into historical verification.

This decision is a generic resource-evidence contract. It does not authorize a
generic provider base class, plugin loader, universal resource interface,
shared open-weight runtime abstraction, or registry-only admission. Consistent
with Decision 0007 §3.3 and Decision 0008 §14, the first implementation must
remain an explicit provider-specific/versioned branch.

Material changes to platform, driver, CUDA or relevant libraries,
runtime/build, worker topology, allocation path, accounting behavior, or
enforcement semantics require a new justified binding and, where outside the
admitted closed set, recharacterization or a new versioned decision.

---

## 16. Consequences

The architecture treats host-accounted and NVIDIA per-process memory as
distinct evidence domains with independent enforcement obligations. This
avoids both missing device allocations that do not appear equivalently in the
cgroup ledger and double-counting values whose unified-memory semantics may
overlap.

Admission becomes conservative: every required ledger and the machine reserve
must pass. The cost includes additional characterization, version binding,
allocation-path controls, evidence retention, failure injection, and terminal
verification.

RSS, PSS, global free memory, successful return, and cleanup observations remain
useful evidence within their limits. None receives authority it did not
demonstrate.

Startup variability is treated as a measured reserve problem rather than hidden
inside an arbitrary allowance. A higher valid observation cannot be erased by
averaging it with lower warm observations.

This decision preserves a narrow next experiment while preventing that
experiment from being mistaken for model or production admission.

---

## 17. Non-Goals

This decision does not:

- accept itself on Amy's behalf;
- canonically preserve the Tranche A evidence merely by recording its digest;
- open or begin Tranche B;
- authorize any Acer/GN100 execution or host change;
- authorize cgroup-limit configuration, CUDA execution, compilation, package
  installation, or dependency changes;
- open or load the pinned GLM artifact;
- authorize inference, model-specific kernels, model contexts, or model
  tensors;
- establish a final production memory budget;
- select or implement a preventative GPU allocation mechanism;
- implement or register a provider adapter;
- generalize provider or runtime architecture;
- allocate protocol, lifecycle, evidence, or failure-schema versions;
- reinterpret historical evidence; or
- authorize publication beyond the separately approved local one-file commit.

---

## 18. Deferred Implementation Proofs

A later, separately reviewed and authorized checkpoint must prove:

1. **Canonical evidence:** the retained Tranche A bytes and provenance are
   complete, immutable or equivalently protected, and independently digest
   verified.
2. **Host attribution:** dedicated cgroup identity and exact membership bind all
   intended worker host charges and exclude unrelated processes.
3. **Host enforcement:** real limits and `memory.events` demonstrate the
   intended behavior at and across boundaries.
4. **Device attribution:** NVIDIA per-process observations bind the exact worker
   PID and GPU UUID throughout their relevant lifetimes.
5. **Preventative device enforcement:** concurrent, asynchronous, boundary,
   one-over, failure, and release cases cannot overshoot the admitted live
   allocation budget.
6. **Machine reserve:** required system and desktop headroom remains available
   without summing overlapping ledger semantics.
7. **Startup reserve:** cold/warm randomized characterization supports a
   conservative upper envelope, explicit margin, and exact version binding.
8. **Combined footprint:** all required simultaneous live components are
   measured under both ledgers with time-correlated attribution.
9. **Failure distinction:** allocation failure, host-limit hit, device-limit
   hit, timeout, cancellation, and other failures preserve supported causal
   evidence without manufactured classifications.
10. **Cleanup:** every required success and failure path establishes owned
    cleanup, termination/reaping, no NVIDIA compute process, no transient unit,
    communication closure, and no retry/fallback/successor execution.
11. **Authority/observation separation:** expected budgets, digests, labels,
    manifests, and stored verdicts cannot masquerade as measured evidence.
12. **Verifier and compatibility:** independent terminal reconstruction rejects
    missing, stale, malformed, contradictory, cross-version, and historical
    fallback claims.
13. **Exact Tranche B boundary:** if later authorized, the native `sm_121a`
    experiment cannot load model artifacts or acquire inference/provider scope.

Fresh boundary tests, randomized characterization, fault injection, and
complete readback remain required where applicable. Documentary reasoning does
not constitute implementation or runtime proof.
