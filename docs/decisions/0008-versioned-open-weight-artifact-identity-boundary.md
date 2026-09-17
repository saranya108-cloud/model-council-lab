# Decision 0008 — Versioned Open-Weight Artifact Identity Boundary

## 1. Status

Accepted by Human Chair

Amy, as Human Chair, accepted Decision 0008 after independent review and bounded re-review resolved F1–F13. This acceptance is architecture-only; it does not constitute provider admission or implementation authorization.

Canonical MCL baseline:

- Repository: `/Users/aclab/aclab/model-council-lab`
- Branch: `m1-live-adapter-dev`
- HEAD: `df378d9750c38dc1845d2204ecf63ff9889b5a76`

Decisions 0004, 0006, 0007, and accepted P3-A remain controlling, subject only to the explicit open-weight identity-form replacement proposed here.

The investigation of:

`llama.cpp b6000 / 4762ad7316dcdec20016ab5985fb46a27902204d`

is uncommitted documentary feasibility context produced during the architecture investigation.

It has not been accepted or committed as a repository artifact and is not part of canonical HEAD.

That witness motivated and informed this proposal.

Decision 0008's validity does not depend on accepting it as normative architecture.

If retained later as an accepted artifact, it requires its own review, acceptance, and publication path.

---

## 2. Context

Configured model names and deployment descriptions do not independently establish which computational artifacts produced an open-weight result.

MCL requires an observed-identity mechanism connecting actual artifact consumption to the authorized execution and its terminal result.

Artifact identity and execution binding are distinct: measuring the correct package does not alone establish that an authorized attempt used it.

Decision 0006 §4.4 rule 15 and Decision 0007 anticipate a later explicit, versioned identity decision.

This decision supplies that boundary without weakening other admission, execution, treatment, cleanup, or verification obligations.

---

## 3. Decision

MCL may admit artifact-based observed identity only through an explicitly accepted, provider-specific, versioned admission path.

Before execution, trusted run authority must freeze:

- The authorized artifact identity and effective-model composition.
- The applicable provider admission and observed-identity semantics.
- One exact admitted runtime/build identity, or an explicitly enumerated closed set if later architecture permits one.
- The separately defined treatment and execution limits.

An expected digest or other expected artifact identity is authority. Observed identity must be a separately recorded measurement derived from the artifacts actually consumed.

Copied expected values are not observations. A stored boolean such as `identity_match=true` is not observation evidence. The independent verifier must compare independently measured evidence against frozen authority.

The following cannot independently prove observed identity:

- Configured labels, filenames, aliases, or repository names.
- Caller-supplied hashes or manifests by themselves.
- Operator or deployment assertions.
- Artifact-embedded names or checksums.
- Runtime-reported model labels.
- Server response model fields whose provenance is configuration.

### Open-weight replacement of historical response-field identity form

For the admitted open-weight artifact-identity path only, execution-bound artifact observation replaces the historical requirement that observed identity originate from a provider response field, identity field, or provider-field extraction rule.

This replacement applies wherever that historical form appears in the controlling architecture, including:

**Decision 0006**

- §3 identity row requiring provider-observed identity;
- §4.4 rule 14;
- §6 Exact observed identity conformance row;
- §8 precondition 2 requiring the exact model identity field to be named;
- §8 precondition 6 requiring exact provider-observed model matching.

**Decision 0007**

- §4 identity row requiring extraction of the admitted observed field;
- §4 requirements for exact observed-model match from an admitted response field and a named observation field/extraction rule;
- §7 identity row;
- §8 prerequisite requiring an admitted observed identity field and extraction rule;
- the closing §8 statement describing the initial identity rule.

**P3-A**

- §1 summary language requiring an admitted response field;
- V1’s response-field interpretation.

For this path, the admitted artifact-measurement and execution-binding method satisfies the architectural role previously assigned to an observed identity field and extraction rule.

This replacement changes **only the form by which observed identity is obtained**.

The substantive identity requirements remain fully controlling:

- observed identity must exactly correspond to frozen authority under the admitted artifact-identity rules;
- no alias, prefix, snapshot, normalization, family-name, or inferred equivalence may substitute for exact admitted identity;
- configured labels, runtime-reported model names, manifests, caller-supplied values, or other configured identity cannot supply a missing observation;
- missing, malformed, contradictory, mismatched, or ambiguous identity evidence fails closed;
- unsuccessful execution preserves its supported failure classification rather than manufacturing an identity-mismatch cause;
- terminal verification independently recomputes the identity result from frozen authority and trusted measured evidence rather than accepting a stored verdict.

Every other requirement of Decisions 0006, 0007, and accepted P3-A remains controlling.

Historical OpenAI, legacy, and previously accepted evidence retains its original identity semantics and is not reinterpreted by this decision.

Runtime-reported model names may be retained as diagnostic evidence but are never compared as authoritative observed identity under the open-weight artifact-identity path.

---

## 4. Scope

This boundary applies to an explicitly admitted open-weight provider serving existing homogeneous A/B/C workflows.

One authorized effective-model identity governs the run.

Distinct instances may serve separately authorized attempts where admitted, but each needs a justified association with the same frozen authority.

The contract requires no particular runtime, artifact format, operating system, filesystem, or protection mechanism.

An execution context is:

> the runtime execution scope and state in which the authorized attempt is evaluated.

A compliant runtime need not expose separate model and context objects.

Where these concepts are combined internally, equivalent evidence must establish the required causal relationships.

Prepared-instance or instance-reuse behavior requires explicit admission and continuity proof.

Cross-run prepared-instance reuse is not admitted by default.

---

## 5. Artifact Identity

The identity boundary must include every computational artifact whose material contribution changes the effective model used by the admitted path, including where applicable:

- weights and all required shards;
- architecture/configuration metadata, whether embedded or stored separately;
- tokenizer data, including material vocabulary, normalization, merge, and special-token information;
- active adapters;
- projectors and auxiliary computational models;
- control vectors and equivalent model-altering artifacts.

The admitted interpretation must define complete membership, roles, composition, and material ordering.

Missing, additional, substituted, or ambiguously composed artifacts cannot satisfy exact identity.

Effective-model composition also includes, when material:

- active adapter identity and scale;
- control-vector identity, strength, and application range;
- architecture-changing metadata overrides;
- load-time weight transformations;
- requantization, merging, dtype conversion, and equivalent transformations.

These values may also require treatment reconstruction, but cannot be classified only as treatment.

Changing them changes model identity/composition and requires a new justified binding consistent with frozen authority.

It does not authorize changing the run's model.

Runtime/build identity remains separate from model-package identity.

Tokenizer and architecture semantics may depend jointly on package data and runtime implementation; both sides of that relationship must be bound.

Unconsumed neighboring files, model cards, and training artifacts need not enter identity merely because they share a directory or repository.

---

## 6. Execution-Bound Observation

An eligible result requires a reconstructible chain:

`measured artifacts`
→ `successful load`
→ `model instance`
→ `execution context`
→ `authorized MCL attempt`
→ `generation lifecycle`
→ `terminal result`

These are causal relationships, not prescribed runtime objects or schema fields.

Successful load must establish completion of the required loading work and its association with the measured artifacts.

File opening, metadata parsing, progress reporting, and metadata-only or tokenizer-only loads are insufficient.

Instance associations must account for lifecycle/reference semantics, creation, destruction, recreation, and admitted reuse.

A relationship cannot extend beyond the lifetime in which it was established.

No single digest, PID, pointer, request ID, manifest, or configured label establishes the chain.

Such identifiers may participate only with justified association and lifetime evidence.

Independent verification reconstructs the admitted evidence relationships.

It does not require repeating inference and must not accept an adapter's stored verdict as proof.

---

## 7. Measurement-to-Load Requirements

The admitted path must establish that measured artifacts are the artifacts actually consumed by the loader, including material metadata and computational data.

The proof must cover:

- separate opens or reads of the same nominal artifact;
- every shard and auxiliary artifact;
- pathname replacement and object-reference reuse;
- in-place modification during measurement or loading;
- lazy reads, mappings, deferred transfers, and backing-object lifetimes;
- partial loading, cancellation, and failed validation;
- any admitted transformation from measured artifacts to effective-model composition.

Hashing a pathname and later reopening it is insufficient without justified continuity.

Protection must begin early enough to cover measurement and relevant consumption.

For eager loading, the proof must establish when dependence on backing artifacts ends.

Deferred consumption requires protection through the last relevant access.

No specific operating-system mechanism is mandated.

Any proposed mechanism must demonstrate the complete guarantees required by this contract.

---

## 8. Runtime Trust Boundary

This decision adopts Decision 0004's trusted, project-controlled harness boundary.

Measurement, loading, runtime integration, lifecycle reporting, and evidence handling must occur within a reviewed, admitted trusted boundary.

Open-source availability or a familiar API does not itself establish trust.

The executing runtime/build identity must be established through trusted evidence inside that boundary.

A runtime's own version string or self-reported build label cannot independently prove its identity.

Model outputs remain untrusted.

MCL retains authority over identity, configuration, permitted context, limits, permission, retries, persistence, promotion, and evaluation.

Any load path that executes artifact-supplied code is inadmissible for the initial path.

This includes arbitrary serialized-object execution, remote-code loading, and equivalent mechanisms unless separately admitted by future architecture.

Deliberate same-user hostile mutation outside the trusted harness and privileged hostile mutation remain outside the M1 threat model.

This decision also does not require defense against a malicious kernel, hostile trusted harness code, or arbitrary replacement of the trusted evidence anchor.

The architecture does require protection against accidental mutation, ordinary races, concurrent non-hostile modification, stale or mismatched objects, and unsupported configuration.

This decision does not require external cryptographic notarization.

Expanding the threat model requires a separate architecture decision.

---

## 9. Exactly-One Execution

Each authorized stage attempt may initiate one bounded semantic generation.

The initial path preserves:

- zero internal semantic retries;
- zero automatic harness retries;
- no fallback or alternate-model execution;
- no duplicate-completion fan-out;
- no hidden successor execution;
- no supervisor, client, transport, or service replay.

One API invocation or one final response does not independently prove one execution.

Numerical or resource recovery remains within the same semantic execution only when:

1. already-committed output and sampler state are preserved;
2. model-visible context is unchanged across the recovery;
3. admitted backend, device, precision, and effective-model composition remain unchanged.

The recovery must also preserve the submitted request, capabilities, authorization, execution continuity, and result authority.

The following are not ordinary numerical recovery:

- restarting the prompt or regenerating committed output;
- dropping, truncating, or shifting model-visible context;
- changing backend, device, or precision;
- switching models;
- reissuing the request after OOM or another failure.

Operator-configured draft-model speculative decoding, lookahead models/heads, and equivalent auxiliary inference are material execution/model capabilities requiring explicit admission.

They are not automatically opaque numerical internals.

Ambiguity about whether execution occurred cannot authorize replay.

---

## 10. Mutation / Reload Invalidation

An execution-bound identity remains valid only while its admitted continuity conditions hold.

Fail closed on any unadmitted:

- model reload or replacement;
- runtime restart;
- model/context recreation;
- adapter, projector, control-vector, or other model-altering composition change;
- tokenizer or template state change;
- state restoration;
- cross-attempt KV reuse;
- prompt-cache reuse;
- saved-session restoration;
- device change or backend change during an instance;
- artifact-protection loss during a required protection interval;
- semantic replay or successor execution.

Backend/device changes during an active instance invalidate the binding unless continuity across that change was explicitly admitted and proven.

Such admission does not make the change ordinary numerical recovery under Section 9.

An implementation cannot excuse unadmitted restoration or reuse by asserting that it does not change execution semantics.

Equivalent artifact hashes alone do not preserve instance continuity.

A fresh instance requires a fresh justified binding and applicable permission.

Ordinary admitted decoding state is not itself an identity violation.

Artifact replacement after proven eager consumption need not invalidate an instance if the replaced object is no longer a dependency; any later consumption requires a justified binding.

Unknown continuity suppresses eligibility.

---

## 11. Treatment and Reconstruction

Artifact identity does not silently freeze treatment.

The admitted path must separately close, freeze, and reconstruct material templates, generation parameters, context settings, relevant overrides, and backend/device choices.

Settings that alter effective-model composition remain subject to Section 5 as well.

For local/open-weight execution, model-visible input must be defined at the level that determines the actual token sequence.

Reconstruction must therefore close, where applicable:

- template rendering;
- role formatting;
- BOS/EOS behavior;
- special-token handling;
- tokenizer behavior;
- handling of special-token-like content in untrusted prior-stage output.

Untrusted text must not acquire control or role semantics merely by containing provider/runtime special-token strings.

Defaults and transformations must be explicit enough for independent reconstruction.

Unsupported values must fail before execution rather than be silently ignored or substituted.

The verifier must reconstruct expected input and effective admitted parameters from frozen authority and permitted prior-stage artifacts.

Stored digests are comparison evidence, not substitutes for reconstruction.

Every intermediate tokenization artifact need not be stored unless necessary for the admitted reconstruction method.

---

## 12. Evidence Lifecycle

Run-level authority freezes the open-weight identity, effective-model composition, exact admitted runtime/build identity, treatment, and provider semantics governing the run.

Per-attempt permission authorizes one specific stage attempt to use one specific admitted model/runtime instance or justified prepared instance.

It must bind the exact instance and execution context used by that attempt.

### Authority

Freeze the run's admitted identity, runtime/build, composition, treatment, semantics, and limits.

### Measurement

Establish separately recorded observed artifact identity and required protection/continuity facts.

### Load

Establish successful required loading and its association with measured artifacts and composition.

### Context

Establish the execution scope, admitted initial state, and association with the model/runtime instance.

### Permission

Authorize that specific attempt to use the exact justified instance and context before semantic generation.

### Execution

Cross the semantic generation boundary once and remain within admitted semantics and limits.

### Outcome

Preserve return, error, cancellation, and incomplete-execution observations before normalization.

### Cleanup

Establish required owned-resource cleanup, worker termination/reaping, and communication closure separately.

### Verification

Independently reconstruct authority, observations, request, lifecycle, cleanup, and terminal eligibility.

The admission path must define causal ordering where preparation and permission are staged.

Preparation alone never authorizes generation.

If measurement/load evidence predates the current run's authority:

- it must be durably incorporated into the current run's independently verifiable evidence set;
- continuity from creation through current use must be proven;
- evidence existing only in runtime memory or another run is insufficient.

Cross-run prepared-instance reuse is not admitted by default.

Evidence must be bounded, attributable, and retained sufficiently for verification.

Normal return does not establish cleanup, and worker reaping does not establish every owned-resource cleanup obligation.

Missing observations remain uncertainty.

---

## 13. Failure Semantics

Required pre-generation identity conditions must be established before the semantic generation boundary.

When any required identity condition is known to have failed before that boundary, MCL must perform zero semantic generation.

Examples include:

- artifact mismatch or incomplete membership;
- failed protection;
- runtime/build mismatch;
- invalid effective-model composition;
- failed load provenance.

A later verifier veto is not an acceptable substitute for preventing generation when failure was already known.

The actual supported failure observation must be preserved.

This decision allocates no new failure category.

Load failure, cancellation, resource exhaustion, malformed output, incomplete generation, and other failures retain their applicable neutral classification.

Missing identity on an unsuccessful load does not automatically replace that load failure with an identity-mismatch classification.

Otherwise successful execution with missing, contradictory, mismatched, or invalidated identity evidence is ineligible for successful promotion.

Required cleanup failure suppresses pending outcome publication where the admitted lifecycle requires cleanup before publication.

Earlier valid observations remain preserved.

No failure, uncertainty, cleanup ambiguity, or retry hint grants permission for replay, fallback, successor execution, downstream execution, or successful-candidate evaluation.

---

## 14. Versioning Boundary

This is the explicit later identity decision anticipated by Decisions 0006/0007.

Its proposed replacement is limited to the observed-identity form identified in Section 3.

Artifact-based identity requires a provider-specific, trusted, versioned admission and verifier path consistently selected by parent execution, worker authorization, persisted authority/evidence, and terminal verification.

It must not silently reuse historical OpenAI response-field identity semantics, alias itself to an existing provider kind, or reinterpret historical evidence.

Existing OpenAI, legacy, live_stub, and accepted historical emission and verification meanings remain unchanged.

Unsupported, missing, or contradictory admission selection fails closed without historical fallback.

Decision 0008 defines a generic architectural evidence contract only.

It does not authorize a generalized provider base class, plugin loader, dynamic callback registry, universal reconstruction interface, or shared open-weight runtime abstraction contrary to Decision 0007 §3.3.

The initial implementation must remain an explicit provider-specific/versioned branch.

No protocol number, schema identifier, database field, lifecycle event name, or runtime API is allocated here.

A later proposal must enumerate exact changes and compatibility obligations.

---

## 15. Consequences

Open-weight identity may be established through execution-bound observation of consumed artifacts and effective-model composition.

Frozen expected identity remains authority.

Separately measured evidence supplies observation.

Neither package measurement nor an execution identifier is sufficient alone.

Admission applies to the complete measurement, runtime, lifecycle, treatment, and verification path.

Prepared instances, state reuse, transformations, and auxiliary inference increase proof obligations and receive no implicit admission.

The contract permits different implementations while preserving exact identity, one semantic execution, and independent reconstruction.

It does not authorize a generic implementation framework.

Costs may include measurement, protected storage, restricted reuse, initialization overhead, and conservative failure handling.

Those costs do not justify weaker identity semantics.

---

## 16. Non-Goals

This decision does not:

- select a foundation model or production runtime;
- accept or publish the documentary feasibility witness;
- download artifacts or run inference;
- implement or register an adapter;
- allocate versions, schemas, fields, or APIs;
- admit auxiliary inference, cross-run reuse, state restoration, tools, sessions, continuation, or heterogeneous routing by default;
- require a particular runtime, artifact format, or OS protection mechanism;
- guarantee deterministic numerical output;
- expand Decision 0004's threat model;
- authorize repository writes, dependencies, host changes, provider execution, or publication.

---

## 17. Deferred Implementation Proofs

A later, separately authorized provider-specific proposal must prove:

1. **Authority/observation separation:** expected values cannot masquerade as measurements, and stored verdicts cannot replace comparison.

2. **Exact runtime/build identity:** trusted evidence identifies executing binaries, dependencies, backends, and material build configuration.

3. **Artifact/composition closure:** all material artifacts, application settings, overrides, and transformations are included.

4. **Consumption binding:** all relevant opens, reads, transformations, and deferred accesses remain bound to measured artifacts.

5. **Mutation resistance:** required protection covers races, concurrent non-hostile modification, stale objects, and the complete dependency interval.

6. **Load completion:** partial, cancelled, metadata-only, tokenizer-only, or otherwise incomplete loads cannot yield eligible instances.

7. **Instance continuity:** lifecycle associations, prepared evidence, permitted reuse, and per-attempt permission cannot create false bindings.

8. **Single execution:** no semantic retry, replay, fallback, fan-out, or hidden successor; recovery preserves Section 9's invariants.

9. **Input/treatment reconstruction:** actual token-determining semantics are closed, including safe handling of untrusted special-token-like text.

10. **Pre-generation enforcement:** known identity failures produce zero semantic generation.

11. **Bounds/cancellation/cleanup:** limits, owned cleanup, termination, reaping, closure, and uncertainty are independently justified.

12. **Verifier and compatibility:** malformed or contradictory evidence fails closed, while historical semantics remain unchanged.

13. **Executable-content exclusion:** the initial load path cannot execute artifact-supplied code.

Fresh negative tests and fault injection remain necessary where applicable.

Documentary reasoning does not constitute implementation proof.
