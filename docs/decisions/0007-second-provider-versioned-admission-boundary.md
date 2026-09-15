# Decision 0007 — Versioned Second-Provider Admission Boundary

## 1. Status, baseline, and relationship to Decision 0006

**Accepted by Human Chair**

Checkpoint: **P2 — Versioned Second-Provider Admission Boundary Specification**.

This document prepares a later implementation proposal. It does not implement,
register, select, or production-admit a second provider. Authorization to create
this document is not acceptance of its proposed decision or authorization for
source, test, schema, configuration, dependency, or provider changes.

The inspected canonical baseline is:

- repository: `/Users/aclab/aclab/model-council-lab`;
- branch: `m1-live-adapter-dev`;
- HEAD: `f4a1d705189bc1f1ba0c048ecaebd8ee405c2df8`;
- working tree and index: clean before this document was created;
- divergence: zero ahead and zero behind the existing upstream tracking ref,
  without fetching or independently refreshing remote state; and
- accepted Decision 0006 SHA-256:
  `b98a49b3705a54d41ea46560576a3d11918b8d91d3c02f8daf62a792b19bcda9`.

[Decision 0006](0006-second-provider-admission-contract.md) remains the
controlling admission contract. This proposal fixes where future admission
semantics enter the architecture; it neither reopens that contract nor claims
that its Section 8 implementation preconditions have been satisfied.

Evidence labels in this document mean:

- **Current source:** directly visible behavior at the canonical HEAD.
- **Source-supported inference:** a consequence of the interaction of those
  source paths, not a claim of observed execution.
- **Proposed requirement:** the boundary specified here for a later authorized
  provider-bounded implementation.
- **Future verification obligation:** a test requirement, not an implemented
  fixture or an executed test result.

No application tests or live provider calls were executed for P2. No protocol
number, schema identifier, lifecycle event, or runtime API is allocated here.

## 2. Current source evidence and distributed OpenAI-specific gates

### Current source

| Concern | Source and symbols | Boundary relevant to this proposal |
| --- | --- | --- |
| Trusted profile selection | `src/model_council/protocol.py`: `ADAPTER_KIND_PROFILES`, `execution_profile_for_kind` | Unknown kinds fail closed. The mapping selects an execution profile, not a separately qualified production-admission path. |
| Callable registration | `src/model_council/adapters.py`: `REGISTRY`, `LIVE_REGISTRY` | `live_stub` and `openai_responses` are the registered live kinds. The stub is not a provider implementation. |
| Worker dispatch | `src/model_council/worker.py`: `_main`, `_run_live` | Profile validation precedes dispatch; lifecycle descriptor validation and the writer passed to the adapter are specific to `openai_responses`. |
| Parent authorization | `src/model_council/executor.py`: `SubprocessAdapter.invoke_live`, `_spawn_worker` | The OpenAI branch validates the prepared journal, grants permission, and transfers the lifecycle descriptor. Other live kinds do not acquire this behavior through registration. |
| Frozen authority and identity activation | `src/model_council/runner.py`: `ExperimentRunner.execute`, `_treatment_declaration`, `_check_identity` | Run authority is frozen before stages. Provider-observed exact identity policy and the zero-automatic-retry admission gate are activated for OpenAI. |
| Neutral request, outcome, and treatment | `src/model_council/live_contract.py`: `LiveInvocationRequest`, `ProviderCallOutcome`, `build_live_invocation_request`; `src/model_council/security.py`: `normalize_provider_treatment_config` | Neutral contracts bound observations and denied authority. Generic treatment validation does not replace a closed provider-specific capability validator. |
| Retry authority | `src/model_council/retry_policy.py`: `is_retry_candidate`; `src/model_council/runner.py`: `_execute_stage_body` | MCL owns category policy and attempt authorization. Provider hints are not inputs to the retry-policy function. |
| Lifecycle contract | `src/model_council/attempt_lifecycle.py`: `LIFECYCLE_PROTOCOL`, `_validate_binding`, `AttemptJournal`, `JournalWriter` | The existing lifecycle is explicitly bound to v15, attempt 1, zero retries, and no predecessor. Its structural similarity to a possible future lifecycle is not admission authority. |
| Wire reconstruction | `src/model_council/artifacts.py`: `_verify_lifecycle_evidence`; `src/model_council/openai_adapter.py`: `build_openai_responses_request` | Terminal verification reconstructs trusted inputs and invokes the OpenAI wire builder to recompute the wire-request digest. |
| Historical reconstruction | `src/model_council/artifacts.py`: `_reconstruct_treatment`, `_verify_provider_identity_policy_evidence`; `src/model_council/invocation.py`: `build_invocation_record`, `serialize_invocation_record` | Historical treatment reconstruction uses the profile lookup. Existing version branches restrict identity and lifecycle claims and preserve historical invocation schemas. |
| Cleanup and publication | `src/model_council/openai_adapter.py`: `_perform_openai_responses_transport`, `openai_responses_skeleton` | Return/exception observations precede extraction or normalization. Required owned-client cleanup can veto a pending result before lifecycle outcome publication. |
| Promotion and evaluation | `src/model_council/runner.py`: `_assert_lifecycle_outcome`, `_commit_stage_transaction`, `_finalize_evaluation`; `src/model_council/artifacts.py`: `verify_terminal_run` | MCL owns lifecycle validation, artifact promotion, seals, evaluation, and independent terminal verification. |

### Source-supported inference

Adding a callable and profile entry would not supply the missing identity,
lifecycle, transport, cleanup, or terminal-verification qualification. Replacing
the OpenAI wire-builder call with an interface would address only one of these
distributed gates. Neither change constitutes production admission.

This is a future admission boundary, not evidence of a defect in accepted F6b
production behavior. No existing provider behavior is reopened by this proposal.

## 3. Proposed versioned admission selection

### 3.1 Separate profile selection from production admission

An execution profile describes the invocation contract. Registry membership
provides callable reachability. Production admission additionally requires the
accepted provider-specific obligations, their enforcement, and independent
terminal reconstruction. `live_contract_v1` and registry membership are not
sufficient substitutes.

A future second-provider admission must use a closed, trusted combination of:

- harness protocol;
- adapter kind; and
- provider-admission discriminator.

These are conceptual selection inputs, not a newly allocated serialized schema
or runtime API. The later named-provider proposal must define their exact
representation and every discriminator it introduces or changes before code is
authorized.

### 3.2 Freeze selection for the whole run

The selected combination must be bound in trusted run authority before dispatch
permission. One configured adapter/model identity governs the existing
homogeneous A/B/C topology. No stage can select another provider, model, or
admission interpretation.

Parent execution, worker authorization, persisted authority, and terminal
verification must agree on the selected combination. An adapter response,
provider metadata, retry hint, configured model alias, or stored verdict cannot
select or broaden admission semantics.

Unknown, missing, contradictory, or unsupported new-path discriminators must
fail closed. A registered provider without the admitted path and verifier
support must not dispatch. Terminal evidence with unsupported selection must
not fall back to historical verification or claim promotion or success.

These new-path requirements do not retroactively require an admission field in
historical artifacts that never had one.

### 3.3 Use an explicit provider-specific initial branch

The first implementation must use a small, explicit provider-specific/versioned
branch. It must not introduce a generalized provider base class, plugin loader,
dynamic callback registry, or universal reconstruction interface.

Existing neutral contracts remain available where their meaning is unchanged.
A callable seam may be considered in a later proposal only when concrete
implementations demonstrate an identical responsibility and input contract.
Possible future reuse is not sufficient justification for extracting accepted
OpenAI production behavior now.

## 4. Harness, provider, and terminal-verifier responsibilities

| Responsibility | Harness | Trusted provider-specific adapter | Independent terminal verifier |
| --- | --- | --- | --- |
| Admission selection | Select and freeze the trusted run-wide combination; refuse unsupported execution | Consume the authorized selection without changing it | Select only supported semantics from bound authority and reject contradictions |
| Identity | Freeze requested/configured identity and the admitted policy | Translate the frozen wire model and extract the admitted observed field | Recompute eligibility from authority and bounded provider observation |
| Capabilities and treatment | Copy, bound, freeze, and persist non-secret treatment | Apply a closed provider-specific validator before dispatch; reject unsupported capabilities | Reconstruct the admitted request and confirm capability closure |
| Request binding | Build authorized role inputs, output contract, limits, and time grant | Deterministically translate only the authorized request | Reconstruct from frozen authority and trusted prior-stage artifacts; recompute bindings |
| Request count and retries | Own permission and enforce zero automatic retries for initial admission | Make one bounded provider request per authorized attempt; no internal retries, fallback, or hidden child execution | Reject later attempts, predecessor links, redispatch, and contradictory evidence |
| Observations and normalization | Preserve bounded evidence without assigning it authority | Record the call boundary and return/exception observation before later extraction or normalization | Distinguish historical observations from eligible normalized outcomes |
| Ownership and cleanup | Own worker cancellation, collection, closure decisions, and conservative uncertainty handling | Expose ownership and complete required owned-resource cleanup before publication eligibility | Validate the admitted evidence relation; never infer owned-client cleanup from generic worker closure |
| Promotion, storage, and evaluation | Own paths, persistence, contract checks, seals, promotion, and evaluator invocation | No artifact-path, promotion, retry, or evaluator authority | Independently verify evidence, topology, eligibility, and terminal claims |

The provider-specific reconstruction branch must cover model-visible content,
wire model, output contract, ceilings, statelessness/tool controls, and admitted
treatment. Remaining timeout must retain its separately bound enforcement
meaning. Stored wire digests are comparison evidence, not substitutes for
reconstructing and hashing the expected request.

Configured identity is provenance and routing authority, not provider
attestation. For initial admission, an otherwise eligible successful response
must contain an exact observed-model match from the admitted response field.
Missing, malformed, ambiguous, alias, prefix, or inferred-equivalent identity
cannot authorize successful promotion.

The named-provider proposal must identify the exact observation field and
extraction rule. Unsuccessful provider outcomes retain their applicable neutral
failure classification; absence of successful-response identity evidence must
not automatically replace that classification with an identity failure.

The later proposal must also identify the evidence and trusted control flow
that make outcome publication conditional on required cleanup. Neither a
generic `returned` status nor direct-worker closure attests owned-client cleanup.

## 5. Historical compatibility and version boundaries

The existing v13/v14/v15 labels, record schemas, lifecycle events, digest
construction, identity predicates, and terminal-verification meanings remain
unchanged. The new provider must not be aliased to `openai_responses` or silently
inserted into the historical OpenAI path.

The future versioned path must preserve both backward verification and existing
run emission. Introducing it must not globally restamp existing OpenAI, legacy,
or `live_stub` runs with new semantics.

Execution admission and historical lookup are separate concerns. In particular,
`execution_profile_for_kind` participates in historical treatment reconstruction;
it must not be repurposed into a new execution-admission policy that changes the
meaning of old artifacts.

P2 prepares a new versioned path without allocating or activating it. The later
provider-bounded proposal must enumerate every protocol/evidence discriminator
it changes, the exact selection behavior, and backward-verification obligations.
It must not assume that a new harness label alone resolves every record-level
semantic change, or that every neutral schema must change merely because a new
provider exists.

Exact observed-model matching is an initial admission restriction, not a
universal identity architecture. A future local/open-weight provider needing a
different identity model would require a later explicit decision and versioned
verifier path. This proposal leaves that possibility open without adding alias
rules, artifact attestation schemes, or local-provider exceptions now.

## 6. Failure semantics and publication ordering

The conceptual order remains:

permission / call boundary → provider return or exception → extraction /
normalization → required cleanup → outcome eligibility → promotion eligibility
/ independent terminal verification.

This ordering allocates no lifecycle event names. It specifies causal and
eligibility obligations, not a replacement event vocabulary for existing runs.

The following invariants are mandatory for the later admission path:

1. MCL retains permission, retries, closure, persistence, promotion, evidence,
   and evaluation authority.
2. One configured adapter/model identity governs homogeneous A/B/C execution.
3. Initial admission allows one bounded provider request per authorized stage
   attempt, zero internal retries, and zero automatic harness retries.
4. Unsupported capabilities fail before dispatch, including unadmitted sessions,
   continuation, tools, storage, background work, fallback, and hidden child
   execution.
5. Earlier valid return/exception observations survive later extraction or
   normalization failure. Later failure cannot fabricate success or rewrite
   those observations into events that did not occur.
6. Required owned-client cleanup failure suppresses a pending provider outcome
   where the lifecycle architecture requires cleanup before publication. This
   applies to pending success and pending normalized failure alike.
7. Refusal, malformed protocol, incomplete result, quota exhaustion,
   authentication/configuration, and other applicable failures retain their
   existing neutral categories and permitted bounded observations. A shared
   terminal class does not make categories interchangeable.
8. A disqualifying failure or unpublished outcome cannot authorize successful
   promotion, downstream execution, or successful-candidate evaluation, even if
   worker closure completes.
9. `provider_retry_hint` and `retry_after_seconds` remain observations. They do
   not modify frozen policy, grant another request, authorize redispatch, or
   override MCL retry authority.
10. Missing, torn, contradictory, or ambiguous evidence cannot establish false
    closure, retry safety, outcome eligibility, or success. Historical evidence
    retains its original meaning.

F6b response-body limits, identity-only response encoding, owned-client
lifecycle, deterministic cleanup, cleanup-failure precedence, and
deadline/cleanup uncertainty remain protected. No F6b changes follow from P2.

## 7. Future offline verification matrix

Every row below is a **future verification obligation**. P2 implements no tests
or fixtures and reports no application-test execution. Synthetic fixture
success will not itself qualify a real provider's dependency or transport.

| Fixture category | Required observable assertions |
| --- | --- |
| Admission selection | Unknown kind, registration without admission, missing/wrong/mismatched discriminator, and absent verifier support produce zero provider dispatch. Unsupported terminal selection fails verification without historical fallback. |
| Supported A/B/C success | Supported closed treatment, exact observed identity, one request per authorized attempt, required cleanup, eligible outcome, valid stage promotion, and independent terminal reconstruction succeed for the admitted homogeneous workflows. |
| Unsupported capabilities | Sessions, continuation, tools, fallback, internal retries, and every other unadmitted provider field fail before the provider call boundary; no requested capability is silently discarded or reinterpreted. |
| Neutral failures | Refusal, malformed protocol, incomplete result, quota, and authentication/configuration preserve the exact applicable category and permitted bounded observations. No successful promotion, downstream execution, or successful-candidate evaluation occurs, including after closure. |
| Retry hints and budgets | Vary hint and retry-after independently of category. Frozen policy is unchanged and no second provider request occurs. Nonzero automatic harness retry budget is rejected before dispatch. |
| Identity | Otherwise eligible exact-match success passes. Missing, malformed, ambiguous, alias, prefix, snapshot mismatch, and other mismatch observations fail closed. Configured labels cannot fill missing observation; unsuccessful provider outcomes preserve their applicable category. |
| Normalization failure | The valid provider return/exception observation remains after extraction or normalization fails. No fabricated success or promotion follows. |
| Cleanup veto | Required cleanup failure suppresses pending success and pending failure publication. Earlier observations remain. Generic closure or reason `returned` cannot prove owned-client cleanup or authorize promotion, downstream execution, or evaluation. |
| Transport and materialization bounds | Exact-boundary and one-over fixtures cover the provider's admitted byte/item/depth/time limits at transport, response admission, extraction, normalized outcome, raw evidence, diagnostics, and worker protocol boundaries. Bounds are not inferred from OpenAI's transport policy. |
| Deadline, reaping, and EOF uncertainty | Timeout, missing EOF, uncertain reaping, incomplete cleanup, and contradictory evidence cannot establish false closure, redispatch authority, publication eligibility, or success. |
| Adversarial terminal reconstruction | Tampered kind, version, identity, treatment, request binding, outcome, stored verdict, seal, or topology fails independent verification, including coordinated local rehashing. |
| Historical compatibility | Existing v13/v14/v15 fixtures retain their original verification results. New-provider claims cannot acquire historical OpenAI semantics. Existing OpenAI, legacy, and `live_stub` emission remains unchanged. |

Existing coverage references to preserve include `tests/test_execution_profile.py`,
`tests/test_provider_identity_policy.py`, `tests/test_provider_treatment_config.py`,
`tests/test_attempt_lifecycle_dispatch.py`,
`tests/test_attempt_lifecycle_terminal.py`, `tests/test_retry_policy.py`,
`tests/test_live_contract.py`, `tests/test_openai_adapter_transport.py`,
`tests/test_executor_response_bounds.py`, and
`tests/test_openai_response_guard.py`. They remain unchanged in P2. Their future
execution requires the separately authorized source/test checkpoint.

The broader-suite conflict in
`test_openai_canary.TestOpenAICanary.test_06_import_and_help_create_no_output_directory`
is separate: it assumes `runs/` is absent while historical evidence is retained.
Do not delete or move that evidence, weaken the test, or claim the whole suite
is green while this known conflict remains.

P2 verification is documentary: confirm the exact changed-path scope, unchanged
Decision 0006 digest, unchanged existing tracked files, complete readback, and
the proposed document's SHA-256 for independent review. These checks do not
prove future provider behavior.

## 8. Named-provider implementation prerequisites and non-goals

Before provider implementation, a separately reviewed proposal must satisfy
Decision 0006 Section 8 and provide evidence for:

- the named provider, endpoint/API surface, exact model, admitted observed
  identity field, extraction rule, and trusted adapter boundary;
- dependency versions and automatic retry, redirect, fallback, and hidden
  execution behavior;
- deterministic request translation, a closed non-secret treatment schema,
  unsupported-capability rejection, and one-call proof;
- explicit transport/materialization bounds and deadline enforcement;
- acquisition, ownership transfer, close-once behavior, required cleanup,
  worker reaping, EOF, and conservative uncertainty semantics;
- sanitized neutral failure mapping and permitted bounded observations;
- the exact version/discriminator path and independently reconstructible
  request, identity, lifecycle, promotion, and terminal evidence;
- every source and test path to change, the offline tests implementing the
  matrix, and protection of existing behavior; and
- separate authorization for any dependency/configuration change, credential
  access, paid/provider call, or live compatibility check.

P2 does not choose a provider. Cloud, Muse or another API-accessible provider,
local/open-weight endpoints, and OpenAI-compatible servers receive no preference
or qualification here. API compatibility alone does not satisfy admission.
An endpoint without the required observed identity cannot satisfy this initial
identity rule through configured-label substitution.

P2 does not implement or register an adapter, add executable conformance
fixtures, extract OpenAI machinery, design Condition D or heterogeneous routing,
add sessions/tools/children, change retry policy or failure categories, allocate
versions/schemas/events/APIs, or resolve all future local-model identity needs.

The OpenAI `Accept-Encoding: identity` real-provider compatibility canary remains
separate. Optional F6b test hardening and the retained-evidence suite conflict
also remain separate. No implementation, test execution, live call, credential
access, agent/subagent use, or Git publication is authorized by this document.

After exact-byte review of this proposal, stop for Human Chair acceptance. Any
later implementation requires its own bounded authorization; acceptance of P2
does not waive Decision 0006's outstanding named-provider preconditions.
