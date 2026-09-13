# Decision 0006 — Second-Provider Admission Contract and Evidence Map

## Status

Accepted by Human Chair

## Decision class and evidence labels

This ADR is a design and documentation checkpoint. It does not admit or
implement a second provider.

The following labels distinguish what this document knows from what it
proposes:

- **Current implementation** — behavior directly visible in the repository at
  `af25d885387063b61e23da5581fc438aa0710d91`.
- **Source-supported inference** — a conclusion required by the interaction of
  current source paths, but not itself an activated admission rule.
- **Proposed requirement** — a condition a second provider must satisfy before
  production admission.
- **Existing test coverage** — a checked-in offline test that names or exercises
  a relevant current behavior. No test was run for this ADR.
- **Future test obligation** — coverage required in a separately authorized
  implementation checkpoint.

## 1. Baseline and bounded scope

### Current implementation

The current harness supports only Conditions A, B, and C in
`model_council.types.Condition`. Their stage topology, allowed context, output
artifacts, and role instructions are fixed by
`model_council.roles.CONDITION_STAGES`, `ALLOWED_INPUT_KEYS`,
`EXPECTED_ARTIFACTS`, `STAGE_OUTPUT_KEYS`, and `ROLE_INSTRUCTIONS`.
`WORKFLOW_NOTES` describes B as serial self-refinement by one model identity
and C as a homogeneous role-separated council using one model lineage.

`model_council.protocol.ADAPTER_KIND_PROFILES` maps trusted adapter kinds to an
execution profile, and `execution_profile_for_kind` fails closed for unknown
kinds. `model_council.adapters.LIVE_REGISTRY` currently contains `live_stub`
and `openai_responses`; the `live_stub` profile declaration in
`model_council.protocol.ADAPTER_KIND_PROFILES` explicitly says it is not a
provider implementation. Therefore OpenAI Responses is the only currently
registered production live provider adapter.

The active neutral contracts are `m1-live-contract-v4` and
`live_contract_v1`. The current harness protocol is `m1-dev-harness-v15`.
These names have different version domains and must not be conflated.

### Proposed requirement

The first second-provider admission is bounded to one trusted,
project-controlled, single-request adapter serving the existing homogeneous
A/B/C workflows. One configured adapter/model identity governs an entire run.
No stage may select a different provider or model.

This tranche does not:

- implement or register another provider;
- change production lifecycle machinery;
- add Condition D or heterogeneous routing;
- allocate a protocol, lifecycle, invocation, or evidence-schema version;
- rename events, change schemas, or alter digest construction;
- design a generalized runtime, conversation, session, tool, or child-agent
  architecture;
- change OpenAI, legacy, `live_stub`, canary, or accepted F6b behavior; or
- resolve real-provider compatibility of OpenAI's
  `Accept-Encoding: identity` request policy.

## 2. Current-state evidence map with exact source symbols

| Concern | Current implementation evidence | Boundary or source-supported inference |
| --- | --- | --- |
| Trusted execution-profile selection | `model_council.protocol.ADAPTER_KIND_PROFILES`; `SUPPORTED_EXECUTION_PROFILES`; `execution_profile_for_kind` | The mapping is trusted harness configuration, but a live profile is not production admission. |
| Child-side callable selection | `model_council.adapters.REGISTRY`; `LIVE_REGISTRY`; `model_council.worker._main`; `_run_live`; `_run_legacy` | `LIVE_REGISTRY` membership makes a callable reachable after profile validation. It does not add provider identity policy, lifecycle authority, terminal reconstruction, or production qualification. |
| One run identity | `model_council.types.AdapterIdentity.key`; `RunSpec.model_identifier`; `model_council.runner.ExperimentRunner.execute`; `_check_identity` | The runner checks configured identity before stages and resolved identity after each invocation. Current provider-observed exact matching is activated only for `openai_responses`. |
| Homogeneous A/B/C topology | `model_council.types.Condition`; `model_council.roles.CONDITION_STAGES`; `ALLOWED_INPUT_KEYS`; `validate_stage_sequence`; `WORKFLOW_NOTES` | There is no Condition D enum or heterogeneous per-stage routing path. |
| Frozen run authority | `ExperimentRunner.execute`; `_treatment_declaration`; `_treatment_hash`; `model_council.artifacts.ArtifactStore.write_execution_binding`; `write_treatment_declaration`; `freeze_run_authority` | Run-defining identity, adapter configuration, treatment, evaluator binding, and protocol/profile labels are persisted before execution. |
| Frozen non-secret provider treatment | `model_council.executor.SubprocessAdapter.__init__`; `persisted_provider_treatment_config`; `model_council.security.normalize_provider_treatment_config`; `deep_freeze` | Generic neutral code bounds and freezes JSON treatment and rejects secret-like fields; each provider still needs a closed provider-specific capability validator. |
| Reconstructible request binding | `model_council.live_contract.build_live_invocation_request`; `parse_live_invocation_request`; `_input_content_digest`; `_request_parameter_digest`; `model_council.invocation.treatment_digest_for_attempt` | Model-visible input and frozen parameters are digest-bound. A second provider needs a versioned verifier path that can reconstruct its provider-specific wire request without trusting stored verdicts. |
| Denied adapter authority | `model_council.live_contract.DENIED_AUTHORITY`; `LiveInvocationRequest.authority`; `parse_live_invocation_request` | The adapter is denied retry, alternate-model selection, artifact writes, and evaluator access in the neutral request. |
| One neutral attempt/outcome | `LiveInvocationRequest`; `ProviderCallOutcome`; `parse_provider_call_outcome` | Their docstrings define one runner-authorized attempt and one provider request. The parser requires `adapter_internal_retry_count == 0`; provider-specific code must still prove that its transport makes exactly one request. |
| Runner attempt authority | `ExperimentRunner._execute_stage_body`; `_invoke_authorized_attempt`; `model_council.retry_policy.is_retry_candidate` | The runner owns attempt count, remaining deadline, cumulative input ceiling, and retry decisions. Provider retry hints are observational only. |
| OpenAI zero-retry gate | `ExperimentRunner.execute`; `model_council.attempt_lifecycle._validate_binding` | `openai_responses` requires `max_stage_retries == 0`, and its lifecycle binding requires attempt 1 with no predecessor. This gate is not generic to every live kind. |
| Provider-specific single transport call | `model_council.openai_adapter.build_openai_responses_request`; `_validate_openai_transport_request`; `_perform_openai_responses_transport`; `openai_responses_skeleton` | OpenAI builds a stateless request, configures SDK retries to zero, and calls `client.responses.create` once. Equivalent proof does not yet exist for a second provider. |
| Tools and statefulness | `build_openai_responses_request`; `_validate_openai_transport_request`; `validate_openai_provider_treatment`; `model_council.live_contract.DENIED_AUTHORITY` | Current OpenAI translation fixes `store=False`, `background=False`, `tools=[]`, `tool_choice="none"`, and `parallel_tool_calls=False`, and rejects stateful treatment controls. The neutral contract alone does not validate every provider-specific capability. |
| Worker boundary | `model_council.executor.SubprocessAdapter.invoke_live`; `_spawn_worker`; `model_council.worker._run_live` | Invocation payload data crosses as serialized JSON. The trusted launcher separately supplies a narrow runtime environment and, for the OpenAI path, dedicated protocol and append-only lifecycle descriptors plus the applicable child credential boundary. Those descriptors carry capabilities required for protocol and lifecycle operation. The subprocess is timeout/process isolation, not an OS sandbox against hostile adapter code. |
| Communication and materialization bounds | `model_council.live_contract.MAX_TRANSPORT_RAW_BYTES`; `MAX_RAW_EVIDENCE_BYTES`; `MAX_STRUCTURED_EVIDENCE_BYTES`; `MAX_STAGE_OUTPUT_ENVELOPE_BYTES`; `model_council.executor._collect_openai_worker`; `model_council.openai_adapter._OpenAIExtractionBudget` | Neutral outcome bounds exist, while early response-body interception, extraction, protocol-channel, diagnostic, and cleanup bounds are provider/transport-specific. |
| Dispatch permission and call boundary | `model_council.attempt_lifecycle.AttemptJournal.create`; `permit`; `JournalWriter.append`; `validate_prepared_binding`; `validate_worker_binding`; `model_council.openai_adapter._perform_openai_responses_transport` | Durable permission precedes OpenAI's `sdk_call_boundary`. The worker receives only one append capability. This path is currently OpenAI-specific. |
| Outcome and cleanup evidence | `JournalWriter.outcome`; `AttemptJournal.close`; `inspect`; `model_council.executor._WorkerReaping`; `_run_openai_worker`; `_collect_openai_worker` | Outcome observation, direct-child reaping, pipe EOF, and cleanup completion are distinct facts. Missing or ambiguous cleanup remains conservative evidence, not permission to retry. |
| Artifact promotion | `ExperimentRunner._check_identity`; `_check_output_and_tool_budget`; `_check_contract`; `_commit_stage_transaction`; `ArtifactStore.seal_stage`; `verify_sealed_stage` | Identity, budgets, output contract, invocation persistence, sealing, and re-verification precede a successful stage transition. The adapter cannot choose artifact destinations or promotion. |
| Evaluation isolation | `ExperimentRunner._finalize_evaluation`; `model_council.evaluator.ExternalEvaluator`; `ArtifactStore.verify_completed_run` | Evaluation begins only after the complete stage topology verifies; evaluator configuration is not supplied to the adapter. |
| Terminal independent verification | `ArtifactStore.verify_terminal_run`; `model_council.artifacts._assert_invocation_profile_binding`; `_assert_invocation_treatment_digests`; `_verify_provider_identity_policy_evidence`; `_verify_lifecycle_evidence`; `_assert_provider_identity_topology`; `_assert_terminal_status_topology` | The verifier recomputes topology, request/treatment bindings, identity verdicts, lifecycle, and promotion coherence. Identity and lifecycle verification are currently explicitly restricted to `openai_responses`. |
| Historical compatibility | `model_council.protocol.HISTORICAL_HARNESS_PROTOCOL_VERSION`; `F2_HARNESS_PROTOCOL_VERSION`; `HARNESS_PROTOCOL_VERSION`; `VERIFIABLE_HARNESS_PROTOCOL_VERSIONS`; `model_council.invocation.HISTORICAL_INVOCATION_SCHEMA`; `INVOCATION_SCHEMA` | Current verification deliberately preserves distinct historical paths. A second provider cannot be inserted by reinterpreting those paths. |

The central source-supported inference is that adding a provider kind to
`ADAPTER_KIND_PROFILES` and `LIVE_REGISTRY` would be insufficient and unsafe as
a production-admission act. Such a kind could reach the neutral live path, but
the runner would not create the OpenAI-only exact identity policy or lifecycle
journal, and the terminal verifier currently rejects those claims for a
non-OpenAI adapter. Registry membership alone therefore never grants
production admission.

## 3. Harness / adapter / terminal-verifier ownership matrix

| Property | Harness ownership | Trusted adapter ownership | Terminal-verifier ownership |
| --- | --- | --- | --- |
| Run topology | Select A/B/C and exact role order; construct allowed context | Consume only the provided role request | Reconstruct expected roles, inputs, artifacts, seals, and downstream eligibility |
| Identity authority | Freeze requested/configured `AdapterIdentity` and one run-level `model_identifier` | Translate only to that configured wire model; report provider-observed identity | Recompute exact-match eligibility from frozen authority and observed provider evidence |
| Capability admission | Freeze zero tools and the admitted non-secret treatment | Reject unsupported, stateful, tool, fallback, or multi-request capabilities before dispatch | Confirm the recorded request/treatment is the admitted closed form |
| Dispatch | Persist run authority and attempt preparation; grant one bounded attempt | Cross the provider call boundary once and only after permission | Verify permission, request binding, call-boundary topology, outcome prefix, and closure |
| Retry and fallback | Sole authority; for initial second-provider admission configure zero automatic retries | Never retry internally, fall back, or select another endpoint/model | Reject nonzero internal retries, later attempts, predecessor links, redispatch, or contradictory topology |
| Time and cancellation | Grant the remaining absolute stage allowance; terminate and reap the direct worker | Apply only the granted residual timeout; expose bounded observations | Distinguish response, timeout, reaping, EOF, cleanup, and uncertainty without converting ambiguity into success or retry safety |
| Transport and materialization | Bound parent protocol and diagnostics; keep provider data out of harness authority | Bound response bytes before unsafe parsing where required; bound extraction and owned data; sanitize failures | Verify recorded bounded forms and absence of unrecognized evidence, without trusting provider objects |
| Output contract | Define exact artifacts and closed structured schemas; validate before promotion | Translate a successful provider result into the requested closed stage envelope | Verify hashes, manifest, invocation binding, seals, promotion decision, and terminal topology |
| Persistence and evaluation | Own artifact paths, writes, seals, promotion, final candidate, and evaluator invocation | No artifact/evaluator authority | Verify that only eligible evidence reached promotion/evaluation |
| Secrets | Supply a narrowly scoped runtime credential only at the authorized child boundary | Consume it without persistence or disclosure | Reject secret-bearing persisted fields; do not require or inspect credentials |

No matrix entry delegates permission, stage promotion, closure, retry, or
terminal acceptance to an adapter or provider.

## 4. Proposed second-provider admission rules

The following are proposed requirements for the first production admission of
one second provider. They are constraints on that checkpoint, not claims that
the current repository already enforces them for arbitrary live kinds.

### 4.1 Trust and bounded applicability

1. The adapter must be trusted, project-controlled harness code under the trust
   model of Decision 0004. Arbitrary third-party or model-supplied adapter code
   is not admissible.
2. The adapter may serve only existing Conditions A, B, and C with their current
   role, context, artifact, and structured-output contracts.
3. A run must freeze exactly one adapter identity and one model identity.
   Conditions B and C remain homogeneous; provider/model selection cannot vary
   by stage.
4. Condition D, heterogeneous routing, sessions, compaction, tools, child-agent
   execution, and generalized runtime orchestration remain outside admission.

### 4.2 Pre-dispatch capability closure

5. Provider-specific configuration must be a closed, bounded, non-secret
   treatment object, copied and frozen before execution and persisted in
   run-defining authority.
6. The implementation must explicitly enumerate supported provider request
   capabilities. Any requested capability outside that set must fail before
   dispatch. It must not be silently discarded, defaulted into a different
   meaning, or accepted merely because the neutral contract has no matching
   field.
7. The admitted request must disable tools and persistent conversation/session
   semantics. It must also disable provider-side storage, background work,
   server-managed continuation, automatic truncation, fallback, or analogous
   stateful/multi-step behavior wherever the provider exposes those controls.
8. The adapter and its dependencies must not launch hidden child executions,
   delegate work, initiate tool calls, or create additional provider requests.
   If offline evidence cannot establish these properties, the adapter is not
   admitted; any request for such behavior must fail before dispatch.

### 4.3 Exactly one bounded request

9. Each runner-authorized stage attempt permits exactly one bounded provider
   request. There is no adapter, SDK, HTTP-client, middleware, or provider
   fallback retry. `adapter_internal_retry_count` must remain zero.
10. The initial second-provider production admission requires
    `max_stage_retries == 0`. Thus each stage can have at most one authorized
    attempt. This is an initial admission constraint, not a universal rule for
    every future provider architecture.
11. The provider-specific wire request must be deterministically
    reconstructible from frozen run authority and the trusted prior-stage
    artifacts. The binding must cover the model-visible content, configured
    model, output contract, ceilings, statelessness/tool controls, and admitted
    treatment. Remaining timeout is enforcement metadata and must remain
    separately bound as such.
12. Transport, response-body admission, extraction, normalized outcome,
    structured output, raw evidence, diagnostics, and parent protocol must each
    have explicit byte/item/depth/time bounds appropriate to the provider.
    Cleanup ownership, close-once behavior, direct-worker reaping, EOF, and
    uncertainty must be explicit evidence rather than assumptions.

### 4.4 Identity and evidence

13. Before dispatch, requested and configured identities must equal the frozen
    run identity. A configured provider/model/version label is provenance and
    routing authority; it is not provider attestation.
14. A successful response must contain a provider-observed model identity from
    an admitted response field. For this initial scope, that observed model ID
    must exactly equal the frozen wire model. Aliases, family prefixes,
    snapshots, compatibility maps, and inferred equivalence are not accepted.
    Missing, malformed, or ambiguous provider-observed identity prevents
    successful admission and promotion.
15. Exact observed-model matching is an initial second-provider admission
    constraint, not a universal claim that all future provider architectures
    expose identity in this form. Any later relaxation requires a new,
    explicitly versioned decision and verifier path.
16. Provider output and metadata remain untrusted observations. They cannot
    rewrite configured authority, broaden identity policy, select evidence
    locations, grant retry, authorize promotion, or influence evaluator
    configuration.

### 4.5 MCL authority and conservative terminal semantics

17. MCL retains sole authority for permission, attempt preparation, stage
    deadlines, retry decisions, context construction, contract validation,
    artifact persistence, promotion, sealing, stage transitions, evaluation,
    closure, and terminal classification.
18. Permission must be durably bound to one run, stage, attempt, execution
    instance, request, identity policy, treatment, resource limits, and time
    grant before the provider call boundary is crossed.
19. Outcome, provider-call boundary, returned/exception observation, cleanup,
    worker quiescence, and closure must remain separately inspectable. Missing,
    torn, contradictory, or ambiguous evidence never authorizes redispatch,
    promotion, downstream execution, evaluation, or success.
20. Terminal evidence must be independently reconstructible from trusted run
    authority, canonical invocation/lifecycle evidence, admitted provider wire
    translation, artifacts, manifest entries, seals, and the terminal record.
    Stored verdicts and registry membership are not trusted substitutes for
    recomputation.
21. Existing OpenAI, legacy, and `live_stub` behavior and evidence meanings must
    remain byte/schema/semantic compatible unless a later checkpoint explicitly
    authorizes a versioned change.

## 5. Historical compatibility and version boundary

### Current implementation

`model_council.protocol` recognizes these harness protocol labels:

- v13: `HISTORICAL_HARNESS_PROTOCOL_VERSION = "m1-dev-harness-v13"`;
- v14: `F2_HARNESS_PROTOCOL_VERSION = "m1-dev-harness-v14"`; and
- v15: `HARNESS_PROTOCOL_VERSION = "m1-dev-harness-v15"`.

`ArtifactStore.verify_terminal_run` accepts those explicit labels and routes
verification through current compatibility checks. In
`_verify_provider_identity_policy_evidence`, v13 cannot claim the provider
identity policy, non-OpenAI kinds cannot claim that policy, and lifecycle
evidence is restricted to the v15 OpenAI path. Historical v13/v14 invocation
records use `m1-invocation-record-v2`; current v15 records use
`m1-invocation-record-v3` with lifecycle fields.

The Protocol v15 B/C closure record preserves the different historical
provenance values of the accepted B and C runs without reinterpreting them. It
also limits that milestone to accepted OpenAI plumbing evidence rather than
general performance or cross-provider compatibility.

### Proposed requirement

This decision does not extend, reinterpret, or silently generalize Protocol
v15. It preserves existing v13, v14, and v15 evidence meanings and the accepted
OpenAI F6b behavior.

A later, separately authorized implementation proposal must define the
explicitly versioned admission and terminal-verification path for the second
provider. It must state which protocol/evidence discriminators change, how old
records remain verifiable, and how the verifier selects the new semantics. No
new version is allocated here. In-place event renaming, schema widening,
digest changes, or treating a new provider as if it were OpenAI are rejected.

## 6. Offline conformance scenarios and existing coverage references

These references identify checked-in tests only. They are not a test result,
and no application test was run while authoring this ADR.

### Required failure-semantic conformance floor

The following are proposed requirements for the second provider. They describe
the semantic result that future offline conformance tests must prove; they do
not add neutral categories or prescribe new lifecycle event names.

1. Policy refusal, malformed provider protocol, incomplete provider result,
   quota exhaustion, and authentication/configuration failure must retain their
   applicable existing `ProviderErrorCategory`: `policy_refusal`,
   `malformed_provider_protocol`, `incomplete_provider_result`,
   `quota_exhausted`, or `authentication_configuration`. Each path must also
   retain the bounded response ID, request ID, status, finish reason, raw or
   structured output, usage, timing, and provider metadata observations that
   the provider exposed and the evidence model permits. A shared terminal
   status does not permit one neutral category to be silently collapsed into
   another.
2. Each such failure remains non-success even if lifecycle closure completes.
   It cannot produce successful stage promotion, authorize a downstream stage,
   or authorize evaluation as a successful candidate. Closure proves only the
   facts defined by its lifecycle evidence; it does not convert a provider or
   protocol failure into success.
3. `provider_retry_hint` and `retry_after_seconds` are observations only. They
   do not change the frozen `model_council.retry_policy` mapping, authorize
   another provider request, grant redispatch authority, or override the
   MCL-owned retry decision. The initial second-provider constraint of zero
   automatic retries remains controlling regardless of either observation.
4. A provider return or exception observed after the call boundary remains a
   historical observation if later extraction or normalization fails. The
   later failure cannot erase that observation, fabricate a successful
   normalized `ProviderCallOutcome`, or support successful stage promotion.
   Observation and normalized, publishable outcome remain distinct.
5. If required owned-client cleanup fails after a pending normalized success or
   failure exists, that pending provider outcome must not be published into the
   lifecycle/evidence path. Successful stage promotion is prohibited. Generic
   worker or lifecycle closure, including a closure reason of `returned`, does
   not prove that owned-client cleanup completed successfully. Earlier valid
   return/exception observations remain historical facts, but they do not by
   themselves make an outcome eligible for publication or promotion. This
   preserves, and does not alter, accepted F6b semantics.
6. The conceptual ordering requirement is: durable dispatch permission and the
   provider call-boundary observation precede the applicable provider
   return/exception observation; extraction or normalization follows that
   observation; required owned-resource cleanup completes before a pending
   publishable outcome becomes eligible for publication; and MCL validation
   and terminal verification independently determine whether evidence permits
   promotion. A later failure does not rewrite an earlier valid observation
   into a different event or into an event that never occurred. A future
   implementation may satisfy this ordering only through an explicitly
   versioned evidence path; this ADR allocates no event vocabulary or schema.

| Conformance area | Existing test coverage reference | Future test obligation for the second provider |
| --- | --- | --- |
| Trusted profile and registry separation | `tests/test_execution_profile.py::TestTrustedExecutionProfile` | Prove the new kind cannot execute until both its versioned admission discriminator and verifier support are present; registry-only activation must fail closed. |
| Harness/live version handshakes | `tests/test_execution_profile.py::TestProtocolHandshake`; `TestLiveContractV4Binding` | Prove wrong, missing, historical, and unallocated provider-admission versions fail before dispatch and remain verifiable under their original semantics. |
| A/B/C request and output contracts | `tests/test_live_contract.py::TestLiveInvocationRequest`; `tests/test_execution_profile.py::TestLiveOutcomeMapping`; `tests/test_runner_boundaries.py::TestContractEnforcement` | Exercise all A/B/C roles through the new adapter, including exact context, artifact names, structured schemas, and no Condition D path. |
| Frozen treatment and reconstruction | `tests/test_provider_treatment_config.py::TestProviderTreatmentConfigImmutability`; `TestProviderTreatmentConfigAuthority`; `TestProviderTreatmentConfigVerification` | Prove the provider's closed treatment rejects unsupported/stateful/tool/fallback fields before dispatch and that terminal verification reconstructs the same wire parameters. |
| One request and no internal retry | `tests/test_live_contract.py::TestProviderCallOutcome::test_nonzero_adapter_retry_count_rejected`; `tests/test_retry_policy.py::TestInternalRetryCount`; `tests/test_openai_adapter_transport.py::TestOpenAITransportExactlyOneCall`; `TestOpenAITransportNoRetry` | Count provider transport calls across success and every failure class; inspect dependency configuration; prove no retry, redirect-to-alternate-model, fallback, or second request occurs. |
| Zero harness retries | `tests/test_provider_identity_policy.py::TestF2RemainingBlockers::test_nonzero_retry_budget_is_rejected_before_any_dispatch`; `test_f5_refuses_configured_retry_even_when_second_response_would_succeed` | Prove nonzero `max_stage_retries` is rejected before the new provider's permission/call boundary and all admitted lifecycle attempts are exactly attempt 1. |
| Neutral failure classification and eligibility | `tests/test_live_contract.py::TestV4RefusalAndIncompleteSemantics`; `tests/test_retry_policy.py::TestRetryTotalityV4`; `TestPolicyRefusalAndIncompleteLiveStub`; `tests/test_openai_adapter_transport.py::TestOpenAITransportExceptionMapping::test_specific_sdk_classes_map_to_closed_categories`; `TestOpenAIProductionActivation::test_malformed_refusal_incomplete_and_tool_responses_are_translated`; `test_classified_transport_failures_preserve_kind_category_and_bounded_evidence` | For refusal, malformed protocol, incomplete result, quota exhaustion, and authentication/configuration failure, assert the exact applicable existing category and bounded observations; assert non-success despite closure, no successful promotion, no downstream stage, and no evaluation as a successful candidate. Where terminal classes coincide, assert that persisted neutral categories remain distinct. |
| Provider retry hints remain observational | `tests/test_live_contract.py::TestProviderCallOutcome::test_provider_retry_hint_is_observational_and_constrained`; `tests/test_retry_policy.py::TestRetryPolicyOwnership::test_provider_retry_hint_cannot_change_frozen_policy`; `TestNeutralFailureTerminalMapping::test_auth_hint_to_retry_still_does_not_retry`; `test_rate_limit_hint_discouraged_still_retries`; `TestRetryTotalityV4::test_provider_hints_cannot_alter_quota_or_refusal_policy` | Vary `provider_retry_hint` and `retry_after_seconds` independently of category and prove they cannot change frozen MCL policy, authorize a provider request, grant redispatch, or override the zero-retry admission constraint. |
| Exact observed identity | `tests/test_provider_identity_policy.py::TestProviderIdentityPromotionGate`; `TestProviderIdentityCrossStage`; `TestProviderIdentityTerminalVerification` | Cover exact match, missing, malformed, alias, prefix, snapshot, and mismatch observations for every A/B/C stage; prove no promotion, downstream stage, or evaluation after rejection. |
| Return/exception observation and normalization order | `tests/test_attempt_lifecycle_dispatch.py::TestDispatchAuthorization::test_sdk_return_survives_normalization_failure`; `TestDurableDispatchFaults::test_malformed_and_transport_loss_keep_conservative_facts`; `tests/test_openai_adapter_transport.py::TestOpenAITransportExceptionMapping::test_exception_observation_precedes_normalization_and_survives_failure`; `tests/test_openai_response_guard.py::TestTransportCleanupOrdering` | Prove call-boundary-before-return/exception ordering; preserve the return/exception observation through later extraction or normalization failure; prohibit fabricated successful outcomes and promotion; and verify that later failure does not rewrite earlier observations. |
| Owned cleanup and outcome publication | Decision 0005, `Cleanup and lifecycle ordering`; `tests/test_openai_response_guard.py::TestTransportCleanupOrdering::test_pending_success_or_normalized_failure_is_vetoed_by_close_failure`; `TestRealWorkerOfflineIntegration::test_close_failure_after_sdk_return_or_exception_vetoes_outcome`; `test_guard_rejection_and_owned_client_close_failure_suppress_outcome` | For the new provider's ownership model, prove required cleanup completes before pending outcome publication. On cleanup failure, retain prior observations, publish no pending provider outcome where the lifecycle architecture requires suppression, prohibit promotion/downstream/evaluation, and prove that generic closure reason `returned` is not cleanup-success evidence. |
| Cleanup and communication uncertainty | `tests/test_executor_response_bounds.py::DeterministicContract`; `ActiveCollectorContract`; `ActiveLaunchMapping`; `tests/test_attempt_lifecycle_terminal.py::TestActivatedClosureAuthority` | Exercise provider-specific acquisition, partial launch, timeout, diagnostic/protocol overflow, response, close failure, missing EOF, and uncertain reaping without false closure, retry safety, outcome eligibility, or success. |
| Materialization bounds | `tests/test_live_contract.py::TestV4ClosedSchemaAndRoundTrips`; `TestV4ProviderMetadata`; `tests/test_openai_adapter_transport.py::TestOpenAITransportBounds`; `tests/test_openai_response_guard.py::TestBoundedBodyChunks` | Establish exact boundary/one-byte-over cases for response admission before parsing, extraction items/bytes/depth, normalized outcome, raw evidence, and worker protocol. Provider-specific bounds must not be inferred from OpenAI's body policy. |
| Artifact and invocation integrity | `tests/test_invocation_evidence.py::TestInvocationPathsAndWriteOnce`; `TestIntegrityAdversary`; `tests/test_artifacts.py::TestArtifactStore` | Prove the new provider cannot choose paths or promotion and that tampering, deletion, substitution, extra records, or contradictory seals fail terminal verification. |
| Terminal semantic reconstruction | `tests/test_attempt_lifecycle_terminal.py::TestLifecycleTerminal`; `tests/test_provider_identity_policy.py::TestProviderIdentityTerminalVerification`; `tests/test_provider_treatment_config.py::TestProviderTreatmentConfigVerification` | Add positive and adversarial terminal fixtures for every terminal class, with recomputation from frozen authority rather than stored verdicts. |
| Existing behavior preservation | `tests/test_openai_adapter_skeleton.py::TestOpenAIAdapterSkeleton::test_existing_fake_and_live_stub_paths_remain_unchanged`; `tests/test_execution_profile.py::TestTrustedExecutionProfile::test_legacy_fake_kind_still_accepts_legacy_response` | Run focused and neighboring offline regression suites showing unchanged OpenAI, legacy, `live_stub`, v13/v14/v15 verification, and accepted F6b behavior. |

The OpenAI canary test files are historical/current launcher-contract
references, not second-provider conformance coverage. Live canaries, provider
calls, credentials, and real-provider compatibility checks require separate
authorization and are not prerequisites for accepting this proposed ADR.

## 7. Rejected alternatives

### Register the adapter and rely on `live_contract_v1`

Rejected. Current source shows that live registry reachability is separate from
OpenAI-specific identity, lifecycle, wire-request reconstruction, and terminal
verification. This would create execution without complete production
admission evidence.

### Alias the second provider to `openai_responses`

Rejected. Provider-specific wire translation, identity observations,
transport bounds, SDK behavior, credentials, failures, and cleanup cannot be
proven by relabeling another provider as OpenAI. It would also corrupt
historical evidence meaning.

### Generalize all production lifecycle machinery now

Rejected for this tranche. A broad abstraction could change accepted F6b
behavior and Protocol v15 semantics before a concrete second provider exposes
the minimum necessary seam. The later implementation proposal must remain
provider-bounded and versioned.

### Permit sessions, tools, provider retries, or fallback and record totals

Rejected. Totals do not make individual provider requests, permissions,
identities, or retry decisions reconstructible. Hidden steps would defeat the
single-request admission model and MCL-owned authority.

### Accept configured labels or model-family equivalence as identity evidence

Rejected. Configured labels are harness authority, not provider attestation.
For the initial admission, absence of exact provider-observed identity is a
failure, not an invitation to infer an alias.

### Extend Protocol v15 in place

Rejected. Changing the interpretation of an accepted historical discriminator
would make old and new evidence ambiguous. A later implementation must define
an explicit version boundary.

### Add heterogeneous Condition D routing with the second provider

Rejected. Admission of one homogeneous provider adapter and experimental
heterogeneous routing are separate decisions with different identity,
counterbalancing, comparison, and evidence obligations.

## 8. Preconditions for a separately authorized implementation checkpoint

No implementation may begin from this proposed ADR alone. A later checkpoint
requires all of the following:

1. Amy accepts this ADR's exact reviewed bytes.
2. The target provider, endpoint/API surface, exact model identity field, SDK
   or HTTP dependency behavior, and trusted adapter boundary are named.
3. A bounded implementation proposal identifies every source and test path to
   change and demonstrates why existing OpenAI, legacy, `live_stub`, canary,
   F6b, and historical verification paths remain unchanged.
4. The proposal defines an explicit new version/discriminator path for
   admission and terminal verification, including backward verification of
   v13/v14/v15 evidence. Version allocation occurs only in that separately
   authorized checkpoint.
5. The provider-specific request schema enumerates admitted treatment and
   rejects unsupported capabilities before dispatch, including sessions,
   continuation, tools, storage, background work, fallback, internal retries,
   and hidden child execution.
6. The proposal specifies deterministic wire-request reconstruction, exact
   provider-observed model matching, one-call proof, zero harness retries,
   transport/materialization ceilings, sanitized failure mapping, credential
   handling, ownership transfer, cleanup, reaping, EOF, and conservative
   uncertainty semantics. Its failure mapping must preserve the applicable
   existing neutral category and permitted bounded observations for refusal,
   malformed protocol, incomplete result, quota exhaustion, and
   authentication/configuration failure without treating a shared terminal
   class as category equivalence.
7. The terminal verifier design independently recomputes identity, treatment,
   request, lifecycle, promotion, and topology without trusting adapter
   assertions, stored verdicts, or registry membership. It must reject
   promotion, downstream execution, and successful-candidate evaluation after
   any ineligible failure or unpublished outcome, even when closure exists.
8. Offline conformance and regression tests are specified for the scenarios in
   Section 6, including category-preservation, retry-hint non-authority,
   return/exception observation survival, normalization failure, cleanup-gated
   outcome publication, observation ordering, and adversarial and historical
   fixtures. Test execution is authorized only with that checkpoint.
9. Any live canary, credential access, paid/provider call, dependency change,
   configuration change, or real-provider compatibility question receives its
   own explicit authorization. The OpenAI `Accept-Encoding: identity`
   compatibility question remains separate.
10. Independent review accepts the implementation proposal before source,
    tests, schemas, versions, configuration, or provider integrations change.

Until those preconditions are met, a second provider is not production
admitted, even if code exists locally or its kind appears in a registry.
