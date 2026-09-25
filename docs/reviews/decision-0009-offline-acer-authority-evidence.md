# Decision 0009 Offline Acer Authority Evidence and Coverage Ledger

## 1. Scope and claim boundary

This document records the evidence supporting the proposed authority
reconciliation. It is not a comprehensive adapter conformance review. It makes
no live Acer, CUDA/NVML, process, cgroup, library, model, provider, production
durability, or Tranche B claim.

The evidence checklist was fixed before conclusions:

1. baseline, index, lock, tracking ref, target-path, and source-hash identity;
2. historical record type, role, content, digest, and acceptance relationship;
3. explicit Revision 3 and source-supported Revision 4 supersession boundaries;
4. accepted architecture versus human requirements versus proposals versus
   implementation/tests/observations;
5. takeover ordering, readiness, reentrancy, failure, and history cases;
6. complete publication/window identity and partial-operation proposal terms;
7. spawn, custody, evidence-layer, F5, and inherited accounting boundaries;
8. downstream consumers and missing proof obligations; and
9. fresh validation followed by final direct file and Git-state inspection.

## 2. Initial baseline evidence

Inspection used `GIT_OPTIONAL_LOCKS=0` and no fetch or live remote query.

| Item | Initial observed result |
|---|---|
| Repository | `/Users/aclab/aclab/model-council-lab` |
| Branch | `m1-live-adapter-dev` |
| HEAD | `5a64eec6650a3a0f6ec3a7cd7204d02af7490579` |
| Upstream | `origin/m1-live-adapter-dev` |
| Local divergence | `+0/-0` from `git status --porcelain=v2 --branch` |
| Worktree/index | Original documentation-phase record: clean; porcelain status contained only branch headers and cached diff was empty |
| Local upstream ref | `5a64eec6650a3a0f6ec3a7cd7204d02af7490579` |
| `.git/index.lock` | Absent |
| Proposed paths | AR/original phase reports both absent before creation; the current remediation can authenticate that record but cannot prove the earlier filesystem state from a current observation |
| Live remote | Not checked |

Required source fingerprints matched:

```text
d1b89eae519a9511d492b984869f66b0e3b892c10283b884dd46e87b429f7e0c  tools/decision_0009/acer_adapter/supervisor.py
e8947fb1be09b2ba22d533f0dca465f82ae35f3d001edb6eeb0ea5226018ddda  tests/decision_0009/test_acer_adapter_supervisor.py
```

The original phase reports that its combined baseline command exited `1` only
because the final `rg --files -g AGENTS.md` lookup found no repository
`AGENTS.md`; every preceding baseline check printed the expected result. That is
historical command evidence, not a result rerun by the current remediation.
The Human Chair supplied the applicable AGENTS instructions directly.

## 3. Historical source authentication

Digest method:

- `raw SHA-256` hashes the exact JSONL record bytes including its terminating
  LF, as selected by the named record/line locator.
- `text SHA-256` hashes the concatenated `input_text` or `output_text` message
  bytes with no added trailing LF.
- The locator is not treated as identity by itself; record type, payload type,
  role, content type, length, digest, and relevant content were also checked.

| ID | Exact source / locator | Verified role | Text characters | Raw SHA-256 | Text SHA-256 | Bounded relevant excerpt | Authority significance |
|---|---|---:|---:|---|---|---|---|
| R2 | `/Users/aclab/.codex/sessions/2026/09/21/rollout-2026-09-21T13-10-36-01a0c597-842d-7782-b784-b3024db6b1b1.jsonl`, record 53 | assistant | 45,688 | `5f3bc52b1b7ef52c1172d00b4fd1e7cd2a4b657904996642fd6e1e6d5ac10ba8` | `67df5118b79acb74fe0acc6c268dda02106c0e9937eeb86c3fcbb347cd105a93` | “proposed architecture for independent review… does not authorize implementation, deployment, or execution”; §10: A fake “crash” discards volatile state and revokes execution-session authority. It must not merely instantiate a new supervisor against a dictionary retaining everything. | Base proposal later accepted through IA as amended by R3/R4; the §10 fake-crash provision is unaffected by those amendments |
| R3 | Same JSONL, record 72 | assistant | 12,519 | `a239363dba7ef0744b883963411f6cfb42e3f43f142c5f6fea08448378164406` | `55dec77be057c9fb085ed305b9cac5f2d09b350ad5c3626a76b10dc581158679` | “These amendments replace the corresponding Revision 2 provisions. Other provisions remain unchanged.” | Explicit amendment relationship |
| R4 | Same JSONL, record 91 | assistant | 12,471 | `b206ba492153adc7c7a0565660981f21427c5d9bde06f42a5f8974e061efabfc` | `b9532ffe17721dee6a4bdad9db5eecd5f9f28764dd2485ee55fabfac084cde8c` | Defines revised closure sequences, nonrecursive verification root, effect boundary, and “Canonical closed state enumeration” | Final proposal layer named by IA |
| R4-NR | `/Users/aclab/.codex/sessions/2026/09/21/rollout-2026-09-21T13-44-21-01a0c5b6-686f-7500-a255-c1b40b412f7f.jsonl`, record 260 | assistant | 3,242 | `2a50e48bdf02a1a50b0e5e50f76d33ef0db8f423ceef7fc399d93e013e6841ad` | `1f5876bd4abfc1ac08c0192d6480fe8c5d864551197b4b963c4f5d2615689491` | “Independent review: NOT READY”; three blockers remain | Earlier interim verdict, superseded for readiness by R4-A after Revision 4; retained as history |
| R4-A | Same JSONL, record 338 | assistant | 2,236 | `09bdda4732e15a061c33aa04d55ef045d531152f61a6e7208068984ce2875095` | `07fc8598c41a006bca8cfe0010d66d9f3cdcb60f3a51650c636e1fe55620c7cb` | “ACCEPT” and “Revision 4 resolves all three blockers for offline implementation authorization readiness” | Final technical architecture-readiness review only; not completed-adapter acceptance or live authority |
| IA | `/Users/aclab/.codex/sessions/2026/09/21/rollout-2026-09-21T14-23-44-01a0c5da-76ec-75b1-a8ca-386ace8ed244.jsonl`, record 9 | user | 9,296 | `350002ccbbea4c379da7393b7a13bf507cdd5fcdf7f35f27c7be3daafdb72418` | `df5611f588e5da3ddcfb936158952958d4073d79427b5ebbfca1db86c7708b61` | “Implement the architecture accepted through Revision 4 and Sol’s final ACCEPT review.” | Explicit Human Chair acceptance/implementation authorization for the exact 13-file offline scope |
| PW-P | `/Users/aclab/.codex/sessions/2026/09/22/rollout-2026-09-22T18-47-13-01a0cbf2-0fee-70f3-9bc4-63353c86075f.jsonl`, record 187 | assistant | 11,884 | `9a470dd531a0facdeab9093b97084a319bc242ba28b6e4aef6d69b6faedd86ac` | `01f6b7d7477e212ac4510e87defe09209d16d5213a56ab86524e8ff9710c44a6` | “This is a proposal, not an edit manifest or authorization.” | Proposal only |
| PW-R | Same JSONL, record 197 | user | 1,014 | `94d16d394ad0b719c5bff5f9a5a07b4a3a12cebdfbfcece2aa7c434ba6824c84` | `cffa4086f6712bb20252deedb89b41ea9f1311065a1ba8dfa2d1178d692d3a26` | “Before implementation approval, add…” and “No edits” | Human-requested contents for the proposal, not implementation acceptance |
| PW-A | Same JSONL, record 215 | assistant | 11,933 | `eb8e2d620919597ce5e1d516c7bf1c88dd390fdbbc437cfa18d6b8a9ca4a1474` | `16dc46bd9b8012b38fb647ba351021f0113bdb3086eeb5221e642c9ca03f1cbc` | “The addendum remains confined to publication identity and measurement-window provenance.” | **Proposed for Human Chair acceptance**; no acceptance found in the enumerated search scope |
| TA | `/Users/aclab/.codex/sessions/2026/09/23/rollout-2026-09-23T06-44-33-01a0ce82-ca83-7de1-8feb-45600614f4ac.jsonl`, record 9 | user | 5,923 | `278a6b95834897e87beaf70734c5118f1733df3c7bf852426a86b3f83db0a050` | `aa43647dffa03471243417e1806ff7fd3a3fa9b5eb7b3f7aca08d85da8182ff5` | “Takeover and authority-dependent operations must have an unambiguous order” | Explicit Human Chair repair requirements |
| TR-S | `/Users/aclab/.codex/sessions/2026/09/23/rollout-2026-09-23T07-48-57-01a0cebd-bfe1-7e21-b0ef-4e15a0a4642a.jsonl`, record 9 | user | 9,404 | `1073539caa32c3d2f19e1315df5608f90c070de5757b94592f6360aead92da9e` | `ad83ff5530e535635567acbc1e3a12147f7da8309a0d5ea8281847181a621a54` | Bounded READ-ONLY R1–R7 correctness review scope | Human-defined review scope; no repair authority |
| TR-A | Same JSONL, record 352 | assistant | 4,384 | `1ca18a38df568dbd83a306bd458a3c8efc8dc100edc3b3dcbb0426bc6289475c` | `3e32c3da131459ad2801292bfab44bff8d72521e4ce66caab3031d0f8b1a7ef9` | “Verdict: ACCEPT for the bounded supervisor-takeover repair.” | Technical acceptance only; not architecture or live authority |
| AR | `/Users/aclab/.codex/sessions/2026/09/25/rollout-2026-09-25T05-39-35-01a0d894-0ac2-7683-a935-e8a19ca20012.jsonl`, record 258 | assistant | 42,961 | `49340520b01e10bc82350649af7ea4d966123b43b39b34c167ab0b2b05257ebb` | `e27fb738eb044be9eb7e587134e8c34bedd116a28d28b7c6c429bc27958f7350` | “documentation-only authority reconciliation… Tranche B remains closed” | Current prompt identifies Amy’s accepted version as controlling this two-file phase |
| DP-P | `/Users/aclab/.codex/sessions/2026/09/25/rollout-2026-09-25T06-17-54-01a0d8b7-1c48-7030-a217-41a4b9ff1b0f.jsonl`, record 9 | user | 9,005 | `22bfc53aac08c13c9c130429fc9bf219a52cd6669f5c7db1e80c9b8372ed1a99` | `8140fd3323543801b080a7b1a4d0c3fe747c4816bb5f12cc48455e09faf4d981` | Proposed documentation-only phase; “Do not begin writes until Amy explicitly authorizes this phase and the exact two-file manifest” | Proposed scope, not authorization by itself |
| DP-R | Same JSONL, record 46 | assistant | 1,007 | `65bd28ee6225fa4b09433a8b8ebf063e3bcea10f88022d6fbaf825180b1aeca1` | `adafcaedddff1ea0264bebd9c8e416e62bfa96676b6df672dcd58d66e24ee187` | Requests approval for exactly the two named documentation files | Exact approval request; no work yet |
| DP-A | Same JSONL, record 53 | user | 19 | `f406b4748ce9a05be0c0e4cfb04454ec12577fa6a4935373ae3606a7c9951693` | `80cd518d0c97942a074f26e317ed6de41aebc617938c3a8457c1445ef0350f2c` | “I approve . Proceed” | Authorizes the bounded documentary phase identified by DP-R; does not ratify unresolved architecture |

R4-A is the final review after R4-NR, not a reinterpretation of the earlier
verdict. Its `ACCEPT` concerns architecture readiness for the authorized offline
implementation. It does not accept the completed adapter or authorize Acer,
CUDA/NVML, model, publication, or Tranche B work.

The fake-crash acceptance chain is explicit. R3 says, “These amendments replace
the corresponding Revision 2 provisions. Other provisions remain unchanged.”
R4 revises closure, effect authorization, and the state vocabulary but does not
replace R2 §10. IA then directs implementation of “the architecture accepted
through Revision 4 and Sol’s final ACCEPT review.” The R2 §10 fake-crash rule is
therefore an accepted architecture requirement; implementation and tests remain
evidence against it, not authority to weaken it.

Two Human Chair records describe the missing artifact as approved: TA directs
the implementer to locate “the approved Astra proposal and addendum,” and TR-S
says “Astra did not have the takeover-specific approved proposal/addendum.” The
publication/window addendum is not thereby authenticated as that artifact. No
exact standalone identity, contents, acceptance record, or relationship to
PW-P/PW-A was established; U-01 preserves both the approval description and the
missing identity.

The bounded PW acceptance search covered the named R2/R3/R4, IA, PW-P/PW-R/PW-A,
TA, TR-S/TR-A, AR, and DP-P/DP-R/DP-A records; user messages after PW-A within
the same PW JSONL; the current `5a64eec…` implementation commit; and TA's
instruction to retain the publication-identity and window-provenance
regressions. It found no later acceptance of PW-P/PW-A in that enumerated
scope. Implementation and regression-preservation context are not acceptance,
and no claim is made about unsearched history.

PW-P, PW-R, and PW-A each record Revision 4 as unavailable in their working
context. That contemporaneous limitation is relevant to U-03 but cannot resolve
the discrepancy against R4's closed vocabulary or IA's implementation command.

DP-P, DP-R, and DP-A authenticate the documentation-phase authorization chain.
DP-A authorized the exact two-file documentary operation requested in DP-R; it
did not accept PW-P/PW-A, resolve `PUBLICATION_WRITTEN`, accept the adapter,
authorize Git publication, or open Tranche B.

## 4. Repository input fingerprints

These hashes identify read-only inputs inspected for this package:

```text
2cbfa72752439713522cc255df03f1eba8c311558f1835a80ac13025e16992be  docs/decisions/0004-m1-adapter-trust-model.md
b98a49b3705a54d41ea46560576a3d11918b8d91d3c02f8daf62a792b19bcda9  docs/decisions/0006-second-provider-admission-contract.md
1d714648da91a931f029b4ba76345ab1567a482b51ee6be8b1d5fda0149b6b12  docs/decisions/0007-second-provider-versioned-admission-boundary.md
9fcc02eb47ad6377a4a14da23d6874cbfc2de6e472a41988d43949138ef399a0  docs/decisions/0008-versioned-open-weight-artifact-identity-boundary.md
fc4b9bac222cd2d017dc0e34e8e2a86a3eb719d0f3c5275fd3b7ac9d141b794d  docs/decisions/0009-split-memory-admission-and-accounting-boundary.md
7bbbc0450a70d527b771be68290ba725df0b106c1406038e3b3f40bc734da2e8  tools/decision_0009/startup_characterization/README.md
95fcef4f436aab432d4eaa99071ec8d4c5d9315553d7bfb513452215ee8b0b59  tools/decision_0009/startup_characterization/schema-v1.json
361fa09c9af86d0c585247891288782b02a1a810f05971205b2c1a7badc3dbf0  tools/decision_0009/acer_adapter/README.md
db728fc8a51c4080ef737f55964fc19bd9b0036c3f7037a28212fe446690dfc1  tools/decision_0009/acer_adapter/contracts.py
8f487cf2966d2599aa9561e2747a6fb26ba0d3208e5ba0039bae7d67231d1835  tools/decision_0009/acer_adapter/custody.py
57baad8d655093e90c41bc36775ebf3848fff336f27de095ca5bcdf7d95287f0  tools/decision_0009/acer_adapter/evidence.py
d1b89eae519a9511d492b984869f66b0e3b892c10283b884dd46e87b429f7e0c  tools/decision_0009/acer_adapter/supervisor.py
e8947fb1be09b2ba22d533f0dca465f82ae35f3d001edb6eeb0ea5226018ddda  tests/decision_0009/test_acer_adapter_supervisor.py
ecaa4bdd05f9b0667065a028621ca8b78ef35a8d2471f10fe03665f8698b2848  tests/decision_0009/test_acer_adapter_evidence.py
```

The startup schema identifies Draft 2020-12 definitions for `manifest`, `event`,
`sample`, `trial`, and `campaign_seal`. Reading it establishes schema content,
not live evidence or authority to change the accepted core.

## 5. Coverage inventory

Status values here describe whether a case exists and what it exercises, not
whether the complete adapter conforms to architecture.

| Coverage obligation | Implementation symbols inspected | Existing test/probe evidence | Current evidence classification | Limitation / future proof obligation |
|---|---|---|---|---|
| Publication excluded from measured preparation, dwell, and residual clearance | `MEASUREMENT_WINDOWS`; `PublicationScheduler.schedule`; `_assert_publication_binding` | `test_publication_is_prohibited_during_measured_windows`; authoritative-window, rollover, and restart cases | Accepted prohibition has direct offline regressions | PW window-operation provenance is a separate unaccepted proposal; no production publisher |
| Fresh authenticated boots 2–4 activation with identity and predecessor bindings | `BootActivation.__post_init__` rejects `authenticated=False`; `activate_next_boot` rejects an `activation_id` already in `activation_ids`, wrong ordinal or predecessor digest, and a reused observed boot ID; activation consumption; validated boot-closure registry | `test_boots_two_through_four_require_fresh_exact_activations` positively exercises boots 2–4; `test_authorization_replay_wrong_activation_and_stale_fence_fail` directly rejects a wrong ordinal, but its replay assertion is campaign-authorization replay; `test_reused_boot_id_is_rejected_before_a_new_fence_is_taken` rejects a reused boot ID; `test_boot_activation_operation_cannot_bypass_transition_preconditions` rejects a forged consume operation while the session is still boot 1, before predecessor-digest checking is isolated; `test_forged_boot_closure_history_is_not_reconstructed_and_boot_two_cannot_activate` shows forged closure history fails closed and boot 2 cannot activate | Positive boots 2–4, wrong ordinal, and reused boot ID have direct assertions; forged operation/history cases demonstrate fail-closed behavior but do not directly isolate a mismatched predecessor digest at a valid handoff; reused activation ID and authentication are implementation observations | No direct negative test reuses an activation ID, constructs `BootActivation(authenticated=False)`, or isolates the valid-handoff mismatched-predecessor branch; fixture authentication/identity only; no reboot or live Chair authentication |
| Single linearizable `authorize_and_dispatch` decision | `ArtifactVerificationPrimitive`; `authorize_and_dispatch`; effect capability/result registries | substitution race, stale fence/session, direct dispatch, reserved transition, and ambiguous result tests | Offline boundary exercised at named seams | Not a production atomicity or external-effect proof |
| Exact execution-byte revalidation before each effect | `ArtifactBinding`; verifier; dispatch boundary; manifest bindings | substitution-between-verification-and-dispatch, later-boot changed-byte, and artifact-label tests | Offline negative cases exist for named effect paths | Comprehensive entry-point coverage remains for a later conformance review; fake verifier only |
| `CANONICAL_HEAD` provenance versus accepted-core/manifests execution authority | `PROVENANCE_CANONICAL_HEAD`; `CORE_EXECUTION_COMMIT`; authorization/artifact manifests | artifact-label, wrong-content, changed-byte, and authorization-binding tests | Distinction is represented and tested offline | Constants and fixtures do not authenticate deployed bytes |
| Immutable exclusive-create/no-overwrite publication and exact readback | `ImmutablePublication`; object-store operations; `PublicationReceipt` | exclusive/immutable/reconcile, lost-ack, partial-object, and readback-failure tests | Offline object semantics exercised | Fake in-memory publisher; no external destination or independent reader |
| Candidate → publication/readback → completion closure order | closure finalizers/completers and validators | boot/campaign ordering, pre-finalization publication, candidate substitution, missing manifest, and reconstruction tests | Direct offline ordering evidence | Publication vocabulary remains U-03; external durability unproven |
| Closed vocabulary; removed/unknown names rejected | `parse_state` checks membership in `STATE_DOMAINS[domain]`; it has no separate `REMOVED_STATES` rejection branch; `REMOVED_STATES` is a separate constant used by an effect-boundary test | `ContractTests.test_closed_revision_4_vocabulary_rejects_removed_and_unknown_names` accepts `SLOT_SPAWN_ELIGIBLE` in `attempt`, rejects the listed removed names plus `MADE_UP` when each is passed in `attempt`, and rejects `ATTEMPT_COMPLETE` in `boot`; `test_vocabulary_is_partitioned_into_closed_domains` checks set disjointness; `SupervisorTests.test_removed_states_never_cross_effect_boundary` separately iterates `REMOVED_STATES` | Direct membership rejection is demonstrated for the named values/domains only; the partition test proves disjoint configured sets, not exhaustive rejection across every domain | The contract test is not exhaustive across all state domains; current extra `PUBLICATION_WRITTEN` remains U-03, not a passing conformance conclusion |
| F8 attribution and unavailable-value semantics | `GPUAttribution`; `normalize_gpu_attribution`; `AttributionUnavailable` | exact match; PID reuse; namespace/GPU mismatch; partial, sentinel, conflict, duplicate, helper, and API-coverage cases | Offline normalization and fail-closed cases exist | No NVML or target-host attribution evidence |
| Independent custodian semantics | `OfflineCustodian`; `OfflineSurvivor`; create/reap/transfer registries | concurrent/ambiguous create, custodian death, survivor separation, and receipt-binding tests | Offline ownership model exercised | No real custodian, watchdog, process handle, subreaper, or survivor |
| Operation-first window ordering | `_AuthorizationLock`; `_supervisor_takeover`; `_set_measurement_window`; `_register_window_operation`; `_bind_window_result` | `SupervisorTakeoverTests.test_window_operation_finishes_before_takeover_can_advance_generation` | Direct offline regression; historical TR-A R1 PASS | Repeat independently in later conformance review; production scheduler unproven |
| Operation-first all five publication operations | `issue_publication_grant`; `perform_publication`; `_consume_publication_grant`; `_bind_publication_grant` | `test_publication_operation_finishes_before_takeover_can_advance_generation` subtests `intent/create/write/durable/verify` | Direct offline regression; historical TR-A R1 PASS | Five-operation vocabulary is proposal-only pending U-03 |
| Constructor and direct-claim operation-first | `PersistentSupervisor.__init__`; `OfflineDurableStore.claim_supervisor` | operation-first helper plus `test_bare_claim_waits_for_window_and_publication_operations` | Both takeover entry points persistently covered at the pre-registration/consumption seam | Persistent bare-claim/post-result-binding coverage is missing; historical TR-A reports that probe; actual process restart not covered |
| Result binding and state exposure | `_bind_window_result` followed by window/epoch exposure; `_bind_publication_grant` followed by result return | `test_takeover_waits_through_result_binding_and_window_exposure` | Direct deterministic constructor-takeover seam coverage | Publication has no separate exposed cache; persistent test does not combine the bound seam with bare claim |
| Takeover-first stale denial | `supervisor_is_current`; `_ensure_session`; `_assert_publication_binding` | `test_takeover_first_denies_stale_window_and_publication_without_effects` covers window plus five operations | Direct offline regression; historical TR-A R2 PASS | Retained shared store model only |
| Reconstruction readiness and lower boundary | `_supervisor_takeover` clears readiness; constructor enables after `_reconstruct`; `authorize_and_dispatch` checks current generation/readiness | `test_reconstruction_cannot_expose_authority_or_reenter_takeover`; `test_bare_generation_claim_never_makes_authority_ready` | Supervisor/lower-boundary denial and post-readiness permission are covered under the retained original session; historical TR-A R3 PASS | `_restart` reuses the original session; whether generation change is R2's “new supervisor incarnation” is unresolved; no process-restart authority |
| Accepted fake-crash session revocation | `OfflineDurableStore.crash` clears `_volatile`; `PersistentSupervisor.__init__` reconstructs over the supplied store/session | `SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker` calls `crash()`, uses `_restart` with the same store and original session, reconstructs `BOOT_CUSTODY_COMPLETE` without violations, makes a slot eligible, receives `BLOCKED` from `spawn_worker`, and observes one underlying creation | Direct evidence of current fake-crash/reconstruction behavior only; it is not proof that R2 §10's accepted session-revocation rule is satisfied | U-04 remains for Astra/Amy: decide the generation/new-incarnation question and whether this behavior conforms; no test of a fake crash that demonstrably revokes execution-session authority |
| Same-thread reentrancy and normal nested authorization | `_AuthorizationLock.owned_by_current_thread`; `_supervisor_takeover` pre-mutation denial | `test_reentrant_takeover_is_denied_before_shared_state_changes`; historical TR-A reports ordinary nested authorization and unwrapped-lock probes | Constructor/claim × window/publication/interlock/verifier callbacks covered | Production callbacks absent; fresh phase does not add probes |
| Competing successors | takeover lock covers generation, session registration, custody rebinding, reconstruction, readiness | `test_competing_successors_serialize_reconstruction_and_custody_binding` | Two successors serialize as generations 2 then 3; older successor mutation denied | In-memory threads only |
| Ordinary and BaseException takeover failures | `_supervisor_takeover` catches `BaseException` and installs failure latch | `test_takeover_failure_is_sticky_for_session_custody_and_reconstruction` uses `RuntimeError` and `KeyboardInterrupt` at session/custody/reconstruction | Six persistent injected combinations assert latches after constructor failure returns; historical TR-A R6 separately reports pre-outer-lock-release probes | Persistent suite does not directly assert the pre-release moment; no process-kill or durable external recovery evidence |
| Started-operation interruption before/after binding | `_prohibit_started_operation`; operation exception boundaries | `test_interrupted_operation_installs_prohibition_before_waiting_takeover`; `ConsolidatedOrderingTests` | Window/publication × before/after bind; latches observed inside `register_session` after successor lock acquisition and before replay can derive them | Publication takeover case uses `intent`; broader partial-operation tests cover all five without takeover |
| Pending windows and consumed unbound grants | `_window_operations/_window_results`; `_publication_grants/_consumed_publication_grants/_publication_grant_records`; reconstruction violation handling | consolidated partial window and publication tests; interruption integration tests | No fallback, refund, fabricated result, or automatic promotion | Rules derive from proposal PW-A except where independently required by TA fail-closed scope |
| Complete publication object identity | `PublicationIdentity`; full equality before consumption | `test_each_identity_substitution_is_rejected_before_consumption_for_every_operation`; integration duplicate | All five identity fields × all five operations | Proposal status remains unresolved |
| Complete operation/result identity | `PublicationOperationBinding`; `OperationResultBinding`; attestation and store registries | operation-binding substitutions, historical record/result/proof substitutions | All 13 non-object operation fields, five nested object fields, attestation, and three result fields exercised | Test coverage cannot accept the contract |
| Window provenance and initial rule | `MeasurementWindowTransition`; `_validated_window_history`; initialization token | window field/result substitutions, smuggled history, partial stages, fresh/empty/interrupted/old-history initialization, outside→dwell→outside restart | Broad offline positive/negative coverage | Proposal status and production migration remain unresolved |
| Historical recovery without stale authority | `publication_record_provenanced`; `window_record_provenanced`; `publication_snapshot`; `ImmutablePublication.reconcile` | completed-history and repeated-restart tests; stale grants/supervisors denied | Historical bytes/results remain readable while mutation remains current-generation only | Depends on retained in-memory registries |
| Downstream snapshot and receipt consumers | `publication_snapshot`; `_verify_publication_receipts`; `_validate_publication_frames` | consolidated downstream tamper tests and evidence publisher tests | Identity/window tamper rejects snapshot and receipts | Not comprehensive adapter conformance |
| Boot/campaign closure consumers | `_closure_publication_proof`; `_publication_bound_to_candidate`; `complete_boot`; `complete_campaign`; reconstruction validators | invalid identity/window prevents boot and campaign closure; valid control reconstructs | Candidate-before-publication-before-completion ordering exercised | Publication vocabulary authority unresolved; external publisher is fake |
| Same-boot successor separation | `LocalAttemptEvidence.successor_eligible`; validated completion/custody registries | each local prerequisite individually required; pending external publication not a same-boot gate | Matches accepted R3/R4 local-versus-external separation | Real reaping, residual observation, and durable local readback absent |
| Durable spawn intent / at-most-one / ambiguity | `spawn_worker`; `create_once`; `inspect_spawn`; effect result registries | spawn ordering, concurrent duplicate create, crash windows, unresolved restart | Offline invariant covered | No real launcher, subreaper, pidfd, or durable registry |
| Custody/taint/consumption stickiness | `record_custodian_loss`; store taint/consumption; survivor transfer | custody, store, supervisor, and containment tests | No synthetic reap/clearance/successor; survivor action does not clear taint | Production ownership and survivor proof absent |
| Raw/normalized/core distinction | `BoundedRawJournal`; `EvidencePipeline.normalize/freeze_core/readback` | three-layer, malformed input, exact correspondence, mutation divergence tests | Offline byte/cross-reference behavior exercised | Does not prove canonical external preservation |
| Reap/residual/closure distinction | completion validator, custodian reap registry, residual objects, closure candidate validators | missing/forged/empty manifests and successor prerequisite tests | Labels alone rejected; each retained object revalidated | Simulated lifecycle only |
| F5 and accepted startup core | `enforce_f5_mapping`; startup worker mapping/terminal gates; unchanged schema | missing `libcuda`, extra family, expected-as-observed negative tests; startup protocol/schema suites | Fail-closed offline contract and unchanged core tests | No actual library load or Acer observation |
| Host/cgroup, GPU, machine reserve independence | D9; startup observer/controller policy; `normalize_gpu_attribution` | startup protocol/schema and adapter attribution tests | Offline data-shape and failure checks | No actual enforcement, simultaneous combined footprint, preventative allocation, or reserve proof |

## 6. Current implementation observations

These are observations, not authority:

1. `contracts.py` defines publication operations
   `intent/create/write/durable/verify` and maps them to five states, including
   `PUBLICATION_WRITTEN`.
2. R4’s recovered canonical state table lists only four publication states and
   explicitly calls the state vocabulary closed, removes `EXCLUSIVE_WRITE`, and
   rejects unknown/removed names. IA independently commands the canonical R4
   vocabulary only. A later amendment accepting `PUBLICATION_WRITTEN` has not
   been identified in the enumerated search scope.
3. `parse_state` rejects a state when it is not a member of the selected
   `STATE_DOMAINS` entry; it does not consult `REMOVED_STATES`. The named contract
   test passes every listed removed name and `MADE_UP` only through the `attempt`
   domain, plus one wrong-domain `boot` case. That is bounded evidence, not an
   exhaustive cross-domain rejection matrix.
4. `BootActivation.__post_init__` rejects `authenticated=False`, and
   `PersistentSupervisor.activate_next_boot` rejects an activation ID already in
   `activation_ids` and a mismatched predecessor digest. No direct negative test
   was found for those branches. The forged operation test fails before it
   isolates predecessor-digest checking, while the forged-history test shows
   fail-closed non-activation rather than that exact valid-handoff branch. The
   replay assertion in `test_authorization_replay_wrong_activation_and_stale_fence_fail`
   is campaign-authorization replay, not activation replay.
5. `OfflineDurableStore.crash()` clears volatile frames but retains the store
   object, operation registries, sessions, witness, custody binding, and durable
   frames. New `PersistentSupervisor` objects therefore model takeover/replay
   over retained state, not an unexpected operating-system process restart.
   The test helper `_restart` also passes the original session; tested
   post-readiness permission is under that retained session. The named legitimate
   custody test makes a slot eligible and observes one underlying creation after
   `crash()` and reconstruction. This behavior is in unresolved tension with R2
   §10's accepted fake-crash rule and does not prove conformance to it.
6. `_supervisor_takeover` holds the shared authorization lock through generation
   change, session registration, custody rebinding, reconstruction, and readiness.
7. Historical provenance checks deliberately compare a record to the session,
   generation, fence, grant/operation, and result that produced it; current
   mutation separately requires the current ready supervisor.
8. The startup harness forbids the allocations needed for Decision 0009’s
   combined-footprint and preventative-device-allocation gates. Its passing
   tests cannot satisfy those gates.
9. The startup harness calls its thresholds conservative experiment tripwires,
   not measured startup budgets. Those tripwires are not final production
   budgets and cannot establish the Decision 0009 startup reserve.

## 7. Historical review evidence

TR-A reported bounded `ACCEPT` with:

- 24 operation-first normal-lock cases;
- 6 takeover-first cases;
- 6 constructor failure injections;
- 11 focused takeover tests;
- 19 neighboring regression tests;
- 175 complete adapter tests;
- 62 startup protocol tests; and
- 33 startup schema tests.

Those are historical technical-review results. This phase does not reinterpret
them as current test output, comprehensive adapter acceptance, architecture
authority, live evidence, or Tranche B admission.

## 8. Original documentation implementation validation

The original documentation implementation phase recorded interpreter
`Python 3.14.7`. This is historical evidence, not a fresh remediation
observation.

All suites were invoked once from the repository root with bytecode writes
disabled. Counts are unittest test-method counts; subtests are not counted as
separate methods. No failure was retried.

| Command | Methods | Failures | Skips | Duration | Exit result |
|---|---:|---:|---:|---:|---|
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests/decision_0009 .venv/bin/python -B -m unittest test_acer_adapter_supervisor.SupervisorTakeoverTests -v` | 11 | 0 | 0 | unittest reported 0.060s | The unittest runner completed with `OK`. The surrounding zsh wrapper then exited 1 because its post-run bookkeeping attempted to assign zsh's read-only variable `status`; this occurred after all 11 results and the `OK` summary were printed. The suite was not rerun. |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest discover -s tests/decision_0009 -p 'test_acer_adapter_*.py'` | 175 | 0 | 0 | unittest 453.982s; shell elapsed marker 454s | 0 |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest discover -s tests/decision_0009 -p 'test_startup_characterization_*.py'` | 95 | 0 | 0 | unittest 378.228s; shell elapsed marker 378s | 0 |

These are the original implementation validation results. The focused runner
printed all 11 results and `OK` before the separate zsh bookkeeping error; that
later wrapper error does not convert the tests to a failure or the shell command
to exit 0. The 175- and 95-method suites separately exited 0. None of these
results ratifies PW-P/PW-A, resolves `PUBLICATION_WRITTEN`, proves comprehensive
adapter conformance, supplies live observations, or opens Tranche B.

## 9. Claude Opus 5.5 review validation

The supplied review input is
`/Users/aclab/.codex/attachments/b11de04d-3202-42a5-89d1-d41c86f0cbf5/Pasted text.txt`
(14,047 bytes; SHA-256
`9771d04af3172374314b6be6677343fd76c516817190e4c9ea4541e635a007ca`).

Opus reports that the exact repository-interpreter command exited `127` in its
Linux review shell because `.venv/bin/python` resolved to an unavailable macOS
Homebrew interpreter. It therefore classified the intended-environment result
as unverified. It also reports a supplementary Python 3.10.12 run of the same
test class: 11 tests, `OK`, exit 0, 0.082s, with no `__pycache__`. That
supplementary result does not substitute for the repository interpreter or the
original implementation validation.

## 10. Fresh remediation validation

The repository interpreter was available and reported `Python 3.14.7`. The
required command was run directly once, without a wrapper or assignment to
zsh's reserved `status` variable:

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests/decision_0009 .venv/bin/python -B -m unittest test_acer_adapter_supervisor.SupervisorTakeoverTests -v`

Result: 11 test methods, 0 failures, 0 skips, `OK`, unittest duration
0.059s, process exit 0. This is a fresh regression check after documentation-
only edits. It is not adapter conformance, architecture ratification, live
evidence, or Tranche B admission. The lengthy full suites were not rerun.

## 11. Fresh second-remediation validation

The repository interpreter was available and reported `Python 3.14.7`. Source
inspection established that the named fake-crash test belongs to
`SolSixBootCustodyEvidenceTests`, so only that class component of the supplied
selector was corrected. The two selections were then run together once:

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests/decision_0009 .venv/bin/python -B -m unittest test_acer_adapter_supervisor.SupervisorTakeoverTests test_acer_adapter_supervisor.SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker -v`

Result: 12 test methods, 0 failures, 0 skips, `OK`, unittest duration 0.061s,
process exit 0. The fake-crash test confirms the documented current behavior;
it does not establish conformance to R2 §10, resolve U-04, ratify architecture,
supply live evidence, or admit Tranche B. The lengthy full suites were not
rerun.

## 12. Missing tests and evidence

No tests, fixtures, validators, or source changes are authorized in this phase.
The following remain named future proof obligations rather than inferred passes:

- recovery from independently persisted production state after actual process
  death, with authenticated new session and custody semantics;
- offline fake-crash evidence that demonstrates volatile-state discard and
  execution-session-authority revocation without merely reconstructing a new
  supervisor over retained authority-bearing state;
- direct negative activation tests for a reused activation ID,
  `BootActivation(authenticated=False)`, and a mismatched predecessor digest at
  an otherwise valid handoff, kept distinct from campaign-authorization replay,
  wrong ordinal, reused boot ID, and the existing forged operation/history cases;
- a persistent bare-claim/post-result-binding takeover case, separate from the
  historical TR-A probe report;
- a persistent takeover/reconstruction-failure assertion taken before the
  outer takeover lock is released, separate from post-return latch assertions;
- production durability/rollback/fencing across independent failure domains;
- real custodian, watchdog, process handle, cgroup, reap, and survivor behavior;
- actual immutable/exclusive external publication and independent readback;
- actual pre-`cudaSetDevice` four-family mapping proof including `libcuda`;
- exact target-host PID/cgroup/GPU attribution and complete NVML coverage;
- actual cgroup enforcement and `memory.events` behavior;
- preventative device-allocation enforcement, including concurrency and release;
- simultaneous combined-footprint evidence;
- contemporaneous machine reserve evidence;
- failure-specific live cleanup/no-successor evidence;
- canonical Tranche A evidence-byte recovery and independent digest verification;
- Human Chair resolution of PW-P/PW-A and `PUBLICATION_WRITTEN`; and
- a separately authorized comprehensive offline conformance review after
  authority ratification.

## 13. Closeout fields

Final documentation hashes, final Git status, unchanged source fingerprints,
and direct-inspection results are reported in the implementation handoff. This
document does not embed its own digest because doing so would change that
digest. No source, test, schema, policy, existing documentation, configuration,
dependency, historical record, or Git state was authorized to change.
