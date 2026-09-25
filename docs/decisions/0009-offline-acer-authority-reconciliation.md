# Decision 0009 — Offline Acer Authority Reconciliation

## Status

**Proposed for Human Chair acceptance.**

This document is a source-attributed reconciliation of existing Decision 0009
authority. It does not amend executable behavior, resolve an authority gap,
accept the complete offline adapter, authorize publication, or open Tranche B.
The underlying accepted records retain their existing authority independently
of this proposal. Proposal-only material below remains proposal-only unless Amy,
as Human Chair, separately accepts it.

## 1. Purpose and disposition

The next offline conformance review needs one stable requirement ledger. The
current repository contains an accepted resource-admission decision, an offline
adapter implementation, accepted amendments recovered from historical records,
a later publication/window proposal, and a narrowly accepted takeover repair.
Those categories are not interchangeable.

This reconciliation therefore:

1. identifies the source and authority for each proposed review requirement;
2. reconstructs Revision 4 through its explicit Revision 3 and Revision 4
   amendments rather than silently merging drafts;
3. preserves proposal-only publication/window requirements without promoting
   them to accepted architecture;
4. records implementation and test behavior as evidence, not authority; and
5. leaves every unresolved point for Human Chair or architecture disposition.

The companion evidence ledger is
[`../reviews/decision-0009-offline-acer-authority-evidence.md`](../reviews/decision-0009-offline-acer-authority-evidence.md).

## 2. Authority classes and precedence

| Class | Meaning in this package |
|---|---|
| Accepted architecture | A repository decision marked accepted by the Human Chair, or an architecture revision whose acceptance is explicitly established by a Human Chair instruction. |
| Explicit human requirement | A bounded requirement stated by the Human Chair for an authorized implementation or repair. It governs that stated scope; it is not automatically a general architecture amendment. |
| Proposed for acceptance | Assistant-authored design or addendum without recovered Human Chair acceptance. It may define a future review question but not a currently accepted permission. |
| Technical acceptance evidence | A bounded reviewer verdict showing that a named implementation target satisfied its stated review scope. It does not create architecture or execution authority. |
| Implementation behavior | What current source does. Code cannot ratify its own contract. |
| Test/probe evidence | A demonstrated offline case. Passing tests do not prove comprehensive conformance or live behavior. |
| Observation | A repository or historical-record fact established by inspection. |
| Missing authority | A decision, source, or acceptance link not established by the recovered evidence. |

Precedence is narrow. Explicit accepted amendments replace only the provisions
they identify. Later implementation, tests, or technical review cannot silently
supersede architecture. When two authoritative records conflict without an
explicit supersession, the conflict remains unresolved and returns to Amy/Astra.

## 3. Source identities

The exact record roles, digests, and bounded excerpts are in the companion
evidence ledger. These identifiers are used below:

- **D9** — `docs/decisions/0009-split-memory-admission-and-accounting-boundary.md`.
- **D4/D6/D7/D8** — inherited accepted Decisions 0004, 0006, 0007, and 0008.
- **R2** — `rollout-2026-09-21T13-10-36-01a0c597-842d-7782-b784-b3024db6b1b1.jsonl`, assistant response record 53.
- **R3** — the same JSONL, assistant response record 72.
- **R4** — the same JSONL, assistant response record 91.
- **R4-NR** — `rollout-2026-09-21T13-44-21-01a0c5b6-686f-7500-a255-c1b40b412f7f.jsonl`, assistant response record 260, the earlier `NOT READY` verdict.
- **R4-A** — the same JSONL, assistant response record 338, Sol's final `ACCEPT` verdict for offline implementation authorization readiness.
- **IA** — `rollout-2026-09-21T14-23-44-01a0c5da-76ec-75b1-a8ca-386ace8ed244.jsonl`, user record 9.
- **PW-P** — `rollout-2026-09-22T18-47-13-01a0cbf2-0fee-70f3-9bc4-63353c86075f.jsonl`, assistant record 187.
- **PW-R** — the same JSONL, user record 197.
- **PW-A** — the same JSONL, assistant record 215.
- **TA** — `rollout-2026-09-23T06-44-33-01a0ce82-ca83-7de1-8feb-45600614f4ac.jsonl`, user record 9.
- **TR-S** — `rollout-2026-09-23T07-48-57-01a0cebd-bfe1-7e21-b0ef-4e15a0a4642a.jsonl`, user record 9.
- **TR-A** — the same JSONL, assistant record 352.
- **AR** — `rollout-2026-09-25T05-39-35-01a0d894-0ac2-7683-a935-e8a19ca20012.jsonl`, assistant record 258, especially Sections D–J; the current Human Chair instruction identifies the accepted version of this report as the controlling design for this documentation phase.
- **DP-P / DP-R / DP-A** — `rollout-2026-09-25T06-17-54-01a0d8b7-1c48-7030-a217-41a4b9ff1b0f.jsonl`, records 9, 46, and 53: the documentation-phase prompt, the exact approval request, and Amy's approval.

Historical instructions above are evidence of historical authority. They are not
current authorization to rerun their old effects.

## 4. Revision 4 reconstruction

Revision 4 is not a standalone repository document. It is reconstructed as an
explicit amendment chain:

| Layer | Documentary status | Relationship |
|---|---|---|
| R2 | Assistant proposal for independent review; expressly not implementation or execution authority. | Base architecture text. |
| R3 | Assistant amendment stating that its affected sections replace the corresponding R2 provisions and all other R2 provisions remain unchanged. | Replaces R2 custody-loss, execution-byte revalidation, first-worker baseline, local-versus-external publication, boot activation, and spawn-ordering provisions. |
| R4 | Assistant amendment resolving closure circularity, the verification root/effect boundary, and the closed state vocabulary. | Unlike R3, R4 has no general express replacement clause. Its headings say “Revised,” and its removed-name section says named draft states are “removed entirely”; those words support replacement of the corresponding closure, verification, and state-name provisions, but not a broader invented supersession. |
| R4-A | Sol's final `ACCEPT` after the earlier R4-NR `NOT READY` verdict. | Accepts Revision 4 for offline implementation authorization readiness only; it does not accept a completed adapter or authorize live work. |
| IA | User instruction: “Implement the architecture accepted through Revision 4 and Sol’s final ACCEPT review.” | Establishes Human Chair implementation acceptance of the R2 base as amended by R3 and R4 and reviewed in R4-A, within the exact 13-file offline scope. |

The reconstruction does not absorb PW-P or PW-A. They were produced later and
remain a separate publication/window proposal family. It also does not treat TA
as a recovered standalone takeover addendum; TA is a later explicit bounded
repair instruction.

R4-NR is an earlier verdict on the unresolved Revision 3 blockers. R4-A is the
later final verdict after Revision 4 addressed those blockers. Neither verdict
is comprehensive adapter acceptance or live execution authority.

## 5. Requirement and authority ledger

Every row includes the fields required for the next review. “Current evidence”
means implementation/test evidence only; it is not a conformance conclusion.

| ID | Exact statement | Source identity / locator | Authority classification | Acceptance evidence | Scope | Supersession | Code symbols | Test/probe evidence | Limitations | Unresolved action |
|---|---|---|---|---|---|---|---|---|---|---|
| D9-IND | “Three coordinated controls must pass independently”: host/cgroup budget, GPU-process/device budget, and machine safety reserve; no one substitutes for another. | D9 §§4–7, lines 109–232 | Accepted architecture | D9 status is “Accepted by Human Chair.” | Resource admission and accounting | None recovered | Startup `observer.py`, `controller.py`; adapter `normalize_gpu_attribution` only models part of attribution | Startup protocol/schema tests and adapter attribution tests exercise offline structures | No current target-host enforcement, machine reserve proof, or preventative device enforcement | Preserve as conjunctive live admission obligations; do not infer satisfaction from offline tests |
| D9-OBS | Configured limits, expected values, digests, labels, manifests, or stored verdicts cannot replace separately obtained observations and independent comparison. | D9 §§4, 12, 18; D8 §§3, 6, 12 | Accepted architecture | D9 and D8 are accepted decisions | Authority/observation separation | D8 changes only the observation form for the admitted open-weight path | `ArtifactVerificationPrimitive`; `EvidencePipeline`; `normalize_gpu_attribution` | Artifact-label substitution, raw/normalized/core, and F8 tests | Offline expected-byte comparison is not target-host observation | Retain missing observations as unknown |
| R4-SPAWN | Durable spawn intent precedes `create_once`; one spawn token permits at most one underlying creation; ambiguous outcomes never authorize retry. | R3 “Spawn ordering”; IA implementation requirements | Accepted architecture plus explicit human implementation requirement | IA explicitly authorizes architecture accepted through R4 and repeats these invariants | Offline adapter spawn/custody model | R3 replaces the earlier R2 ordering where `WORKER_CREATION_IN_PROGRESS` could be read as a pre-create prerequisite | `PersistentSupervisor.spawn_worker`; `OfflineCustodian.create_once`, `inspect_spawn`; store effect capability/result registries | `SupervisorTests.test_spawn_intent_is_witnessed_before_create_and_in_progress_follows`; crash/ambiguity/concurrency custody tests | Deterministic in-memory custodian; no real process creation or durable token service | Production custody/create mechanism remains separately required |
| R4-STICKY | Custody uncertainty, taint, and consumption remain sticky; custody loss proves no exit, cleanup, reap, clearance, or successor. | R3 “Custodian death”; IA custody requirements | Accepted architecture plus explicit human implementation requirement | IA acceptance/authorization through R4 | Offline custody and recovery | R3 replaces less explicit R2 custodian-loss language | `OfflineCustodian.die`; `PersistentSupervisor.record_custodian_loss`; store taint/consumption; `OfflineSurvivor` | Custody death/survivor/store stickiness and containment tests | No production survivor, watchdog, handle, or persistence proof | Preserve sticky semantics; defer production mechanism |
| R4-EVID | Raw adapter bytes, normalized core-facing structures, exact immutable core bytes, provenance, actual reap, residual clearance, attempt completion, publication, and closure retain distinct meanings. | R2 evidence lifecycle; R3 local finalization; R4 closure sequences; IA evidence requirements | Accepted architecture plus explicit human implementation requirement | IA acceptance/authorization through R4 | Offline evidence and closure | R3 separates local finalization from external publication; R4 replaces circular closure sequence | `BoundedRawJournal`; `EvidencePipeline`; `LocalAttemptEvidence`; `_validate_attempt_completion_record`; closure candidate/completion methods | Evidence tests; completion/closure reconstruction tests; successor prerequisite test | In-memory object store and fake publication; no production durability or immutable external destination | Keep each proof independent in later review |
| R4-F5 | The accepted startup core and its 60-second preparation baseline remain unchanged; required mapping families include `libcuda`; missing pre-`cudaSetDevice` `libcuda` observation fails closed. | R3 “First-worker boot custody”; R2/R3 F5; IA | Accepted architecture plus explicit human implementation requirement | IA repeats unchanged core and F5 fail-closed constraints | Startup core integration boundary | R3 removes only the extra adapter pre-spawn 60-second baseline | `enforce_f5_mapping`; startup `worker.run`, mapping gates and schema | Adapter F5 negative tests; startup mapping/barrier tests | No Acer/library observation; imports/tests do not prove checkpoint feasibility | F5 remains unresolved; no preload, moved checkpoint, or expected-as-observed workaround |
| R4-WINDOW | External publication work must not execute during measured preparation, dwell, or residual-clearance windows. | IA implementation invariants and Evidence section | Accepted architecture plus explicit human implementation requirement | IA directs implementation of the R4 architecture and repeats this prohibition; R4-A accepts offline implementation readiness, not completed conformance | Publication scheduling boundary | Separate from PW-P/PW-A's later proposed window-provenance mechanism | `MEASUREMENT_WINDOWS`; `PublicationScheduler.schedule`; `_assert_publication_binding`; publication grant/result paths | `EvidenceTests.test_publication_is_prohibited_during_measured_windows`; authoritative-window, window-change, and restart regressions | Tests cover the offline scheduler/store model, not a production publication worker | Preserve the accepted prohibition; decide PW provenance separately |
| R4-BOOT-ACT | Boots 2–4 require a fresh, authenticated, one-time Human Chair activation bound to the parent authorization digest, exact next ordinal, independently observed new boot ID, and exact predecessor boot-closure digest. | R2 §1 “Planned boot transitions” and §5; R3 “Boot activation”; IA invariants | Accepted architecture plus explicit human implementation requirement | IA implements architecture accepted through R4 and repeats fresh authenticated activation for boots 2–4; R4-A preserves fresh activation | Planned boot handoff only | R3 restates the exact bindings; R4 requires durable `BOOT_COMPLETE`, not a candidate alone, as predecessor | `BootActivation.__post_init__`; boot-activation consumption; `PersistentSupervisor.activate_next_boot`; `activation_ids`; validated boot-closure registry | `test_boots_two_through_four_require_fresh_exact_activations` covers successful boots 2–4; `test_authorization_replay_wrong_activation_and_stale_fence_fail` directly rejects a wrong ordinal, while its replay assertion concerns campaign authorization; `test_reused_boot_id_is_rejected_before_a_new_fence_is_taken` rejects a reused boot ID; `test_boot_activation_operation_cannot_bypass_transition_preconditions` rejects a forged consume operation before it can isolate predecessor-digest checking; `test_forged_boot_closure_history_is_not_reconstructed_and_boot_two_cannot_activate` shows forged closure history cannot produce an activatable boot 2, not a direct mismatched-digest assertion at a valid handoff | Authentication and boot identity are offline fixtures; no real reboot or Chair authentication; no direct negative test supplies a reused activation ID, constructs `BootActivation(authenticated=False)`, or isolates a mismatched predecessor digest at a valid handoff | Preserve the implementation checks at `activate_next_boot` and `BootActivation.__post_init__` as observations; add direct reused-activation-ID, unauthenticated-activation, and valid-handoff mismatched-predecessor negative tests in a separately authorized phase; production activation/authentication remains required |
| R4-DISPATCH | One logical `authorize_and_dispatch(...)` operation makes a linearizable authorization decision covering fresh artifact binding, fence/session and transition validation, durable CAS, single-use capability issuance, and dispatch binding. | R4 §2 “Linearizable effect authorization”; IA Supervisor requirements | Accepted architecture plus explicit human implementation requirement | IA expressly requires the boundary; R4-A accepts it for offline implementation readiness | Every effect-bearing transition; restricted non-authorizing evidence writes are the stated exception to execution-artifact verification, not effect authority | R4 revises the earlier recursive verifier/effect boundary | `ArtifactVerificationPrimitive`; `authorize_and_dispatch`; effect-capability/result registries | substitution-between-verification-and-dispatch, direct-dispatch, stale-fence, reserved-transition, and ambiguity tests | Unit tests do not prove production atomicity, external effect containment, or durable recovery | Recheck each effect-bearing entry point in comprehensive conformance review |
| R4-BYTES | Revalidate the exact authorized core, adapter, policy, and schema bytes before every effect-bearing transition and maintain their immutable binding through effect acceptance. | R3 “Execution-byte revalidation”; IA accepted invariants | Accepted architecture plus explicit human implementation requirement | IA repeats exact execution-byte revalidation for every effect-bearing transition; R4-A found the nonrecursive boundary ready | Artifact/effect boundary | R4 supplies the nonrecursive verification root and linearizable effect boundary | `ArtifactVerificationPrimitive.verify`; `ArtifactBinding`; `authorize_and_dispatch` | `test_substitution_between_verification_and_dispatch_denies_effect`; `test_changed_bytes_before_first_worker_of_later_boot_denies_create`; artifact-label substitution tests | Fake verifier and in-memory immutable bindings only | Production verifier identity, artifact continuity, and dispatch integration remain unproven |
| R4-CORE-ID | `policy.CANONICAL_HEAD = 724700…` is provenance only; execution authority binds accepted core `de04b26…` and exact authorized byte manifests. | R2 §5; R3 “Execution-byte revalidation”; IA accepted invariants | Accepted architecture plus explicit human implementation requirement | IA states both halves explicitly; R4-A preserves accepted-core isolation | Core provenance versus execution authorization | R3 clarifies the distinction; neither constant nor label alone grants execution | `PROVENANCE_CANONICAL_HEAD`; `CORE_EXECUTION_COMMIT`; authorization/artifact manifest contracts | `test_artifact_labels_cannot_authorize_wrong_content`; changed-byte and authorization-binding tests | Offline constants and fake manifests do not authenticate deployed bytes | Retain exact-manifest checks and independently verify any future execution bytes |
| R4-PUB | Evidence publication is immutable, exclusive-create, no-overwrite, and advances to verification only after exact independent readback; an existing different or partial object cannot be overwritten. | R4 §3 and “Publication immutability” test delta; IA accepted invariants | Accepted architecture plus explicit human implementation requirement | IA repeats immutable/exclusive-create/no-overwrite publication; R4-A confirms exact readback and no overwrite | Publication object behavior | R4 preserves the earlier rule while replacing draft state names | `ImmutablePublication`; `PublicationReceipt`; object-store create/write/durable/readback paths | `EvidenceTests.test_publication_is_exclusive_immutable_and_exactly_reconcilable`; lost-ack and readback-failure tests | Fake in-memory object store; no external immutable destination | Production publication and independent readback remain required |
| R4-CLOSE | Boot and campaign closure order is immutable candidate finalization → publication/exact readback → final completion; the candidate excludes its future completion event, and a published candidate alone is not closure. | R4 §1; IA accepted invariants | Accepted architecture plus explicit human implementation requirement | IA expressly requires both sequences; R4-A accepts the circularity repair | Boot/campaign closure | R4 revises the circular R2/R3 closure sequence | `finalize_boot_closure_candidate`; `complete_boot`; `finalize_campaign_closure_candidate`; `complete_campaign`; closure validators | boot/campaign ordering, candidate-substitution, missing-manifest, pre-finalization-publication, and reconstruction tests | Offline publication/readback only; tests do not establish external durability | Preserve ordering and require production publication/readback proof before live closure |
| R4-VOCAB | Use only the canonical closed Revision 4 state vocabulary; reject removed or unknown names. R4 expressly removes `EXCLUSIVE_WRITE` in favor of `EXCLUSIVE_CREATE`. | R4 §3 “Canonical closed state enumeration” and “Removed names”; IA Contracts requirements | Accepted architecture plus explicit human implementation requirement | IA says “Include the canonical Revision 4 vocabulary only” and “Reject removed/unknown state names”; R4-A accepts the closed enumeration | Durable state domains and parsing | R4's “Revised” and “removed entirely” language supports replacement of corresponding state-name provisions; it is not a general R3-style replacement clause | `STATE_DOMAINS`; `parse_state`; separate `REMOVED_STATES` constant | `ContractTests.test_closed_revision_4_vocabulary_rejects_removed_and_unknown_names` accepts one valid attempt state, rejects the listed removed names plus `MADE_UP` when each is passed in the `attempt` domain, and rejects `ATTEMPT_COMPLETE` in the `boot` domain; `parse_state` rejects through closed-domain membership, not a separate `REMOVED_STATES` branch; `SupervisorTests.test_removed_states_never_cross_effect_boundary` separately iterates `REMOVED_STATES` | The named contract test is not exhaustive across every domain; current implementation also defines `PUBLICATION_WRITTEN`, which is not in R4's four-state publication domain | U-03 requires an identified later amendment or a code correction; this document decides neither |
| R4-F8 | F8 binds host PID, namespace mapping, process start, executable/cgroup/custodian/spawn identity, and exact GPU UUID; incomplete, sentinel, conflicting, ambiguous, or identity-discontinuous observations are unavailable, never numeric zero, while only proven absence normalizes to zero. | R2 §6 “F8 process/GPU attribution contract”; IA accepted invariants | Accepted architecture plus explicit human implementation requirement | IA repeats exact F8 unavailable/attribution semantics; R4-A reports F8 not reopened | Offline attribution normalization | Unchanged by R3/R4 | `GPUAttribution`; `normalize_gpu_attribution`; `AttributionUnavailable` | attribution tests for exact match, PID reuse, namespace/GPU mismatch, partial/sentinel/conflicting data, duplicates, helpers, and API coverage | Fixture data only; no NVML call, target-host identity, or full production API coverage | Obtain complete live attribution evidence separately; preserve unavailable values without coercion |
| R4-CUST | The transient supervisor is never the sole custodian; custody is independently owned, `create_once` is at most once, and any survivor has separate identity, authority, lifetime, handles, and evidence. | R2 §3 “Required independent custodian”; R3 custody-loss amendment; IA accepted invariants and Custody requirements | Accepted architecture plus explicit human implementation requirement | IA repeats independent custodian semantics and directs the abstract custodian contract; R4-A preserves custody/survivorship as a deployment blocker | Spawn custody, containment, reap, and survivor evidence | R3 makes custodian loss sticky `CUSTODY_UNCERTAIN`; it does not select a production mechanism | `OfflineCustodian`; `OfflineSurvivor`; `PersistentSupervisor.spawn_worker`; custody/reap registries | duplicate/concurrent `create_once`, ambiguous create, custodian death, survivor separation, receipt-binding, and lifecycle tests | Deterministic in-memory components; no real process owner, watchdog, pidfd, subreaper, or survivor | Select and prove a production independent custodian separately |
| R2-FAKE-CRASH | A fake “crash” discards volatile state and revokes execution-session authority. It must not merely instantiate a new supervisor against a dictionary retaining everything. | R2 §10 “Offline fake-port semantics,” final paragraph before §11 | Accepted architecture | R3 expressly preserves unaffected R2 provisions; R4 does not replace this rule; IA accepts the architecture through R4 | Offline fake-port crash semantics and execution-session authority | No R3 or R4 supersession identified | `OfflineDurableStore.crash`; `PersistentSupervisor.__init__` | `SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker` calls `crash()`, reconstructs with `_restart` over the same store and original session, observes `BOOT_CUSTODY_COMPLETE` with no reconstruction violations, makes the first slot eligible, receives `BLOCKED` from `spawn_worker`, and observes one underlying creation | `crash()` clears only `_volatile`; `_restart` retains the store, verifier, custodian, authorization, and original session; this test establishes current behavior, not conformance to the accepted rule | Astra and Amy must decide whether the modeled crash/reconstruction conforms and, if not, the architectural remedy; this document leaves both unresolved |
| TA-OP | If an old operation wins, its protected mutation, result binding, state exposure, or failure prohibition completes before takeover advances generation. | TA “Required invariant”; TR-S R1 and R6 review criteria | Explicit human repair requirement; later review criteria | TA is the direct requirement; TR-S adds the pre-registration/consumption and post-result-binding review seams without creating repair authority | Window and publication operation/takeover ordering | Later and narrower than R4; does not supersede broader lifecycle rules | `_AuthorizationLock`; `OfflineDurableStore._supervisor_takeover`; `_set_measurement_window`; `perform_publication` | Persistent tests cover constructor takeover at pre-operation and post-result seams and bare claim at the pre-operation seam; historical TR-A R1 reports both entry points at both seams; interruption coverage is stated separately in TA-FAIL | The persistent suite lacks a bare-claim/post-result-binding case; offline threads and retained store only | Preserve the missing persistent case as a future proof obligation; no production scheduling claim |
| TA-TF | If takeover wins, the stale supervisor cannot begin protected mutation using stale authority. | TA “Required invariant” | Explicit human repair requirement | Direct user authorization | Window plus all five implemented publication operations | None | `_supervisor_takeover`; `supervisor_is_current`; `_assert_publication_binding`; `_ensure_session` | `test_takeover_first_denies_stale_window_and_publication_without_effects`; historical TR-A R2 | Denies modeled mutations; does not model actual process restart | Preserve no-registration/no-consumption/no-result/no-effect assertions |
| TA-READY | Successor authority must not become usable before reconstruction is complete; readiness itself does not create execution entitlement. Separately, a fake crash must revoke execution-session authority rather than merely instantiate a supervisor over a dictionary retaining everything. | TA required invariant; TR-S R3 review criteria; R2 unexpected-restart rule and §10 “Offline fake-port semantics” | Explicit human repair requirement plus accepted architecture boundary; review criteria do not add authority | TA supplies the repair requirement; R3 preserves the R2 fake-crash rule, R4 does not replace it, IA accepts the architecture through R4, and TR-S defines the lower-boundary checks | Modeled supervisor takeover and fake crash/reconstruction over retained state | No rule authorizes an actual unexpected restart to regain execution or exempts retained-session fake crashes from R2 §10 | `_supervisor_takeover`; `OfflineDurableStore.crash`; `PersistentSupervisor.__init__`; `_reconstruct`; `supervisor_is_current`; `authorize_and_dispatch` | `test_reconstruction_cannot_expose_authority_or_reenter_takeover`; `test_bare_generation_claim_never_makes_authority_ready`; `SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker`; historical TR-A R3 | `_restart` passes the original `session` into the new supervisor; the named fake-crash test shows post-readiness slot eligibility and one underlying creation under that retained session; these are current-behavior observations, not proof of fake-crash conformance or a new authenticated process session | U-04 must decide both whether a generation change over a retained session is R2's “new supervisor incarnation” and whether the current fake-crash/reconstruction behavior conforms to R2 §10; actual process restart remains non-authorizing and unproven |
| TA-FAIL | Failure during takeover/reconstruction and interruption of a started operation remain fail-closed; the governing requirement is that prohibition be installed before the shared authority lock is released. | TA required invariant; TR-S R6 review criteria; PW-A partial-operation proposal is analogous but independently unaccepted | TA is the repair authority; TR-S supplies the before-lock-release review criterion; PW-A does not ratify TA or vice versa | TA directly requires fail-closed takeover/reconstruction; TR-S defines review timing | Session registration, custody rebinding, reconstruction, window, publication | PW-A contains analogous partial-operation rules but is not needed as authority for TA's takeover scope | `_supervisor_takeover`; `install_failure_latch`; `_prohibit_started_operation` | `test_takeover_failure_is_sticky_for_session_custody_and_reconstruction` inspects latches after constructor failure returns; `test_interrupted_operation_installs_prohibition_before_waiting_takeover` observes them inside `register_session` after the successor acquires the lock and before replay derives them; historical TR-A R6 separately reports pre-outer-lock-release fault probes | No persistent test directly observes takeover/reconstruction-failure latches before outer lock release; no process-death durability proof | Preserve the timing distinction and sticky prohibition; production persistence remains open |
| TA-REENT | Reentrancy cannot bypass authority or deadlock supported paths; same-thread takeover is denied before shared generation/session/custody mutation, while ordinary nested authorization remains supported. | TA implementation direction; TR-S R4 review criteria | Explicit human repair requirement plus non-authorizing review criteria | TA requires accounting for `RLock` and supported callbacks; TR-S specifies constructor/direct-claim callback cases and normal nested authorization | Constructor and direct-claim callbacks in supported offline paths | None | `_AuthorizationLock.owned_by_current_thread`; `_supervisor_takeover` | `test_reentrant_takeover_is_denied_before_shared_state_changes`; historical TR-A R4 adds normal-lock and ordinary-nested probes | Production callbacks absent; test wrapper is not production synchronization | Recheck lock ordering and normal-lock behavior in conformance review |
| TA-HIST | Valid operations completed before takeover remain readable as historical evidence; historical validity does not authorize stale grants, stale supervisors, or new execution. | TA required invariant; TR-S R7 review criteria; PW-P/PW-A historical-validity rules are proposal-only | Explicit human repair requirement plus non-authorizing review/proposal detail | TA supplies the historical-readability requirement; TR-S defines retained-protection review cases; PW adds proposal detail without acceptance | Historical read-only recovery | Compatible with R2/R4 restart prohibition | `publication_record_provenanced`; `_validated_window_history`; `publication_snapshot`; historical effect lookup | completed-history, repeated-restart, stale-grant, unprovenanced-window, pending/unbound tests; historical TR-A R7 | Retained in-memory registries are part of the proof | Production reconstruction must establish equivalent durable registries without granting execution |
| PW-ID | Publication object identity is exactly `(intent_id, destination, object_key, object_digest, length)`; operation proof also binds store, grant, operation, expected prior state, window epoch, authorization/campaign/boot/candidate/generation/session/fence identities, and one exact result `(event_id, revision, event_digest)`. | PW-P record 187; PW-A §§2–3, record 215 | **Proposed for Human Chair acceptance** | PW-R requested additions but did not accept implementation; the enumerated search scope in the evidence ledger found no later acceptance of PW-P/PW-A | Proposed publication identity/provenance contract | Does not supersede R4 while unaccepted | `PublicationIdentity`; `PublicationOperationBinding`; `OperationResultBinding`; grant registries | Consolidated identity/result substitution tests and evidence integration tests | Current code and commit `5a64eec…` implement much of the proposal, and TA requires preservation of its regressions; neither fact supplies PW acceptance | Amy must accept, revise, or reject this contract before it becomes a conformance requirement |
| PW-WIN | A window transition binds store identity, unique operation ID, operation name `set-measurement-window`, event ID, previous/new window and epoch, authorization, campaign, generation, session, fence, and exact result binding. | PW-P record 187; PW-A §§1–3 | **Proposed for Human Chair acceptance** | PW-R asked that the proposal add these rules; no acceptance found in the enumerated search scope | Proposed measurement-window provenance | None while unaccepted | `MeasurementWindowTransition`; `_register_window_operation`; `_bind_window_result`; `_validated_window_history` | explicit field/result substitutions, smuggled window, outside→dwell→outside tests | Offline store-owned registries only | Amy disposition required |
| PW-INIT | Only first successful `admit_campaign` against a fresh empty store may establish `(None, 0) → (OUTSIDE_MEASURED_WINDOWS, 1)`; missing or old unprovenanced history is retained but never automatically upgraded. | PW-A §1 | **Proposed for Human Chair acceptance** | No acceptance found in the enumerated search scope | Proposed initialization/reconstruction rule | None while unaccepted | `_begin_window_initialization`; `_set_measurement_window`; `_validated_window_history` | consolidated initialization tests | Implementation behavior is not ratification | Amy disposition required; production migration policy remains undefined |
| PW-PART | Ordering is validate → mark started → append/mutate → bind result → expose completion under the shared authorization lock; pending windows and consumed unbound grants are non-authorizing, with no refund, inferred registration, redispatch, or fabricated completion. | PW-A §2 | **Proposed for Human Chair acceptance** | No acceptance found in the enumerated search scope | Proposed window/publication partial-operation rules | TA independently authorizes fail-closed takeover ordering but does not ratify the full PW contract | `_set_measurement_window`; `perform_publication`; incomplete-operation registries; reconstruction | partial window/publication tests; bound-result interruption tests; ordering test | Modeled crash retains store object/registries; not production crash atomicity | Amy disposition and production durability proof required |
| PW-OPS | The proposed publication operation sequence has five operations: `intent`, `create`, `write`, `durable`, `verify`. | PW-P/PW-A | **Proposed for Human Chair acceptance** | No acceptance found in the enumerated search scope | Proposed publication operation contract | Conflicts/corresponds incompletely with R4’s four canonical publication states | `PUBLICATION_OPERATIONS`; `PUBLICATION_OPERATION_STATES`; `ImmutablePublication` | all-five operation tests | R4 names only `PUBLICATION_INTENT`, `EXCLUSIVE_CREATE`, `DURABLE_BYTES`, `PUBLICATION_VERIFIED`; implementation adds `PUBLICATION_WRITTEN` | Human Chair must resolve the state/operation correspondence; this document does not ratify it |

Compound ledger rows preserve source boundaries: TA supplies bounded repair
requirements; TR-S supplies review criteria only; PW-P/PW-A supply proposal-only
detail; and TR-A supplies historical technical observations. None of those roles
is silently promoted into another authority class.

## 6. Publication/window proposal transcription

This section is deliberately labeled proposal. It is included so a future
Human Chair decision can accept, revise, or reject exact terms without relying
on code as the specification.

PW-P proposes one canonical contract per authority-producing operation, used
without weaker duplicate field lists at creation, consumption, historical
validation/reconstruction, and every downstream consumer. For publication,
those consumers include snapshots, receipt verification, closure proof, and
reconstruction. For windows, replay and publication-chain validation derive
their window/epoch view only from the same provenanced transition contract.

### 6.1 Complete identities

- Object identity:
  `(intent_id, destination, object_key, object_digest, length)`.
  The source bytes must match `object_digest` and `length`; `intent_id` cannot
  substitute for `destination` or `object_key`.
- Publication operation identity:
  `store_identity`, `grant_id`, `operation`, the complete object identity,
  `expected_prior_state`, `window_epoch`, `authorization_digest`, `campaign_id`,
  `boot_id`, `boot_ordinal`, `closure_candidate_event_digest` or `None`,
  `supervisor_generation`, `session_id`, and `fence_epoch`.
- Operation result binding:
  `(event_id, revision, event_digest)`.
- Window operation identity:
  `store_identity`, a unique `operation_id`, operation name
  `set-measurement-window`, `event_id`, previous window and epoch, new window
  and epoch, `authorization_digest`, `campaign_id`, `supervisor_generation`,
  `session_id`, and `fence_epoch`, plus the exact result binding.
  Its produced record retains `record_type=MEASUREMENT_WINDOW` and
  `authorizes_execution=False`.

The proposal preserves, rather than redesigns, the four then-existing window
values—`MEASURED_PREPARATION`, `DWELL`, `RESIDUAL_CLEARANCE`, and
`OUTSIDE_MEASURED_WINDOWS`—and their then-existing allowed transitions. The
proposal changes the provenance proof for a transition, not scheduling policy.

### 6.2 Initial window and historical records

A fresh empty store begins at `(window=None, window_epoch=0)` and permits no
publication. The proposal allows only the first successful `admit_campaign`
operation, begun against that fresh store, to establish
`(None, 0) → (OUTSIDE_MEASURED_WINDOWS, 1)` with full operation provenance.
Eligibility for that initialization must be established before any admission
writes and is usable only inside that one `admit_campaign` call. “No window
found” is not sufficient.

Entirely empty history remains uninitialized. A valid registered initial
transition reconstructs epoch 1. Existing campaign history with missing initial
window, missing provenance, or incomplete initialization remains non-authorizing.
Old unprovenanced history is retained; it is not deleted, upgraded, or supplied
with a proof during replay. A crash after campaign admission but before initial
window registration completes does not permit replay to supply the missing
transition.

### 6.3 Ordering and partial-operation rules

The proposal retains `store.authorization_lock` across authority checks,
mutation, result registration, and exposure of in-memory state. Lock order is
authorization lock before store lock.

| Stage | Window transition | Publication operation |
|---|---|---|
| Validate | Current authority, healthy store, initial rule or proven predecessor, next epoch | Current authority, full grant identity, operation, prior state, current window epoch, candidate binding, unused grant |
| Mark started | Register the exact pending window operation before append | Consume the registered grant before object or publication-record mutation |
| Append/mutate | Append and witness the exact window record | Perform the bounded object operation, then append and witness its exact result record |
| Bind result | Bind the pending operation to exact event ID, revision, and digest | Bind the consumed grant to exact event ID, revision, and digest |
| Expose completion | Update window/epoch only after result binding | Return the operation result only after result binding |

The recovered partial-operation rules are:

- Pending window without bound result: deny publication immediately and after
  reconstruction; do not fall back to an earlier outside window.
- Consumed publication grant without bound result: retain consumption and deny
  promotion; no refund, redispatch, or inferred result.
- Appended frame without result registration, including lost append
  acknowledgement: retain it as unprovenanced and non-authorizing; replay does
  not finish registration.
- Bound result followed by interruption before cache exposure or caller
  acknowledgement: reconstruction may recover the exact completed historical
  operation but must not repeat it.
- Unconsumed grant without result: it proves no operation occurred and grants
  no historical state or current-generation bypass.
- After a started operation fails, sticky prohibition is installed before the
  shared authorization lock is released; fallible diagnostics follow.
- Reconstruction inspects pending window operations and consumed publication
  grants without results even when no frame was appended. Absence of a frame
  cannot erase the store-owned pending/consumed fact.

### 6.4 Literal negative-test inventory

PW-A requires the negative inventory to be written literally and independently
of production projection helpers or dataclass-field enumeration. The proposal
names:

- publication object identity: `intent_id`, `destination`, `object_key`,
  `object_digest`, `length`;
- publication operation binding: `store_identity`, `grant_id`, `operation`,
  `expected_prior_state`, `window_epoch`, `authorization_digest`, `campaign_id`,
  `boot_id`, `boot_ordinal`, `closure_candidate_event_digest`,
  `supervisor_generation`, `session_id`, `fence_epoch`;
- window operation binding: `store_identity`, unique `operation_id`, operation
  name, `event_id`, previous window, previous epoch, new window, new epoch,
  `authorization_digest`, `campaign_id`, `supervisor_generation`, `session_id`,
  `fence_epoch`; and
- each result binding: `event_id`, `revision`, `event_digest`.

It additionally names missing proof, changed attestation, wrong `record_type`,
and `authorizes_execution=True`. These remain proposal terms; existing tests
are evidence about implementation behavior, not acceptance.

## 7. Publication-state discrepancy

R4’s canonical publication domain contains four states:

`PUBLICATION_INTENT`, `EXCLUSIVE_CREATE`, `DURABLE_BYTES`,
`PUBLICATION_VERIFIED`.

R4 calls the enumeration closed, says unknown and removed names are rejected,
and removes `EXCLUSIVE_WRITE` in favor of `EXCLUSIVE_CREATE`. IA separately
instructs the implementer to include only the canonical Revision 4 vocabulary
and reject removed or unknown names. PW-P, PW-R, and PW-A state that Revision 4
was unavailable to them; that context explains an evidence limitation but does
not resolve or excuse the vocabulary discrepancy.

Current `contracts.py` and the adapter README contain a fifth state,
`PUBLICATION_WRITTEN`, corresponding to the separate `write` operation between
exclusive creation and durability. PW-P/PW-A describe all five operations and
the current tests exercise the five-state implementation. Within the enumerated
search scope, no identified later Human Chair amendment accepts the additional
state or explains whether it is an allowed refinement of `EXCLUSIVE_CREATE`, a
replacement vocabulary, or a conflict with R4’s closed enumeration.

Disposition: **unresolved; do not resolve or ratify through this document.**

## 8. Takeover, reconstruction, and actual restart

The accepted bounded repair orders modeled takeover against operations sharing
the same `OfflineDurableStore`, authorization lock, session registry, custodian,
and in-memory operation/result registries. It establishes useful offline
ordering evidence.

R2 §10, “Offline fake-port semantics,” states:

> A fake “crash” discards volatile state and revokes execution-session authority. It must not merely instantiate a new supervisor against a dictionary retaining everything.

R3 expressly leaves unaffected R2 provisions unchanged, R4 does not replace
this rule, and IA accepts the architecture through R4. The rule therefore remains
an accepted requirement, not a test-derived preference.

Current behavior sits in unresolved tension with that requirement.
`OfflineDurableStore.crash()` clears only `_volatile`. The test helper `_restart`
constructs a new `PersistentSupervisor` over the same store, verifier, custodian,
authorization, and original session. In
`SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker`,
the test calls `crash()`, reconstructs `BOOT_CUSTODY_COMPLETE` with no
reconstruction violations, makes the first slot eligible, receives `BLOCKED`
from `spawn_worker`, and observes one underlying creation. That green test is
evidence of current behavior, not authority or proof of conformance to R2 §10.

The test helper `_restart` passes the original `session` into the new
`PersistentSupervisor`, and persistent tests demonstrate post-readiness
permission under that retained session. They do not establish a newly
authenticated process session. Whether a generation change over a retained
session is R2’s “new supervisor incarnation” is one unresolved question.
Whether the fake-crash path above actually revokes execution-session authority
as R2 §10 requires is a separate unresolved question. This document does not
choose an architectural remedy.

It does not establish that an unexpected operating-system process restart
retains an original execution session or may resume execution. R2 states that a
new supervisor incarnation receives containment/evidence authority only for an
interrupted campaign; an unexpected restart taints the campaign and cannot
restore execution. A ready reconstructed supervisor is therefore not, by
readiness alone, entitled to execute. Production persistence, process death,
session loss, custody continuity, and restart authentication remain unproven.

## 9. Unresolved decision register

| ID | Unresolved item | Why unresolved | Required disposition |
|---|---|---|---|
| U-01 | Separately named approved takeover proposal/addendum | TA instructs the implementer to locate “the approved Astra proposal and addendum,” and TR-S says “Astra did not have the takeover-specific approved proposal/addendum.” Those Human Chair records describe an artifact as approved, but no exact standalone source, contents, acceptance record, or relationship to PW-P/PW-A was established. TA supplies explicit repair requirements without identifying the artifact. | Identify and authenticate the approved artifact and its relationship, if any, to PW-P/PW-A; otherwise state which bounded instruction controls. Do not convert “unidentified” into “never approved.” |
| U-02 | PW-P/PW-A acceptance | The records call the material a proposal/addendum; PW-R requests additions and forbids edits but does not accept implementation. The bounded search found no later acceptance, while `5a64eec…` implementation behavior and TA's regression-preservation instruction are non-ratifying context. | Human Chair accept, revise, or reject. |
| U-03 | `PUBLICATION_WRITTEN` | R4's closed publication domain has four states, explicitly removes `EXCLUSIVE_WRITE`, and IA requires only canonical names; implementation has five. PW's contemporaneous lack of R4 access does not resolve the conflict, and an identified later amendment accepting `PUBLICATION_WRITTEN` has not been established. | Human Chair/Astra resolve exact state and operation vocabulary; do not infer legitimacy from code or tests. |
| U-04 | Supervisor generation, accepted fake-crash semantics, and unexpected process restart | Two questions remain distinct. First, current tests reconstruct over retained in-memory store state and pass the original session through `_restart`; it is unresolved whether a generation change on this model is R2's “new supervisor incarnation.” Second, R2 §10 requires a fake crash to discard volatile state and revoke execution-session authority rather than merely instantiate a supervisor over a dictionary retaining everything, while `OfflineDurableStore.crash()` clears only `_volatile` and `SolSixBootCustodyEvidenceTests.test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker` reconstructs with the same store/session, makes a slot eligible, and observes one underlying creation. The test proves current behavior, not conformance. | Astra and Amy must decide both the generation/new-incarnation question and whether the fake-crash path conforms to the accepted rule, without this document choosing the remedy. Preserve R2's fail-closed unexpected-restart rule, do not grant process-restart authority, and separately prove any production restart semantics. |
| U-05 | Comprehensive offline adapter conformance | The only independent acceptance is the bounded TA repair review. | Run a separately authorized conformance review after authority ratification. |
| U-06 | Production durability/custody/publication | Current store, witness, custodian, survivor, and publisher are deterministic offline models. | Separately design, authorize, implement, and verify production mechanisms. |
| U-07 | F5 | Actual pre-`cudaSetDevice` `libcuda` proof on Acer is absent. | Obtain separately authorized live evidence at the unchanged checkpoint or fail closed. |
| U-08 | Decision 0009 live admission gates | Host/cgroup enforcement, GPU attribution/enforcement, machine reserve, combined footprint, and failure-specific cleanup are not established by this phase. | Satisfy every D9 §13 gate with separately authorized evidence. |
| U-09 | Canonical Tranche A evidence bytes | D9 records a digest and observations, but this package does not locate and independently verify qualifying retained bytes and provenance. | Recover/preserve bytes and independently verify digest/acquisition context. |

## 10. Tranche B remains closed

The following remain independent, conjunctive obligations: canonical Tranche A
evidence; cold/warm randomized startup characterization and margin; simultaneous
combined-footprint observation; actual cgroup enforcement; preventative device
allocation enforcement; exact worker/PID/GPU attribution; machine reserve;
failure-specific cleanup and no-successor evidence; production custody,
storage/witness, and publication; F5; execution-bound artifact/runtime identity;
and explicit Human Chair authorization.

Offline implementation, green tests, documentary reconciliation, independent
review, or later acceptance of this proposal does not satisfy those gates and
does not authorize Acer access, CUDA/NVML, model work, or Tranche B.

The startup harness's conservative experiment tripwires are not measured
startup reserves and are not final production budgets. They cannot satisfy the
startup-reserve or admission gates.

## 11. Review and publication boundary

This package is intended for Claude Opus 5.5 independent review of documentary
faithfulness. Review must distinguish source authority, implementation behavior,
test evidence, unresolved decisions, and missing live proof. A favorable review
does not accept the unresolved clauses, authorize remediation, mutate Git, or
open Tranche B. Documentary remediation and publication each require separate
Human Chair authorization.

The original documentation phase was separately authorized by DP-P → DP-R →
DP-A: the prompt fixed the exact two-file manifest, the assistant requested
approval for that exact operation, and Amy replied “I approve . Proceed.” That
authorization permitted the documentary phase only; it did not ratify any
unresolved architecture, authorize Git publication, or open Tranche B.
