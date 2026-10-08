# Decision 0009 Acer adapter — offline tranche

**U-04 Checkpoint C local implementation candidate — independent review pending.**
The accepted A/B foundation remains in place. C adds only deterministic offline
recovery publication and its migration/validation evidence. The A/B delivery
sections below retain their historical status statements; current C behavior is
described in the final section. Implementation is not Human Chair acceptance or
live admission. Source-bound results, rather than this document, establish which
checks passed.

This directory implements the accepted Revision 4 behavioral contracts and
Revision 6 A/B/C mechanisms as deterministic offline models. It grants
no Acer, CUDA, NVML, process, cgroup, filesystem
publication, reboot, model, GGUF, tokenizer, inference, provider, or Tranche B
authority. Importing these modules performs no host action and loads no vendor
library. Production ports are deliberately absent.

The accepted startup-characterization core is unchanged. In particular,
`policy.CANONICAL_HEAD = 724700217f8d7183757768fb2a856872b64a3cf3`
remains provenance only. Adapter execution authorization binds accepted core
commit `de04b26c14f7e7d60173f463e9d79f9b7134a700`, its exact byte manifest,
the exact adapter manifest, and policy/schema digests.

## Modules

- `contracts.py` defines frozen closed records, strict integer/boolean handling,
  the Revision 4 state domains, authorization, activation, artifact, fencing,
  capability, custody, identity, attribution, reap/residual, evidence,
  publication, and closure contracts.
- `authorization.py` verifies exact canonical v2 approvals and boot activations
  against immutable offline enrollment supplied by trusted bootstrap. It issues
  authentication results, not execution capabilities.
- `custody.py` models an independent custodian, durable token registry,
  blocked fake workers, at-most-one creation, watchdog containment, actual
  simulated wait/reap receipts, custodian death, and a separately identified
  survivor. It has no real worker launcher.
- `supervisor.py` models append-only history, a separate high-water witness,
  fencing, CAS, stale reads, torn/lost writes, rollback quarantine, sticky
  consumption/taint, the nonrecursive artifact verifier, the linearizable
  `authorize_and_dispatch(...)` boundary, and the persistent lifecycle reducer.
- `evidence.py` models bounded raw capture, closed normalization sidecars, exact
  core bytes, F8 attribution, F5 mapping proof, local readback, immutable
  exclusive-create publication, measured-window scheduling, and boot/campaign
  closure candidates.

## Closed state domains

States are domain-specific. Unknown names, wrong-domain names, and the removed
draft names are rejected rather than coerced.

| Domain | States |
|---|---|
| Authorization | `AUTHORIZATION_ADMITTED` |
| Local evidence | `RAW_CAPTURED`, `NORMALIZATION_BOUND`, `IMMUTABLE_BYTES_STORED`, `READBACK_VERIFIED`, `ATTEMPT_EVIDENCE_FINALIZED` |
| Publication | `PUBLICATION_INTENT`, `EXCLUSIVE_CREATE`, `PUBLICATION_WRITTEN`, `DURABLE_BYTES`, `PUBLICATION_VERIFIED` |
| Attempt | `SLOT_SPAWN_ELIGIBLE`, `SPAWN_INTENT_PERSISTED`, `WORKER_CREATION_IN_PROGRESS`, `WORKER_IDENTITY_ESTABLISHED`, `WORKER_IDENTITY_DURABLY_RECORDED`, `RELEASE_ELIGIBLE`, `RELEASE_INTENT`, `RELEASED_OR_POSSIBLY_RELEASED`, `CUDA_CALL_GATE_PASSED`, `CLEANUP_REQUESTED`, `EXIT_OBSERVED`, `REAPING_PROVEN`, `RESIDUAL_CLEARANCE_PROVEN`, `ATTEMPT_COMPLETE` |
| Boot | `BOOT_CUSTODY_ESTABLISHED`, `BOOT_CUSTODY_COMPLETE`, `BOOT_CLOSURE_CANDIDATE_FINALIZED`, `BOOT_COMPLETE`, `BOOT_HANDOFF_PENDING` |
| Campaign | `CAMPAIGN_ADMITTED`, `CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED`, `CAMPAIGN_COMPLETE`, `CAMPAIGN_CLOSED_FAILED` |
| Sticky safety | `ABORTED`, `TAINTED`, `CUSTODY_UNCERTAIN`, `CONTAINMENT_ONLY_RECOVERY` |

Removed names are `LOCAL_ATTEMPT_FINALIZED`, `LOCAL_READBACK_VERIFIED`,
`VALID_ADAPTER_ATTEMPT_COMPLETE`, `EXCLUSIVE_WRITE`,
`DURABLE_EXTERNAL_BYTES`, `INDEPENDENT_READBACK`, and
`EXTERNAL_READBACK_VERIFIED`.

## Authority and lifecycle

`ArtifactVerificationPrimitive` is an independently authorized, nonrecursive
verification root. It hashes the bytes in closed core and adapter file
manifests, binds the core manifest to execution commit
`de04b26c14f7e7d60173f463e9d79f9b7134a700`, and hashes the actual policy and
schema bytes before comparing them with the immutable authorization. Caller
supplied digest labels are not evidence. The verifier cannot mutate
authorization, clear taint, or grant an effect by itself.

`authorize_and_dispatch(...)` makes one logical authorization decision across
fresh artifact verification, current fence/session validation, transition CAS,
single-use effect-capability consumption, continuity revalidation, and dispatch
binding. Creation additionally requires the original acknowledged, witnessed
first-dispatch intent in the current incarnation. The target must accept the
exact journal-issued capability while the authorization lock still protects
the fence, and the capability must match the witnessed durable event, session,
target, operation, generation, and lifecycle predecessor. CAS or verification
failure yields no capability. A committed intent with a missing result remains
unresolved; it is not refunded or redispatched. The effect order is intent,
witnessed `EFFECT_ACCEPTED`, durable acknowledgement, independent currentness
and artifact checks, independent initiation/observation, then versioned durable
result. Control and publication results use the closed `EFFECT_PORT_RECEIPT`
with original producer, acceptance, target, immutable observation and independent
port attestation. A known result replays only in
its current generation, while older generations have a separate read-only
historical receipt lookup.
Artifact substitution after verification and before dispatch records sticky
taint and denies the effect.

Bounded raw/failure/taint writes are non-authorizing. They remain available when
normal execution-artifact verification fails, but cannot mint a capability,
clear a prohibition, assert valid completion, or advance an execution gate.

### General versus dedicated transitions

`append-transition` is the only general operation. It accepts only the closed
`GENERIC_TRANSITION_SCHEMAS` allowlist — the custody observations
`WORKER_IDENTITY_ESTABLISHED`, `WORKER_IDENTITY_DURABLY_RECORDED`,
`RELEASE_ELIGIBLE`, `RELEASE_INTENT`, and `RELEASED_OR_POSSIBLY_RELEASED` —
each with a closed payload (`slot_id` plus optional `spawn_token`, `host_pid`,
`start_ticks`) bound to the current spawned attempt. They grant nothing and
reconstruct as unresolved custody. Unknown fields, reserved control metadata
(`record_type`, window, activation, effect-result, completion, candidate, or
operation-selector fields), and every boundary-owned field are rejected; the
stored event is built from trusted boundary data plus only the allowed fields.

Every other transition — authorization and campaign admission, boot custody,
slot eligibility, spawn intent, worker creation and lifecycle, local evidence,
residual clearance, reaping, attempt completion, closure candidates, boot and
campaign completion, handoff, and boot activation — is produced only by its
dedicated operation in `DEDICATED_OPERATIONS`, which requires module-private
dedicated authority and an exact payload schema. Capability registration is
boundary-owned, and a durable record has provenance only when its effect
capability, operation, event ID, revision, and digest all match.

The dedicated authority token is API discipline only. It is importable and is
never treated as evidence: each state-producing operation re-checks the
semantic evidence its state requires. In particular, the custody operations
validate custodian-issued custody evidence themselves (see *Boot and successor
gates*), and boot/campaign completion re-checks that its publication was
performed for the exact finalized candidate.

Reconstruction never treats a reserved label or `record_type` as proof.
Reserved records without provenance, smuggled control metadata, and malformed
records fail closed (execution revoked, publication prohibited, taint).
`ATTEMPT_COMPLETE`, closure candidates, `BOOT_COMPLETE`, boot activation, and
`CAMPAIGN_COMPLETE` are re-derived from retained evidence: the provenanced
candidate bytes and digest, bound boot/campaign identity, validated attempt or
boot closures preceding the candidate, a verified publication chain for the
exact manifest that began after the candidate finalization event and is bound
to it, and no intervening sticky prohibition. Boot activation re-validates that
closure evidence, not merely the presence of a label. `BOOT_CUSTODY_ESTABLISHED`
and `BOOT_CUSTODY_COMPLETE` are re-derived from the custodian's retained
attestation, and every retained publication record must be the result of its
own consumed operation grant; otherwise reconstruction fails closed.

Creation requires a store-backed slot capability registered by the dedicated
eligibility operation and reserved by the dedicated spawn-intent operation for
the exact campaign, boot, slot, attempt, predecessor completion, generation,
session, fence, token, launch specification, and custodian.
`custodian.create_once` re-checks that reservation at the creation boundary.

`complete_worker_lifecycle` is itself a contained operation. Any failure in its
verification, direct verifier call, containment, wait/reap, or transitions
first installs the sticky execution/publication prohibition, then attempts
owned-worker containment (never claiming reap or clearance), and only then
writes a best-effort failure record carrying the primary and secondary
failures. A durable failure record re-installs the prohibition on
reconstruction.

The only spawn order is:

```text
SLOT_SPAWN_ELIGIBLE
→ SPAWN_INTENT_PERSISTED (durable and witnessed)
→ EFFECT_ACCEPTED (durable, independently read back and witnessed)
→ durable acknowledgement and independent captured-incarnation checks
→ custodian.create_once(...)
→ WORKER_CREATION_IN_PROGRESS
```

Recovery after a durable intent calls `inspect_spawn` or containment behavior.
It never calls creating behavior again. An ambiguous result means possibly live.
Each spawn token permits at most one underlying creation, including concurrent
or duplicate calls and the child-before-supervisor-PID-record crash window.

Loss of custody enters sticky `CUSTODY_UNCERTAIN` and taints the boot and
campaign. It proves no exit, cleanup, reap, residual clearance, or successor.
Containment is unavailable unless a separate survivor proves its own identity,
authority, lifetime, target binding, artifact binding, and surviving rights.
Survivor evidence does not clear taint or restore successor eligibility.

## Boot and successor gates

`BOOT_CUSTODY_COMPLETE` adds no pre-spawn 60-second baseline or replacement
sampling. The accepted core's existing 60-second preparation baseline remains
unchanged.

Boot custody evidence is a `BootCustodyAttestation` issued and retained by the
single custodian bound to the store (`OfflineCustodian.attest_boot_custody`). It
names the live custodian, that custodian's ready watchdog, and a separately
identified observer isolated from the custodian, watchdog, and supervisor, and
it binds the exact store, authorization, campaign, admitted boot ID and ordinal,
supervisor generation, session, and fence. `BOOT_CUSTODY_ESTABLISHED` carries
the attestation; the boundary accepts it only when it equals the custodian's
registered record and every identity matches. `BOOT_CUSTODY_COMPLETE` binds the
unique established event digest and attestation digest under the same
supervisor authority while the custodian remains live. Only then does the store
register validated custody, and slot eligibility requires that validated
custody (and its custodian) rather than the `BOOT_CUSTODY_COMPLETE` label.
Reconstruction re-derives validated custody from the same evidence; custody that
cannot be re-established is a reconstruction violation, so no slot or worker
can follow. The five generic custody observations are not consumed as custody
proof.

Same-boot successor eligibility is derived from store and custodian records;
caller-constructed `LocalAttemptEvidence` is rejected. It requires retained raw
bytes, normalization correspondence, exact frozen/read-back core bytes, the
custodian registry's actual reap receipt, residual observations, a durable
adapter-completion record, no unresolved owned worker, the live original
session/current fence, and no taint. The resulting slot capability is
store-backed and single-use. External publication is deliberately absent from
this predicate.

Boots 2–4 require a fresh authenticated one-time activation bound to the parent
authorization, exact ordinal, independently observed new boot ID, and exact
durable predecessor `BOOT_COMPLETE` digest. Activation cannot override taint,
skip a boot, reopen a slot, or reuse an earlier activation.

## Evidence and closure

The evidence layers are:

1. Bounded original adapter bytes and acquisition metadata.
2. Newly constructed closed normalized structures with raw cross-references.
3. Exact immutable core bytes using sorted keys, compact separators,
   `allow_nan=False`, UTF-8, and one trailing newline.

Local finalization/readback is independent of external publication. Every
publication intent, reserve/create, write, durability operation, and
readback/verify uses a store-registered single-use grant bound to the exact
operation, intent, prior state, supervisor generation, session, fence, and
authoritative measurement-window epoch. The grant attestation also binds the
boot ID and ordinal and the closure candidate finalized in the current
lifecycle (`closure_candidate_event_digest`, or none), and a grant whose
lifecycle point changed before use is rejected. Each consumed grant is bound in
the store to the single record it produced (event ID, revision, and digest).
Valid bytes prove object consistency only: reconstruction and every chain
validation require each record's registered, consumed, bound grant with
matching identity, prior state, window epoch, generation, session, and fence.
Mutations are impossible during
measured preparation, dwell, and residual-clearance windows; read-only
historical reconciliation remains available. Publication records separate
reserved, written, durable, and verified state; unwritten is not represented by
empty bytes. Publication uses exact registered intents, exclusive
destination-object creation, durable complete bytes, exact independent readback,
and no overwrite.
Lost acknowledgements reconcile only the same intent and exact bytes.

Boot closure is:

```text
all required boot evidence finalized/read back
→ BOOT_CLOSURE_CANDIDATE_FINALIZED
→ candidate and manifest-bound objects published/read back
→ BOOT_COMPLETE
```

Every manifest publication chain must begin after the candidate finalization
event and carry that event's digest, which covers the bound validated attempt
completion set, so a publication performed before finalization, or one from an
earlier boot with identical bytes, never satisfies closure. The completion
boundary, the live completion call, and reconstruction all apply this check.

Campaign closure uses `CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED` and then
`CAMPAIGN_COMPLETE` equivalently. A candidate excludes its future completion
event and future publication receipt. The completion event binds the candidate,
verified publication receipt, revision, and fence. Intervening taint prevents
closure. A published candidate alone is not a completed boot or campaign.

## F8 and F5

F8 attribution requires matching live pre/post process observations across host
PID, namespace, start ticks, executable, cgroup, custody token, and exact GPU
UUID, with complete query coverage. PID reuse, namespace ambiguity, wrong GPU,
worker exit, unavailable/sentinel fields, partial enumeration, conflicting API
values, or ambiguous multiple contexts remains unavailable; it is never numeric
zero. Only exact duplicate records may collapse. Host and GPU ledgers remain
separate.

F5 remains unresolved for Acer. The required observed families are exactly
`libcudart`, `libcublasLt`, `libcublas`, and `libcuda`. Missing actual
pre-`cudaSetDevice` `libcuda` proof fails closed. This tranche does not preload
`libcuda`, move the checkpoint, or synthesize observed identity from expected
identity.

## Store and failure model

The offline store has separate volatile and durable frames plus an independent
witness. It models revision/fence CAS, monotonic non-reusable fencing epochs,
duplicate event IDs, concurrent writers, torn writes, lost acknowledgements,
stale reads, rollback, snapshot rollback, witness/journal divergence, sticky
consumption and taint, and containment-only quarantine. Hash chaining alone is
not treated as rollback detection. A fake crash discards volatile state without
restoring execution rights or consumed identities.

A new supervisor replays witnessed durable history to recover boot/campaign and
attempt state, consumed slots, activation and boot identities, exact finalized
closure candidates, validated completions, historical measurement window and
epoch, taint/custody prohibitions, and unresolved spawn/release intents. It never
registers historical sessions as live or resumes execution/publication/window
authority. Complete pre-loss ORIGIN shutdown permits non-executing waiting;
planned admission is a separate store-owned transaction protocol.
Completion replay revalidates every retained raw, normalized, core, reap, and
residual object before adding it to the completion index. A witnessed spawn
intent without a resolved child remains possibly live after restart. Malformed
input installs an in-memory execution and publication prohibition and requests
containment before attempting the fallible durable failure record, so witness
or diagnostic failure cannot restore eligibility.

Production durable storage, witness independence, Chair authentication,
custodian/survivor mechanisms, process and cgroup integration, NVML/CUDA
attribution, immutable publication, Acer compatibility, deployment, reboot,
model work, active characterization, and Tranche B remain outside this tranche.

## U-04 Checkpoint A implementation status

The governing architecture is accepted Revision 6, SHA-256
`07247b2b053fc5dbc98f01e3388cd1f79e90b4adaf0984afb49a6ceb810bef39`.
The authorized baseline is `m1-live-adapter-dev` at
`8178aeb9692883caaa5e86dece5599c8ca228410`. The source of Astra's implementation
design is planning session `01a1030d-0153-7e10-838e-5f4416b2d528`.

| Task | Integrated foundation |
|---|---|
| 1: deterministic characterization | Original nine triggers pass; uninterrupted controls and missing-evidence negatives retained |
| 2: v2 / OCAV | Pinned canonical authorization and activation verification integrated into fresh INIT and planned ADMIT; policy/permission and substitution negatives |
| 3: persistence kernel | ENTRY, INIT, EXEC, RESULT, SHUTDOWN, ADMIT, HISTORY and DENY use witnessed transactions; closed writer cross-product and independently retained-byte confirmation |
| 4: identity/reset/entry | Opaque captured actors and reconciliation bindings, exhaustive reset, historical reconstruction, evidence-derived non-live entry and eight positive-evidence denial predicates |
| 5: durable effects | Durable acceptance, independent acknowledgement/currentness checks, independent worker/control/publication observations and closed versioned result writes; unknown outcomes never replace execution |
| 6: Option B | Shutdown-only handoff, independent quiescence, ORIGIN logical exit, waiting proof and separate consumed activation reservation/admission with all-lower-fence acknowledgement |

Final validation under Python 3.14.7 passes 250/250 full adapter tests,
138/138 focused tests, 17/17 lower-port checks and 95/95 unchanged startup
characterization tests. Every final run has zero failures, errors and skips,
with matching before/after/current Python source hashes. The startup source
and tests also match HEAD bytes. The full run includes all 119 supervisor tests.

`authorization.py` performs offline trusted-enrollment verification only. It
implements no cryptographic Chair identity, signing, or protected provisioning.
Passing OCAV or parsing an `EFFECT_RESULT` is never an execution capability.
The store rejects legacy append/session registration as an operational route.
Constructors never expose execution; only complete acknowledged INIT or ADMIT
does. Recovery publication remains unavailable. Each lower effect port checks
the captured actor and the independent witness acknowledgement immediately
before initiating an effect.

The original 44 store fields and ten added fields are classified by
`STORE_FIELD_DOMAINS` and `STORE_FIELD_CLASSIFICATION`. The new fields are `_current_actor`, `_entry_mode`,
`_health`, `_pending_reset`, `_authentication_service`, and
`_historical_producers`, `_acceptance_acks`, `_activation_authentication_service`,
`_artifact_verifier`, and `_current_reconciler`.
Store acknowledgement/session dictionaries are derived views. The current
opaque session and acknowledgement registrations belong to W and are revoked
at loss/logical exit. The root itself remains external immutable I
configuration; `_authentication_service` is a pinned B reference to that service.
The actual artifact-verification primitive and independent custodian are pinned
for lower-port continuity and observation checks. Legacy identity/acceptance
ports cannot mint execution authority. Reconciliation holds a distinct opaque
current binding that loss/reset immediately invalidates.
The verifier's own identity, authorization and artifact-reader references are
pinned too. Every lower control/worker continuity check independently compares
all four artifact digests and the verifier's complete authorization with the
original witnessed admitted approval; a supplied old digest cannot substitute
new execution policy bytes.

Quarantine is a deny-only local diagnostic retained conservatively across reset;
reset re-derives health from actual D/W and never repairs quarantined bytes.
That diagnostic cannot confer permission or establish the independent permanent
campaign-denial latch. Store field inventory records this exact reset treatment.

The configured `offline-local-reader` inspector repeats verification through the
pinned OCAV service and exposes independently verified prefix frames separately
from untrusted raw bytes. It has no actor, generation allocation, execution or
writer rights. Its binding models trusted local offline setup, not remote reader
authentication. Original survivor-transfer containment validates its witnessed
HISTORY frame and independent custodian record; a session cache has no role in
that proof. The fuller recovery-containment interface remains Checkpoint B work.

The original 85 constructor/restart sites remain individually tracked. Evidence
and containment tests and supervisor tests have been migrated with historical
reads, denial and uninterrupted controls. There are 92 current syntactic sites:
84 retained originals plus eight new sites. The second legacy restart in
`SupervisorTakeoverTests._operation_first` was consolidated into its retained
final historical recheck; both original ordering/history purposes remain.
All 85 original dispositions, exact old/current source and assertions, and new
sites are recorded in the authenticated review inventory with their passing
final-source test IDs. The supplementary independent fault-world fixture
factory is separately recorded; it is not a runtime restart route.

Fault tests cover eight commit stages across all eight transaction types, plus
reconciliation interruption for every transaction type, retained-history
corruption for every type, and revocation before initiation. Additional tests
cover post-initiation loss, result acknowledgement loss, exact non-executing
result reconciliation, independent registry loss, all eight positive latch
triggers, unavailable evidence without latching, and failed denial mirroring.
The focused and full runs record all 128 common cases (64 commit stages, 32 interrupted
exact reconciliations and 32 retained-history corruption cases), with no missing
cells. Acknowledgement/initiation/result stages are separately traced where
effects exist; ENTRY/INIT/SHUTDOWN/ADMIT have commit and exposure stages, not
worker creation. Every recorded subcase in the final full run passes.

The serialization memo caches only a pure calculation keyed by every immutable
envelope input; fresh retained D bytes and W receipts remain independently
compared. Historical evidence verification uses ephemeral read-only views with
no session, actor, grant, writer or dispatcher. Retained validated-completion
and closure dictionaries cannot grant authority independently of D/W evidence.

Recovery publication remains unavailable. Checkpoint B's remaining recovery,
containment, and closed-writer integration and Checkpoint C's recovery-publication
ports/continuation matrix have not begun. No live storage, Acer, model/provider,
CUDA/NVML, process/cgroup, reboot, deployment, or Git mutation is part of this work.

Temporary continuation evidence is under `/private/tmp/u04-checkpoint-a.pvjk78/`.
The fixed independent-review package is
`/private/tmp/u04-checkpoint-a.pvjk78/checkpoint-a-opus-review-20261003/`: exact
accepted Revision 6 bytes/hash, Chair authorization, Astra design, complete
tracked diff and all 13 source files, baseline red-to-green evidence, final
commands/results, authenticated field/site inventories, A01–A18 source/test
mapping, deterministic fault cases, and remaining B/C work. Package checksums
bind its contents. This is an implementation candidate package, not an Opus
acceptance. It has not been sent to Opus; staging, commit, push and B/C remain
outside this stop boundary.


## Checkpoint B implementation candidate (historical delivery)

The Checkpoint A paragraphs above are historical delivery notes. B implementation
starts from corrective commit `e5360a25dc01786302c7f22047c7d249379540ad`
and implements accepted Checkpoint B Architecture Revision 3. Independent review
and Human Chair acceptance of this candidate remain separate steps.

Healthy RECOVERY and TERMINAL actors may obtain an opaque current
`RecoveryWriterBinding` for the three closed RW evidence records. WAITING has no
generic RW right. Pending tails require A's exact reconciliation; quarantine or
unavailable W permits no new journal/object write, incarnation or establishment.
Original execution results retain the versioned RESULT path and cannot redispatch.
PUBLICATION_READBACK is reserved until a corresponding recovery publication
result can exist. RP has no registered boundary; Checkpoint C remains closed.

The trusted offline factory permanently reserves an original containment
identity, stores its exact descriptor and acknowledged ORIGIN delegation,
prepares the independent token-domain handle and C proof, then exposes one
nonserializable survivor endpoint. Pre-exposure loss cannot finish through
recovery. The independent lifecycle source must attest actual original controller
or required-custody terminal/invalidation facts; the original cleanup boundary
requires the captured current HISTORY actor and its exact ORIGIN failure Ref.
Public evidence and copied wrappers confer neither producer nor call authority.

C and the native token-domain port repeat endpoint, target, implementation and
trigger checks. Consumption and CLAIMED publish atomically; CLAIMED is never
retryable. Source containment, survivor containment and RELEASE share exclusion.
Containment seals the domain before its one physical initiation. The actual worker
permanently retains its first domain handle; loss of a factory index cannot bind
a replacement port or reopen RELEASE. Lost proof means UNKNOWN. Original cleanup
uses its retained admitted ownership binding even after fresh artifact verification
fails, preserving A cleanup. Survivor dispatch still requires fresh artifact
continuity. Original source joins retain the source's actual receipt and actor.
Deferred source/authority loss reporting and arbitrary control dispatch callbacks
run after C/port exclusion releases.

Survivor receipts are immutable existing CustodianReceipt observations restricted
to IN_PROGRESS, UNKNOWN and EXITED. Exit proves neither causation, reap nor residual
clearance. New observations require their actual live observer; archived evidence
can be reported after observer loss when independent provenance survives. Only the
actual original parent can produce a genuine ReapReceipt. Closed FAILURE_ENVELOPE
observations bind the original ORIGIN diagnostic and bounded exact Ref/Obj bytes
(at most 16 references per tuple and 64 KiB raw evidence).

This is a deterministic offline model. It creates no host processes, signals,
cgroups, model/provider requests or destination writes. Fixture manifests and
lifetime transitions model trusted services; they do not prove real OS handle
transfer, process authentication, host/power-loss durability or live admission.
The fixed Human Chair review package records exact source hashes, test/subcase
results, requirements, field/site inventories and remaining proof limits.

## Checkpoint C offline recovery publication

Trusted test setup may supply exact `OfflinePublicationDestination` instances to
`OfflineDurableStore(publication_destinations=...)`, together with the original
producer/normalizer instances. The normal publication path and RP path consult
that same independent destination. `ImmutablePublication.intent(source_proof=...)`
captures the actual originally produced EvidenceObject, not a caller's producer
name or coincidentally matching bytes. Existing history without that original
proof cannot acquire it through recovery. No destination is enabled by default.

`recovery_publication_binding` requires the exact current healthy RECOVERY or
TERMINAL actor, its allowed publisher identity, canonical admitted v2 approval,
the pinned verifier, and `exact_byte_recovery_authorized=True`. Its opaque binding
and grants are separate from normal publication, EXEC, RW and survivor authority.
Subject builders resolve the original witnessed publication INTENT transaction
and exact object/supplement rule. No copied identifier or historical grant can
become a current capability.

| RP action | Required permission |
|---|---|
| ENSURE_EXACT_OBJECT or CONTINUE_RESERVED_EXACT | WRITE_EXACT |
| ESTABLISH_DURABILITY | ESTABLISH_DURABILITY |
| VERIFY_EXACT_OBJECT or destination query/readback | VERIFY_EXACT |
| Any supplement action | The above permission plus PUBLISH_RECOVERY_SUPPLEMENT |

`perform_recovery_publication` is a compound operation that also queries and
persists its destination result, so it requires VERIFY_EXACT in addition to the
named operation's permission. `query_recovery_publication` obtains no effect
grant. Both write only the four closed R6 RP record types. Validation precedes
the RP intent; exact witnessed acceptance and independent acknowledgement precede
the lower-port claim. The lower port rechecks authority, all source/precondition
proofs and writer exclusion while sharing authorization exclusion with reset.

An independently absent key permits one exact create. A positively proven
original owned-empty reservation permits one full-byte continuation under the
same owner, intent and key. Empty intended bytes need no append. Exact existing
bytes need only missing durability and independent verification. Stable partial
bytes, wrong bytes and wrong owners are preserved. In-flight, CLAIMED or UNKNOWN
operations are query-only; missing registry entries never mean NOT_STARTED.
Only positively proven NOT_STARTED permits a replacement grant for the same
logical operation. Controller loss never resets destination claims or counts.

Verification requires actual independent exact readback, length/digest, object
durability, namespace durability and linked authenticated results. Receipts are
authenticated against the pinned destination's retained original observations;
a checksum or constructed receipt is insufficient. Verified history may be
returned without replay and remains historical evidence when a service is lost.

C replaces B's temporary blanket DESTINATION rejection with a semantic verifier.
A truthful obligation identifies an actual original destination and supported
condition, or a precisely proven authorization failure for that actual object.
Membership or an arbitrary target remains insufficient (B-1). PUBLICATION_READBACK
requires its corresponding committed VERIFIED RP result and exact independently
authenticated source/verifier evidence. Supplement publication uses only the R6
deterministic child key and preserves original evidence. UNKNOWN/in-flight
precedence prevents transient samples from becoming integrity-conflict triggers.
Only independently stable conflicting evidence can set the existing irreversible
PUBLICATION_INTEGRITY_CONFLICT latch; failed journal mirroring cannot clear it.

The journal and immutable proof objects are D; checkpoints, reservations,
generations and denial are W; original production proof, destination registry,
bytes, durability, claims, counts and archived receipts are C-domain facts.
Pinned service identities/references and synchronization are B (the trust root
remains I). RP bindings, grants, transient proof authorization, pending original
source bindings and eligible-grant indexes are V and are cleared on loss.
`STORE_FIELD_DOMAINS` and `DESTINATION_FIELD_DOMAINS` enumerate those fields.
Missing C evidence cannot be restored from D labels. Quarantine, unavailable W
and reconcilable tails permit no new RP effect or record; A's exact reconciliation
of an already reserved frame remains available under its existing conditions.

Publication neither cancels nor strengthens B survivor containment. It does not
prove original-parent reap, residual clearance, custody, execution, a resumed
measurement window, or a new closure. Successful publication cannot remove
consumption, taint or the W execution-denial latch.

C evidence is retained only in `logs/u04-checkpoint-c-20261007/`. The original R6
44-field and 85-site inventories remain separate historical populations from the
broader current A/B/C inventories. The candidate package identifies the final
source hashes, all changed paths, classified fields/routes, requirement mappings,
raw test/subcase results and deterministic fault observations. Intermediate logs
are not final-candidate proof. Final validation includes the complete adapter
suite and unchanged startup-characterization suite with bytecode disabled.

This model proves no real storage durability, protected provisioning/signing,
process/host fencing, reboot survival, provider behavior, GPU/CUDA/NVML operation,
or production readiness. No live recovery publication port is provided.
