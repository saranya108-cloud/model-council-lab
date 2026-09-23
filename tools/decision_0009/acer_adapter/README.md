# Decision 0009 Acer adapter — offline tranche

This directory implements the accepted Revision 4 contracts as deterministic
offline models. It grants no Acer, CUDA, NVML, process, cgroup, filesystem
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
binding. Creation additionally requires a short-lived store-active first-dispatch
grant bound to the current supervisor generation. The target must accept the
exact store-registered capability while the authorization lock still protects
the fence, and the capability must match the witnessed durable event, session,
target, operation, generation, and lifecycle predecessor. CAS or verification
failure yields no capability. A committed intent with a missing result remains
unresolved; it is not refunded or redispatched. A known result replays only in
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
closure candidates, validated completions, authoritative measurement window and
epoch, taint/custody prohibitions, and unresolved spawn/release intents.
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
