"""Persistent offline reducer, durable-store model, and effect authorization.

Everything in this module is an in-memory failure model.  No default live-effect
implementation exists.  Callers must inject offline dispatch functions.
"""

from dataclasses import asdict, dataclass, replace
from contextlib import contextmanager, nullcontext
from functools import lru_cache
import copy
import hashlib
import json
import threading

from .contracts import (
    ArtifactBinding, Authorization, BootActivation, ContractError, EffectCapability,
    FenceSession, HistoricalEffectReceipt, LocalAttemptEvidence, SlotCapability,
    MeasurementWindowTransition, OperationResultBinding, PublicationIdentity,
    PublicationOperationBinding, PublicationOperationGrant, SpawnToken, STATE_DOMAINS,
    CustodianReceipt, MEASUREMENT_WINDOWS, OUTSIDE_MEASURED_WINDOWS,
    PUBLICATION_OPERATIONS, WINDOW_OPERATION,
    parse_state,
    AUTHORIZATION_V2_SCHEMA, JournalReference, ImmutableObjectReference,
    U04EffectResultRecord, parse_effect_result_record, validate_recovery_record,
    RECOVERY_RECORD_FIELDS, closed_canonical_bytes, parse_closed_canonical,
    require_recovery_permission, validate_rp_record, RP_PUBLICATION_FIELDS,
    RP_RECORD_FIELDS, RP_GRANT_FIELDS,
)


class StoreError(RuntimeError):
    pass


class CASMismatch(StoreError):
    pass


class DuplicateEvent(StoreError):
    pass


class StaleRead(StoreError):
    pass


class Quarantined(StoreError):
    pass


class AuthorizationDenied(ContractError, StoreError):
    pass


class DispatchUncertain(RuntimeError):
    pass


class LostAcknowledgement(StoreError):
    def __init__(self, receipt):
        super().__init__("durable append acknowledgement lost")
        self.receipt = receipt


TRANSITION_PREDECESSORS = {
    "authorization": {"AUTHORIZATION_ADMITTED": (None,)},
    "campaign": {"CAMPAIGN_ADMITTED": (None,),
                 "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED": ("CAMPAIGN_ADMITTED",),
                 "CAMPAIGN_COMPLETE": ("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",),
                 "CAMPAIGN_CLOSED_FAILED": ("CAMPAIGN_ADMITTED",
                                            "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")},
    "boot": {"BOOT_CUSTODY_ESTABLISHED": (None,),
             "BOOT_CUSTODY_COMPLETE": ("BOOT_CUSTODY_ESTABLISHED",),
             "BOOT_CLOSURE_CANDIDATE_FINALIZED": ("BOOT_CUSTODY_COMPLETE",),
             "BOOT_COMPLETE": ("BOOT_CLOSURE_CANDIDATE_FINALIZED",),
             "BOOT_HANDOFF_PENDING": ("BOOT_COMPLETE",)},
    "attempt": {
        "SLOT_SPAWN_ELIGIBLE": (None, "ATTEMPT_COMPLETE"),
        "SPAWN_INTENT_PERSISTED": ("SLOT_SPAWN_ELIGIBLE",),
        "WORKER_CREATION_IN_PROGRESS": ("SPAWN_INTENT_PERSISTED",),
        "WORKER_IDENTITY_ESTABLISHED": ("WORKER_CREATION_IN_PROGRESS",),
        "WORKER_IDENTITY_DURABLY_RECORDED": ("WORKER_IDENTITY_ESTABLISHED",),
        "RELEASE_ELIGIBLE": ("WORKER_IDENTITY_DURABLY_RECORDED",),
        "RELEASE_INTENT": ("RELEASE_ELIGIBLE",),
        "RELEASED_OR_POSSIBLY_RELEASED": ("RELEASE_INTENT",),
        "CUDA_CALL_GATE_PASSED": ("RELEASED_OR_POSSIBLY_RELEASED",),
        "CLEANUP_REQUESTED": ("CUDA_CALL_GATE_PASSED",),
        "EXIT_OBSERVED": ("CLEANUP_REQUESTED",),
        "REAPING_PROVEN": ("EXIT_OBSERVED",),
        "RESIDUAL_CLEARANCE_PROVEN": ("REAPING_PROVEN",),
        "ATTEMPT_COMPLETE": ("RESIDUAL_CLEARANCE_PROVEN",),
    },
    "local_evidence": {
        "RAW_CAPTURED": (None, "ATTEMPT_EVIDENCE_FINALIZED"),
        "NORMALIZATION_BOUND": ("RAW_CAPTURED",),
        "IMMUTABLE_BYTES_STORED": ("NORMALIZATION_BOUND",),
        "READBACK_VERIFIED": ("IMMUTABLE_BYTES_STORED",),
        "ATTEMPT_EVIDENCE_FINALIZED": ("READBACK_VERIFIED",),
    },
}


_CONTROL_APPEND = object()
# Held only by the dedicated, evidence-validating supervisor operations below.
# The general ``append-transition`` surface never receives it.
_DEDICATED_AUTHORITY = object()

# Closed allowlist of transitions that remain available through the general
# ``append-transition`` operation.  They are custody observations that grant no
# successor, creation, completion, publication, window, or activation authority,
# and every one reconstructs as unresolved custody (containment only).  Each
# carries a closed payload bound to the current spawned attempt.
GENERIC_TRANSITION_SCHEMAS = {
    "WORKER_IDENTITY_ESTABLISHED": frozenset(("slot_id", "spawn_token", "host_pid",
                                              "start_ticks")),
    "WORKER_IDENTITY_DURABLY_RECORDED": frozenset(("slot_id", "spawn_token")),
    "RELEASE_ELIGIBLE": frozenset(("slot_id", "spawn_token")),
    "RELEASE_INTENT": frozenset(("slot_id", "spawn_token")),
    "RELEASED_OR_POSSIBLY_RELEASED": frozenset(("slot_id", "spawn_token")),
}
_GENERIC_INTEGER_FIELDS = frozenset(("host_pid", "start_ticks"))

_SPAWN_INTENT_FIELDS = frozenset((
    "spawn_token", "launch_spec_digest", "slot_id", "attempt_id", "boot_id",
    "campaign_id", "custodian_id", "supervisor_generation"))
_ATTEMPT_MANIFEST_FIELDS = (
    "slot_id", "attempt_id", "authorization_digest", "campaign_id",
    "boot_id", "boot_ordinal", "worker_ordinal", "thermal_state",
    "handle_order", "spawn_token", "launch_spec_digest", "custodian_id",
    "supervisor_generation", "raw_object_id", "raw_digest",
    "raw_readback_digest", "normalized_object_id", "normalized_digest",
    "normalized_readback_digest", "core_object_id", "core_digest",
    "core_readback_digest", "reap_receipt_id", "reap_receipt_digest",
    "residual_object_ids", "residual_sample_digests",
    "residual_sample_count",
)
_LIFECYCLE_TOKEN_FIELDS = frozenset(("slot_id", "spawn_token"))
_CANDIDATE_FIELDS = frozenset(("candidate_digest", "candidate_kind", "candidate_bytes",
                               "object_digests"))
_CLOSURE_FIELDS = frozenset(("candidate_digest", "candidate_kind",
                             "candidate_event_digest", "publication_receipt_id",
                             "publication_manifest", "closure_revision"))

# Every reserved transition is produced only by exactly one dedicated operation
# with an exact (closed) payload schema.
DEDICATED_OPERATIONS = {
    "admit-authorization": {"AUTHORIZATION_ADMITTED": frozenset()},
    "admit-campaign": {"CAMPAIGN_ADMITTED": frozenset(("boot_id", "activation_id"))},
    "establish-boot-custody": {"BOOT_CUSTODY_ESTABLISHED": frozenset((
        "boot_id", "custody_attestation"))},
    "complete-boot-custody": {"BOOT_CUSTODY_COMPLETE": frozenset((
        "extra_pre_spawn_baseline_ns", "custody_established_event_digest",
        "custody_attestation_digest"))},
    "make-slot-eligible": {"SLOT_SPAWN_ELIGIBLE": frozenset((
        "slot_id", "attempt_id", "boot_id", "spawn_token", "custodian_id",
        "predecessor_slot_id", "predecessor_completion_digest"))},
    "blocked-create": {"SPAWN_INTENT_PERSISTED": _SPAWN_INTENT_FIELDS},
    "record-worker-creation": {"WORKER_CREATION_IN_PROGRESS": frozenset((
        "slot_id", "spawn_token", "custodian_receipt"))},
    "worker-lifecycle": {
        "WORKER_IDENTITY_ESTABLISHED": frozenset(("slot_id", "spawn_token", "host_pid",
                                                  "start_ticks")),
        "WORKER_IDENTITY_DURABLY_RECORDED": _LIFECYCLE_TOKEN_FIELDS,
        "RELEASE_ELIGIBLE": _LIFECYCLE_TOKEN_FIELDS,
        "RELEASE_INTENT": _LIFECYCLE_TOKEN_FIELDS,
        "RELEASED_OR_POSSIBLY_RELEASED": _LIFECYCLE_TOKEN_FIELDS,
        "CUDA_CALL_GATE_PASSED": _LIFECYCLE_TOKEN_FIELDS,
        "CLEANUP_REQUESTED": _LIFECYCLE_TOKEN_FIELDS,
        "EXIT_OBSERVED": _LIFECYCLE_TOKEN_FIELDS,
        "REAPING_PROVEN": frozenset(("slot_id", "spawn_token", "reap_receipt_id")),
    },
    "persist-local-evidence": {
        "RAW_CAPTURED": frozenset(("slot_id", "attempt_id", "object_id", "object_digest",
                                   "declared_length", "retained_length", "truncated")),
        "NORMALIZATION_BOUND": frozenset(("slot_id", "attempt_id", "raw_object_id",
                                          "raw_digest", "normalized_object_id",
                                          "normalized_digest")),
        "IMMUTABLE_BYTES_STORED": frozenset(("slot_id", "attempt_id", "core_object_id",
                                             "core_digest")),
        "READBACK_VERIFIED": frozenset(("slot_id", "attempt_id", "raw_readback_digest",
                                        "normalized_readback_digest",
                                        "core_readback_digest")),
        "ATTEMPT_EVIDENCE_FINALIZED": frozenset((
            "slot_id", "attempt_id", "completion_digest", "raw_object_id",
            "normalized_object_id", "core_object_id")),
        "RESIDUAL_CLEARANCE_PROVEN": frozenset((
            "slot_id", "attempt_id", "spawn_token", "sample_digests", "empty_cgroup",
            "no_owned_descendants", "complete_gpu_coverage")),
    },
    "complete-attempt": {"ATTEMPT_COMPLETE": frozenset(
        _ATTEMPT_MANIFEST_FIELDS + ("completion_digest",))},
    "finalize-boot-closure-candidate": {"BOOT_CLOSURE_CANDIDATE_FINALIZED":
                                        _CANDIDATE_FIELDS | {"boot_id",
                                                             "attempt_completion_digests"}},
    "complete-boot": {"BOOT_COMPLETE": _CLOSURE_FIELDS | {"boot_id"}},
    "begin-boot-handoff": {"BOOT_HANDOFF_PENDING": frozenset()},
    "consume-boot-activation": {"BOOT_HANDOFF_PENDING": frozenset((
        "record_type", "activation_id", "activated_boot_ordinal", "observed_boot_id",
        "predecessor_closure_digest"))},
    "finalize-campaign-closure-candidate": {"CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED":
                                            _CANDIDATE_FIELDS | {"boot_closure_digests"}},
    "complete-campaign": {"CAMPAIGN_COMPLETE": _CLOSURE_FIELDS},
}

# Fields that only the authorization boundary writes.  A caller can never set
# them on a general event; a dedicated payload may name one only when its value
# equals the boundary's trusted value.
TRUSTED_EVENT_FIELDS = frozenset((
    "state", "effect_id", "state_domain", "session_id", "session_owner",
    "session_live", "fence_epoch", "boot_ordinal", "session_boot_ordinal",
    "supervisor_generation", "authorization_digest", "campaign_id", "target",
    "operation", "verification_id", "authorizes_execution", "dispatch_resolved",
    "consumption",
))

# Publication identity, operation binding, and measurement-window transition
# fields are defined once, by the closed contracts in ``contracts.py``.
_PUBLICATION_OPERATIONS = PUBLICATION_OPERATIONS
_BOOT_CUSTODY_ATTESTATION_FIELDS = frozenset((
    "attestation_id", "custodian_id", "watchdog_id", "observer_id", "store_identity",
    "authorization_digest", "campaign_id", "boot_id", "boot_ordinal",
    "supervisor_generation", "session_id", "fence_epoch", "custody_proof_digest",
    "observer_isolated", "watchdog_ready"))
_STICKY_HISTORY_STATES = frozenset(("TAINTED", "CUSTODY_UNCERTAIN", "ABORTED"))

_RESERVED_RECORD_TYPES = frozenset((
    "BOOT_ACTIVATION", "EFFECT_RESULT", "MEASUREMENT_WINDOW", "PUBLICATION",
))
_RESERVED_STATES = frozenset().union(*(
    states for domain, states in STATE_DOMAINS.items() if domain != "safety"
))


def _is_reserved_control_record(event):
    return (
        event.get("state") in _RESERVED_STATES or
        event.get("record_type") in _RESERVED_RECORD_TYPES or
        event.get("authorizes_execution") is True
    )


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise StoreError("event is not canonically serializable") from exc


def _sha(value):
    if type(value) is str:
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _publication_grant_attestation(binding):
    """Digest of one grant's complete canonical operation binding.

    The binding carries the full publication identity (intent ID, destination,
    object key, object digest, length) and every operation field, so a grant
    attests only the exact record it may produce."""
    if not isinstance(binding, PublicationOperationBinding):
        raise AuthorizationDenied("canonical publication operation binding required")
    return binding.attestation_digest()


@dataclass(frozen=True)
class WindowHistory:
    """The single validated measurement-window history of a store.

    ``window``/``window_epoch`` are the last validated transition; they
    authorize nothing unless the history is complete (no unprovenanced record,
    broken chain, pending operation, or orphaned result)."""
    window: object
    window_epoch: int
    epoch_windows: tuple
    accepted_event_ids: frozenset
    violations: tuple

    @property
    def complete(self):
        return not self.violations

    @property
    def authorizing_window(self):
        return self.window if self.complete else None

    def window_at(self, epoch):
        return dict(self.epoch_windows).get(epoch)


def _validated_window_history(store, authorization):
    """Validate every retained measurement-window record against the store's
    registered window operations and their bound results.

    Only a record that is the exact bound result of its registered operation,
    continues the validated chain, and belongs to this authorization is
    accepted.  The initial ``(None, 0) -> (OUTSIDE_MEASURED_WINDOWS, 1)``
    transition is accepted only when it was registered by fresh-store
    admission and follows the provenanced campaign admission."""
    violations = []
    window, epoch = None, 0
    epoch_windows = {}
    accepted = set()
    admitted = False
    for frame in store._durable:
        event = frame["event"]
        if (not admitted and event.get("state") == "CAMPAIGN_ADMITTED" and
                store.frame_has_provenance(frame)):
            admitted = True
        if event.get("record_type") != "MEASUREMENT_WINDOW":
            continue
        if not store.window_record_provenanced(frame):
            violations.append("unprovenanced-measurement-window")
            continue
        transition = MeasurementWindowTransition.from_record(store.identity, frame['event_id'], event)
        if (transition.authorization_digest != authorization.authorization_digest or
                transition.campaign_id != authorization.campaign_id or
                transition.previous_window != window or
                transition.previous_window_epoch != epoch or
                (transition.initial and not admitted)):
            violations.append("invalid-window-history")
            continue
        window, epoch = transition.window, transition.window_epoch
        epoch_windows[epoch] = window
        accepted.add(frame["event_id"])
    for operation_id in (sorted(store._window_operations) if store._authentication_service is None else ()):
        result = store._window_results.get(operation_id)
        if result is None:
            violations.append("pending-window-operation")
        elif result.event_id not in accepted:
            violations.append("window-result-without-validated-record")
    return WindowHistory(window, epoch, tuple(sorted(epoch_windows.items())),
                         frozenset(accepted), tuple(violations))


def _is_publication_record(event):
    """Only store-owned nonauthorizing publication records carry authority."""
    return (event.get("record_type") == "PUBLICATION" and
            event.get("authorizes_execution") is False and
            "effect_id" not in event and "state_domain" not in event and
            event.get("operation") in _PUBLICATION_OPERATIONS)


def _publication_frame_groups(store):
    groups = {}
    for index, frame in enumerate(store._durable):
        event = frame["event"]
        if _is_publication_record(event):
            envelope = frame.get('envelope')
            if type(envelope) is JournalEnvelope and json.loads(envelope.authority_fact_bytes).get('publication_grant', {}).get('phase') != 'RESULT':
                continue
            groups.setdefault((event.get("destination"), event.get("object_key")),
                              []).append((index, frame))
    return groups


def _validate_publication_frames(store, authorization, frames, *, require_verified,
                                window_history=None):
    """Validate one retained publication chain.

    Every record is decoded through the canonical publication operation
    binding: complete identity and chain-invariant binding must agree, operations
    follow RESERVED -> WRITTEN -> DURABLE -> VERIFIED order, every window epoch
    must be a validated outside window, and every record must be the exact
    bound result of its registered, consumed, single-use grant
    (``store.publication_record_provenanced``).  Object bytes and readback are
    verified independently below; neither kind of check substitutes for the
    other.
    """
    if type(frames) is not list or not frames:
        raise AuthorizationDenied("publication history absent")
    events = [frame["event"] for frame in frames]
    try:
        bindings = [PublicationOperationBinding.from_record(store.identity, event)
                    for event in events]
    except ContractError as exc:
        raise AuthorizationDenied(
            "publication record is not a canonical operation result") from exc
    operations = tuple(binding.operation for binding in bindings)
    if (operations != _PUBLICATION_OPERATIONS[:len(operations)] or
            (require_verified and operations != _PUBLICATION_OPERATIONS)):
        raise AuthorizationDenied("publication history is incomplete or contradictory")
    first_binding = bindings[0]
    first = events[0]
    if (any(binding.chain_invariant() != first_binding.chain_invariant()
            for binding in bindings) or
            first_binding.authorization_digest != authorization.authorization_digest or
            first_binding.campaign_id != authorization.campaign_id):
        raise AuthorizationDenied("publication history identity mismatch")
    history = (window_history if window_history is not None else
               _validated_window_history(store, authorization))
    for binding, frame in zip(bindings, frames):
        if history.window_at(binding.window_epoch) != OUTSIDE_MEASURED_WINDOWS:
            raise AuthorizationDenied("publication operation provenance mismatch")
        if not store.publication_record_provenanced(frame):
            raise AuthorizationDenied("publication record lacks its operation grant")
    source = store.read_object(first.get("source_object_id"), first.get("source_digest"))
    try:
        first_binding.identity.verify_source(source)
    except ContractError as exc:
        raise AuthorizationDenied("publication source evidence mismatch") from exc
    if len(events) >= 2 and type(events[1].get("reservation_id")) is not str:
        raise AuthorizationDenied("exclusive reservation evidence absent")
    if len(events) >= 3:
        written_event = events[2]
        written = store.read_object(written_event.get("written_object_id"),
                                    written_event.get("written_digest"))
        if (len(written) != written_event.get("written_length") or
                written_event.get("write_revision") != frames[2]["receipt"].revision):
            raise AuthorizationDenied("written publication object evidence mismatch")
    if len(events) >= 4:
        durable = events[3]
        if (durable.get("written_object_id") != events[2].get("written_object_id") or
                durable.get("written_digest") != events[2].get("written_digest") or
                durable.get("write_revision") != events[2].get("write_revision") or
                type(durable.get("durability_ack_id")) is not str):
            raise AuthorizationDenied("durability acknowledgement is foreign")
    if len(events) >= 5:
        verified = events[4]
        readback = store.read_object(verified.get("written_object_id"),
                                     verified.get("written_digest"))
        if (verified.get("durability_ack_id") != events[3].get("durability_ack_id") or
                verified.get("write_revision") != events[3].get("write_revision") or
                type(verified.get("verification_id")) is not str or
                verified.get("readback_digest") != _sha(readback) or
                readback != source):
            raise AuthorizationDenied("independent publication readback is invalid")
    return [copy.deepcopy(event) for event in events]


def _publication_bound_to_candidate(store, authorization, candidate_frame, entries,
                                    before_index):
    """True when a verified chain was produced for the exact finalized candidate.

    The chain must begin after the candidate finalization event, carry that
    event's digest (which covers the bound validated attempt or boot closure
    set) and identity on every record, and be verified before ``before_index``.
    """
    candidate_index = store.frame_index(candidate_frame["event_id"])
    candidate = candidate_frame["event"]
    candidate_digest = candidate_frame["receipt"].event_digest
    if candidate_index is None or not entries:
        return False
    if not candidate_index < entries[0][0] or not entries[-1][0] < before_index:
        return False
    for _, frame in entries:
        event = frame["event"]
        if (event.get("closure_candidate_event_digest") != candidate_digest or
                event.get("campaign_id") != candidate.get("campaign_id") or
                event.get("authorization_digest") !=
                candidate.get("authorization_digest")):
            return False
        if (candidate.get("state") == "BOOT_CLOSURE_CANDIDATE_FINALIZED" and
                (event.get("boot_ordinal") != candidate.get("boot_ordinal") or
                 event.get("boot_id") != candidate.get("boot_id"))):
            return False
    try:
        _validate_publication_frames(store, authorization,
                                     [frame for _, frame in entries],
                                     require_verified=True)
    except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
            ValueError):
        return False
    return True


def _closure_publication_proof(store, authorization, candidate_frame, manifest,
                               before_index):
    """Every manifest digest is published and verified for the exact candidate,
    after its finalization and before ``before_index``.  Digest equality alone
    never satisfies closure."""
    candidate = candidate_frame["event"]
    expected = sorted([candidate.get("candidate_digest"),
                       *(candidate.get("object_digests") or ())])
    if type(manifest) is not list or manifest != expected:
        raise AuthorizationDenied("closure publication manifest")
    groups = _publication_frame_groups(store)
    proof = []
    for digest_value in manifest:
        chain = next((entries for entries in groups.values()
                      if entries[0][1]["event"].get("object_digest") == digest_value and
                      _publication_bound_to_candidate(store, authorization,
                                                      candidate_frame, entries,
                                                      before_index)), None)
        if chain is None:
            raise AuthorizationDenied(
                "closure publication was not performed for the finalized candidate")
        proof.append(chain[-1][1]["receipt"].event_digest)
    return proof


def _boot_custody_attestation_digest(store, record, expected):
    """Validate custodian-issued custody evidence against the store's bound
    custodian registry and the exact identity in ``expected``."""
    if type(record) is not dict or set(record) != _BOOT_CUSTODY_ATTESTATION_FIELDS:
        raise AuthorizationDenied("closed custody attestation required")
    custodian = store.bound_custodian()
    lookup = getattr(custodian, "boot_custody_attestation", None)
    registered = (lookup(record["attestation_id"]) if callable(lookup) and
                  type(record["attestation_id"]) is str else None)
    as_record = getattr(registered, "record", None)
    if not callable(as_record) or _canonical(as_record()) != _canonical(record):
        raise AuthorizationDenied("custody evidence is not the custodian's attestation")
    if (record["custodian_id"] != custodian.identity or
            record["watchdog_id"] != custodian.watchdog_identity or
            record["store_identity"] != store.identity or
            record["observer_isolated"] is not True or
            record["watchdog_ready"] is not True or
            record["observer_id"] in (record["custodian_id"], record["watchdog_id"],
                                      expected["session_owner"]) or
            any(record[name] != expected[name] for name in (
                "authorization_digest", "campaign_id", "boot_id", "boot_ordinal",
                "supervisor_generation", "session_id", "fence_epoch"))):
        raise AuthorizationDenied("custody evidence identity")
    return _sha(_canonical(record))


def _boot_custody_proof(store, authorization, boot_ordinal, completion, completion_index=None):
    """Re-derive what retained boot custody records prove.

    ``BOOT_CUSTODY_COMPLETE`` must bind the unique provenanced
    ``BOOT_CUSTODY_ESTABLISHED`` record of the same boot and supervisor
    authority, whose custodian attestation is re-checked against the bound
    custodian registry and the admitted boot identity.
    """
    frames = [frame for frame in store.provenanced_frames(
                  "BOOT_CUSTODY_ESTABLISHED", "establish-boot-custody")
              if frame["event"].get("boot_ordinal") == boot_ordinal]
    if len(frames) != 1:
        raise AuthorizationDenied("unique provenanced custody establishment required")
    established = frames[0]
    event = established["event"]
    boot_id = store.boot_identity(boot_ordinal)
    if (boot_id is None or event.get("boot_id") != boot_id or
            event.get("authorization_digest") != authorization.authorization_digest or
            event.get("campaign_id") != authorization.campaign_id):
        raise AuthorizationDenied("custody establishment identity")
    expected = {name: event.get(name) for name in (
        "supervisor_generation", "session_id", "fence_epoch", "session_owner")}
    expected.update(authorization_digest=authorization.authorization_digest,
                    campaign_id=authorization.campaign_id, boot_id=boot_id,
                    boot_ordinal=boot_ordinal)
    attestation_digest = _boot_custody_attestation_digest(
        store, event.get("custody_attestation"), expected)
    if (completion.get("custody_established_event_digest") !=
            established["receipt"].event_digest or
            completion.get("custody_attestation_digest") != attestation_digest or
            completion.get("extra_pre_spawn_baseline_ns") != 0 or
            any(completion.get(name) != event.get(name) for name in (
                "boot_ordinal", "supervisor_generation", "session_id", "fence_epoch",
                "session_owner", "authorization_digest", "campaign_id"))):
        raise AuthorizationDenied("custody completion is not bound to its evidence")
    if (completion_index is not None and
            not store.frame_index(established["event_id"]) < completion_index):
        raise AuthorizationDenied("custody completion precedes its establishment")
    return {"boot_ordinal": boot_ordinal, "boot_id": boot_id,
            "custodian_id": event["custody_attestation"]["custodian_id"],
            "attestation_digest": attestation_digest,
            "established_event_digest": established["receipt"].event_digest}


def _boot_custody_evidence(store, authorization, operation, source_event, trusted):
    """Semantic evidence check at the custody-state producing boundary."""
    if operation == "establish-boot-custody":
        boot_id = store.boot_identity(trusted["boot_ordinal"])
        if boot_id is None or source_event["boot_id"] != boot_id:
            raise AuthorizationDenied("custody establishment boot identity")
        expected = {name: trusted[name] for name in (
            "authorization_digest", "campaign_id", "boot_ordinal",
            "supervisor_generation", "session_id", "fence_epoch", "session_owner")}
        expected["boot_id"] = boot_id
        _boot_custody_attestation_digest(store, source_event["custody_attestation"],
                                         expected)
        return None
    custodian = store.bound_custodian()
    if custodian is None or getattr(custodian, "alive", False) is not True:
        raise AuthorizationDenied("custodian watchdog is not ready")
    completion = dict(source_event)
    completion.update(trusted)
    return _boot_custody_proof(store, authorization, trusted["boot_ordinal"], completion)


@dataclass(frozen=True)
class AppendReceipt:
    store_identity: str
    revision: int
    event_id: str
    event_digest: str
    chain_digest: str
    fence_epoch: int
    witness_receipt: str
    durable: bool


_U04_BOUNDARIES = {name: object() for name in (
    "ENTRY", "INIT", "EXEC", "RESULT", "SHUTDOWN", "ADMIT", "DENY", "HISTORY", "RW", "RP",
)}
_U04_MODES = frozenset(("FRESH", "LIVE_PENDING", "LIVE", "RECOVERY", "WAITING", "TERMINAL",
                        "SHUTDOWN_ONLY", "EXITED"))
_U04_DENIAL_CODES = frozenset((
    "UNFINISHED_BOOT_LOSS", "UNPLANNED_HANDOFF_LOSS", "SHUTDOWN_PENDING_AT_LOSS",
    "INTERRUPTED_ADMISSION", "EXPLICIT_ABORT_OR_FAILURE", "PUBLICATION_INTEGRITY_CONFLICT",
    "DURABLE_HISTORY_CONTRADICTION", "CUSTODY_LOSS_PROVEN",
))

# All fourteen Revision 6 entries have one writer and one authority meaning.
# RW/RP entries are named here only to reject them throughout Checkpoint A.
_U04_RECORD_BOUNDARIES = {
    'SUPERVISOR_INCARNATION': ('ENTRY', 'CONTROL', False),
    'PLANNED_SHUTDOWN_COMMITTED': ('SHUTDOWN', 'CONTROL', False),
    'ACTIVATION_RESERVED': ('ADMIT', 'CONTROL', False),
    'ACTIVATION_ADMITTED': ('ADMIT', 'EXECUTION', True),
    'EFFECT_ACCEPTED': ('EXEC', 'EXECUTION', True),
    'EFFECT_RESULT': ('RESULT', 'EVIDENCE', False),
    'CAMPAIGN_EXECUTION_DENIED': ('DENY', 'DENIAL', False),
    'RECOVERY_ENTRY': ('RW', 'EVIDENCE', False),
    'RECOVERY_OBLIGATION': ('RW', 'EVIDENCE', False),
    'RECOVERY_SUPPLEMENT': ('RW', 'EVIDENCE', False),
    'RECOVERY_PUBLICATION_INTENT': ('RP', 'EVIDENCE', False),
    'RECOVERY_PUBLICATION_ACCEPTED': ('RP', 'EVIDENCE_RECOVERY', False),
    'RECOVERY_PUBLICATION_RESULT': ('RP', 'EVIDENCE', False),
    'RECOVERY_PUBLICATION_VERIFIED': ('RP', 'EVIDENCE', False),
}

# Every store field is explicitly classified. D bytes and W/C/I references
# survive reset; V indexes and handles are rebuilt or discarded, never retained
# as independent authority. B locks/service references confer no entitlement.
STORE_FIELD_DOMAINS = {
    "identity": "B", "witness": "B/W", "_custodian": "B/C",
    "_lock": "B", "_authorization_lock": "B", "authorization_lock": "B",
    "_durable": "D", "_objects": "D", "torn_tail": "D",
    "_receipts": "V/D", "_event_bytes": "V/D", "_volatile": "V",
    "_sessions": "V", "_effect_capabilities": "V/D", "_effect_status": "V/D",
    "_effect_results": "V/D", "_effect_acceptance_counts": "V/D",
    "_accepted_effects": "V/D", "_active_creation_grants": "V",
    "_invalidated_effects": "V/D", "_taint": "V/D/W", "_consumed": "V/D",
    "quarantined": "V", "containment_only": "V", "_execution_revoked": "V",
    "_publication_prohibited": "V", "_supervisor_generation": "V/W",
    "_supervisor_ready": "V", "_measurement_window": "V/D", "_window_epoch": "V/D",
    "_publication_grants": "V/D", "_consumed_publication_grants": "V/D",
    "_publication_grant_records": "V/D", "_publication_grant_sequence": "V/D",
    "_window_operations": "V/D", "_window_results": "V/D",
    "_initial_window_operations": "V/D", "_window_operation_sequence": "V/D",
    "_initialization_token": "V", "_slot_grants": "V",
    "_validated_completions": "V/D", "_validated_boot_closures": "V/D",
    "_validated_campaign_closure": "V/D", "_validated_boot_custody": "V/D",
    "_current_actor": "V", "_entry_mode": "V/D/W", "_health": "V/D/W",
    "_pending_reset": "V", "_authentication_service": "B/I",
    "_historical_producers": "V/D",
    "_acceptance_acks": "V",
    "_activation_authentication_service": "B/I",
    "_artifact_verifier": "B",
    "_current_reconciler": "V", "_recovery_writer": "V",
    "_publication_destinations": "B/C", "_rp_binding": "V", "_rp_grants": "V", "_rp_proofs": "V",
}

_STORE_AUTHORITY_GROUPS = {
    'durable authority': ('_durable',),
    'immutable provenance': ('identity', 'witness', '_custodian', '_objects',
        '_authentication_service', '_activation_authentication_service', '_artifact_verifier',
        '_publication_destinations'),
    'current volatile capability': ('_current_actor', '_current_reconciler', '_recovery_writer',
        '_rp_binding', '_rp_grants', '_rp_proofs'),
    'derived historical view': ('_receipts', '_event_bytes', '_effect_capabilities', '_effect_status',
        '_effect_results', '_effect_acceptance_counts', '_accepted_effects', '_invalidated_effects',
        '_taint', '_consumed', '_measurement_window', '_window_epoch', '_publication_grants',
        '_consumed_publication_grants', '_publication_grant_records', '_window_operations',
        '_window_results', '_initial_window_operations', '_slot_grants', '_validated_completions',
        '_validated_boot_closures', '_validated_campaign_closure', '_validated_boot_custody',
        '_historical_producers', '_sessions', '_acceptance_acks', '_active_creation_grants'),
    'volatile cache': ('_supervisor_generation', '_publication_grant_sequence',
                       '_window_operation_sequence', '_initialization_token'),
    'non-authorizing diagnostic state': ('_lock', '_authorization_lock', 'authorization_lock',
        'torn_tail', '_volatile', 'quarantined', 'containment_only', '_execution_revoked',
        '_publication_prohibited', '_supervisor_ready', '_entry_mode', '_health', '_pending_reset'),
}
STORE_FIELD_CLASSIFICATION = {
    name: {'domain': STORE_FIELD_DOMAINS[name], 'authority_class': category,
           'reset': ('preserve exact D bytes or pinned B/I/W/C service reference'
                     if name in ('identity', 'witness', '_custodian', '_objects', '_durable', 'torn_tail',
                                 '_authentication_service', '_activation_authentication_service',
                                 '_artifact_verifier', '_publication_destinations',
                                 '_lock', '_authorization_lock', 'authorization_lock') else
                     'discard; rebuild only validated history, never execution membership')}
    for category, names in _STORE_AUTHORITY_GROUPS.items() for name in names
}
if set(STORE_FIELD_CLASSIFICATION) != set(STORE_FIELD_DOMAINS):
    raise RuntimeError('every store field needs explicit authority/reset classification')


@dataclass(frozen=True, eq=False)
class RecoveryWriterBinding:
    """Current opaque RW registration. Copying fields never copies membership."""
    actor: object
    store_identity: str
    authorization_digest: str
    campaign_id: str
    generation: int
    incarnation_id: str
    session_id: str
    fence: int
    registry: tuple
    token: object


@dataclass(frozen=True, eq=False)
class RecoveryPublicationBinding:
    actor: object
    authorization: object
    token: object


@dataclass(frozen=True, eq=False)
class RecoveryPublicationGrant:
    """Opaque store registration; canonical bytes contain only R6 G fields."""
    binding: RecoveryPublicationBinding
    canonical_bytes: bytes
    token: object


@dataclass(frozen=True, eq=False)
class IncarnationActor:
    """Opaque volatile registration. IDs alone cannot reproduce membership."""
    store_identity: str
    authorization_digest: str
    campaign_id: str
    generation: int
    incarnation_id: str
    session_id: str
    owner_identity: str
    fence: int
    mode: str
    token: object
    execution_session: object = None

    @property
    def execution_live(self):
        return self.mode == "LIVE"

    def producer(self):
        return {"generation": self.generation, "incarnation_id": self.incarnation_id,
                "session_id": self.session_id, "fence": self.fence,
                "owner_identity": self.owner_identity, "mode": self.mode}


def _u04_canonical(value):
    def check(item):
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) in (tuple, list):
            for child in item:
                check(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                check(child)
            return
        raise StoreError("closed canonical transaction value required")
    check(value)
    return _canonical(value)


@dataclass(frozen=True)
class JournalEnvelope:
    schema_version: str
    transaction_id: str
    revision: int
    predecessor_revision: int
    predecessor_hash: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    producer_bytes: bytes
    boundary: str
    authority_class: str
    payload_bytes: bytes
    payload_digest: str
    authority_fact_bytes: bytes

    def record(self):
        return {"schema_version": self.schema_version, "transaction_id": self.transaction_id,
                "revision": self.revision, "predecessor_revision": self.predecessor_revision,
                "predecessor_hash": self.predecessor_hash, "store_identity": self.store_identity,
                "authorization_digest": self.authorization_digest, "campaign_id": self.campaign_id,
                "producer": json.loads(self.producer_bytes), "boundary": self.boundary,
                "authority_class": self.authority_class, "payload": json.loads(self.payload_bytes),
                "payload_digest": self.payload_digest,
                "authority_facts": json.loads(self.authority_fact_bytes)}

    def canonical_bytes(self):
        # Pure computation cache keyed by every immutable input byte/value.
        # Revision or mutable frame identity alone is never a cache key.
        return _journal_envelope_bytes((self.schema_version, self.transaction_id,
            self.revision, self.predecessor_revision, self.predecessor_hash,
            self.store_identity, self.authorization_digest, self.campaign_id,
            self.producer_bytes, self.boundary, self.authority_class,
            self.payload_bytes, self.payload_digest, self.authority_fact_bytes))

    @property
    def frame_digest(self):
        return _sha(bytes.fromhex(self.predecessor_hash) + self.canonical_bytes())


@lru_cache(maxsize=2048)
def _journal_envelope_bytes(immutable_fields):
    """V-domain derived computation; it contains no issuance or membership."""
    return _u04_canonical(JournalEnvelope(*immutable_fields).record())


@dataclass(frozen=True)
class WitnessReservation:
    store_identity: str
    transaction_id: str
    revision: int
    frame_digest: str
    authorization_digest: str
    campaign_id: str
    initiator_bytes: bytes
    boundary: str


@dataclass(frozen=True)
class WitnessCommit:
    reservation: WitnessReservation
    completion_mode: str
    completer_bytes: bytes
    frozen_frontier: int
    receipt_id: str


@dataclass(frozen=True, eq=False)
class ReconciliationBinding:
    reservation: WitnessReservation
    generation: int
    incarnation_id: str
    session_id: str
    fence: int
    frozen_frontier: int
    token: object


class TransactionPending(StoreError):
    """Exact identity retained; outcome is pending/unknown, never retry permission."""
    def __init__(self, transaction_id, stage, status="PENDING"):
        super().__init__("%s transaction %s at %s" % (status, transaction_id, stage))
        self.transaction_id, self.stage, self.status = transaction_id, stage, status


class OfflineWitness:
    """Independent high-water fake; it is never reconstructed from the store."""

    def __init__(self, identity):
        self.identity = identity
        self.high_revision = 0
        self.high_chain_digest = "0" * 64
        self.high_fence = 0
        self.current_fence = 0
        self.pending = {}
        self.quarantined = False
        self.available = True
        self._lock = threading.Lock()
        self.high_generation = 0
        self._store_identity = None
        self._actors = {}
        self._frontiers = {}
        self._commits = {}
        self._reconcilers = {}
        self._denials = {}
        self._custodian = None
        self._store = None
        self._acknowledged = {}

    def allocate_generation(self, store_identity, fault=None):
        with self._allocation_context():
            self._check_bound_store_health()
            with self._lock:
                if not self.available or self.quarantined:
                    raise Quarantined("witness generation unavailable")
                if (self._store_identity not in (None, store_identity) or
                        self._store is not None and store_identity != self._store.identity):
                    raise AuthorizationDenied("witness belongs to another store")
                self._store_identity = store_identity
                self.high_generation += 1
                allocated = self.high_generation
                if fault == "lost_ack":
                    raise TransactionPending("generation-%d" % allocated, "allocation", "UNKNOWN")
                return allocated

    def register_actor(self, actor, *, _entry=None):
        with self._lock:
            if (_entry is not _U04_BOUNDARIES["ENTRY"] or
                    type(actor) is not IncarnationActor or actor.mode == "LIVE" or
                    actor.store_identity != self._store_identity or
                    actor.generation != self.high_generation or actor.mode not in _U04_MODES or
                    actor.fence != self.current_fence or actor.token is None):
                raise AuthorizationDenied("witness actor binding")
            if actor.store_identity in self._actors:
                raise AuthorizationDenied("outgoing actor must be fenced before registration")
            self._actors[actor.store_identity] = actor

    def authenticate(self, actor, store_identity, boundary):
        if (not self.available or self.quarantined or type(actor) is not IncarnationActor or
                self._store is None or self._store._current_actor is not actor or
                self._actors.get(store_identity) is not actor or
                actor.generation != self.high_generation or actor.fence != self.current_fence):
            raise AuthorizationDenied("captured witness actor is not current")
        modes = {
            "ENTRY": {"FRESH", "LIVE_PENDING", "RECOVERY", "WAITING", "TERMINAL"},
            "INIT": {"FRESH"}, "EXEC": {"LIVE"},
            "RESULT": {"LIVE", "RECOVERY", "TERMINAL"},
            "SHUTDOWN": {"SHUTDOWN_ONLY"}, "ADMIT": {"WAITING", "LIVE_PENDING"},
            "DENY": {"LIVE", "RECOVERY", "WAITING", "TERMINAL", "FRESH", "LIVE_PENDING"},
            "HISTORY": {"LIVE", "FRESH", "LIVE_PENDING", "RECOVERY", "WAITING", "TERMINAL"},
            "RW": {"RECOVERY", "TERMINAL"},
            "RP": {"RECOVERY", "TERMINAL"},
        }
        if actor.mode not in modes.get(boundary, set()):
            raise AuthorizationDenied("witness boundary/mode mismatch")
        if boundary in ("EXEC", "INIT", "ADMIT") and self.denial(actor) is not None:
            raise AuthorizationDenied("irreversible campaign execution denial")
        return actor

    def freeze_actor(self, actor):
        with self._lock:
            if self._actors.get(actor.store_identity) is actor:
                if not self.available:
                    # Volatile store revocation already prevents every dependent
                    # operation; no frontier is invented when W is unreadable.
                    raise TransactionPending(actor.incarnation_id, "fencing", "UNKNOWN")
                self._frontiers[(actor.store_identity, actor.generation, actor.incarnation_id)] = (
                    self.high_revision, self.high_chain_digest)
                del self._actors[actor.store_identity]
                self._acknowledged = {key: value for key, value in self._acknowledged.items()
                                      if value.store_identity != actor.store_identity}
            return self._frontiers.get((actor.store_identity, actor.generation, actor.incarnation_id))

    def reserve_frame(self, actor, envelope, boundary_token):
        # Keep the core local: there is no second callable lower reservation port
        # that can omit the B semantic check or reverse A -> journal -> W locks.
        def reserve_exact():
            with self._lock:
                self.authenticate(actor, envelope.store_identity, envelope.boundary)
                if _U04_BOUNDARIES.get(envelope.boundary) is not boundary_token:
                    raise AuthorizationDenied("dedicated witness boundary required")
                if (envelope.schema_version != "u04-transaction/v1" or
                        type(envelope.transaction_id) is not str or not envelope.transaction_id or
                        envelope.transaction_id in self._commits or
                        envelope.authorization_digest != actor.authorization_digest or
                        envelope.campaign_id != actor.campaign_id or
                        envelope.producer_bytes != _u04_canonical(actor.producer()) or
                        envelope.predecessor_revision != self.high_revision or
                        envelope.predecessor_hash != self.high_chain_digest or
                        envelope.revision != self.high_revision + 1 or self.pending):
                    raise AuthorizationDenied("exact witnessed reservation binding")
                reservation = WitnessReservation(envelope.store_identity, envelope.transaction_id,
                    envelope.revision, envelope.frame_digest, envelope.authorization_digest,
                    envelope.campaign_id, envelope.producer_bytes, envelope.boundary)
                self.pending[envelope.revision] = reservation
                return reservation

        if envelope.boundary in ('RW', 'RP'):
            if self._store is None:
                raise AuthorizationDenied('RW requires its bound original store')
            with self._store.authorization_lock, self._store._lock:
                if envelope.boundary == 'RP':
                    self._store._validate_rp_envelope(actor, envelope)
                else:
                    self._store._validate_rw_envelope(actor, envelope)
                return reserve_exact()
        return reserve_exact()

    def commit_frame(self, actor, envelope, reservation, boundary_token, readback_bytes):
        with self._lock:
            self.authenticate(actor, envelope.store_identity, envelope.boundary)
            if (_U04_BOUNDARIES.get(envelope.boundary) is not boundary_token or
                    self.pending.get(envelope.revision) != reservation or
                    reservation.transaction_id != envelope.transaction_id or
                    reservation.initiator_bytes != _u04_canonical(actor.producer()) or
                    reservation.frame_digest != envelope.frame_digest or
                    readback_bytes != envelope.canonical_bytes() or
                    not self._retained_frame_matches(envelope, readback_bytes)):
                raise AuthorizationDenied("witness commit differs from exact validated reservation")
            result = self._commit_reserved(reservation, "ORIGIN", envelope.producer_bytes,
                                           self.high_revision)
            if envelope.boundary == 'SHUTDOWN':
                # W commit is logical exit, within the same exclusion boundary.
                self._frontiers[(actor.store_identity, actor.generation, actor.incarnation_id)] = (
                    self.high_revision, self.high_chain_digest)
                del self._actors[actor.store_identity]
                self._acknowledged = {key: value for key, value in self._acknowledged.items()
                                      if value.store_identity != actor.store_identity}
            return result

    def _retained_frame_matches(self, envelope, raw):
        """W reads its pinned actual D source, independently of caller bytes."""
        if self._store is None or not 1 <= envelope.revision <= len(self._store._durable):
            return False
        retained = self._store._durable[envelope.revision - 1]
        return (retained.get('envelope') == envelope and retained.get('bytes') == raw and
                self._store._u04_frame_valid(retained))

    def acknowledge_frame(self, actor, receipt, *, _boundary):
        with self._lock:
            committed = self._commits.get(receipt.event_id)
            if (committed is None or _U04_BOUNDARIES.get(committed.reservation.boundary) is not _boundary or
                    self._actors.get(actor.store_identity) is not actor or
                    receipt.witness_receipt != committed.receipt_id or receipt.revision != committed.reservation.revision or
                    committed.completion_mode != 'ORIGIN'):
                raise AuthorizationDenied('current original acknowledgement registration required')
            frame = self._store._durable[receipt.revision - 1]
            if (frame['receipt'] != receipt or not self._store._u04_frame_valid(frame) or
                    frame['envelope'].frame_digest != committed.reservation.frame_digest or
                    frame['envelope'].producer_bytes != _u04_canonical(actor.producer())):
                raise AuthorizationDenied('acknowledgement must match independently retained original transaction')
            self._acknowledged[receipt.event_id] = actor

    def acknowledged_current(self, actor, event_id):
        with self._lock:
            return (actor is not None and self.available and not self.quarantined and self._actors.get(actor.store_identity) is actor and
                    actor.generation == self.high_generation and actor.fence == self.current_fence and
                    self._acknowledged.get(event_id) is actor)

    def _commit_reserved(self, reservation, mode, completer_bytes, frontier):
        receipt_id = "witness-u04-" + _sha(_u04_canonical({
            "witness": self.identity, "transaction_id": reservation.transaction_id,
            "revision": reservation.revision, "frame_digest": reservation.frame_digest,
            "initiator": json.loads(reservation.initiator_bytes),
            "completion_mode": mode, "completer": json.loads(completer_bytes),
            "frozen_frontier": frontier}))
        commit = WitnessCommit(reservation, mode, completer_bytes, frontier, receipt_id)
        self._commits[reservation.transaction_id] = commit
        self.pending.pop(reservation.revision)
        self.high_revision = reservation.revision
        self.high_chain_digest = reservation.frame_digest
        return commit

    def query_transaction(self, transaction_id):
        if not self.available:
            raise TransactionPending(transaction_id, "query", "UNKNOWN")
        committed = self._commits.get(transaction_id)
        if committed is not None:
            return "COMMITTED", committed
        matches = [r for r in self.pending.values() if isinstance(r, WitnessReservation)
                   and r.transaction_id == transaction_id]
        return ("PENDING", matches[0]) if len(matches) == 1 else ("ABSENT", None)

    def issue_reconciler(self, envelope):
        """One exact prior reservation; no writer or execution entitlement."""
        with self._allocation_context():
            if self._store is None or self._store._authentication_service is None:
                raise AuthorizationDenied("bound authenticated reconciliation store required")
            with self._store._lock:
                status, _ = self._store._validate_reconciliation_frame(envelope)
                if status != "PENDING":
                    raise AuthorizationDenied("exact pending reconciliation tail required")
                with self._lock:
                    reservation = self.pending.get(envelope.revision)
                    producer = json.loads(envelope.producer_bytes)
                    frontier = self._frontiers.get((envelope.store_identity, producer["generation"],
                                                   producer["incarnation_id"]))
                    if (not self.available or self.quarantined or
                            type(reservation) is not WitnessReservation or frontier is None or
                            reservation.transaction_id != envelope.transaction_id or
                            reservation.frame_digest != envelope.frame_digest or
                            reservation.initiator_bytes != envelope.producer_bytes or
                            envelope.predecessor_revision != self.high_revision or
                            envelope.predecessor_hash != self.high_chain_digest):
                        raise AuthorizationDenied("unchanged fenced reservation required")
                    self.high_generation += 1
                    self.high_fence += 1
                    self.current_fence = self.high_fence
                    generation = self.high_generation
                    binding = ReconciliationBinding(reservation, generation,
                        "%s-reconciliation-%d" % (envelope.store_identity, generation),
                        "%s-reader-%d" % (envelope.store_identity, generation), self.current_fence,
                        frontier[0], object())
                    self._reconcilers[envelope.transaction_id] = binding
                    return binding

    def reconcile_frame(self, binding, envelope, retained_bytes):
        with self._allocation_context():
            if self._store is None or self._store._authentication_service is None:
                raise AuthorizationDenied("bound authenticated reconciliation store required")
            with self._store._lock:
                status, _ = self._store._validate_reconciliation_frame(envelope)
                if status != "PENDING":
                    raise AuthorizationDenied("exact pending reconciliation tail required")
                with self._lock:
                    if (not self.available or self.quarantined or
                            type(binding) is not ReconciliationBinding or
                            self._store is None or self._store._current_reconciler is not binding or
                            self._reconcilers.get(envelope.transaction_id) is not binding or
                            binding.generation != self.high_generation or
                            binding.fence != self.current_fence or
                            self.pending.get(envelope.revision) != binding.reservation or
                            binding.reservation.frame_digest != envelope.frame_digest or
                            binding.reservation.initiator_bytes != envelope.producer_bytes or
                            retained_bytes != envelope.canonical_bytes() or
                            not self._retained_frame_matches(envelope, retained_bytes)):
                        raise AuthorizationDenied("exact non-executing reconciliation binding required")
                    completer = _u04_canonical({"generation": binding.generation,
                        "incarnation_id": binding.incarnation_id, "session_id": binding.session_id,
                        "fence": binding.fence, "mode": "RECOVERY_RECONCILE"})
                    result = self._commit_reserved(binding.reservation, "RECOVERY_RECONCILE",
                                                   completer, binding.frozen_frontier)
                    del self._reconcilers[envelope.transaction_id]
                    return result

    def deny_pending_reconciliation(self, binding, envelope, prefix):
        """A fenced exact reservation plus complete frontier proves loss."""
        with self._lock:
            if (not self.available or self._reconcilers.get(envelope.transaction_id) is not binding or
                    binding.generation != self.high_generation or binding.fence != self.current_fence or
                    self.pending.get(envelope.revision) != binding.reservation or
                    len(prefix) != self.high_revision or envelope.predecessor_hash != self.high_chain_digest):
                raise AuthorizationDenied('exact readable loss frontier required before reconciliation')
            previous = '0' * 64
            for revision, old in enumerate(prefix, 1):
                commit = self._commits.get(old.transaction_id)
                if (old.revision != revision or old.predecessor_hash != previous or commit is None or
                        commit.reservation.frame_digest != old.frame_digest):
                    raise AuthorizationDenied('complete authenticated reconciliation prefix required')
                previous = old.frame_digest
            if previous != self.high_chain_digest:
                raise AuthorizationDenied('unknown loss frontier cannot establish denial')
            if envelope.boundary == 'SHUTDOWN':
                code = 'SHUTDOWN_PENDING_AT_LOSS'
            elif envelope.boundary in ('ADMIT', 'INIT'):
                code = 'INTERRUPTED_ADMISSION'
            elif envelope.boundary in ('EXEC', 'RESULT'):
                # Committed terminal closure excludes boot loss. A pending
                # closure is not part of this authenticated committed prefix.
                if any(json.loads(old.payload_bytes).get('state') == 'CAMPAIGN_COMPLETE'
                       for old in prefix):
                    return None
                code = 'UNFINISHED_BOOT_LOSS'
            else:
                return None
            key = (envelope.store_identity, envelope.authorization_digest, envelope.campaign_id)
            self._denials.setdefault(key, (code, tuple([p.transaction_id for p in prefix] +
                                                       [envelope.transaction_id])))
            return self._denials[key]

    def denial(self, actor):
        return self._denials.get((actor.store_identity, actor.authorization_digest, actor.campaign_id))

    def deny_durable_digest_conflict(self, store, *, _boundary):
        """The pinned D readback source positively contradicts a committed W digest.

        Read failures and absence do not establish this predicate. No actor,
        generation, journal record, or execution capability is created here.
        """
        with self._lock:
            if (_boundary is not _U04_BOUNDARIES['DENY'] or self._store is not store or
                    not self.available or self.quarantined):
                raise AuthorizationDenied('pinned readable contradiction verifier required')
            for frame in store._durable:
                envelope = frame.get('envelope')
                if type(envelope) is not JournalEnvelope:
                    continue
                committed = self._commits.get(envelope.transaction_id)
                if committed is None or committed.reservation.revision != envelope.revision:
                    continue
                try:
                    raw = store._independent_frame_readback(envelope.revision)
                    if type(raw) is not bytes:
                        continue
                    retained = json.loads(raw)
                    observed = _sha(bytes.fromhex(retained['predecessor_hash']) + raw)
                except (OSError, ValueError, KeyError, TypeError, IndexError):
                    continue
                reservation = committed.reservation
                if observed != reservation.frame_digest:
                    key = (reservation.store_identity, reservation.authorization_digest, reservation.campaign_id)
                    self._denials.setdefault(key, ('DURABLE_HISTORY_CONTRADICTION', (reservation.transaction_id,)))
                    return self._denials[key]
            raise AuthorizationDenied('no positive independently observed committed digest conflict')

    def change_mode(self, actor, mode, *, _boundary, execution_session=None):
        """Replace current membership; historical producer bytes never change."""
        with self._lock:
            boundary = next((name for name, token in _U04_BOUNDARIES.items() if token is _boundary), None)
            self.authenticate(actor, actor.store_identity, boundary)
            permitted = {('INIT', 'FRESH', 'LIVE'),
                         ('EXEC', 'LIVE', 'SHUTDOWN_ONLY'),
                         ('ADMIT', 'LIVE_PENDING', 'LIVE')}
            if (boundary, actor.mode, mode) not in permitted:
                raise AuthorizationDenied('mode transition requires dedicated admission/exit')
            required = {('INIT', 'LIVE'): ('MEASUREMENT_WINDOW', None),
                        ('ADMIT', 'LIVE'): ('ACTIVATION_ADMITTED', None),
                        ('EXEC', 'SHUTDOWN_ONLY'): (None, 'BOOT_HANDOFF_PENDING')}[(boundary, mode)]
            frames = [f for f in self._store._durable if
                (required[0] is None or f['event'].get('record_type') == required[0]) and
                (required[1] is None or f['event'].get('state') == required[1]) and
                type(f.get('envelope')) is JournalEnvelope and f['envelope'].boundary == boundary and
                f['envelope'].producer_bytes == _u04_canonical(actor.producer())]
            if not frames or self._acknowledged.get(frames[-1]['event_id']) is not actor:
                raise AuthorizationDenied('mode exposure requires acknowledged original transaction in this incarnation')
            frame = frames[-1]
            committed = self._commits.get(frame['event_id'])
            if (committed is None or not self._store._u04_frame_valid(frame) or
                    frame['envelope'].frame_digest != committed.reservation.frame_digest or
                    frame['receipt'].witness_receipt != committed.receipt_id or
                    committed.completion_mode != 'ORIGIN'):
                raise AuthorizationDenied('mode exposure requires the independently confirmed original frame')
            if mode == 'LIVE':
                ordinal = 1 if boundary == 'INIT' else frames[-1]['event']['next_boot_ordinal']
                if execution_session != FenceSession(actor.fence, actor.session_id, actor.owner_identity, ordinal, True):
                    raise AuthorizationDenied('admission must expose the exact fresh session')
            changed = replace(actor, mode=mode, execution_session=execution_session)
            self._actors[actor.store_identity] = changed
            return changed

    def deny_observed_rollback(self, store, before, *, _boundary):
        """Verify the offline storage fault primitive's observed D rollback.

        Unlike a missing tail, this supplies both the previously independently
        verified complete stream and the exact shorter stream produced by the
        pinned storage primitive. It creates no checkpoint or replacement bytes.
        """
        with self._lock:
            if (self._store is not store or _boundary is not _U04_BOUNDARIES['DENY'] or
                    not self.available or self.quarantined or type(before) is not tuple or
                    len(before) != self.high_revision or len(store._durable) >= len(before)):
                raise AuthorizationDenied('independently observed complete rollback required')
            previous = '0' * 64
            for revision, frame in enumerate(before, 1):
                envelope = frame.get('envelope')
                commit = self._commits.get(frame.get('event_id'))
                if (type(envelope) is not JournalEnvelope or commit is None or
                        not store._u04_frame_valid(frame) or envelope.revision != revision or
                        envelope.predecessor_hash != previous or
                        commit.reservation.frame_digest != envelope.frame_digest or
                        commit.reservation.initiator_bytes != envelope.producer_bytes or
                        frame['receipt'].witness_receipt != commit.receipt_id):
                    raise AuthorizationDenied('rollback source lacks independently committed provenance')
                previous = envelope.frame_digest
            if previous != self.high_chain_digest:
                raise AuthorizationDenied('rollback source is not the complete original frontier')
            for revision, frame in enumerate(store._durable, 1):
                if store._independent_frame_readback(revision) != before[revision - 1]['bytes']:
                    raise AuthorizationDenied('rollback result differs from the observed exact prefix')
            for frame in before[len(store._durable):]:
                envelope = frame['envelope']
                key = (envelope.store_identity, envelope.authorization_digest, envelope.campaign_id)
                self._denials.setdefault(key, ('DURABLE_HISTORY_CONTRADICTION', (envelope.transaction_id,)))


    def advance_admission_fence(self, actor, reservation, fence):
        with self._lock:
            committed = self._commits.get(reservation.event_id)
            if (self._actors.get(actor.store_identity) is not actor or actor.mode != 'LIVE_PENDING' or
                    committed is None or committed.reservation.boundary != 'ADMIT' or
                    fence != self.current_fence or fence <= actor.fence):
                raise AuthorizationDenied('fence advance requires exact reserved admission')
            changed = replace(actor, fence=fence)
            self._actors[actor.store_identity] = changed
            return changed

    def deny_campaign(self, actor, code, envelopes, *, _boundary):
        with self._allocation_context(), self._lock:
            self.authenticate(actor, actor.store_identity, 'DENY')
            return self._deny_from_complete_frontier(actor, code, envelopes, _boundary=_boundary)

    def deny_frozen_campaign(self, store, actor, code, envelopes, *, _boundary):
        """A negative-only verifier of the original frozen producer's loss."""
        with self._lock:
            key = (actor.store_identity, actor.generation, actor.incarnation_id)
            if (self._store is not store or store._current_actor is not None or
                    not self.available or self.quarantined or key not in self._frontiers or
                    actor.generation != self.high_generation or actor.fence != self.current_fence or
                    not any(all(json.loads(commit.reservation.initiator_bytes).get(name) == value
                                for name, value in actor.producer().items() if name not in ('mode', 'fence')) and
                            json.loads(commit.reservation.initiator_bytes)['fence'] <= actor.fence
                            for commit in self._commits.values())):
                raise AuthorizationDenied('independent complete frozen original producer proof required')
            return self._deny_from_complete_frontier(actor, code, envelopes, _boundary=_boundary)

    def _deny_from_complete_frontier(self, actor, code, envelopes, *, _boundary):
        if _boundary is not _U04_BOUNDARIES['DENY'] or code not in _U04_DENIAL_CODES:
            raise AuthorizationDenied('closed positive-evidence denial boundary')
        previous = '0' * 64
        for revision, envelope in enumerate(envelopes, 1):
            committed = self._commits.get(envelope.transaction_id)
            if (type(envelope) is not JournalEnvelope or envelope.revision != revision or
                    envelope.predecessor_hash != previous or committed is None or
                    committed.reservation.frame_digest != envelope.frame_digest or
                    envelope.store_identity != actor.store_identity or
                    envelope.authorization_digest != actor.authorization_digest):
                raise AuthorizationDenied('complete authenticated denial frontier required')
            previous = envelope.frame_digest
        if len(envelopes) != self.high_revision or previous != self.high_chain_digest:
            raise AuthorizationDenied('incomplete denial frontier')
        events = [json.loads(e.payload_bytes) for e in envelopes]
        # An earlier boot's valid shutdown does not excuse loss in a
        # later admitted boot. Evaluate the latest activation segment.
        starts = [i for i, e in enumerate(events) if e.get('state') == 'CAMPAIGN_ADMITTED' or
                  e.get('record_type') == 'ACTIVATION_RESERVED']
        start = starts[-1] if starts else 0
        segment = events[start:]
        segment_envelopes = envelopes[start:]
        lost = [e for e in segment_envelopes if (
            e.store_identity, json.loads(e.producer_bytes)['generation'],
            json.loads(e.producer_bytes)['incarnation_id']) in self._frontiers]
        shutdowns = [e for e in segment_envelopes if json.loads(e.payload_bytes).get('record_type') ==
                     'PLANNED_SHUTDOWN_COMMITTED' and self._commits[e.transaction_id].completion_mode == 'ORIGIN']
        complete = not self.pending
        terminal = any(e.get('state') == 'CAMPAIGN_COMPLETE' for e in segment)
        if code == 'UNFINISHED_BOOT_LOSS':
            active = any(e.get('state') == 'CAMPAIGN_ADMITTED' or
                         e.get('record_type') == 'ACTIVATION_ADMITTED' for e in segment)
            valid = complete and bool(lost) and active and not shutdowns and not terminal and not any(
                e.get('state') == 'BOOT_HANDOFF_PENDING' for e in segment)
        elif code == 'UNPLANNED_HANDOFF_LOSS':
            valid = complete and bool(lost) and not shutdowns and not terminal and any(
                e.get('operation') == 'begin-boot-handoff' for e in segment)
        elif code == 'INTERRUPTED_ADMISSION':
            valid = complete and bool(lost) and not shutdowns and not terminal and any(
                e.get('state') == 'AUTHORIZATION_ADMITTED' or
                e.get('record_type') in ('ACTIVATION_RESERVED', 'ACTIVATION_ADMITTED') for e in segment)
        elif code == 'SHUTDOWN_PENDING_AT_LOSS':
            recovered = [e for e in segment_envelopes if json.loads(e.payload_bytes).get('record_type') ==
                'PLANNED_SHUTDOWN_COMMITTED' and self._commits[e.transaction_id].completion_mode == 'RECOVERY_RECONCILE']
            valid = complete and bool(lost) and not shutdowns and bool(recovered)
        elif code == 'EXPLICIT_ABORT_OR_FAILURE':
            valid = any(e.get('state') in ('ABORTED', 'TAINTED') and
                        e.get('campaign_id') == actor.campaign_id for e in events)
        elif code == 'CUSTODY_LOSS_PROVEN':
            valid = complete and not shutdowns and not terminal and self._custodian is not None and any(
                e.get('state') == 'BOOT_CUSTODY_ESTABLISHED' and
                self._custodian.confirms_required_custody_loss(e.get('custody_attestation')) for e in segment)
        elif code == 'PUBLICATION_INTEGRITY_CONFLICT':
            valid = complete and self._custodian is not None and any(
                e.get('record_type') == 'PUBLICATION' and
                any(a.get('record_type') == 'EFFECT_ACCEPTED' and
                    a.get('effect_id') == e.get('operation_id') for a in events) and
                self._custodian.confirms_publication_conflict(e) for e in events)
            if complete and not valid and self._store is not None:
                valid = any(self._store._independent_rp_conflict(e) for e in events
                            if e.get('record_type') == 'RECOVERY_PUBLICATION_RESULT')
        else:
            # Remaining positive predicates stay unavailable until their
            # exact independent proof verifier is integrated.
            valid = False
        if not valid:
            raise AuthorizationDenied('denial trigger lacks accepted positive evidence')
        key = (actor.store_identity, actor.authorization_digest, actor.campaign_id)
        self._denials.setdefault(key, (code, tuple(e.transaction_id for e in envelopes)))
        return self._denials[key]

    def acquire_fence(self, owner, fail=False):
        with self._allocation_context():
            self._check_bound_store_health()
            with self._lock:
                self.high_fence += 1
                epoch = self.high_fence
                if not fail:
                    self.current_fence = epoch
                return epoch

    def reserve(self, revision, chain_digest):
        if self._store is not None and self._store._authentication_service is not None:
            raise AuthorizationDenied('legacy witness reservations cannot mutate a U-04 journal')
        if not self.available:
            raise Quarantined("witness unavailable")
        if revision != self.high_revision + 1 or revision in self.pending:
            self.quarantined = True
            raise Quarantined("witness revision divergence")
        self.pending[revision] = chain_digest
        return "reservation-%d-%s" % (revision, chain_digest[:12])

    def commit(self, revision, chain_digest):
        if self._store is not None and self._store._authentication_service is not None:
            raise AuthorizationDenied('legacy witness commits cannot mutate a U-04 journal')
        if self.pending.get(revision) != chain_digest:
            self.quarantined = True
            raise Quarantined("witness reservation mismatch")
        self.pending.pop(revision)
        self.high_revision = revision
        self.high_chain_digest = chain_digest
        return "witness-%d-%s" % (revision, chain_digest[:12])

    def _check_bound_store_health(self):
        # Read actual D/W outside W's lock to preserve the store->witness lock
        # order. Allocated numbers confer no actor or writer entitlement.
        if self._store is not None and self._store._authentication_service is not None:
            self._store.assert_healthy_authority()
            self._store.read_verified(0)

    def _allocation_context(self):
        return (self._store.authorization_lock if self._store is not None and
                self._store._authentication_service is not None else nullcontext())


class _AuthorizationLock:
    """RLock with portable, per-thread ownership tracking.

    Ordinary authorization helpers may nest.  Takeover may not nest inside
    them: a callback must not replace authority halfway through an operation.
    Keep this distinct from the journal lock; acquire authorization first.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._local = threading.local()

    def owned_by_current_thread(self):
        return getattr(self._local, "depth", 0) > 0

    def acquire(self, blocking=True, timeout=-1):
        acquired = self._lock.acquire(blocking, timeout)
        if acquired:
            self._local.depth = getattr(self._local, "depth", 0) + 1
        return acquired

    def release(self):
        self._lock.release()
        self._local.depth -= 1

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc_info):
        self.release()


_LOCAL_INSPECTION_BOUNDARY = object()
_LOCAL_INSPECTION_READER_ID = 'offline-local-reader'


class OfflineReadOnlyInspector:
    """A bootstrap-supplied local reader; never an actor or a writer.

    The pinned OCAV service is the offline trusted-local setup boundary. This
    models configured local read permission, not remote identity authentication.
    """
    def __init__(self, store, service, authorization, reader_identity, *, _entry):
        if _entry is not _LOCAL_INSPECTION_BOUNDARY:
            raise AuthorizationDenied('trusted local inspection binding required')
        self._store, self._service = store, service
        self._authorization, self._reader_identity = authorization, reader_identity

    def snapshot(self):
        store = self._store
        if (self._service is not store._authentication_service or
                self._reader_identity != _LOCAL_INSPECTION_READER_ID):
            raise AuthorizationDenied('configured original local reader required')
        self._service.verify(self._authorization, store_identity=store.identity,
                             campaign_id=self._authorization.campaign_id)
        prefix = store.verified_prefix()
        raw = tuple(bytes(frame['bytes']) for frame in store._durable)
        if any(frame['envelope'].authorization_digest != self._authorization.authorization_digest or
               frame['envelope'].campaign_id != self._authorization.campaign_id for frame in prefix['frames']):
            return {'frames': (), 'stop_reason': 'AUTHORIZATION_UNPROVEN', 'untrusted_raw_bytes': raw,
                    'reader_identity': self._reader_identity, 'authorizes_execution': False}
        return dict(prefix, reader_identity=self._reader_identity, untrusted_raw_bytes=raw)
        return False


class OfflineDurableStore:
    """Append-only framed-journal model with independent witness semantics."""

    def __setattr__(self, name, value):
        if (name in ('identity', 'witness', '_custodian', '_authentication_service', '_activation_authentication_service', '_artifact_verifier', '_publication_destinations') and
                name in self.__dict__ and self.__dict__[name] is not value):
            raise AuthorizationDenied('bootstrap identity and authentication references are pinned for this store lifetime')
        object.__setattr__(self, name, value)

    def __init__(self, identity, witness, *, chair_verifier=None, activation_verifier=None,
                 publication_destinations=()):
        if witness._store is not None:
            raise AuthorizationDenied('independent witness is already bound to its original store')
        self.identity = identity
        self.witness = witness
        self._artifact_verifier = None
        witness._store = self
        self._durable = []
        self._volatile = []
        self._receipts = {}
        self._event_bytes = {}
        self._lock = threading.RLock()
        self._authorization_lock = _AuthorizationLock()
        self.authorization_lock = self._authorization_lock
        self.quarantined = False
        self.containment_only = False
        self._taint = set()
        self._consumed = set()
        self._sessions = {}
        self._effect_capabilities = {}
        self._effect_status = {}
        self._effect_results = {}
        self._active_creation_grants = set()
        self._effect_acceptance_counts = {}
        self._accepted_effects = set()
        self._invalidated_effects = set()
        self._execution_revoked = False
        self._publication_prohibited = False
        self._objects = {}
        self._supervisor_generation = 0
        self._supervisor_ready = False
        self._measurement_window = None
        self._window_epoch = 0
        # Publication operation requests (grant ID -> immutable grant), their
        # consumption, and the single result each consumed grant produced
        # (grant ID -> OperationResultBinding).  Retained store-owned facts
        # under the offline restart model.
        self._publication_grants = {}
        self._consumed_publication_grants = set()
        self._publication_grant_sequence = 0
        self._publication_grant_records = {}
        # Measurement-window operations: operation ID -> exact registered
        # transition (pending until its result is bound), operation ID -> the
        # single bound result, and the operation IDs registered as the initial
        # transition of fresh-store admission.
        self._window_operations = {}
        self._window_results = {}
        self._initial_window_operations = set()
        self._window_operation_sequence = 0
        self._initialization_token = None
        self._custodian = None
        # Store-owned authority derived only by dedicated operations (live) or
        # by evidence revalidation (reconstruction).  Labels never populate them.
        self._slot_grants = {}
        self._validated_completions = {}
        self._validated_boot_closures = {}
        self._validated_campaign_closure = None
        self._validated_boot_custody = {}
        self.torn_tail = b""
        self._current_actor = None
        self._recovery_writer = None
        self._current_reconciler = None
        self._entry_mode = "INSPECTION"
        self._health = "HEALTHY"
        self._pending_reset = False
        # B service reference only; the sealed I root remains owned by the
        # authentication service chosen by trusted bootstrap before runtime.
        self._authentication_service = chair_verifier
        self._historical_producers = {}
        self._acceptance_acks = {}
        self._activation_authentication_service = activation_verifier
        self._publication_destinations = tuple(publication_destinations)
        self._rp_binding = None
        self._rp_grants = {}
        self._rp_proofs = {}
        from .evidence import OfflinePublicationDestination
        if (any(type(p) is not OfflinePublicationDestination for p in self._publication_destinations) or
                len({p.destination_id for p in self._publication_destinations}) != len(self._publication_destinations) or
                len({p.port_identity for p in self._publication_destinations}) != len(self._publication_destinations)):
            raise AuthorizationDenied('unique exact offline destination setup required')
        for port in self._publication_destinations:
            port.bind_store(self)

    @property
    def health(self):
        if not self.witness.available:
            return 'UNKNOWN'
        return self._health

    def begin_fresh_entry(self, chair_verifier, authorization, owner_identity, fault=None):
        """Authenticated FRESH binding only. Constructor/OCAV cannot grant LIVE."""
        from .authorization import OfflineChairAuthorizationVerifier
        if (type(chair_verifier) is not OfflineChairAuthorizationVerifier or
                chair_verifier is not self._authentication_service):
            raise AuthorizationDenied("trusted bootstrap authentication service required")
        chair_verifier.verify(authorization, store_identity=self.identity,
                              campaign_id=authorization.campaign_id)
        with self.authorization_lock:
            if (self._durable or self.torn_tail or self.witness.high_revision or
                    self.witness.high_generation or self.witness.high_fence or
                    self.witness.pending or self._current_actor is not None or
                    self.witness._actors):
                raise AuthorizationDenied("witness-backed genuine freshness required")
            self._check_healthy()
            generation = self.witness.allocate_generation(self.identity)
            fence = self.witness.acquire_fence(owner_identity)
            actor = IncarnationActor(self.identity, authorization.authorization_digest,
                authorization.campaign_id, generation,
                "%s-incarnation-%d" % (self.identity, generation),
                "%s-session-%d" % (self.identity, generation), owner_identity, fence,
                "FRESH", object())
            self.witness.register_actor(actor, _entry=_U04_BOUNDARIES["ENTRY"])
            self._current_actor = actor
            self._supervisor_generation = generation
            self._entry_mode = "FRESH"
            event = self._u04_common(actor, "SUPERVISOR_INCARNATION", "CONTROL", False)
            event.update(mode="FRESH", entry_refs=[],
                         witness_generation_receipt="generation-%d" % generation,
                         incarnation_id=actor.incarnation_id)
            try:
                self._commit_u04(actor, "ENTRY", event, fault=fault)
            except BaseException:
                self._execution_revoked = self._publication_prohibited = True
                self.witness.freeze_actor(actor)
                self._current_actor = None
                raise
            return actor

    def _validate_init_payload(self, actor, event, facts):
        if event.get('record_type') != 'MEASUREMENT_WINDOW' and (
                event.get('authority_class') != 'CONTROL' or event.get('authorizes_execution') is not False):
            raise AuthorizationDenied('INIT binding is CONTROL and never execution authority')
        if event.get('state') == 'AUTHORIZATION_ADMITTED':
            expected = {'state_domain', 'state', 'store_identity', 'authorization_id',
                'authorization_digest', 'campaign_id', 'canonical_authorization_hex',
                'root_id', 'root_version', 'core_manifest_digest', 'adapter_manifest_digest',
                'policy_digest', 'schema_digest', 'authority_class', 'authorizes_execution'}
            from .contracts import authorization_from_record
            payload = json.loads(bytes.fromhex(event['canonical_authorization_hex']))
            payload['authorization_digest'] = event['authorization_digest']
            authorization = authorization_from_record(payload)
            checked = self._authentication_service.verify(authorization,
                store_identity=self.identity, campaign_id=actor.campaign_id)
            if (checked.root_id != event['root_id'] or checked.root_version != event['root_version'] or
                    authorization.authorization_id != event['authorization_id'] or
                    any(getattr(authorization, name) != event[name] for name in (
                        'core_manifest_digest', 'adapter_manifest_digest', 'policy_digest', 'schema_digest')) or
                    any(f['event'].get('state') == 'AUTHORIZATION_ADMITTED' for f in self._committed_frames())):
                raise AuthorizationDenied('INIT requires exact independent original authentication')
        elif event.get('state') == 'CAMPAIGN_ADMITTED':
            expected = {'state_domain', 'state', 'store_identity', 'authorization_digest',
                'campaign_id', 'boot_id', 'activation_id', 'session_id', 'session_owner',
                'session_live', 'fence_epoch', 'boot_ordinal', 'session_boot_ordinal',
                'supervisor_generation', 'authority_class', 'authorizes_execution'}
            expected.add('operation')
            if not any(f['event'].get('state') == 'AUTHORIZATION_ADMITTED'
                       for f in self._committed_frames()):
                raise AuthorizationDenied('original admission required before campaign binding')
            if type(facts) is not dict or set(facts) != {'consumptions', 'activation_authentication'}:
                raise AuthorizationDenied('INIT requires independently authenticated exact activation')
            proof = facts['activation_authentication']
            activation = BootActivation(**json.loads(bytes.fromhex(proof['canonical_bytes_hex'])))
            checked = self._activation_authentication_service.verify(activation,
                store_identity=self.identity, authorization=self._admitted_payload(), predecessor_digest=None)
            if (proof != {'verifier_id': checked.verifier_id, 'canonical_bytes_hex': checked.canonical_bytes.hex(),
                          'digest': checked.digest} or activation.activation_id != event['activation_id'] or
                    activation.observed_boot_id != event['boot_id'] or activation.boot_ordinal != 1 or
                    facts['consumptions'] != [['authorization', self._admitted_payload().authorization_id],
                                             ['boot_activation', activation.activation_id]]):
                raise AuthorizationDenied('INIT activation differs from authenticated binding')
        elif event.get('record_type') == 'MEASUREMENT_WINDOW':
            transition = MeasurementWindowTransition.from_record(self.identity,
                'measurement-' + event['operation_id'], event)
            expected = set(transition.record())
            if not transition.initial or self._window_epoch != 0:
                raise AuthorizationDenied('INIT window may not resume historical admission')
        else:
            raise AuthorizationDenied('closed INIT record required')
        if (set(event) != expected or
                event.get('authorization_digest') != actor.authorization_digest or
                event.get('campaign_id') != actor.campaign_id):
            raise AuthorizationDenied('closed INIT identity required')
        if event.get('state') == 'CAMPAIGN_ADMITTED' and any(event.get(name) != value for name, value in {
                'store_identity': self.identity, 'session_id': actor.session_id,
                'session_owner': actor.owner_identity, 'session_live': False, 'fence_epoch': actor.fence,
                'supervisor_generation': actor.generation, 'boot_ordinal': 1, 'session_boot_ordinal': 1,
                'authority_class': 'CONTROL', 'authorizes_execution': False, 'operation': 'admit-campaign'}.items()):
            raise AuthorizationDenied('INIT cannot substitute a caller identity for its captured actor')
        if event.get('record_type') == 'MEASUREMENT_WINDOW' and (
                transition.session_id != actor.session_id or transition.supervisor_generation != actor.generation or
                transition.fence_epoch != actor.fence):
            raise AuthorizationDenied('initial window must bind the captured INIT actor')

    def complete_fresh_admission(self, actor, authorization, activation):
        """No live membership escapes an incomplete fresh INIT."""
        with self.authorization_lock:
            self.require_actor(actor, 'INIT')
            if self._activation_authentication_service is None:
                raise AuthorizationDenied('independent activation authentication unavailable')
            verified = self._activation_authentication_service.verify(activation, store_identity=self.identity,
                authorization=authorization, predecessor_digest=None)
            if (not isinstance(activation, BootActivation) or activation.boot_ordinal != 1 or
                    activation.authorization_digest != authorization.authorization_digest or
                    activation.chair_identity != authorization.chair_identity or
                    self.is_consumed('boot_activation', activation.activation_id)):
                raise AuthorizationDenied('exact fresh authenticated activation required')
            self.admit_authorization(actor, authorization)
            event = {'state_domain': 'campaign', 'state': 'CAMPAIGN_ADMITTED',
                'store_identity': self.identity, 'authorization_digest': actor.authorization_digest,
                'campaign_id': actor.campaign_id, 'boot_id': activation.observed_boot_id,
                'activation_id': activation.activation_id, 'session_id': actor.session_id,
                'session_owner': actor.owner_identity, 'session_live': False,
                'fence_epoch': actor.fence, 'boot_ordinal': 1, 'session_boot_ordinal': 1,
                'supervisor_generation': actor.generation, 'authority_class': 'CONTROL',
                'authorizes_execution': False, 'operation': 'admit-campaign'}
            self._commit_u04(actor, 'INIT', event, facts={'consumptions': [
                ['authorization', authorization.authorization_id],
                ['boot_activation', activation.activation_id]],
                'activation_authentication': {'verifier_id': verified.verifier_id,
                    'canonical_bytes_hex': verified.canonical_bytes.hex(), 'digest': verified.digest}},
                event_id='event-campaign-admitted')
            transition = MeasurementWindowTransition(self.identity, WINDOW_OPERATION,
                'window-operation-1', 'measurement-window-operation-1', None, 0,
                OUTSIDE_MEASURED_WINDOWS, 1, actor.authorization_digest, actor.campaign_id,
                actor.generation, actor.session_id, actor.fence)
            receipt = self._commit_u04(actor, 'INIT', transition.record(),
                event_id=transition.event_id)
            self._window_operations[transition.operation_id] = transition
            self._window_results[transition.operation_id] = OperationResultBinding(
                receipt.event_id, receipt.revision, receipt.event_digest)
            self._initial_window_operations.add(transition.operation_id)
            self._window_operation_sequence = self._window_epoch = 1
            self._measurement_window = OUTSIDE_MEASURED_WINDOWS
            session = FenceSession(actor.fence, actor.session_id, actor.owner_identity, 1, True)
            live = self.witness.change_mode(actor, 'LIVE', _boundary=_U04_BOUNDARIES['INIT'], execution_session=session)
            self._current_actor = live
            self._entry_mode = 'LIVE'
            self._supervisor_ready = True
            self._execution_revoked = self._publication_prohibited = self.containment_only = False
            self._sessions[live.session_id] = session
            return live, session

    def _u04_common(self, actor, record_type, authority_class, authorizes_execution):
        return {"schema_version": "u04-record/v1", "record_type": record_type,
                "record_id": "%s-%d" % (actor.incarnation_id, self.revision + 1),
                "store_identity": self.identity, "authorization_digest": actor.authorization_digest,
                "campaign_id": actor.campaign_id, "writer_generation": actor.generation,
                "writer_incarnation_id": actor.incarnation_id, "writer_session_id": actor.session_id,
                "writer_fence": actor.fence, "authority_class": authority_class,
                "authorizes_execution": authorizes_execution}

    def _commit_u04(self, actor, boundary, event, *, facts=None, fault=None, event_id=None):
        """Single-journal kernel; only registered dedicated boundaries enter it."""
        with self.authorization_lock, self._lock:
            self._check_healthy()
            if self._durable:
                self.read_verified(0)
            if self._current_actor is not actor:
                raise AuthorizationDenied("captured current store actor required")
            self.witness.authenticate(actor, self.identity, boundary)
            if facts is not None and (boundary in ('RESULT', 'SHUTDOWN', 'DENY', 'HISTORY', 'RW', 'RP') or
                    boundary == 'INIT' and event.get('state') != 'CAMPAIGN_ADMITTED'):
                raise AuthorizationDenied('this record admits no additional authority facts')
            if event.get('schema_version') == 'u04-record/v1':
                policy = _U04_RECORD_BOUNDARIES.get(event.get('record_type'))
                if (policy is None or boundary != policy[0] or
                        event.get('authority_class') != policy[1] or
                        event.get('authorizes_execution') is not policy[2]):
                    raise AuthorizationDenied('closed record writer and authority meaning required')
            if event.get('schema_version') == 'u04-record/v1' and any(
                    event.get(name) != value for name, value in self._u04_common(actor,
                        event.get('record_type'), event.get('authority_class'),
                        event.get('authorizes_execution')).items()):
                raise AuthorizationDenied('record writer must match captured incarnation')
            if boundary == "ENTRY":
                common = set(self._u04_common(actor, "SUPERVISOR_INCARNATION", "CONTROL", False))
                if (set(event) != common | {"mode", "entry_refs", "witness_generation_receipt",
                                           "incarnation_id"} or
                        event.get("record_type") != "SUPERVISOR_INCARNATION" or
                        event.get("authorizes_execution") is not False or
                        event.get("mode") != actor.mode or
                        event.get("incarnation_id") != actor.incarnation_id or facts is not None or
                        event.get('witness_generation_receipt') != 'generation-%d' % actor.generation or
                        any(f.get('envelope') is not None and
                            f['envelope'].producer_bytes == _u04_canonical(actor.producer())
                            for f in self._durable)):
                    raise AuthorizationDenied("closed ENTRY record required")
                if actor.mode == 'FRESH':
                    if self._durable or event['entry_refs'] != []:
                        raise AuthorizationDenied('FRESH entry may not reinterpret existing history')
                elif actor.mode in ('RECOVERY', 'WAITING', 'TERMINAL'):
                    frames = self._committed_frames()
                    if (event['entry_refs'] != [self._reference(f['receipt']) for f in frames[-1:]] or
                            actor.mode != self._derived_nonlive_mode(self._admitted_payload())):
                        raise AuthorizationDenied('ENTRY membership and references must derive from exact history')
                else:
                    raise AuthorizationDenied('LIVE_PENDING is bound only inside an ADMIT transaction')
            elif boundary == "INIT":
                self._validate_init_payload(actor, event, facts)
            elif boundary == 'EXEC':
                self._validate_execution_payload(actor, event, facts)
            elif boundary == 'RESULT':
                parsed = parse_effect_result_record(_u04_canonical(event))
                self._validate_result_payload(actor, parsed)
            elif boundary == 'SHUTDOWN':
                self._validate_shutdown_payload(actor, event)
            elif boundary == 'ADMIT':
                self._validate_admission_payload(actor, event, facts)
            elif boundary == 'HISTORY':
                self._validate_original_diagnostic(actor, event)
            elif boundary == 'RW':
                self._require_recovery_writer(self._recovery_writer, actor)
                self._validate_recovery_payload(event)
            elif boundary == 'RP':
                self._require_rp_binding(self._rp_binding, actor)
                self._validate_rp_payload(event)
            elif boundary == 'DENY':
                denial = self.witness.denial(actor)
                required = set(self._u04_common(actor, 'CAMPAIGN_EXECUTION_DENIED', 'DENIAL', False)) | {
                    'trigger_code', 'trigger_refs', 'witness_latch_receipt'}
                if (denial is None or set(event) != required or
                        event['record_type'] != 'CAMPAIGN_EXECUTION_DENIED' or
                        event['authority_class'] != 'DENIAL' or event['authorizes_execution'] is not False or
                        event['trigger_code'] != denial[0] or event['trigger_refs'] != [
                            self._reference(self.event_receipt(identity)) for identity in denial[1]] or
                        event['witness_latch_receipt'] != _sha(_u04_canonical([self.witness.identity, denial]))):
                    raise AuthorizationDenied('DENY may only mirror exact independently retained W fact')
            else:
                raise AuthorizationDenied("U-04 writer not yet integrated")
            payload = _u04_canonical(event)
            transaction_id = (event_id if event_id is not None else event.get("record_id", "%s-%d" % (
                actor.incarnation_id, self.revision + 1)))
            if (type(transaction_id) is not str or not transaction_id or
                    any(frame['event_id'] == transaction_id for frame in self._durable)):
                raise AuthorizationDenied('unused exact transaction identity required')
            envelope = JournalEnvelope("u04-transaction/v1", transaction_id,
                self.revision + 1, self.revision, self.chain_digest, self.identity,
                actor.authorization_digest, actor.campaign_id,
                _u04_canonical(actor.producer()), boundary, event.get("authority_class", 'CONTROL'),
                payload, _sha(payload), _u04_canonical(dict(
                    facts or {}, producer=actor.producer())))
            exact = envelope.canonical_bytes()
            if fault == "before_reservation":
                raise TransactionPending(envelope.transaction_id, fault, "ABSENT")
            reservation = self.witness.reserve_frame(actor, envelope, _U04_BOUNDARIES[boundary])
            if fault == "reservation_response_lost":
                self._health = "UNKNOWN"
                raise TransactionPending(envelope.transaction_id, fault, "UNKNOWN")
            if fault == "reserved_before_frame":
                self._health = "QUARANTINED"
                self.quarantined = self.containment_only = True
                raise Quarantined("reserved frame missing")
            receipt = AppendReceipt(self.identity, envelope.revision, envelope.transaction_id,
                envelope.payload_digest, envelope.frame_digest, actor.fence,
                "pending-" + envelope.transaction_id, False)
            frame = {"event_id": envelope.transaction_id, "event": copy.deepcopy(event),
                     "bytes": bytes(exact), "receipt": receipt, "envelope": envelope}
            self._durable.append(frame)
            self._health = "RECONCILABLE"
            if fault == "frame_before_readback":
                raise TransactionPending(envelope.transaction_id, fault)
            retained = self._independent_frame_readback(envelope.revision)
            if fault == "readback_unavailable":
                self._health = "UNKNOWN"
                raise TransactionPending(envelope.transaction_id, fault, "UNKNOWN")
            if fault == "readback_mismatch":
                self._health = "QUARANTINED"
                self.quarantined = self.containment_only = True
                raise Quarantined("independent retained bytes mismatch")
            if retained != exact or not self._u04_frame_valid(frame):
                self._health = "QUARANTINED"
                self.quarantined = self.containment_only = True
                raise Quarantined("independent retained frame validation failed")
            if fault == "validated_before_commit":
                raise TransactionPending(envelope.transaction_id, fault)
            commit = self.witness.commit_frame(actor, envelope, reservation,
                                               _U04_BOUNDARIES[boundary], retained)
            if boundary == 'SHUTDOWN':
                self._current_actor = None
                self._sessions.clear()
                self._acceptance_acks.clear()
                self._execution_revoked = self._publication_prohibited = True
                self._entry_mode = 'EXITED'
            frame["receipt"] = replace(receipt, witness_receipt=commit.receipt_id, durable=True)
            self._health = "HEALTHY"
            # Independent confirmation checks retained bytes and W's query,
            # rather than the receipt returned by commit_frame alone.
            status, confirmed = self.witness.query_transaction(envelope.transaction_id)
            if (status != "COMMITTED" or confirmed != commit or
                    not self._u04_frame_valid(frame) or
                    self._independent_frame_readback(envelope.revision) != exact):
                self._health = "UNKNOWN"
                raise TransactionPending(envelope.transaction_id, "confirmation", "UNKNOWN")
            self._receipts[envelope.transaction_id] = frame["receipt"]
            self._event_bytes[envelope.transaction_id] = payload
            if fault == "commit_before_ack":
                raise LostAcknowledgement(frame["receipt"])
            if boundary == 'SHUTDOWN':
                return frame['receipt']
            if self._current_actor is not actor:
                raise TransactionPending(envelope.transaction_id, "actor-lost-before-ack", "UNKNOWN")
            self.witness.authenticate(actor, self.identity, boundary)
            self.witness.acknowledge_frame(actor, frame['receipt'], _boundary=_U04_BOUNDARIES[boundary])
            return frame["receipt"]

    def require_actor(self, actor, boundary='EXEC'):
        if self._current_actor is not actor or actor is None:
            raise AuthorizationDenied('captured opaque incarnation is no longer current')
        if not self.witness.available:
            self._execution_revoked = self._publication_prohibited = self.containment_only = True
            raise AuthorizationDenied('witness status unreadable; dependent action denied now')
        self.witness.authenticate(actor, self.identity, boundary)
        return actor

    def actor_for_session(self, session):
        actor = self.require_actor(self._current_actor)
        if (actor.execution_session is not session or
                session.session_id != actor.session_id or
                session.fence_epoch != actor.fence or not session.execution_live):
            raise AuthorizationDenied('current opaque session membership required')
        return actor

    def _committed_frames(self):
        self.read_verified(0)
        return [frame for frame in self._durable if type(frame.get('envelope')) is JournalEnvelope]

    def _validate_execution_payload(self, actor, event, facts):
        self.require_actor(actor)
        if event.get('record_type') == 'PUBLICATION':
            request = PublicationOperationBinding.from_record(self.identity, event)
            if (request.supervisor_generation != actor.generation or request.session_id != actor.session_id or
                    request.fence_epoch != actor.fence or type(facts) is not dict or
                    set(facts) != {'publication_grant'} or
                    facts['publication_grant'].get('attestation') != request.attestation_digest() or
                    facts['publication_grant'].get('phase') not in ('ISSUE', 'INTENT', 'RESULT')):
                raise AuthorizationDenied('closed publication issuance/consumption required')
            phase = facts['publication_grant']['phase']
            grant = PublicationOperationGrant(request, request.attestation_digest())
            extras = {'intent': {'source_object_id', 'source_digest'},
                'create': {'reservation_id'},
                'write': {'written_object_id', 'written_digest', 'written_length', 'write_revision'},
                'durable': {'written_object_id', 'written_digest', 'write_revision', 'durability_ack_id'},
                'verify': {'written_object_id', 'written_digest', 'write_revision', 'durability_ack_id',
                           'readback_digest', 'verification_id'}}
            if set(event) != set(request.record_fields()) | (set() if phase == 'ISSUE' else extras[request.operation]):
                raise AuthorizationDenied('publication payload must use its closed operation schema')
            if phase != 'ISSUE':
                self._publication_issuance(grant, actor)
            if phase == 'RESULT':
                accepted = [f for f in self._committed_frames() if
                    f['event'].get('record_type') == 'EFFECT_ACCEPTED' and f['event'].get('effect_id') == request.grant_id]
                if len(accepted) != 1 or not self.witness.acknowledged_current(actor, accepted[0]['event_id']):
                    raise AuthorizationDenied('publication result requires acknowledged current acceptance')
                original = self._exact_ref(accepted[0]['event']['intent_ref'])
                if PublicationOperationBinding.from_record(self.identity, original['event']) != request:
                    raise AuthorizationDenied('publication result differs from accepted intent')
                self._custodian.validate_publication_result(request.grant_id,
                    _u04_canonical(event), self._custodian.identity)
                if any(f['event'].get('operation_id') == request.grant_id and
                    self.publication_record_provenanced(f) for f in self._committed_frames()):
                    raise AuthorizationDenied('publication result is single use')
            authorization = self._admitted_payload()
            history = _validated_window_history(self, authorization)
            if not history.complete or history.window != OUTSIDE_MEASURED_WINDOWS or history.window_epoch != request.window_epoch:
                raise AuthorizationDenied('publication requires current witnessed outside window')
            previous = _publication_frame_groups(self).get((request.identity.destination, request.identity.object_key), [])
            prior = previous[-1][1]['event']['state'] if previous else None
            if prior != request.expected_prior_state:
                raise AuthorizationDenied('publication exact predecessor mismatch')
            return
        if event.get('record_type') == 'MEASUREMENT_WINDOW':
            transition = MeasurementWindowTransition.from_record(self.identity,
                'measurement-' + event['operation_id'], event)
            if (transition.initial or transition.session_id != actor.session_id or
                    transition.supervisor_generation != actor.generation or
                    transition.fence_epoch != actor.fence or facts is not None):
                raise AuthorizationDenied('current non-initial window operation required')
            history = _validated_window_history(self, self._admitted_payload())
            if (not history.complete or transition.previous_window != history.window or
                    transition.previous_window_epoch != history.window_epoch):
                raise AuthorizationDenied('window predecessor must be witnessed history')
            return
        if event.get('record_type') == 'EFFECT_ACCEPTED':
            required = set(self._u04_common(actor, 'EFFECT_ACCEPTED', 'EXECUTION', True)) | {
                'intent_ref', 'effect_id', 'capability_digest', 'operation', 'target',
                'consumption_id', 'artifact_binding', 'target_acceptance_identity'}
            if set(event) != required or event['authority_class'] != 'EXECUTION':
                raise AuthorizationDenied('closed effect acceptance required')
            if facts is not None and set(facts) == {'publication_acceptance'}:
                intent = self._durable[event['intent_ref']['revision'] - 1]
                if not self.publication_record_provenanced(intent, phase='INTENT'):
                    raise AuthorizationDenied('publication acceptance requires exact witnessed issuance')
                request = PublicationOperationBinding.from_record(self.identity, intent['event'])
                grant = PublicationOperationGrant(request, request.attestation_digest())
                receipt = intent['receipt']
                expected = {'event_id': receipt.event_id, 'revision': receipt.revision, 'payload_digest': receipt.event_digest}
                if (facts['publication_acceptance'] != request.grant_id or event['intent_ref'] != expected or
                        event['effect_id'] != request.grant_id or event['operation'] != request.operation or
                        event['target'] != request.identity.destination or event['consumption_id'] != request.grant_id or
                        event['capability_digest'] != _sha(_u04_canonical(asdict(grant))) or
                        event['target_acceptance_identity'] != request.identity.destination or
                        any(f['event'].get('record_type') == 'EFFECT_ACCEPTED' and
                            f['event'].get('effect_id') == request.grant_id for f in self._committed_frames())):
                    raise AuthorizationDenied('publication acceptance identity mismatch')
                artifact = ArtifactBinding(**event['artifact_binding'])
                authorization = self._admitted_payload()
                if (artifact.session_id != actor.session_id or artifact.fence_epoch != actor.fence or
                        artifact.authorization_digest != actor.authorization_digest or
                        any(getattr(artifact, field) != getattr(authorization, expected) for field, expected in (
                            ('core_digest', 'core_manifest_digest'), ('adapter_digest', 'adapter_manifest_digest'),
                            ('policy_digest', 'policy_digest'), ('schema_digest', 'schema_digest')))):
                    raise AuthorizationDenied('publication artifact binding mismatch')
                return
            if facts is not None:
                raise AuthorizationDenied('execution acceptance admits no unregistered authority facts')
            capability = self.effect_capability(event['effect_id'])
            intent = self.effect_intent(capability)
            original = self.event_receipt(capability.transition_event_id)
            expected = {'event_id': original.event_id, 'revision': original.revision,
                        'payload_digest': original.event_digest}
            if (event['intent_ref'] != expected or event['operation'] != capability.operation or
                    event['target'] != capability.target or event['capability_digest'] !=
                    _sha(_u04_canonical(asdict(capability))) or event['artifact_binding'] !=
                    asdict(capability.artifact_binding) or event['consumption_id'] != capability.effect_id or
                    event['target_acceptance_identity'] != capability.target or
                    any(f['event'].get('record_type') == 'EFFECT_ACCEPTED' and
                        f['event'].get('effect_id') == capability.effect_id for f in self._committed_frames())):
                raise AuthorizationDenied('acceptance must match unique original intent')
            return
        # The existing closed execution schemas are retained. Their issuance,
        # artifact and slot facts now share the event's witnessed envelope.
        operation, state = event.get('operation'), event.get('state')
        schema = (GENERIC_TRANSITION_SCHEMAS.get(state) if operation == 'append-transition'
                  else DEDICATED_OPERATIONS.get(operation, {}).get(state))
        trusted = {'state', 'effect_id', 'state_domain', 'session_id', 'session_owner',
            'session_live', 'fence_epoch', 'boot_ordinal', 'session_boot_ordinal',
            'supervisor_generation', 'authorization_digest', 'campaign_id', 'target',
            'operation', 'authorizes_execution', 'dispatch_resolved', 'consumption',
            'verification_id', 'authority_class'}
        shape_matches = (schema is not None and (set(event) == set(schema) | trusted or
            operation == 'append-transition' and trusted <= set(event) and
            set(event) - trusted <= set(schema) and 'slot_id' in event))
        if (not shape_matches or
                event['session_id'] != actor.session_id or event['fence_epoch'] != actor.fence or
                event['supervisor_generation'] != actor.generation or event['session_live'] is not True or
                event['authorization_digest'] != actor.authorization_digest or
                event['campaign_id'] != actor.campaign_id or
                type(facts) is not dict or set(facts) != {'effect'} or
                set(facts['effect']) != {'capability_id', 'artifact_binding'}):
            raise AuthorizationDenied('closed current execution intent and issuance required')
        artifact = ArtifactBinding(**facts['effect']['artifact_binding'])
        if artifact.session_id != actor.session_id or artifact.fence_epoch != actor.fence:
            raise AuthorizationDenied('issuance artifact identity mismatch')
        authorization = self._admitted_payload()
        session = actor.execution_session
        if session is None or not self.session_registered(session):
            raise AuthorizationDenied('independently current execution session required')
        if (event['session_owner'] != actor.owner_identity or event['boot_ordinal'] != session.boot_ordinal or
                event['session_boot_ordinal'] != session.boot_ordinal or event['dispatch_resolved'] is not False or
                event['consumption'] != {'kind': 'effect', 'identity': event['effect_id']} or
                event['verification_id'] != artifact.verification_id or artifact.transition != state):
            raise AuthorizationDenied('lower mutation must bind all captured producer and issuance facts')
        self.validate_artifact_continuity(artifact)
        if operation in ('admit-campaign', 'admit-authorization', 'consume-boot-activation'):
            raise AuthorizationDenied('admission belongs exclusively to INIT or ADMIT')
        if operation == 'append-transition':
            _closed_payload(operation, state, {k: v for k, v in event.items() if k not in trusted},
                            schema, {k: event[k] for k in trusted}, authorization, session)
            intents = [f for f in self.provenanced_frames('SPAWN_INTENT_PERSISTED', 'blocked-create')
                       if f['event']['boot_ordinal'] == session.boot_ordinal]
            if (not intents or intents[-1]['event']['slot_id'] != event['slot_id'] or
                    event.get('spawn_token', intents[-1]['event']['spawn_token']) != intents[-1]['event']['spawn_token']):
                raise AuthorizationDenied('generic observation must bind the current original spawn')
        prior = self.authoritative_state(event['state_domain'], event['boot_ordinal'])
        if prior not in TRANSITION_PREDECESSORS.get(event['state_domain'], {}).get(state, ()):
            raise AuthorizationDenied('lower mutation boundary predecessor mismatch')
        if self.is_consumed('effect', event['effect_id']):
            raise AuthorizationDenied('lower mutation boundary rejects reused operation')
        if operation == 'make-slot-eligible':
            self._prepare_slot_grant(authorization, session, event)
        elif operation == 'blocked-create':
            self._check_slot_grant_for_creation(authorization, session, event)
        elif operation == 'record-worker-creation':
            capability = self.effect_capability('spawn-intent-' + event['slot_id'])
            original = self.effect_intent(capability)
            result = self.effect_result(capability.effect_id)
            if (original.get('spawn_token') != event['spawn_token'] or result is None or
                    result.receipt.receipt_id != event['custodian_receipt']):
                raise AuthorizationDenied('worker record requires the exact independently observed creation result')
        elif operation == 'worker-lifecycle':
            capability = self.effect_capability('spawn-intent-' + event['slot_id'])
            original = self._durable[capability.transition_revision - 1]['event']
            if original.get('spawn_token') != event['spawn_token']:
                raise AuthorizationDenied('lifecycle must bind the original token-owned worker')
            receipt = self.effect_result(capability.effect_id).receipt
            observed = self._custodian.inspect_spawn(event['spawn_token'])
            identity = observed.process_identity
            if (identity is None or receipt.process_identity is None or
                    identity.host_pid != receipt.process_identity.host_pid or
                    identity.process_start_ticks != receipt.process_identity.process_start_ticks):
                raise AuthorizationDenied('lifecycle requires independently retained original process identity')
            if state == 'WORKER_IDENTITY_ESTABLISHED' and (
                    not observed.possibly_live or event['host_pid'] != identity.host_pid or
                    event['start_ticks'] != identity.process_start_ticks):
                raise AuthorizationDenied('caller process labels cannot replace the original custodian identity')
            if state not in ('WORKER_IDENTITY_ESTABLISHED', 'EXIT_OBSERVED', 'REAPING_PROVEN') and not observed.possibly_live:
                raise AuthorizationDenied('live lifecycle transition requires actual token-owned custody')
            if state == 'EXIT_OBSERVED' and (observed.possibly_live or observed.status not in ('EXITED', 'REAPED')):
                raise AuthorizationDenied('exit record requires independently observed exit')
            if state == 'REAPING_PROVEN':
                reap = self._custodian.get_reap_receipt(event['spawn_token'])
                if (reap is None or event['reap_receipt_id'] != reap.receipt_id or
                        observed.possibly_live or observed.status != 'REAPED'):
                    raise AuthorizationDenied('reap record requires the exact independent receipt')
                self._custodian.validate_reap_receipt(reap)
        elif operation in ('establish-boot-custody', 'complete-boot-custody'):
            _boot_custody_evidence(self, authorization, operation, event, event)
        elif operation == 'complete-attempt':
            _HistoricalEvidenceVerifier(self, authorization)._validate_attempt_completion_record(
                event['slot_id'], event, require_completion_event=False)
        elif operation in ('finalize-boot-closure-candidate', 'finalize-campaign-closure-candidate'):
            view = _HistoricalEvidenceVerifier(self, authorization)
            kind = 'boot' if operation == 'finalize-boot-closure-candidate' else 'campaign'
            candidate, payload = view._rebuild_candidate({'event': event}, kind)
            if kind == 'boot':
                expected = {s.slot_id: self.validated_completion(s.slot_id) for s in authorization.slots
                            if s.boot_ordinal == session.boot_ordinal}
                if (payload.get('boot_id') != self.boot_identity(session.boot_ordinal) or
                        any(v is None for v in expected.values()) or
                        event['attempt_completion_digests'] != {k: v['completion_digest'] for k, v in expected.items()}):
                    raise AuthorizationDenied('lower boot candidate requires actual validated attempt proofs')
            elif (payload.get('campaign_id') != authorization.campaign_id or
                    event['boot_closure_digests'] != [self.validated_boot_closure(i) for i in (1, 2, 3, 4)] or
                    None in event['boot_closure_digests']):
                raise AuthorizationDenied('lower campaign candidate requires actual validated boot proofs')
        elif operation in ('complete-boot', 'complete-campaign'):
            candidates = self.provenanced_frames(
                'BOOT_CLOSURE_CANDIDATE_FINALIZED' if operation == 'complete-boot' else
                'CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED')
            candidates = [f for f in candidates if operation == 'complete-campaign' or
                          f['event']['boot_ordinal'] == session.boot_ordinal]
            if len(candidates) != 1 or candidates[0]['receipt'].event_digest != event['candidate_event_digest']:
                raise AuthorizationDenied('lower closure mutation requires exact candidate')
            _closure_publication_proof(self, authorization, candidates[0], event['publication_manifest'], self.revision)
        elif operation == 'begin-boot-handoff':
            if self.validated_boot_closure(session.boot_ordinal) is None:
                raise AuthorizationDenied('lower handoff mutation requires validated closure')

    def _validate_result_payload(self, actor, result):
        self.require_actor(actor, 'RESULT')
        if (type(result) is not U04EffectResultRecord or
                result.store_identity != self.identity or
                result.authorization_digest != actor.authorization_digest or
                result.campaign_id != actor.campaign_id):
            raise AuthorizationDenied('result authority identity mismatch')
        if result.result_kind == 'EFFECT_PORT_RECEIPT':
            self._validated_port_observation(result)
            return
        capability = self.effect_capability(result.effect_id)
        acceptance = self._acceptance_frame(capability)
        ref = result.acceptance_ref
        receipt = acceptance['receipt']
        original = self.event_receipt(capability.transition_event_id)
        if (asdict(ref) != {'event_id': receipt.event_id, 'revision': receipt.revision,
                           'payload_digest': receipt.event_digest} or
                asdict(result.original_producer_ref) != {'event_id': original.event_id,
                    'revision': original.revision, 'payload_digest': original.event_digest}):
            raise AuthorizationDenied('result exact linked provenance required')
        raw = self.read_object(result.result.object_id, result.result.sha256)
        if result.result.length != len(raw) or result.result_kind != 'CUSTODIAN_RECEIPT':
            raise AuthorizationDenied('independently verifiable result kind required')
        self._custodian.validate_creation_result(capability, raw, result.verifier_id)

    def _validated_port_observation(self, result):
        """Pure historical proof; a port receipt never supplies a current token."""
        if type(result) is not U04EffectResultRecord or result.result_kind != 'EFFECT_PORT_RECEIPT':
            raise AuthorizationDenied('exact versioned independent port result required')
        accepted = self._exact_ref(asdict(result.acceptance_ref))
        event = accepted['event']
        if (event.get('record_type') != 'EFFECT_ACCEPTED' or event['effect_id'] != result.effect_id or
                asdict(result.original_producer_ref) != event['intent_ref']):
            raise AuthorizationDenied('port result must bind the original acceptance and producer')
        raw = self._object_proof(asdict(result.result))
        receipt = self._custodian.validate_effect_port_receipt(result.effect_id, raw, result.verifier_id)
        producer = json.loads(accepted['envelope'].producer_bytes)
        if (asdict(receipt.acceptance_ref) != asdict(result.acceptance_ref) or receipt.target_id != event['target'] or
                receipt.original_generation != producer['generation'] or
                receipt.original_incarnation_id != producer['incarnation_id'] or
                receipt.original_session_id != producer['session_id'] or receipt.original_fence != producer['fence']):
            raise AuthorizationDenied('independent port receipt original identity mismatch')
        observation = self._object_proof(asdict(receipt.result_object))
        if observation != self._custodian.port_observation_bytes(receipt):
            raise AuthorizationDenied('port observation differs from independently retained bytes')
        facts = json.loads(accepted['envelope'].authority_fact_bytes)
        if 'publication_acceptance' in facts:
            self._custodian.validate_publication_result(result.effect_id, observation, result.verifier_id)
        else:
            self._custodian.validate_control_result(self.effect_capability(result.effect_id), observation, result.verifier_id)
        return observation

    def _persist_port_observation(self, actor, effect_id):
        raw = self._custodian.effect_port_receipt_bytes(effect_id)
        parsed = self._custodian.validate_effect_port_receipt(effect_id, raw, self._custodian.identity)
        observation = self._custodian.port_observation_bytes(parsed)
        self.put_object(parsed.result_object.object_id, observation, actor=actor, boundary='RESULT')
        return raw

    def _validate_original_diagnostic(self, actor, event):
        self.require_actor(actor, 'HISTORY')
        if actor.mode != 'LIVE':
            raise AuthorizationDenied('new recovery writers remain unavailable in Checkpoint A')
        if event.get('record_type') == 'SURVIVOR_TRANSFER':
            self._custodian.validate_transfer_record(event)
            return
        required = {'state', 'reason', 'raw_digest', 'raw_length', 'authorization_digest', 'campaign_id', 'authorizes_execution'}
        if 'primary_failure' in event:
            required |= {'primary_failure', 'secondary_failures'}
        if (set(event) != required or event.get('state') != 'TAINTED' or
                event['authorizes_execution'] is not False or
                event['authorization_digest'] != actor.authorization_digest or event['campaign_id'] != actor.campaign_id or
                type(event['raw_length']) is not int or not 0 <= event['raw_length'] <= 1_048_576 or
                type(event['reason']) is not str or not event['reason']):
            raise AuthorizationDenied('closed original bounded failure diagnostic required')

    def record_original_diagnostic(self, actor, event):
        with self.authorization_lock:
            receipt = self._commit_u04(actor, 'HISTORY', event)
            if event.get('state') == 'TAINTED':
                self._taint.add(event['reason'])
                self.witness.deny_campaign(actor, 'EXPLICIT_ABORT_OR_FAILURE',
                    [f['envelope'] for f in self._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                self.mirror_denial(actor)
            return receipt

    def recovery_writer_binding(self, actor):
        with self.authorization_lock:
            self.require_actor(actor, 'RW')
            self._check_healthy()
            self.read_verified(0)
            if self._recovery_writer is None or self._recovery_writer.actor is not actor:
                self._recovery_writer = RecoveryWriterBinding(actor, self.identity,
                    actor.authorization_digest, actor.campaign_id, actor.generation,
                    actor.incarnation_id, actor.session_id, actor.fence,
                    tuple(RECOVERY_RECORD_FIELDS), object())
            return self._recovery_writer

    def recovery_publication_binding(self, actor, authorization):
        with self.authorization_lock:
            self.require_actor(actor, 'RP')
            self._check_healthy()
            self.read_verified(0)
            self.validate_admitted_authorization(authorization)
            if (actor.authorization_digest != authorization.authorization_digest or
                    actor.owner_identity not in authorization.recovery_publisher_ids or
                    not authorization.exact_byte_recovery_authorized):
                raise AuthorizationDenied('current authorized recovery publisher required')
            if self._rp_binding is None or self._rp_binding.actor is not actor:
                self._rp_binding = RecoveryPublicationBinding(actor, authorization, object())
            return self._rp_binding

    def _require_rp_binding(self, binding, actor=None):
        if (type(binding) is not RecoveryPublicationBinding or binding is not self._rp_binding or
                binding.actor is not self._current_actor or
                actor is not None and actor is not binding.actor):
            raise AuthorizationDenied('exact current opaque RP binding required')
        self.require_actor(binding.actor, 'RP')
        self._check_healthy()
        self.validate_admitted_authorization(binding.authorization)
        if (binding.actor.owner_identity not in binding.authorization.recovery_publisher_ids or
                binding.actor.authorization_digest != binding.authorization.authorization_digest or
                not binding.authorization.exact_byte_recovery_authorized):
            raise AuthorizationDenied('recovery publisher identity/policy mismatch')
        return binding.actor

    def _rp_port(self, authorization, destination_id):
        rules = [r for r in authorization.destination_rules if r.destination_id == destination_id]
        ports = [p for p in self._publication_destinations if p.destination_id == destination_id]
        if (len(rules) != 1 or len(ports) != 1 or ports[0]._store is not self or
                ports[0].port_identity != rules[0].port_identity):
            raise AuthorizationDenied('exact configured authorized destination port required')
        return ports[0]

    @staticmethod
    def _rp_object_identity(subject):
        return {name: subject[name] for name in RP_PUBLICATION_FIELDS - {'logical_operation_id'}}

    def _validate_rp_subject(self, binding, subject, operation):
        self._require_rp_binding(binding)
        auth = binding.authorization
        supplement = subject.get('original_or_supplement') == 'SUPPLEMENT'
        require_recovery_permission(auth, operation, supplement=supplement)
        original = self._exact_ref(subject['original_intent_ref'])
        event = original['event']
        if (event.get('record_type') != 'PUBLICATION' or event.get('operation') != 'intent' or
                not self.publication_record_provenanced(original, phase='INTENT') or
                event.get('authorization_digest') != auth.authorization_digest or
                event.get('campaign_id') != auth.campaign_id):
            raise AuthorizationDenied('exact original witnessed INTENT-phase transaction required')
        if supplement:
            return self._validate_rp_supplement_subject(auth, subject, operation, original)
        if (subject.get('original_or_supplement') != 'ORIGINAL' or subject.get('supplement_ref') is not None or
                event.get('destination') != subject['destination_id'] or event.get('object_key') != subject['object_key']):
            raise AuthorizationDenied('original publication branch substitution')
        port = self._rp_port(auth, subject['destination_id'])
        source = port.source(subject['original_intent_ref'], subject['object_key'])
        for field in RP_PUBLICATION_FIELDS - {'logical_operation_id'}:
            if subject[field] != source[field]:
                raise AuthorizationDenied('exact independently retained source/subject binding required')
        raw = self._object_proof(subject['source_object'])
        if (raw != source['source_bytes'] or source['authorization_digest'] != auth.authorization_digest or
                subject['source_object']['object_id'] != event['source_object_id'] or
                subject['source_object']['sha256'] != event['object_digest'] or
                subject['source_object']['length'] != event['length']):
            raise AuthorizationDenied('source object/bytes/admitted authority substitution')
        rules = [r for r in auth.object_rules if r.rule_id == subject['policy_rule_id']]
        if (len(rules) != 1 or rules[0].subject_id != subject['subject_id'] or
                rules[0].destination_id != subject['destination_id'] or rules[0].object_key != subject['object_key'] or
                rules[0].evidence_kind != source['evidence_kind']):
            raise AuthorizationDenied('exact object policy rule required')
        rule = rules[0]
        if rule.evidence_kind in ('CAMPAIGN_EVIDENCE', 'FAILURE_EVIDENCE'):
            if rule.subject_id != event['campaign_id']:
                raise AuthorizationDenied('original campaign evidence subject mismatch')
        elif rule.evidence_kind == 'BOOT_CLOSURE_EVIDENCE':
            candidates = [f for f in self.provenanced_frames('BOOT_CLOSURE_CANDIDATE_FINALIZED')
                if f['event'].get('boot_id') == rule.subject_id and
                f['event'].get('candidate_digest') == subject['source_object']['sha256'] and
                f['event'].get('candidate_bytes') == raw.hex()]
            if len(candidates) != 1:
                raise AuthorizationDenied('original boot evidence subject mismatch')
        else:
            matches = [f for f in self._committed_frames() if f['event'].get('state') == 'ATTEMPT_COMPLETE' and
                rule.subject_id in (f['event'].get('slot_id'), f['event'].get('attempt_id')) and
                f['event'].get('core_digest') == subject['source_object']['sha256']]
            if len(matches) != 1:
                raise AuthorizationDenied('original attempt evidence provenance required')
        allowed_ids = {port.operation_id(source, op) for op in (
            'ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT')}
        if subject['logical_operation_id'] not in allowed_ids or (
                operation != 'QUERY' and subject['logical_operation_id'] != port.operation_id(source, operation)):
            raise AuthorizationDenied('exact original logical operation identity required')
        return port, source

    def _validate_rp_supplement_subject(self, auth, subject, operation, original):
        # Historical semantic proof is also used by RW reporting. Only the RP
        # caller supplies current publication authority; this helper grants none.
        if subject.get('original_or_supplement') != 'SUPPLEMENT' or subject.get('supplement_ref') is None:
            raise AuthorizationDenied('exact supplement branch required')
        supplement = self._exact_ref(subject['supplement_ref'])['event']
        if supplement.get('record_type') != 'RECOVERY_SUPPLEMENT':
            raise AuthorizationDenied('committed original recovery supplement required')
        self._validate_recovery_payload(supplement)
        parent_port = self._rp_port(auth, original['event']['destination'])
        parent_source = parent_port.source(subject['original_intent_ref'], original['event']['object_key'])
        parent = self._exact_ref(supplement['parent_ref'])['event']
        linked = (supplement['parent_ref'] == subject['original_intent_ref'] or
            parent.get('record_type') == 'RECOVERY_PUBLICATION_RESULT' and
            parent.get('original_intent_ref') == subject['original_intent_ref'] or
            _u04_canonical(parent) == parent_source['source_bytes'] or
            parent.get('core_digest') == parent_source['source_object']['sha256'])
        if not linked:
            raise AuthorizationDenied('supplement parent lacks original evidence publication provenance')
        rules = [r for r in auth.supplement_rules if r.rule_id == subject['policy_rule_id']]
        if (len(rules) != 1 or rules[0].destination_id != subject['destination_id'] or
                parent_source['evidence_kind'] not in rules[0].parent_evidence_kinds or
                supplement['supplement_kind'] not in rules[0].supplement_kinds):
            raise AuthorizationDenied('exact supplement parent/kind/policy required')
        raw = self._object_proof(supplement['evidence'])
        key = '%s/recovery/%s/%s/%s/%s' % (rules[0].namespace_prefix,
            _sha(auth.campaign_id.encode('utf-8')), parent_source['source_object']['sha256'],
            supplement['supplement_kind'], _sha(raw))
        if (subject['object_key'] != key or subject['source_object'] != supplement['evidence'] or
                subject['subject_id'] != parent_source['subject_id'] or
                subject['producer_refs'] != [subject['supplement_ref']]):
            raise AuthorizationDenied('immutable supplement key/source/subject substitution')
        port = self._rp_port(auth, subject['destination_id'])
        source = {k: copy.deepcopy(subject[k]) for k in RP_PUBLICATION_FIELDS - {'logical_operation_id'}}
        source.update(source_bytes=raw, evidence_kind=parent_source['evidence_kind'],
            authorization_digest=auth.authorization_digest, campaign_id=auth.campaign_id,
            boot_id=parent_source['boot_id'], original_owner='supplement-' + subject['supplement_ref']['event_id'],
            original_create_ref=None)
        ids = {port.operation_id(source, op) for op in (
            'ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT')}
        if subject['logical_operation_id'] not in ids or (
                operation != 'QUERY' and subject['logical_operation_id'] != port.operation_id(source, operation)):
            raise AuthorizationDenied('exact supplement logical operation required')
        return port, source

    def recovery_supplement_subject(self, binding, original_intent_ref, supplement_ref, operation, *, policy_rule_id):
        with self.authorization_lock:
            self._require_rp_binding(binding)
            require_recovery_permission(binding.authorization, operation, supplement=True)
            original = self._exact_ref(original_intent_ref)['event']
            parent = self._rp_port(binding.authorization, original.get('destination')).source(
                original_intent_ref, original.get('object_key'))
            supplement = self._exact_ref(supplement_ref)['event']
            rules = [r for r in binding.authorization.supplement_rules if r.rule_id == policy_rule_id]
            if len(rules) != 1 or supplement.get('record_type') != 'RECOVERY_SUPPLEMENT':
                raise AuthorizationDenied('exact supplement and policy required')
            raw = self._object_proof(supplement['evidence'])
            subject = dict(original_intent_ref=copy.deepcopy(original_intent_ref), subject_id=parent['subject_id'],
                producer_refs=[copy.deepcopy(supplement_ref)], source_object=copy.deepcopy(supplement['evidence']),
                destination_id=rules[0].destination_id,
                object_key='%s/recovery/%s/%s/%s/%s' % (rules[0].namespace_prefix,
                    _sha(binding.authorization.campaign_id.encode('utf-8')), parent['source_object']['sha256'],
                    supplement['supplement_kind'], _sha(raw)), original_or_supplement='SUPPLEMENT',
                supplement_ref=copy.deepcopy(supplement_ref), policy_rule_id=policy_rule_id)
            port = self._rp_port(binding.authorization, subject['destination_id'])
            subject['logical_operation_id'] = port.operation_id(subject,
                'ENSURE_EXACT_OBJECT' if operation == 'QUERY' else operation)
            self._validate_rp_subject(binding, subject, operation)
            return subject

    def recovery_publication_subject(self, binding, original_intent_ref, operation):
        with self.authorization_lock:
            self._require_rp_binding(binding)
            event = self._exact_ref(original_intent_ref)['event']
            port = self._rp_port(binding.authorization, event.get('destination'))
            source = port.source(original_intent_ref, event.get('object_key'))
            rules = [r for r in binding.authorization.object_rules if r.destination_id == source['destination_id'] and
                     r.object_key == source['object_key']]
            if len(rules) != 1:
                raise AuthorizationDenied('exact original object rule required')
            subject = {k: copy.deepcopy(source[k]) for k in RP_PUBLICATION_FIELDS - {'logical_operation_id'}}
            subject.update(logical_operation_id=port.operation_id(source,
                'ENSURE_EXACT_OBJECT' if operation == 'QUERY' else operation),
                original_or_supplement='ORIGINAL', supplement_ref=None, policy_rule_id=rules[0].rule_id)
            self._validate_rp_subject(binding, subject, operation)
            return subject

    def _rp_intent_for(self, event):
        if event['record_type'] == 'RECOVERY_PUBLICATION_INTENT':
            return event
        if event['record_type'] == 'RECOVERY_PUBLICATION_ACCEPTED':
            candidates = [self._exact_ref(event['recovery_intent_ref'])]
        else:
            candidates = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'RECOVERY_PUBLICATION_INTENT' and
                all(f['event'].get(k) == event[k] for k in RP_PUBLICATION_FIELDS)]
        if not candidates:
            raise AuthorizationDenied('committed exact RP intent required')
        intent = candidates[-1]['event']
        if intent.get('record_type') != 'RECOVERY_PUBLICATION_INTENT' or any(
                intent.get(k) != event[k] for k in RP_PUBLICATION_FIELDS):
            raise AuthorizationDenied('RP intent reference substitution')
        return intent

    def _validate_rp_envelope(self, actor, envelope):
        self._require_rp_binding(self._rp_binding, actor)
        event = parse_closed_canonical(envelope.payload_bytes)
        if (envelope.authority_fact_bytes != _u04_canonical({'producer': actor.producer()}) or
                envelope.authority_class != event['authority_class'] or
                envelope.payload_digest != _sha(envelope.payload_bytes) or
                any(event.get(k) != v for k, v in self._u04_common(actor, event['record_type'],
                    event['authority_class'], False).items())):
            raise AuthorizationDenied('exact closed captured RP envelope required')
        self._validate_rp_payload(event)

    def _validate_rp_payload(self, event):
        validate_rp_record(event)
        binding = self._rp_binding
        kind = event['record_type']
        subject = self._rp_intent_for(event)
        operation = event['operation'] if kind == 'RECOVERY_PUBLICATION_ACCEPTED' else 'QUERY'
        port, source = self._validate_rp_subject(binding, subject, operation)
        if kind == 'RECOVERY_PUBLICATION_INTENT':
            return
        if kind == 'RECOVERY_PUBLICATION_ACCEPTED':
            grant = self._rp_grants.get(event['grant_id'])
            if (grant is None or grant.binding is not binding or
                    parse_closed_canonical(grant.canonical_bytes) != {k: event[k] for k in RP_GRANT_FIELDS} or
                    event['boot_id'] != source['boot_id'] or
                    any(f['event'].get('grant_id') == event['grant_id'] for f in self._committed_frames())):
                raise AuthorizationDenied('registered unconsumed exact RP grant required')
            port.validate_precondition(binding, subject, event['operation'])
            if event['previous_result_ref'] is not None:
                prior = self._exact_ref(event['previous_result_ref'])['event']
                if (prior.get('record_type') != 'RECOVERY_PUBLICATION_RESULT' or
                        self._rp_object_identity(prior) != self._rp_object_identity(subject)):
                    raise AuthorizationDenied('exact same-object prior result required')
            if event['continuation_owner_receipt'] is not None:
                receipt, _ = port.authenticate_receipt(self._object_proof(event['continuation_owner_receipt']))
                if receipt['outcome'] != 'OWNED_EMPTY_RESERVED' or receipt['original_intent_ref'] != subject['original_intent_ref']:
                    raise AuthorizationDenied('exact original owned-empty proof required')
        elif kind == 'RECOVERY_PUBLICATION_RESULT':
            if event['query_or_grant'] == 'GRANT':
                accepted = self._exact_ref(event['acceptance_ref'])['event']
                if (accepted.get('record_type') != 'RECOVERY_PUBLICATION_ACCEPTED' or
                        any(accepted[k] != event[k] for k in RP_PUBLICATION_FIELDS)):
                    raise AuthorizationDenied('exact committed RP acceptance required')
                actual = (self._object_proof(event['destination_receipt'])
                          if event['destination_receipt'] is not None else None)
                if port._grant_results.get(accepted['grant_id']) != (actual, event['reason_code']):
                    raise AuthorizationDenied('destination result must belong to this exact consumed grant')
            if event['destination_receipt'] is None:
                missing = (not port.available or subject['object_key'] not in port._subjects or
                    subject.get('original_or_supplement') == 'SUPPLEMENT' and
                    subject['object_key'] not in port._reserved_subjects or
                    subject['logical_operation_id'] not in port._operations or
                    port.operation_id(source, 'ENSURE_EXACT_OBJECT') not in port._operations)
                unavailable = (missing and event['reason_code'] == 'DESTINATION_REGISTRY_UNAVAILABLE' or
                    not port.readback_available and event['reason_code'] == 'READBACK_UNAVAILABLE')
                if not unavailable:
                    raise AuthorizationDenied('independent destination unavailability required')
            else:
                proof_bytes = self._object_proof(event['destination_receipt'])
                receipt, raw = port.authenticate_receipt(proof_bytes)
                if event['reason_code'] != port.observation_reason(proof_bytes):
                    raise AuthorizationDenied('exact independently supported observation reason required')
                for k in ('original_intent_ref', 'destination_id', 'object_key', 'logical_operation_id',
                          'authorization_digest', 'campaign_id', 'outcome'):
                    if receipt[k] != event[k]:
                        raise AuthorizationDenied('destination result substitution')
                if event['outcome'] == 'VERIFIED' and (raw != source['source_bytes'] or
                        not receipt['object_durable'] or not receipt['namespace_durable']):
                    raise AuthorizationDenied('exact independent bytes and both durability proofs required')
        else:
            for ref in event['result_refs']:
                result = self._exact_ref(ref)['event']
                if (result.get('record_type') != 'RECOVERY_PUBLICATION_RESULT' or
                        result.get('outcome') != 'VERIFIED' or
                        any(result[k] != event[k] for k in RP_PUBLICATION_FIELDS)):
                    raise AuthorizationDenied('exact verified linked destination result required')
            for name in ('durability_receipt', 'independent_readback', 'namespace_ack'):
                receipt, raw = port.authenticate_receipt(self._object_proof(event[name]))
                if (receipt['outcome'] != 'VERIFIED' or raw != source['source_bytes'] or
                        not receipt['object_durable'] or not receipt['namespace_durable'] or
                        receipt['object_key'] != subject['object_key'] or
                        receipt['original_intent_ref'] != subject['original_intent_ref']):
                    raise AuthorizationDenied('independent same-object complete publication proof required')

    def validate_rp_initiation(self, grant):
        with self.authorization_lock:
            if type(grant) is not RecoveryPublicationGrant:
                raise AuthorizationDenied('opaque RP grant required')
            actor = self._require_rp_binding(grant.binding)
            payload = parse_closed_canonical(grant.canonical_bytes)
            if self._rp_grants.get(payload['grant_id']) is not grant:
                raise AuthorizationDenied('historical or copied grant cannot initiate')
            frames = [f for f in self._committed_frames() if f['event'].get('record_type') ==
                      'RECOVERY_PUBLICATION_ACCEPTED' and f['event'].get('grant_id') == payload['grant_id']]
            if len(frames) != 1 or not self.witness.acknowledged_current(actor, frames[0]['event_id']):
                raise AuthorizationDenied('exact independent RP acceptance acknowledgement required')
            event = frames[0]['event']
            intents = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'RECOVERY_PUBLICATION_INTENT' and
                f['event'].get('logical_operation_id') == payload['logical_operation_id']]
            if not intents or self._reference(intents[-1]['receipt']) != payload['recovery_intent_ref']:
                raise AuthorizationDenied('superseded recovery operation cannot initiate')
            if {k: event[k] for k in RP_GRANT_FIELDS} != payload:
                raise AuthorizationDenied('accepted grant bytes differ')
            subject = self._rp_intent_for(event)
            port, source = self._validate_rp_subject(grant.binding, subject, payload['operation'])
            return actor, payload, subject, port, source, self._reference(frames[0]['receipt'])

    def _retain_rp_receipt(self, binding, subject, raw):
        actor = self._require_rp_binding(binding)
        port, _ = self._validate_rp_subject(binding, subject, 'QUERY')
        receipt, _ = port.authenticate_receipt(raw)
        if any(receipt[k] != subject[k] for k in ('original_intent_ref', 'destination_id',
                                                'object_key', 'logical_operation_id')):
            raise AuthorizationDenied('exact requested destination receipt required')
        object_id = 'rp-proof-' + _sha(raw)
        self._rp_proofs[object_id] = (binding, subject, raw)
        try:
            self.put_object(object_id, raw, actor=actor, boundary='RP')
        finally:
            self._rp_proofs.pop(object_id, None)
        return {'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)}

    def _record_rp_result(self, binding, subject, raw, reason, accepted_ref=None, *, fault=None):
        actor = self._require_rp_binding(binding)
        port, source = self._validate_rp_subject(binding, subject, 'QUERY')
        # This lower result entry point validates the complete observation
        # before its first immutable object write, not only at journal commit.
        if raw is None:
            missing = (not port.available or subject['object_key'] not in port._subjects or
                subject.get('original_or_supplement') == 'SUPPLEMENT' and
                subject['object_key'] not in port._reserved_subjects or
                subject['logical_operation_id'] not in port._operations or
                port.operation_id(source, 'ENSURE_EXACT_OBJECT') not in port._operations)
            if not (missing and reason == 'DESTINATION_REGISTRY_UNAVAILABLE' or
                    not port.readback_available and reason == 'READBACK_UNAVAILABLE'):
                raise AuthorizationDenied('independently proven observation unavailability required')
        else:
            observed, content = port.authenticate_receipt(raw)
            if (reason != port.observation_reason(raw) or
                    any(observed[k] != subject[k] for k in ('original_intent_ref', 'destination_id',
                        'object_key', 'logical_operation_id')) or
                    observed['authorization_digest'] != actor.authorization_digest or
                    observed['campaign_id'] != actor.campaign_id or
                    observed['outcome'] == 'VERIFIED' and (content != source['source_bytes'] or
                        not observed['object_durable'] or not observed['namespace_durable'])):
                raise AuthorizationDenied('exact authenticated destination observation required')
        if accepted_ref is not None:
            accepted = self._exact_ref(accepted_ref)['event']
            if (accepted.get('record_type') != 'RECOVERY_PUBLICATION_ACCEPTED' or
                    any(accepted[k] != subject[k] for k in RP_PUBLICATION_FIELDS) or
                    port._grant_results.get(accepted['grant_id']) != (raw, reason)):
                raise AuthorizationDenied('exact accepted original destination initiation/result required')
        proof = self._retain_rp_receipt(binding, subject, raw) if raw is not None else None
        event = self._u04_common(actor, 'RECOVERY_PUBLICATION_RESULT', 'EVIDENCE', False)
        event.update({k: copy.deepcopy(subject[k]) for k in RP_PUBLICATION_FIELDS})
        event.update(acceptance_ref=accepted_ref, query_or_grant='GRANT' if accepted_ref else 'QUERY',
            outcome=json.loads(raw)['outcome'] if raw is not None else 'UNKNOWN',
            destination_receipt=proof, reason_code=reason)
        receipt = self._commit_u04(actor, 'RP', event, fault=fault)
        conflict = self._independent_rp_conflict(event)
        if conflict:
            self.witness.deny_campaign(actor, 'PUBLICATION_INTEGRITY_CONFLICT',
                [f['envelope'] for f in self._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
        if event['outcome'] in ('UNKNOWN', 'PARTIAL', 'CONTENT_CONFLICT', 'OWNER_CONFLICT', 'EXACT_PRESENT'):
            writer = self.recovery_writer_binding(actor)
            self.record_recovery_obligation(writer, obligation_id='publication-obligation-' + receipt.event_id,
                kind='PUBLICATION_UNVERIFIED', reason_code=reason or 'DURABILITY_UNPROVEN',
                subject_refs=[subject['original_intent_ref'], self._reference(receipt)],
                target_ref={'kind': 'DESTINATION', 'identity': self._rp_port(binding.authorization,
                    subject['destination_id']).port_identity, 'destination_id': subject['destination_id'],
                    'object_key': subject['object_key'], 'subject_ref': subject['original_intent_ref'],
                    'subject_state': 'KNOWN', 'evidence_ref': proof,
                    'evidence_state': 'AVAILABLE' if proof is not None else 'UNAVAILABLE'})
        if conflict:
            self.mirror_denial(actor)
        return receipt

    def query_recovery_publication(self, binding, subject, *, intent_fault=None, result_fault=None):
        with self.authorization_lock:
            actor = self._require_rp_binding(binding)
            port, _ = self._validate_rp_subject(binding, subject, 'QUERY')
            event = self._u04_common(actor, 'RECOVERY_PUBLICATION_INTENT', 'EVIDENCE', False)
            event.update(copy.deepcopy(subject))
            # Exact key closure rejects arbitrary request fields before D mutation.
            validate_rp_record(event)
            committed = self._commit_u04(actor, 'RP', event, fault=intent_fault)
            if subject['original_or_supplement'] == 'SUPPLEMENT' and port.available:
                port.register_supplement(binding, subject, self._reference(committed))
            if port.available and subject['object_key'] in port._subjects:
                port.exclude_original_writers(binding, subject)
            raw, reason = port.observe(binding, subject)
            return self._record_rp_result(binding, subject, raw, reason, fault=result_fault)

    def perform_recovery_publication(self, binding, subject, operation, *, fault_at=None, fault=None):
        with self.authorization_lock:
            actor = self._require_rp_binding(binding)
            port, source = self._validate_rp_subject(binding, subject, operation)
            # This compound operation also observes and persists its result.
            self._validate_rp_subject(binding, subject, 'QUERY')
            intent = self._u04_common(actor, 'RECOVERY_PUBLICATION_INTENT', 'EVIDENCE', False)
            intent.update(copy.deepcopy(subject))
            validate_rp_record(intent)
            if operation in ('ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                verified = [f for f in self._committed_frames() if f['event'].get('record_type') ==
                    'RECOVERY_PUBLICATION_VERIFIED' and
                    self._rp_object_identity(f['event']) == self._rp_object_identity(subject)]
                if verified:
                    return verified[-1]['receipt']
                old = port._operations.get(subject['logical_operation_id'])
                if old is not None and old['status'] == 'COMPLETE':
                    result = self.query_recovery_publication(binding, subject)
                    if (operation == 'VERIFY_EXACT_OBJECT' and
                            self._exact_ref(self._reference(result))['event']['outcome'] == 'VERIFIED'):
                        return self._complete_rp_verification(binding, subject, result,
                            fault=fault if fault_at == 'verified' else None)
                    return result
            port.validate_precondition(binding, subject, operation)
            intent_ref = self._reference(self._commit_u04(actor, 'RP', intent,
                fault=fault if fault_at == 'intent' else None))
            if subject['original_or_supplement'] == 'SUPPLEMENT':
                port.register_supplement(binding, subject, intent_ref)
            port.exclude_original_writers(binding, subject)
            before, _ = port.observe(binding, subject)
            owner_ref = self._retain_rp_receipt(binding, subject, before) if operation == 'CONTINUE_RESERVED_EXACT' else None
            prior = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT' and
                self._rp_object_identity(f['event']) == self._rp_object_identity(subject)]
            accepted = self._u04_common(actor, 'RECOVERY_PUBLICATION_ACCEPTED', 'EVIDENCE_RECOVERY', False)
            accepted.update({k: copy.deepcopy(subject[k]) for k in RP_PUBLICATION_FIELDS})
            identity = '%s-rp-%d' % (actor.incarnation_id, self.revision + 1)
            accepted.update(grant_id=identity, consumption_id=identity + '-consumption',
                recovery_intent_ref=intent_ref, boot_id=source['boot_id'], operation=operation,
                recovery_writer_id=actor.owner_identity, chain_position='FOLLOWUP' if prior else 'INITIAL',
                previous_result_ref=self._reference(prior[-1]['receipt']) if prior else None,
                continuation_owner_receipt=owner_ref)
            grant = RecoveryPublicationGrant(binding,
                _u04_canonical({k: accepted[k] for k in RP_GRANT_FIELDS}), object())
            self._rp_grants[identity] = grant
            accepted_ref = self._reference(self._commit_u04(actor, 'RP', accepted,
                fault=fault if fault_at == 'accepted' else None))
            port.arm_recovery_grant(grant)
            raw, reason = port.initiate_recovery(grant, fault=fault if fault_at == 'destination' else None)
            result = self._record_rp_result(binding, subject, raw, reason, accepted_ref,
                fault=fault if fault_at == 'result' else None)
            if operation != 'VERIFY_EXACT_OBJECT':
                return result
            return self._complete_rp_verification(binding, subject, result,
                fault=fault if fault_at == 'verified' else None)

    def _complete_rp_verification(self, binding, subject, result, *, fault=None):
        """Commit independently verified history, including a lost effect response.

        This path never claims or starts a destination operation. The RP writer
        repeats all result/receipt validation before committing the closed record.
        """
        with self.authorization_lock:
            actor = self._require_rp_binding(binding)
            self._validate_rp_subject(binding, subject, 'VERIFY_EXACT_OBJECT')
            shape = self._u04_common(actor, 'RECOVERY_PUBLICATION_INTENT', 'EVIDENCE', False)
            shape.update(copy.deepcopy(subject))
            validate_rp_record(shape)
            proof = self._exact_ref(self._reference(result))['event']['destination_receipt']
            verified = self._u04_common(actor, 'RECOVERY_PUBLICATION_VERIFIED', 'EVIDENCE', False)
            verified.update({k: copy.deepcopy(subject[k]) for k in RP_PUBLICATION_FIELDS})
            verified.update(result_refs=[self._reference(result)], durability_receipt=proof,
                independent_readback=proof, namespace_ack=proof)
            return self._commit_u04(actor, 'RP', verified, fault=fault)

    def _require_recovery_writer(self, binding, actor=None):
        if (type(binding) is not RecoveryWriterBinding or binding is not self._recovery_writer or
                binding.actor is not self._current_actor or actor is not None and binding.actor is not actor):
            raise AuthorizationDenied('exact current opaque RW binding required')
        self.require_actor(binding.actor, 'RW')
        self._check_healthy()
        return binding.actor

    def record_recovery_entry(self, binding, *, fault=None):
        with self.authorization_lock:
            actor = self._require_recovery_writer(binding)
            entries = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'SUPERVISOR_INCARNATION' and
                f['event'].get('incarnation_id') == actor.incarnation_id]
            if len(entries) != 1:
                raise AuthorizationDenied('exact current nonlive entry proof required')
            event = self._u04_common(actor, 'RECOVERY_ENTRY', 'EVIDENCE', False)
            event.update(entry_refs=entries[0]['event']['entry_refs'], health_at_entry='HEALTHY',
                latch_state='SET' if self.witness.denial(actor) else 'CLEAR',
                checkpoint_ref=self._reference(entries[0]['receipt']))
            return self._commit_u04(actor, 'RW', event, fault=fault)

    def record_recovery_obligation(self, binding, *, obligation_id, kind, reason_code,
                                   subject_refs, target_ref, fault=None):
        with self.authorization_lock:
            actor = self._require_recovery_writer(binding)
            event = self._u04_common(actor, 'RECOVERY_OBLIGATION', 'EVIDENCE', False)
            event.update(obligation_id=obligation_id, kind=kind, reason_code=reason_code,
                         subject_refs=copy.deepcopy(subject_refs), target_ref=copy.deepcopy(target_ref), status='OPEN')
            return self._commit_u04(actor, 'RW', event, fault=fault)

    def record_recovery_supplement(self, binding, *, parent_ref, supplement_kind,
                                   evidence_bytes, source_id, verifier_id,
                                   obligation_ref=None, fault=None):
        with self.authorization_lock:
            actor = self._require_recovery_writer(binding)
            if type(evidence_bytes) is not bytes:
                raise AuthorizationDenied('exact independently verified evidence bytes required')
            event = self._u04_common(actor, 'RECOVERY_SUPPLEMENT', 'EVIDENCE', False)
            object_id = 'recovery-evidence-' + _sha(evidence_bytes)
            event.update(parent_ref=copy.deepcopy(parent_ref), parent_digest=parent_ref['payload_digest'],
                obligation_ref=copy.deepcopy(obligation_ref), obligation_link='NONE' if obligation_ref is None else 'LINKED',
                supplement_kind=supplement_kind,
                evidence={'object_id': object_id, 'sha256': _sha(evidence_bytes), 'length': len(evidence_bytes)},
                source_id=source_id, verifier_id=verifier_id)
            # Validate provenance before any D mutation, and repeat at the lower writer.
            self._validate_recovery_payload(event, evidence_bytes=evidence_bytes)
            self.put_object(object_id, evidence_bytes, actor=actor, boundary='RW')
            self._object_proof(event['evidence'])
            return self._commit_u04(actor, 'RW', event, fault=fault)

    def _validate_rw_envelope(self, actor, envelope):
        self._require_recovery_writer(self._recovery_writer, actor)
        self.read_verified(0)
        event=parse_closed_canonical(envelope.payload_bytes)
        if (envelope.authority_class!='EVIDENCE' or
                envelope.authority_fact_bytes!=_u04_canonical({'producer':actor.producer()}) or
                envelope.payload_digest!=_sha(envelope.payload_bytes) or
                any(event.get(k)!=v for k,v in self._u04_common(actor,event.get('record_type'),'EVIDENCE',False).items())):
            raise AuthorizationDenied('closed captured RW transaction binding required')
        self._validate_recovery_payload(event)

    def _validate_recovery_payload(self, event, *, evidence_bytes=None):
        validate_recovery_record(event)
        kind = event['record_type']
        if kind == 'RECOVERY_ENTRY':
            entry = self._exact_ref(event['checkpoint_ref'])
            if (entry['event'].get('record_type') != 'SUPERVISOR_INCARNATION' or
                    entry['event'].get('incarnation_id') != event['writer_incarnation_id'] or
                    entry['event'].get('mode') not in ('RECOVERY', 'TERMINAL') or
                    event['entry_refs'] != entry['event']['entry_refs']):
                raise AuthorizationDenied('recovery entry must report its exact original entry')
            for ref in event['entry_refs']: self._exact_ref(ref)
            expected = 'SET' if self.witness.denial(self._current_actor) else 'CLEAR'
            if event['latch_state'] != expected:
                raise AuthorizationDenied('entry latch observation mismatch')
        elif kind == 'RECOVERY_OBLIGATION':
            if any(f['event'].get('obligation_id') == event['obligation_id'] for f in self._committed_frames()):
                raise AuthorizationDenied('immutable obligation identity already used')
            for ref in event['subject_refs']: self._exact_ref(ref)
            target = event['target_ref']
            if target['subject_ref'] is not None: self._exact_ref(target['subject_ref'])
            if target['evidence_ref'] is not None: self._object_proof(target['evidence_ref'])
            if target['kind'] == 'DESTINATION':
                self._validate_destination_obligation(event)
            if target['kind'] in ('CUSTODIAN','LOCAL_EVIDENCE'):
                self._custodian.validate_containment_obligation(event)
            if target['kind'] == 'EFFECT':
                accepted = [f for f in self._committed_frames() if f['event'].get('record_type') ==
                    'EFFECT_ACCEPTED' and f['event'].get('effect_id') == target['identity']]
                if not accepted:
                    self._custodian.validate_containment_obligation(event)
                else:
                    if (len(accepted)!=1 or event['kind']!='EFFECT_RESULT_UNRESOLVED' or
                            target['subject_state']!='KNOWN' or target['subject_ref']!=self._reference(accepted[0]['receipt']) or
                            target['subject_ref'] not in event['subject_refs']):
                        raise AuthorizationDenied('exact original accepted effect obligation required')
                    results=[f for f in self._committed_frames() if f['event'].get('record_type')=='EFFECT_RESULT' and
                        f['event'].get('effect_id')==target['identity']]
                    reason=event['reason_code']
                    if reason=='OUTCOME_UNKNOWN':
                        valid=not results
                    elif reason=='RESULT_UNAVAILABLE':
                        valid=bool(results) and results[0]['event']['result']['object_id'] not in self._objects
                    else:
                        # No caller assertion can invent independent no-start or
                        # mismatch proof for an original execution port. The B C
                        # operation branch separately verifies those observations.
                        valid=False
                    if not valid:raise AuthorizationDenied('truthful unresolved original effect result required')
        else:
            parent = self._exact_ref(event['parent_ref'])
            if event['parent_digest'] != parent['receipt'].event_digest:
                raise AuthorizationDenied('supplement parent digest substitution')
            if event['obligation_ref'] is not None:
                obligation = self._exact_ref(event['obligation_ref'])['event']
                if (obligation.get('record_type') != 'RECOVERY_OBLIGATION' or
                        event['parent_ref'] not in obligation['subject_refs']):
                    raise AuthorizationDenied('exact matching OPEN obligation required')
            raw = self._object_proof(event['evidence']) if evidence_bytes is None else evidence_bytes
            if _sha(raw) != event['evidence']['sha256'] or len(raw) != event['evidence']['length']:
                raise AuthorizationDenied('exact evidence object required')
            if event['supplement_kind']=='PUBLICATION_READBACK':
                result = parent['event']
                if (result.get('record_type') != 'RECOVERY_PUBLICATION_RESULT' or
                        result.get('outcome') != 'VERIFIED' or
                        result.get('destination_receipt') is None or
                        raw != self._object_proof(result['destination_receipt'])):
                    raise AuthorizationDenied('exact corresponding committed RP readback result required')
                port = self._rp_port(self._admitted_payload(), result['destination_id'])
                receipt, readback = port.authenticate_receipt(raw)
                if (event['source_id'] != port.port_identity or event['verifier_id'] != port.port_identity or
                        receipt['outcome'] != 'VERIFIED' or not receipt['object_durable'] or
                        not receipt['namespace_durable'] or
                        readback != self._object_proof(result['source_object'])):
                    raise AuthorizationDenied('exact independently authenticated publication readback required')
            elif event['supplement_kind'] == 'VERIFIED_EFFECT_RESULT':
                parsed = parse_effect_result_record(_u04_canonical(parent['event']))
                if (type(parsed) is not U04EffectResultRecord or
                        raw != self._object_proof(asdict(parsed.result)) or
                        event['verifier_id'] != parsed.verifier_id or event['source_id'] != parsed.verifier_id):
                    raise AuthorizationDenied('explicit versioned exact verified result required')
                self._validate_result_payload(self._current_actor, parsed)
            else:
                self._custodian.validate_recovery_supplement(parent, event, raw)

    def _validate_destination_obligation(self, event):
        target = event['target_ref']
        auth = self._admitted_payload()
        ports = [p for p in self._publication_destinations if p.destination_id == target['destination_id']]
        if len(ports) != 1 or ports[0]._store is not self:
            raise AuthorizationDenied('actual pinned destination required even for authorization failure')
        port = ports[0]
        original = self._exact_ref(target['subject_ref']) if target['subject_ref'] is not None else None
        if (event['kind'] != 'PUBLICATION_UNVERIFIED' or target['identity'] != port.port_identity or
                target['subject_state'] != 'KNOWN' or original is None or
                original['event'].get('operation') != 'intent' or
                not self.publication_record_provenanced(original, phase='INTENT')):
            raise AuthorizationDenied('actual authorized destination and exact original subject required')
        if event['reason_code'] in ('AUTHORIZATION_MISSING', 'DESTINATION_UNAUTHORIZED'):
            # A proven failure concerns an actual original object, never an
            # arbitrary target named by a caller or allowlist membership alone.
            source = port._known(target['subject_ref'], target['object_key'])
            actual = (original['event'].get('destination') == target['destination_id'] and
                original['event'].get('object_key') == target['object_key'] and
                source['authorization_digest'] == auth.authorization_digest and
                event['subject_refs'] == [target['subject_ref']] and
                target['evidence_state'] == 'UNAVAILABLE' and target['evidence_ref'] is None)
            destination_allowed = any(r.destination_id == target['destination_id'] and
                r.port_identity == port.port_identity for r in auth.destination_rules)
            object_allowed = any(r.destination_id == target['destination_id'] and
                r.object_key == target['object_key'] and r.subject_id == source['subject_id'] and
                r.evidence_kind == source['evidence_kind'] for r in auth.object_rules)
            missing = (not auth.exact_byte_recovery_authorized or
                self._current_actor.owner_identity not in auth.recovery_publisher_ids or
                'VERIFY_EXACT' not in auth.evidence_operations)
            if not actual or not (missing if event['reason_code'] == 'AUTHORIZATION_MISSING'
                                  else not destination_allowed or not object_allowed):
                raise AuthorizationDenied('precisely proven original publication authorization failure required')
            return
        self._rp_port(auth, target['destination_id'])
        results = [self._exact_ref(r)['event'] for r in event['subject_refs']]
        results = [r for r in results if r.get('record_type') == 'RECOVERY_PUBLICATION_RESULT' and
            r.get('original_intent_ref') == target['subject_ref'] and
            r.get('destination_id') == target['destination_id'] and r.get('object_key') == target['object_key']]
        if len(results) != 1 or target['subject_ref'] not in event['subject_refs']:
            raise AuthorizationDenied('one exact committed destination observation required')
        result = results[0]
        subject = self._rp_intent_for(result)
        if subject['original_or_supplement'] == 'SUPPLEMENT':
            self._validate_rp_supplement_subject(auth, subject, 'QUERY', original)
        else:
            rules = [r for r in auth.object_rules if r.rule_id == subject['policy_rule_id'] and
                     r.subject_id == subject['subject_id'] and r.destination_id == target['destination_id'] and
                     r.object_key == target['object_key']]
            if len(rules) != 1:
                raise AuthorizationDenied('exact destination object policy required')
        if result['destination_receipt'] is None:
            missing = (not port.available or target['object_key'] not in port._subjects or
                subject.get('original_or_supplement') == 'SUPPLEMENT' and
                target['object_key'] not in port._reserved_subjects or
                result['logical_operation_id'] not in port._operations)
            unavailable = (missing and result['reason_code'] == 'DESTINATION_REGISTRY_UNAVAILABLE' or
                not port.readback_available and result['reason_code'] == 'READBACK_UNAVAILABLE')
            valid = (unavailable and result['outcome'] == 'UNKNOWN' and
                result['reason_code'] == event['reason_code'] and
                target['evidence_state'] == 'UNAVAILABLE' and target['evidence_ref'] is None)
        else:
            receipt, _ = port.authenticate_receipt(self._object_proof(result['destination_receipt']))
            reason = {'PARTIAL': 'PARTIAL_OBJECT', 'CONTENT_CONFLICT': 'CONTENT_MISMATCH',
                'OWNER_CONFLICT': 'RESERVATION_OWNER_MISMATCH', 'UNKNOWN': result['reason_code'],
                'EXACT_PRESENT': 'DURABILITY_UNPROVEN'}.get(receipt['outcome'])
            valid = (reason is not None and event['reason_code'] == reason and
                target['evidence_state'] == 'AVAILABLE' and target['evidence_ref'] == result['destination_receipt'] and
                all(receipt[k] == result[k] for k in ('original_intent_ref', 'destination_id',
                    'object_key', 'logical_operation_id', 'authorization_digest', 'campaign_id', 'outcome')))
        if not valid:
            raise AuthorizationDenied('independently supported destination condition required')

    def _independent_rp_conflict(self, event):
        if event.get('outcome') not in ('PARTIAL', 'CONTENT_CONFLICT', 'OWNER_CONFLICT'):
            return False
        try:
            proof = event['destination_receipt']
            raw = self._object_proof(proof)
            # Caller holds authorization exclusion, including direct W entry.
            ports = [p for p in self._publication_destinations if p.destination_id == event['destination_id']]
            if len(ports) != 1:
                return False
            receipt, _ = ports[0].authenticate_receipt(raw)
            return (receipt['outcome'] == event['outcome'] and
                receipt['operation_status'] in ('NOT_STARTED', 'COMPLETE') and
                all(receipt[k] == event[k] for k in ('original_intent_ref', 'destination_id',
                    'object_key', 'logical_operation_id', 'authorization_digest', 'campaign_id')))
        except (ContractError, StoreError, KeyError, TypeError):
            return False

    def mirror_denial(self, actor):
        """A failed D mirror never changes the independent irreversible W latch."""
        with self.authorization_lock:
            self.require_actor(actor, 'DENY')
            denial = self.witness.denial(actor)
            if denial is None:
                raise AuthorizationDenied('no positive witness denial to mirror')
            if any(f['event'].get('record_type') == 'CAMPAIGN_EXECUTION_DENIED' for f in self._committed_frames()):
                return
            event = self._u04_common(actor, 'CAMPAIGN_EXECUTION_DENIED', 'DENIAL', False)
            event.update(trigger_code=denial[0], trigger_refs=[
                self._reference(self.event_receipt(identity)) for identity in denial[1]],
                witness_latch_receipt=_sha(_u04_canonical([self.witness.identity, denial])))
            return self._commit_u04(actor, 'DENY', event)

    def _admitted_payload(self):
        from .contracts import authorization_from_record
        frames = [f for f in self._committed_frames() if f['event'].get('state') == 'AUTHORIZATION_ADMITTED']
        if len(frames) != 1:
            raise AuthorizationDenied('unique original admitted authorization required')
        event = frames[0]['event']
        payload = json.loads(bytes.fromhex(event['canonical_authorization_hex']))
        payload['authorization_digest'] = event['authorization_digest']
        authorization = authorization_from_record(payload)
        self.validate_admitted_authorization(authorization)
        return authorization

    @staticmethod
    def _reference(receipt):
        return {'event_id': receipt.event_id, 'revision': receipt.revision,
                'payload_digest': receipt.event_digest}

    def _exact_ref(self, ref):
        parsed = JournalReference(**ref)
        receipt = self.event_receipt(parsed.event_id)
        if receipt is None or self._reference(receipt) != ref:
            raise AuthorizationDenied('exact witnessed predecessor reference required')
        return self._durable[receipt.revision - 1]

    def _object_proof(self, ref):
        parsed = ImmutableObjectReference(**ref)
        raw = self.read_object(parsed.object_id, parsed.sha256)
        if len(raw) != parsed.length:
            raise AuthorizationDenied('exact object proof length mismatch')
        return raw

    def open_execution_effects(self):
        frames = self._committed_frames()
        results = {f['event'].get('effect_id') for f in frames if f['event'].get('record_type') == 'EFFECT_RESULT'}
        return tuple(f['event']['effect_id'] for f in frames if
            (f['event'].get('record_type') == 'EFFECT_ACCEPTED' or
             (f['event'].get('operation') == 'blocked-create' and
              f['event'].get('state') == 'SPAWN_INTENT_PERSISTED')) and
            f['event']['effect_id'] not in results)

    def validate_publication_initiation(self, actor, grant, planned):
        """Independent effect port repeats captured-actor and W-ack checks."""
        with self.authorization_lock:
            self._publication_issuance(grant, actor)
            self._check_healthy()
            accepted = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_ACCEPTED' and f['event'].get('effect_id') == grant.grant_id]
            if len(accepted) != 1 or not self.witness.acknowledged_current(actor, accepted[0]['event_id']):
                raise AuthorizationDenied('current durable acceptance acknowledgement required')
            original = self._exact_ref(accepted[0]['event']['intent_ref'])
            if original['event'] != planned or not self.publication_record_provenanced(original, phase='INTENT'):
                raise AuthorizationDenied('effect port requires exactly the accepted publication request')
            self.validate_artifact_continuity(ArtifactBinding(**accepted[0]['event']['artifact_binding']))
            self.require_actor(actor)
            return original

    def record_publication_effect_result(self, actor, grant):
        with self.authorization_lock:
            self.require_actor(actor, 'RESULT')
            accepted = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_ACCEPTED' and f['event'].get('effect_id') == grant.grant_id]
            if len(accepted) != 1:
                raise AuthorizationDenied('exact accepted publication operation required')
            raw = self._persist_port_observation(actor, grant.grant_id)
            existing = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_RESULT' and f['event'].get('effect_id') == grant.grant_id]
            if existing:
                parsed = parse_effect_result_record(_u04_canonical(existing[0]['event']))
                self._validate_result_payload(actor, parsed)
                return existing[0]['receipt']
            object_id = 'publication-effect-result-' + grant.grant_id
            self.put_object(object_id, raw, actor=actor, boundary='RESULT')
            event = self._u04_common(actor, 'EFFECT_RESULT', 'EVIDENCE', False)
            event.update(acceptance_ref=self._reference(accepted[0]['receipt']), effect_id=grant.grant_id,
                original_producer_ref=accepted[0]['event']['intent_ref'], result={
                    'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)},
                result_kind='EFFECT_PORT_RECEIPT', verifier_id=self._custodian.identity)
            return self._commit_u04(actor, 'RESULT', event)

    def record_control_effect_result(self, actor, capability):
        with self.authorization_lock:
            self.require_actor(actor, 'RESULT')
            accepted = self._acceptance_frame(capability)
            raw = self._persist_port_observation(actor, capability.effect_id)
            object_id = 'control-effect-result-' + capability.effect_id
            self.put_object(object_id, raw, actor=actor, boundary='RESULT')
            event = self._u04_common(actor, 'EFFECT_RESULT', 'EVIDENCE', False)
            event.update(acceptance_ref=self._reference(accepted['receipt']), effect_id=capability.effect_id,
                original_producer_ref=accepted['event']['intent_ref'], result={
                    'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)},
                result_kind='EFFECT_PORT_RECEIPT', verifier_id=self._custodian.identity)
            return self._commit_u04(actor, 'RESULT', event)

    def _shutdown_binding(self, authorization):
        self.validate_admitted_authorization(authorization)
        frames = self._committed_frames()
        handoffs = [f for f in frames if f['event'].get('operation') == 'begin-boot-handoff' and
                    self.frame_has_provenance(f)]
        if not handoffs:
            raise AuthorizationDenied('exact handoff required')
        handoff = handoffs[-1]
        ordinal = handoff['event']['boot_ordinal']
        closures = [f for f in self.provenanced_frames('BOOT_COMPLETE', 'complete-boot')
                    if f['event']['boot_ordinal'] == ordinal]
        candidates = [f for f in self.provenanced_frames('BOOT_CLOSURE_CANDIDATE_FINALIZED')
                      if f['event']['boot_ordinal'] == ordinal]
        if len(closures) != 1 or len(candidates) != 1 or ordinal >= 4:
            raise AuthorizationDenied('exact authorized predecessor closure required')
        closure, candidate = closures[0], candidates[0]
        if (closure['event']['candidate_event_digest'] != candidate['receipt'].event_digest or
                closure['receipt'].revision >= handoff['receipt'].revision or
                closure['event']['boot_id'] != self.boot_identity(ordinal)):
            raise AuthorizationDenied('shutdown predecessor identity/order mismatch')
        published = _closure_publication_proof(self, authorization, candidate,
            closure['event']['publication_manifest'], self.frame_index(closure['event_id']))
        binding = {'handoff_ref': self._reference(handoff['receipt']),
            'predecessor_ordinal': ordinal, 'predecessor_boot_id': closure['event']['boot_id'],
            'closure_digest': closure['receipt'].event_digest,
            'publication_digest': _sha(_u04_canonical(published)), 'next_ordinal': ordinal + 1}
        return binding

    def _validate_shutdown_payload(self, actor, event):
        self.require_actor(actor, 'SHUTDOWN')
        binding = self._shutdown_binding(self._admitted_payload())
        expected = set(self._u04_common(actor, 'PLANNED_SHUTDOWN_COMMITTED', 'CONTROL', False)) | set(binding) | {
            'shutdown_id', 'originating_generation', 'originating_incarnation_id',
            'originating_session_id', 'originating_fence', 'custodian_id', 'quiescence_ack', 'bundle_digest'}
        if (set(event) != expected or any(event[k] != v for k, v in binding.items()) or
                event['originating_generation'] != actor.generation or
                event['originating_incarnation_id'] != actor.incarnation_id or
                event['originating_session_id'] != actor.session_id or event['originating_fence'] != actor.fence or
                event['custodian_id'] != self._custodian.identity or self.open_execution_effects() or
                self._taint or self.witness.denial(actor) is not None):
            raise AuthorizationDenied('closed current shutdown proof required')
        ack = self._custodian.validate_quiescence(self._object_proof(event['quiescence_ack']))
        bundle = {k: v for k, v in event.items() if k not in ('quiescence_ack', 'bundle_digest')}
        if (event['shutdown_id'] != 'shutdown-' + actor.incarnation_id or
                event['bundle_digest'] != _sha(_u04_canonical(bundle)) or
                ack.store_identity != actor.store_identity or ack.authorization_digest != actor.authorization_digest or
                ack.campaign_id != actor.campaign_id or ack.session_id != actor.session_id or
                ack.predecessor_ordinal != binding['predecessor_ordinal'] or
                ack.predecessor_boot_id != binding['predecessor_boot_id'] or
                ack.handoff_digest != binding['handoff_ref']['payload_digest'] or
                ack.generation != actor.generation or ack.incarnation_id != actor.incarnation_id or
                ack.fence != actor.fence or ack.bundle_digest != event['bundle_digest'] or
                ack.closure_digest != binding['closure_digest'] or ack.publication_digest != binding['publication_digest'] or
                ack.next_ordinal != binding['next_ordinal']):
            raise AuthorizationDenied('quiescence proof binding mismatch')

    def commit_shutdown(self, actor, authorization, fault=None):
        with self.authorization_lock:
            self.require_actor(actor, 'SHUTDOWN')
            binding = self._shutdown_binding(authorization)
            event = self._u04_common(actor, 'PLANNED_SHUTDOWN_COMMITTED', 'CONTROL', False)
            event.update(binding, shutdown_id='shutdown-' + actor.incarnation_id,
                originating_generation=actor.generation, originating_incarnation_id=actor.incarnation_id,
                originating_session_id=actor.session_id, originating_fence=actor.fence,
                custodian_id=self._custodian.identity)
            event['bundle_digest'] = _sha(_u04_canonical(event))
            ack = self._custodian.attest_quiescence(actor, binding['predecessor_ordinal'],
                binding['predecessor_boot_id'], binding['next_ordinal'], binding['handoff_ref']['payload_digest'],
                binding['closure_digest'], binding['publication_digest'], event['bundle_digest'])
            raw = _u04_canonical(asdict(ack))
            object_id = 'shutdown-proof-' + actor.incarnation_id
            self.put_object(object_id, raw, actor=actor, boundary='SHUTDOWN')
            event['quiescence_ack'] = {'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)}
            return self._commit_u04(actor, 'SHUTDOWN', event, fault=fault)

    def waiting_shutdown(self, authorization):
        self.validate_admitted_authorization(authorization)
        frames = self._committed_frames()
        shutdowns = [f for f in frames if f['event'].get('record_type') == 'PLANNED_SHUTDOWN_COMMITTED']
        if not shutdowns:
            raise AuthorizationDenied('no qualifying pre-loss shutdown')
        frame = shutdowns[-1]
        envelope, event = frame['envelope'], frame['event']
        status, commit = self.witness.query_transaction(envelope.transaction_id)
        producer = json.loads(envelope.producer_bytes)
        frontier = self.witness._frontiers.get((self.identity, producer['generation'], producer['incarnation_id']))
        key = (self.identity, authorization.authorization_digest, authorization.campaign_id)
        later = frames[frame['receipt'].revision:]
        if (status != 'COMMITTED' or commit.completion_mode != 'ORIGIN' or frontier is None or
                frontier[0] < frame['receipt'].revision or key in self.witness._denials or
                self._taint or self.open_execution_effects() or
                any(f['event'].get('record_type') in ('ACTIVATION_RESERVED', 'ACTIVATION_ADMITTED') or
                    f['event'].get('state') == 'CAMPAIGN_COMPLETE' for f in later)):
            raise AuthorizationDenied('waiting requires complete ORIGIN exit before loss')
        binding = self._shutdown_binding(authorization)
        if any(event[k] != v for k, v in binding.items()):
            raise AuthorizationDenied('waiting predecessor changed')
        ack = self._custodian.validate_quiescence(self._object_proof(event['quiescence_ack']))
        if ack.bundle_digest != event['bundle_digest'] or ack.incarnation_id != producer['incarnation_id']:
            raise AuthorizationDenied('waiting quiescence identity mismatch')
        return frame

    def _validate_admission_payload(self, actor, event, facts=None):
        self.require_actor(actor, 'ADMIT')
        if event.get('record_type') == 'BOOT_ACTIVATION':
            from .contracts import BootActivation
            required = set(DEDICATED_OPERATIONS['consume-boot-activation']['BOOT_HANDOFF_PENDING']) | {
                'state', 'effect_id', 'state_domain', 'session_id', 'session_owner', 'session_live',
                'fence_epoch', 'boot_ordinal', 'session_boot_ordinal', 'supervisor_generation',
                'authorization_digest', 'campaign_id', 'target', 'operation', 'authorizes_execution',
                'dispatch_resolved', 'consumption', 'verification_id'}
            if (set(event) != required or type(facts) is not dict or set(facts) != {'activation_authentication'} or
                    event['authorizes_execution'] is not False or event['session_id'] != actor.session_id):
                raise AuthorizationDenied('closed non-executing activation authentication record')
            shutdown = self.waiting_shutdown(self._admitted_payload())
            activation = BootActivation(event['activation_id'], event['authorization_digest'],
                event['activated_boot_ordinal'], event['observed_boot_id'], event['predecessor_closure_digest'],
                self._admitted_payload().chair_identity, True)
            verified = self._activation_authentication_service.verify(activation,
                store_identity=self.identity, authorization=self._admitted_payload(),
                predecessor_digest=shutdown['event']['closure_digest'])
            if facts['activation_authentication'] != {
                    'verifier_id': verified.verifier_id, 'canonical_bytes_hex': verified.canonical_bytes.hex(),
                    'digest': verified.digest}:
                raise AuthorizationDenied('activation authentication evidence mismatch')
            if any(event.get(name) != value for name, value in {
                    'state': 'BOOT_HANDOFF_PENDING', 'state_domain': 'boot',
                    'effect_id': 'activation-authentication-' + activation.activation_id,
                    'session_owner': actor.owner_identity, 'session_live': False, 'fence_epoch': actor.fence,
                    'supervisor_generation': actor.generation,
                    'boot_ordinal': shutdown['event']['predecessor_ordinal'],
                    'session_boot_ordinal': shutdown['event']['predecessor_ordinal'],
                    'authorization_digest': actor.authorization_digest, 'campaign_id': actor.campaign_id,
                    'target': self.identity, 'operation': 'consume-boot-activation', 'dispatch_resolved': True,
                    'consumption': {'kind': 'effect', 'identity': 'activation-authentication-' + activation.activation_id},
                    'verification_id': verified.verifier_id}.items()):
                raise AuthorizationDenied('activation authentication must bind the actual waiting actor')
            return
        required = set(self._u04_common(actor, event.get('record_type'), 'CONTROL', False)) | {
            'activation_id', 'shutdown_ref', 'predecessor_closure_digest', 'next_boot_ordinal',
            'observed_boot_id', 'new_generation', 'new_incarnation_id', 'activation_authentication_ref'}
        if event.get('record_type') == 'ACTIVATION_ADMITTED':
            required |= {'reservation_ref', 'fresh_session', 'all_lower_fences_ack'}
            reservation = self._exact_ref(event['reservation_ref'])
            if (reservation['event'].get('record_type') != 'ACTIVATION_RESERVED' or
                    any(reservation['event'][k] != event[k] for k in (
                        'activation_id', 'shutdown_ref', 'predecessor_closure_digest', 'next_boot_ordinal',
                        'observed_boot_id', 'new_generation', 'new_incarnation_id', 'activation_authentication_ref'))):
                raise AuthorizationDenied('admission must match exact consumed reservation')
            self._custodian.validate_lower_fences(self._object_proof(event['all_lower_fences_ack']), actor)
            session = FenceSession(**event['fresh_session'])
            if session != FenceSession(actor.fence, actor.session_id, actor.owner_identity,
                                       event['next_boot_ordinal'], True) or facts is not None:
                raise AuthorizationDenied('fresh admitted session mismatch')
        elif event.get('record_type') == 'ACTIVATION_RESERVED':
            shutdown = self.waiting_shutdown(self._admitted_payload())
            if event['shutdown_ref'] != self._reference(shutdown['receipt']):
                raise AuthorizationDenied('reservation shutdown reference mismatch')
            if self.is_consumed('boot_activation', event['activation_id']):
                raise AuthorizationDenied('activation already consumed')
            if facts != {'consumptions': [['boot_activation', event['activation_id']]],
                         'incarnation': actor.producer()}:
                raise AuthorizationDenied('reserved activation and incarnation facts share one exact transaction')
        else:
            raise AuthorizationDenied('closed admission record required')
        if (set(event) != required or event['new_generation'] != actor.generation or
                event['new_incarnation_id'] != actor.incarnation_id):
            raise AuthorizationDenied('closed reserved incarnation required')
        authentication = self._exact_ref(event['activation_authentication_ref'])
        if (authentication['event'].get('record_type') != 'BOOT_ACTIVATION' or
                authentication['envelope'].boundary != 'ADMIT' or
                any(authentication['event'].get(old) != event[new] for old, new in (
                    ('activation_id', 'activation_id'), ('activated_boot_ordinal', 'next_boot_ordinal'),
                    ('observed_boot_id', 'observed_boot_id'),
                    ('predecessor_closure_digest', 'predecessor_closure_digest')))):
            raise AuthorizationDenied('exact independent activation authentication reference required')

    def admit_next_boot(self, authorization, activation, owner_identity, *, reservation_fault=None, admission_fault=None):
        with self.authorization_lock:
            try:
                return self._admit_next_boot(authorization, activation, owner_identity,
                    reservation_fault=reservation_fault, admission_fault=admission_fault)
            except BaseException:
                actor = self._current_actor
                if actor is not None and actor.mode == 'LIVE_PENDING':
                    try:
                        self.crash()
                    except StoreError:
                        pass
                    try:
                        self.witness.deny_frozen_campaign(self, actor, 'INTERRUPTED_ADMISSION',
                            [f['envelope'] for f in self._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                    except (StoreError, ContractError):
                        # Unreadable/pending evidence denies now. It does not
                        # invent a permanent trigger or permit admission repair.
                        pass
                raise

    def _admit_next_boot(self, authorization, activation, owner_identity, *, reservation_fault=None, admission_fault=None):
        with self.authorization_lock:
            shutdown = self.waiting_shutdown(authorization)
            self._custodian._ensure_live()
            event = shutdown['event']
            used_boots = {f['event'].get('boot_id') for f in self._committed_frames()}
            used_boots.update(f['event'].get('observed_boot_id') for f in self._committed_frames())
            if (type(activation) is not BootActivation or activation.authorization_digest != authorization.authorization_digest or
                    activation.chair_identity != authorization.chair_identity or activation.boot_ordinal != event['next_ordinal'] or
                    activation.predecessor_closure_digest != event['closure_digest'] or
                    activation.observed_boot_id in used_boots or self.is_consumed('boot_activation', activation.activation_id)):
                raise AuthorizationDenied('exact fresh unused successor activation required')
            if self._activation_authentication_service is None:
                raise AuthorizationDenied('independent activation authentication unavailable')
            verified = self._activation_authentication_service.verify(activation,
                store_identity=self.identity, authorization=authorization,
                predecessor_digest=event['closure_digest'])
            waiting = self._current_actor
            if waiting is None:
                waiting = self.open_nonlive_entry(authorization, owner_identity)
            self.require_actor(waiting, 'ADMIT')
            authentication = {'record_type': 'BOOT_ACTIVATION', 'activation_id': activation.activation_id,
                'activated_boot_ordinal': activation.boot_ordinal, 'observed_boot_id': activation.observed_boot_id,
                'predecessor_closure_digest': activation.predecessor_closure_digest,
                'state': 'BOOT_HANDOFF_PENDING', 'effect_id': 'activation-authentication-' + activation.activation_id,
                'state_domain': 'boot', 'session_id': waiting.session_id, 'session_owner': waiting.owner_identity,
                'session_live': False, 'fence_epoch': waiting.fence, 'boot_ordinal': event['predecessor_ordinal'],
                'session_boot_ordinal': event['predecessor_ordinal'], 'supervisor_generation': waiting.generation,
                'authorization_digest': waiting.authorization_digest, 'campaign_id': waiting.campaign_id,
                'target': self.identity, 'operation': 'consume-boot-activation', 'authorizes_execution': False,
                'dispatch_resolved': True, 'consumption': {'kind': 'effect',
                    'identity': 'activation-authentication-' + activation.activation_id},
                'verification_id': verified.verifier_id}
            authentication_receipt = self._commit_u04(waiting, 'ADMIT', authentication,
                facts={'activation_authentication': {'verifier_id': verified.verifier_id,
                    'canonical_bytes_hex': verified.canonical_bytes.hex(), 'digest': verified.digest}})
            if self._current_actor is not None:
                self.witness.freeze_actor(self._current_actor)
            generation = self.witness.allocate_generation(self.identity)
            actor = IncarnationActor(self.identity, authorization.authorization_digest, authorization.campaign_id,
                generation, '%s-incarnation-%d' % (self.identity, generation),
                '%s-session-%d' % (self.identity, generation), owner_identity, self.witness.current_fence,
                'LIVE_PENDING', object())
            self.witness.register_actor(actor, _entry=_U04_BOUNDARIES['ENTRY'])
            self._current_actor = actor
            reserved = self._u04_common(actor, 'ACTIVATION_RESERVED', 'CONTROL', False)
            reserved.update(activation_id=activation.activation_id, shutdown_ref=self._reference(shutdown['receipt']),
                predecessor_closure_digest=event['closure_digest'], next_boot_ordinal=activation.boot_ordinal,
                observed_boot_id=activation.observed_boot_id, new_generation=generation,
                new_incarnation_id=actor.incarnation_id,
                activation_authentication_ref=self._reference(authentication_receipt))
            reservation = self._commit_u04(actor, 'ADMIT', reserved, fault=reservation_fault,
                facts={'consumptions': [['boot_activation', activation.activation_id]],
                       'incarnation': actor.producer()})
            fence = self.witness.acquire_fence(owner_identity)
            actor = self.witness.advance_admission_fence(actor, reservation, fence)
            self._current_actor = actor
            ack = self._custodian.revoke_all_lower_fences(actor)
            raw = _u04_canonical(asdict(ack))
            object_id = 'fence-proof-' + actor.incarnation_id
            self.put_object(object_id, raw, actor=actor, boundary='ADMIT')
            session = FenceSession(fence, actor.session_id, owner_identity, activation.boot_ordinal, True)
            admitted = dict(reserved, **self._u04_common(actor, 'ACTIVATION_ADMITTED', 'EXECUTION', True))
            admitted.update(reservation_ref=self._reference(reservation), fresh_session=asdict(session),
                all_lower_fences_ack={'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)})
            self._commit_u04(actor, 'ADMIT', admitted, fault=admission_fault)
            self.require_actor(actor, 'ADMIT')
            live = self.witness.change_mode(actor, 'LIVE', _boundary=_U04_BOUNDARIES['ADMIT'], execution_session=session)
            self._current_actor = live
            self._entry_mode = 'LIVE'
            self._supervisor_generation = generation
            self._supervisor_ready = True
            self._sessions = {live.session_id: session}
            self._acceptance_acks.clear()
            self._execution_revoked = self._publication_prohibited = self.containment_only = False
            return live, session

    def _derived_nonlive_mode(self, authorization):
        if self.provenanced_frames('CAMPAIGN_COMPLETE', 'complete-campaign') and self.validated_campaign_closure():
            return 'TERMINAL'
        try:
            self.waiting_shutdown(authorization)
        except AuthorizationDenied:
            return 'RECOVERY'
        return 'WAITING'

    def open_nonlive_entry(self, authorization, owner_identity):
        """Evidence derives membership. An opaque non-live reader cannot dispatch."""
        with self.authorization_lock:
            self.validate_admitted_authorization(authorization)
            frames = self._committed_frames()
            if self._current_actor is not None:
                self.crash()
            mode = self._derived_nonlive_mode(authorization)
            generation = self.witness.allocate_generation(self.identity)
            fence = self.witness.acquire_fence(owner_identity)
            actor = IncarnationActor(self.identity, authorization.authorization_digest,
                authorization.campaign_id, generation, '%s-incarnation-%d' % (self.identity, generation),
                '%s-session-%d' % (self.identity, generation), owner_identity, fence, mode, object())
            self.witness.register_actor(actor, _entry=_U04_BOUNDARIES['ENTRY'])
            self._current_actor = actor
            self._entry_mode = mode
            self._supervisor_generation = generation
            event = self._u04_common(actor, 'SUPERVISOR_INCARNATION', 'CONTROL', False)
            event.update(mode=mode, entry_refs=[self._reference(f['receipt']) for f in frames[-1:]],
                witness_generation_receipt='generation-%d' % generation, incarnation_id=actor.incarnation_id)
            self._commit_u04(actor, 'ENTRY', event)
            if mode == 'RECOVERY':
                events = [f['event'] for f in frames]
                for code in ('SHUTDOWN_PENDING_AT_LOSS', 'UNPLANNED_HANDOFF_LOSS',
                             'UNFINISHED_BOOT_LOSS', 'INTERRUPTED_ADMISSION'):
                    try:
                        self.witness.deny_campaign(actor, code,
                            [f['envelope'] for f in self._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                    except AuthorizationDenied:
                        continue
                    self.mirror_denial(actor)
                    break
            return actor

    def admit_authorization(self, actor, authorization, fault=None):
        """INIT fixes original authority durably without exposing execution."""
        with self.authorization_lock:
            if self._authentication_service is None:
                raise AuthorizationDenied("pinned offline authentication unavailable")
            result = self._authentication_service.verify(authorization,
                store_identity=self.identity, campaign_id=authorization.campaign_id)
            self.witness.authenticate(actor, self.identity, "INIT")
            if any(frame["event"].get("state") == "AUTHORIZATION_ADMITTED"
                   for frame in self._durable):
                raise AuthorizationDenied("INIT cannot replace admitted authority")
            event = {"state_domain": "authorization", "state": "AUTHORIZATION_ADMITTED",
                "store_identity": self.identity, "authorization_id": authorization.authorization_id,
                "authorization_digest": result.authorization_digest,
                "campaign_id": result.campaign_id,
                "canonical_authorization_hex": result.canonical_authorization_bytes.hex(),
                "root_id": result.root_id, "root_version": result.root_version,
                "core_manifest_digest": authorization.core_manifest_digest,
                "adapter_manifest_digest": authorization.adapter_manifest_digest,
                "policy_digest": authorization.policy_digest, "schema_digest": authorization.schema_digest,
                "authority_class": "CONTROL", "authorizes_execution": False}
            return self._commit_u04(actor, "INIT", event, fault=fault)

    def validate_admitted_authorization(self, authorization):
        """No caller digest, cached Boolean or second valid approval substitutes."""
        with self.authorization_lock:
            if self._authentication_service is None:
                raise AuthorizationDenied("pinned offline authentication unavailable")
            result = self._authentication_service.verify(authorization,
                store_identity=self.identity, campaign_id=authorization.campaign_id)
            self.read_verified(0)
            frames = [frame for frame in self._durable if (
                frame["event"].get("state") == "AUTHORIZATION_ADMITTED" and
                type(frame.get("envelope")) is JournalEnvelope and
                frame["envelope"].boundary == "INIT")]
            if len(frames) != 1:
                raise AuthorizationDenied("unique original witnessed admission required")
            frame = frames[0]
            event = frame["event"]
            if (event.get("authorization_id") != result.authorization_id or
                    event.get("authorization_digest") != result.authorization_digest or
                    event.get("campaign_id") != result.campaign_id or
                    event.get("store_identity") != self.identity or
                    event.get("root_id") != result.root_id or
                    event.get("root_version") != result.root_version or
                    event.get("canonical_authorization_hex") != result.canonical_authorization_bytes.hex()):
                raise AuthorizationDenied("original admitted authority cannot be substituted")
            return frame["receipt"]

    def reset_volatile(self):
        """Exhaustive in-place reset. No historical handle becomes live."""
        if self._authorization_lock.owned_by_current_thread():
            self.crash()
            return
        with self.authorization_lock, self._lock:
            # A loss while W was unreadable already removed the D-side live
            # handle. Once the same original witness returns, fence its exact
            # retained member before allocating any successor. No caller ID or
            # historical session is used to reconstruct an execution token.
            if self._current_actor is None and self.witness.available:
                outgoing = self.witness._actors.get(self.identity)
                if outgoing is not None:
                    self.witness.freeze_actor(outgoing)
            self.crash()
            _journal_envelope_bytes.cache_clear()
            if set(vars(self)) != set(STORE_FIELD_DOMAINS):
                raise StoreError("unclassified store field; reset denied")
            for name in ("_receipts", "_event_bytes", "_sessions", "_effect_capabilities",
                    "_effect_status", "_effect_results", "_effect_acceptance_counts",
                    "_publication_grants", "_publication_grant_records", "_window_operations",
                    "_window_results", "_slot_grants", "_validated_completions",
                    "_validated_boot_closures", "_validated_boot_custody", "_historical_producers", "_acceptance_acks", "_rp_grants", "_rp_proofs"):
                setattr(self, name, {})
            for name in ("_taint", "_consumed", "_active_creation_grants", "_accepted_effects",
                    "_invalidated_effects", "_consumed_publication_grants", "_initial_window_operations"):
                setattr(self, name, set())
            self._volatile = []
            self._current_actor = self._current_reconciler = self._initialization_token = self._recovery_writer = None
            self._rp_binding = None
            self._validated_campaign_closure = None
            self._entry_mode = "INSPECTION"
            self._supervisor_generation = self.witness.high_generation
            self._supervisor_ready = False
            self._execution_revoked = self._publication_prohibited = self.containment_only = True
            self._measurement_window = None
            self._window_epoch = self._window_operation_sequence = self._publication_grant_sequence = 0
            self._pending_reset = False
            # Only independently confirmed committed facts populate indexes.
            # Legacy frames remain exact inspectable bytes, without authority.
            if not self.witness.available:
                self._health = "UNKNOWN"
                return
            previous = "0" * 64
            for revision, frame in enumerate(self._durable, 1):
                envelope = frame.get("envelope")
                if type(envelope) is not JournalEnvelope:
                    previous = frame["receipt"].chain_digest
                    continue
                status, commit = self.witness.query_transaction(envelope.transaction_id)
                if (not self._u04_frame_valid(frame) or envelope.revision != revision or
                        envelope.predecessor_revision != revision - 1 or
                        envelope.predecessor_hash != previous):
                    self._health = "QUARANTINED"
                    self.quarantined = True
                    return
                if status == "PENDING":
                    self._health = "RECONCILABLE"
                    return
                if (status != "COMMITTED" or commit.reservation.frame_digest != envelope.frame_digest or
                        commit.receipt_id != frame["receipt"].witness_receipt):
                    self._health = "QUARANTINED"
                    self.quarantined = True
                    return
                previous = envelope.frame_digest
                self._receipts[envelope.transaction_id] = frame["receipt"]
                self._event_bytes[envelope.transaction_id] = envelope.payload_bytes
                self._historical_producers[envelope.transaction_id] = envelope.producer_bytes
            if self.witness.high_revision != len(self._durable) or self.witness.high_chain_digest != previous:
                self._health = "QUARANTINED"
                self.quarantined = True
                return
            self._health = "HEALTHY"

    def _independent_frame_readback(self, revision):
        """Read retained D bytes, independently of the construction buffer."""
        return bytes(self._durable[revision - 1]["bytes"])

    def _u04_frame_valid(self, frame):
        envelope = frame.get("envelope")
        if type(envelope) is not JournalEnvelope:
            return False
        try:
            if envelope.boundary=='RW':
                event=validate_recovery_record(frame['event'])
                producer=json.loads(envelope.producer_bytes)
                if (producer.get('mode') not in ('RECOVERY','TERMINAL') or
                        envelope.authority_class!='EVIDENCE' or
                        envelope.authority_fact_bytes!=_u04_canonical({'producer':producer}) or
                        event['store_identity']!=envelope.store_identity or
                        event['authorization_digest']!=envelope.authorization_digest or
                        event['campaign_id']!=envelope.campaign_id or
                        any(event[k]!=producer[v] for k,v in (
                            ('writer_generation','generation'),
                            ('writer_incarnation_id','incarnation_id'),('writer_session_id','session_id'),('writer_fence','fence')))):
                    return False
            return (envelope.canonical_bytes() == frame["bytes"] and
                    envelope.payload_bytes == _u04_canonical(frame["event"]) and
                    envelope.payload_digest == _sha(envelope.payload_bytes) and
                    frame["receipt"].event_digest == envelope.payload_digest and
                    frame["receipt"].chain_digest == envelope.frame_digest)
        except (StoreError, ValueError, TypeError, KeyError, ContractError):
            return False

    def _validate_reconciliation_frame(self, envelope):
        """Validate all retained D against W before any reconciliation mutation.

        Called under bound-store authorization/journal exclusion, including
        from W's lower ports. Only one exact pending tail is permitted skew.
        """
        if self.quarantined or self.witness.quarantined or self._health == 'QUARANTINED':
            raise Quarantined('quarantined reconciliation is read-only')
        if not self.witness.available:
            raise TransactionPending(envelope.transaction_id, 'reconciliation-witness', 'UNKNOWN')
        if not self._durable or self._durable[-1].get('envelope') != envelope:
            raise AuthorizationDenied('bound retained reconciliation tail required')

        def divergent(reason):
            self.quarantined = self.containment_only = True
            self._health = 'QUARANTINED'
            raise Quarantined(reason)

        if self.torn_tail:
            divergent('incomplete reconciliation tail')
        previous = '0' * 64
        tail_status, tail_record = None, None
        for revision, frame in enumerate(self._durable, 1):
            old = frame.get('envelope')
            if (not self._u04_frame_valid(frame) or old.revision != revision or
                    old.predecessor_revision != revision - 1 or
                    old.predecessor_hash != previous or old.store_identity != self.identity):
                divergent('invalid complete reconciliation prefix')
            expected = WitnessReservation(old.store_identity, old.transaction_id,
                old.revision, old.frame_digest, old.authorization_digest,
                old.campaign_id, old.producer_bytes, old.boundary)
            status, record = self.witness.query_transaction(old.transaction_id)
            if status == 'PENDING':
                if (revision != len(self._durable) or record != expected or
                        self.witness.pending != {revision: expected} or
                        self.witness.high_revision != revision - 1 or
                        self.witness.high_chain_digest != previous):
                    divergent('frame without exact sole tail reservation')
            elif (status != 'COMMITTED' or record.reservation != expected or
                    record.receipt_id != frame['receipt'].witness_receipt):
                divergent('conflicting committed reconciliation prefix')
            previous = old.frame_digest
            tail_status, tail_record = status, record
        if tail_status == 'COMMITTED' and (self.witness.pending or
                self.witness.high_revision != len(self._durable) or
                self.witness.high_chain_digest != previous):
            divergent('committed reconciliation frontier diverges')
        return tail_status, tail_record

    def reconcile_pending(self, chair_verifier, authorization, fault=None):
        """Finish only the exact retained reservation; never dispatch an effect.

        Incarnation-only reconciliation is available now. Authority-bearing
        pending transactions remain denied until their positive-fact latch
        predicates and dedicated writers are integrated.
        """
        if chair_verifier is not self._authentication_service:
            raise AuthorizationDenied("pinned authentication service required")
        chair_verifier.verify(authorization, store_identity=self.identity,
                              campaign_id=authorization.campaign_id)
        with self.authorization_lock, self._lock:
            if not self.witness.available or self.torn_tail or not self._durable:
                raise Quarantined("exact complete retained frame unavailable")
            frame = self._durable[-1]
            envelope = frame.get("envelope")
            if not self._u04_frame_valid(frame):
                self.quarantined = self.containment_only = True
                self._health = "QUARANTINED"
                raise Quarantined("reconciliation envelope/bytes conflict")
            if (envelope.authorization_digest != authorization.authorization_digest or
                    envelope.campaign_id != authorization.campaign_id):
                raise AuthorizationDenied("caller authorization differs from retained reconciliation binding")
            status, record = self._validate_reconciliation_frame(envelope)
            if status == "COMMITTED":
                return frame["receipt"]
            if self._current_actor is not None:
                self.crash()
            binding = self.witness.issue_reconciler(envelope)
            self._current_reconciler = binding
            if envelope.boundary != 'ENTRY':
                prefix = self._durable[:-1]
                if any(not self._u04_frame_valid(f) for f in prefix):
                    raise Quarantined('unreadable/conflicting prefix prevents dependent reconciliation')
                self.witness.deny_pending_reconciliation(binding, envelope,
                    [f['envelope'] for f in prefix])
            if fault == "before_commit":
                self.crash()
                raise TransactionPending(envelope.transaction_id, "reconciliation-before-commit")
            retained = self._independent_frame_readback(envelope.revision)
            committed = self.witness.reconcile_frame(binding, envelope, retained)
            self._current_reconciler = None
            frame["receipt"] = replace(frame["receipt"], witness_receipt=committed.receipt_id,
                                        durable=True)
            self._health = "HEALTHY"
            self.quarantined = False
            self._receipts[envelope.transaction_id] = frame["receipt"]
            self._event_bytes[envelope.transaction_id] = envelope.payload_bytes
            if fault == "lost_ack":
                raise LostAcknowledgement(frame["receipt"])
            status, confirmed = self.witness.query_transaction(envelope.transaction_id)
            if (status != "COMMITTED" or confirmed != committed or
                    retained != envelope.canonical_bytes()):
                raise TransactionPending(envelope.transaction_id, "reconciliation-confirmation", "UNKNOWN")
            return frame["receipt"]

    @property
    def revision(self):
        return len(self._durable)

    @property
    def chain_digest(self):
        return self._durable[-1]["receipt"].chain_digest if self._durable else "0" * 64

    @property
    def events(self):
        return [copy.deepcopy(frame["event"]) for frame in self._durable]

    @property
    def taint(self):
        return frozenset(self._taint)

    @property
    def last_event_authorizes_execution(self):
        return bool(self._durable and self._durable[-1]["event"].get("authorizes_execution") is True)

    def acquire_fence(self, owner, fail=False):
        with self.authorization_lock:
            return self.witness.acquire_fence(owner, fail=fail)

    def _check_healthy(self):
        if (self.quarantined or self.witness.quarantined or
                not self.witness.available or
                self.witness.high_revision != self.revision or
                self.witness.high_chain_digest != self.chain_digest or
                self.witness.pending):
            self.containment_only = True
            raise Quarantined("store/witness quarantined")

    def assert_healthy_authority(self):
        with self._lock:
            self._check_healthy()
            return True

    def _append(self, expected_revision, fence_epoch, event_id, event, fault=None,
                control_token=None):
        if self._authentication_service is not None:
            raise AuthorizationDenied("legacy append cannot mutate a U-04 foundation")
        if type(expected_revision) is not int or type(fence_epoch) is not int:
            raise CASMismatch("revision and fence must be integers")
        if type(event_id) is not str or type(event) is not dict:
            raise StoreError("closed event")
        if _is_reserved_control_record(event) and control_token is not _CONTROL_APPEND:
            raise StoreError("reserved control record requires store-owned operation")
        encoded = _canonical(event)
        event_digest = _sha(encoded)
        with self._lock:
            self._check_healthy()
            if event_id in self._receipts:
                if self._event_bytes[event_id] != encoded:
                    raise DuplicateEvent("event ID reused with different bytes")
                return self._receipts[event_id]
            if expected_revision != self.revision:
                raise CASMismatch("stale expected revision")
            if fence_epoch != self.witness.current_fence:
                raise CASMismatch("stale fence")
            consumption = event.get("consumption")
            if consumption is not None:
                if (type(consumption) is not dict or set(consumption) != {"kind", "identity"} or
                        type(consumption["kind"]) is not str or
                        type(consumption["identity"]) is not str):
                    raise StoreError("closed consumption record")
                if (consumption["kind"], consumption["identity"]) in self._consumed:
                    raise DuplicateEvent("identity already consumed")
            taint_reason = event.get("taint_reason")
            if taint_reason is not None and (type(taint_reason) is not str or not taint_reason):
                raise StoreError("taint reason")
            revision = self.revision + 1
            chain_digest = _sha(bytes.fromhex(self.chain_digest) + bytes.fromhex(event_digest))
            reservation = self.witness.reserve(revision, chain_digest)
            if fault in ("torn", "witness_ahead"):
                self.torn_tail = encoded[:max(1, len(encoded) // 2)] if fault == "torn" else b""
                self.quarantined = self.containment_only = True
                raise Quarantined("incomplete durable commit")
            pending_receipt = AppendReceipt(
                self.identity, revision, event_id, event_digest, chain_digest,
                fence_epoch, reservation, True,
            )
            frame = {"event_id": event_id, "event": copy.deepcopy(event), "bytes": encoded,
                     "receipt": pending_receipt}
            self._volatile.append(frame)
            self._durable.append(frame)
            self._volatile.clear()
            if fault == "journal_ahead":
                self._health = 'RECONCILABLE'
                self.containment_only = True
                raise TransactionPending(event_id, 'complete-legacy-frame-before-commit')
            witness_receipt = self.witness.commit(revision, chain_digest)
            receipt = replace(pending_receipt, witness_receipt=witness_receipt)
            frame["receipt"] = receipt
            self._receipts[event_id] = receipt
            self._event_bytes[event_id] = encoded
            if consumption is not None:
                self._consumed.add((consumption["kind"], consumption["identity"]))
            if taint_reason is not None:
                self._taint.add(taint_reason)
                self.containment_only = True
            if fault == "lost_ack":
                raise LostAcknowledgement(receipt)
            return receipt

    def append(self, expected_revision, fence_epoch, event_id, event, fault=None):
        return self._append(expected_revision, fence_epoch, event_id, event, fault=fault)

    def _append_control(self, expected_revision, fence_epoch, event_id, event, fault=None):
        return self._append(expected_revision, fence_epoch, event_id, event, fault=fault,
                            control_token=_CONTROL_APPEND)

    def append_nonauthorizing(self, fence_epoch, event_id, event):
        if type(event) is not dict or _is_reserved_control_record(event):
            raise StoreError("reserved control record requires store-owned operation")
        closed = dict(event)
        closed["authorizes_execution"] = False
        return self.append(self.revision, fence_epoch, event_id, closed)

    # ``_append_control`` above is low-level plumbing.  A record it writes is
    # never, by itself, operation provenance: window and publication records
    # carry authority only through the typed result paths below and their
    # bound results.

    def _frame_for_receipt(self, receipt, event_id):
        if (not isinstance(receipt, AppendReceipt) or
                receipt.store_identity != self.identity or
                receipt.event_id != event_id or type(receipt.revision) is not int or
                not 1 <= receipt.revision <= self.revision):
            raise StoreError("operation result receipt")
        frame = self._durable[receipt.revision - 1]
        if (frame["event_id"] != event_id or
                frame["receipt"].event_digest != receipt.event_digest or
                frame["receipt"].revision != receipt.revision):
            raise StoreError("operation result receipt does not name its record")
        return frame

    # ---- measurement-window operations ------------------------------------

    def _begin_window_initialization(self, authority):
        """Before any admission write: a one-shot token when, and only when,
        this store is fresh.  Freshness is never inferred from a missing
        window record alone."""
        self._require_dedicated(authority)
        if self._authentication_service is not None:
            raise AuthorizationDenied('initial window authority belongs only to witnessed INIT')
        with self._lock:
            fresh = (not self._durable and not self._volatile and not self._receipts and
                     self.witness.high_revision == 0 and not self.witness.pending and
                     not self._consumed and not self._publication_grants and
                     not self._window_operations and not self._window_results and
                     not self._initial_window_operations and
                     self._measurement_window is None and self._window_epoch == 0 and
                     self._initialization_token is None)
            if not fresh:
                return None
            token = object()
            self._initialization_token = token
            return token

    def _end_window_initialization(self, authority, token):
        self._require_dedicated(authority)
        with self._lock:
            if token is not None and self._initialization_token is token:
                self._initialization_token = None

    def _next_window_operation_id(self, authority, *, actor=None):
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                return 'window-operation-%d-%d' % (actor.generation, self.revision + 1)
            return "window-operation-%d" % (self._window_operation_sequence + 1)

    def _register_window_operation(self, authority, transition, initialization=None, *, actor=None):
        """Mark a window operation started: register its exact transition as
        pending before anything is appended."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                if (not isinstance(transition, MeasurementWindowTransition) or transition.initial or
                        initialization is not None or transition.session_id != actor.session_id or
                        transition.fence_epoch != actor.fence or transition.supervisor_generation != actor.generation or
                        transition.operation_id != self._next_window_operation_id(authority, actor=actor)):
                    raise AuthorizationDenied('closed current window operation required')
                self._window_operations[transition.operation_id] = transition
                self._window_operation_sequence += 1
                return
            if (not isinstance(transition, MeasurementWindowTransition) or
                    transition.store_identity != self.identity or
                    transition.operation_id !=
                    "window-operation-%d" % (self._window_operation_sequence + 1) or
                    transition.operation_id in self._window_operations or
                    transition.event_id in self._receipts):
                raise StoreError("closed, unused measurement-window operation required")
            if transition.initial:
                if (initialization is None or
                        initialization is not self._initialization_token or
                        self._initial_window_operations or self._window_operations):
                    raise StoreError(
                        "initial measurement window requires fresh-store admission")
                self._initialization_token = None
                self._initial_window_operations.add(transition.operation_id)
            elif initialization is not None:
                raise StoreError("initialization token used outside the initial window")
            self._window_operation_sequence += 1
            self._window_operations[transition.operation_id] = transition

    def _append_window_result(self, authority, transition, fault=None, *, actor=None):
        """Append and witness the exact record of a pending window operation."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                return self._commit_u04(actor, 'EXEC', transition.record(),
                    event_id=transition.event_id, fault=fault)
            if (not isinstance(transition, MeasurementWindowTransition) or
                    self._window_operations.get(transition.operation_id) != transition or
                    transition.operation_id in self._window_results):
                raise StoreError("measurement-window operation is not pending")
            return self._append_control(self.revision, transition.fence_epoch,
                                        transition.event_id, transition.record(),
                                        fault=fault)

    def _bind_window_result(self, authority, operation_id, receipt, *, actor=None):
        """Bind a pending window operation to the exact record it produced."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                frame = self._frame_for_receipt(receipt, receipt.event_id)
                if frame['event'].get('operation_id') != operation_id or not self.window_record_provenanced(frame):
                    raise AuthorizationDenied('only witnessed exact window result may populate a view')
                result = OperationResultBinding(receipt.event_id, receipt.revision, receipt.event_digest)
                self._window_results[operation_id] = result
                return result
            transition = self._window_operations.get(operation_id)
            if transition is None or operation_id in self._window_results:
                raise StoreError("measurement-window result unregistered or already bound")
            frame = self._frame_for_receipt(receipt, transition.event_id)
            if frame["event"] != transition.record():
                raise StoreError("measurement-window result differs from its operation")
            result = OperationResultBinding(receipt.event_id, receipt.revision,
                                            receipt.event_digest)
            self._window_results[operation_id] = result
            return result

    def window_record_provenanced(self, frame):
        """True only for the exact bound result of a registered window
        operation: store identity, operation name and ID, event ID, previous
        and new window/epoch, authorization, campaign, generation, session,
        fence, and the exact result event ID, revision, and digest."""
        event = frame.get("event") if type(frame) is dict else None
        receipt = frame.get("receipt") if type(frame) is dict else None
        if type(event) is not dict or not isinstance(receipt, AppendReceipt):
            return False
        if self._authentication_service is not None:
            envelope = frame.get('envelope')
            if type(envelope) is not JournalEnvelope or envelope.boundary not in ('INIT', 'EXEC'):
                return False
            status, committed = self.witness.query_transaction(envelope.transaction_id)
            if (status != 'COMMITTED' or not self._u04_frame_valid(frame) or
                    committed.reservation.frame_digest != envelope.frame_digest):
                return False
            try:
                transition = MeasurementWindowTransition.from_record(self.identity, frame['event_id'], event)
                producer = json.loads(envelope.producer_bytes)
                return (transition.session_id == producer['session_id'] and
                        transition.fence_epoch == producer['fence'] and
                        transition.supervisor_generation == producer['generation'] and
                        transition.initial == (envelope.boundary == 'INIT'))
            except (ContractError, KeyError, TypeError):
                return False
        operation_id = event.get("operation_id")
        if type(operation_id) is not str:
            return False
        transition = self._window_operations.get(operation_id)
        result = self._window_results.get(operation_id)
        if (transition is None or result is None or
                (result.event_id, result.revision, result.event_digest) !=
                (frame.get("event_id"), receipt.revision, receipt.event_digest) or
                receipt.store_identity != self.identity or
                receipt.fence_epoch != transition.fence_epoch):
            return False
        try:
            produced = MeasurementWindowTransition.from_record(
                self.identity, frame.get("event_id"), event)
        except (ContractError, KeyError, TypeError):
            return False
        if produced != transition:
            return False
        if transition.initial and operation_id not in self._initial_window_operations:
            return False
        session = self._sessions.get(transition.session_id)
        return session is not None and session.fence_epoch == transition.fence_epoch

    # ---- publication operations ---------------------------------------------

    def _next_publication_grant_id(self, authority, *, actor=None):
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                return 'publication-grant-%d-%d' % (actor.generation, self.revision + 1)
            return "publication-grant-%d" % (self._publication_grant_sequence + 1)

    def _publication_issuance(self, grant, actor):
        self.require_actor(actor)
        frames = [f for f in self._committed_frames() if
                  f['event'].get('operation_id') == grant.grant_id and
                  self.publication_record_provenanced(f, phase='ISSUE')]
        if (len(frames) != 1 or PublicationOperationBinding.from_record(self.identity,
                frames[0]['event']) != grant.binding or grant.session_id != actor.session_id or
                grant.supervisor_generation != actor.generation or grant.fence_epoch != actor.fence):
            raise AuthorizationDenied('exact witnessed current publication issuance required')
        return frames[0]

    def _register_publication_grant(self, authority, grant, *, actor=None):
        self._require_dedicated(authority)
        with self.authorization_lock, self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                if (not isinstance(grant, PublicationOperationGrant) or not grant.attestation_valid() or
                        grant.grant_id != self._next_publication_grant_id(authority, actor=actor)):
                    raise AuthorizationDenied('closed unused current publication issuance required')
                self._commit_u04(actor, 'EXEC', grant.binding.record_fields(),
                    facts={'publication_grant': {'attestation': grant.attestation, 'phase': 'ISSUE'}})
                self._publication_grants[grant.grant_id] = grant
                self._publication_grant_sequence += 1
                return grant
            if (not isinstance(grant, PublicationOperationGrant) or
                    grant.binding.store_identity != self.identity or
                    grant.grant_id !=
                    "publication-grant-%d" % (self._publication_grant_sequence + 1) or
                    grant.grant_id in self._publication_grants or
                    not grant.attestation_valid()):
                raise StoreError("closed, unused publication grant required")
            self._publication_grant_sequence += 1
            self._publication_grants[grant.grant_id] = grant
            return grant

    def publication_grant_consumed(self, grant_id):
        if self._authentication_service is not None:
            return any(f['event'].get('record_type') == 'EFFECT_ACCEPTED' and
                f['event'].get('effect_id') == grant_id for f in self._committed_frames())
        return grant_id in self._consumed_publication_grants

    def _consume_publication_grant(self, authority, grant, *, actor=None):
        """Mark a publication operation started.  Consumption is never
        refunded; a consumed grant without a bound result prohibits promotion."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self._publication_issuance(grant, actor)
                if self.publication_grant_consumed(grant.grant_id):
                    raise AuthorizationDenied('publication acceptance cannot be reused')
                return
            if (self._publication_grants.get(grant.grant_id) != grant or
                    grant.grant_id in self._consumed_publication_grants):
                raise StoreError("publication grant is not registered and unused")
            self._consumed_publication_grants.add(grant.grant_id)

    def _append_publication_result(self, authority, grant, event_id, event, *, actor=None):
        """Append and witness the exact result record of a consumed grant."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self._publication_issuance(grant, actor)
                return self._commit_u04(actor, 'EXEC', event, event_id=event_id,
                    facts={'publication_grant': {'attestation': grant.attestation, 'phase': 'RESULT'}})
            if (self._publication_grants.get(grant.grant_id) != grant or
                    grant.grant_id not in self._consumed_publication_grants or
                    grant.grant_id in self._publication_grant_records):
                raise StoreError("publication result requires its consumed, unbound grant")
            try:
                produced = PublicationOperationBinding.from_record(self.identity, event)
            except (ContractError, KeyError, TypeError) as exc:
                raise StoreError("publication result record is not canonical") from exc
            if produced != grant.binding:
                raise StoreError("publication result record differs from its grant")
            return self._append_control(self.revision, grant.fence_epoch, event_id, event)

    def incomplete_publication_operations(self):
        """Consumed grants lacking a result, and results lacking their record."""
        reasons = []
        if self._authentication_service is not None:
            frames = self._committed_frames()
            for frame in frames:
                event = frame['event']
                if (event.get('record_type') == 'EFFECT_ACCEPTED' and
                        'publication_acceptance' in json.loads(frame['envelope'].authority_fact_bytes) and
                        not any(f['event'].get('operation_id') == event['effect_id'] and
                            self.publication_record_provenanced(f) for f in frames)):
                    reasons.append('consumed-publication-grant-without-result')
            return reasons
        for grant_id in sorted(self._consumed_publication_grants):
            result = self._publication_grant_records.get(grant_id)
            if result is None:
                reasons.append("consumed-publication-grant-without-result")
                continue
            frame = (self._durable[result.revision - 1]
                     if 1 <= result.revision <= self.revision else None)
            if frame is None or not self.publication_record_provenanced(frame):
                reasons.append("publication-result-without-record")
        return reasons

    def publication_outcome_unknown(self, identity):
        """Acceptance without a versioned result remains outcome-unknown."""
        frames = self._committed_frames()
        results = {f['event'].get('effect_id') for f in frames if f['event'].get('record_type') == 'EFFECT_RESULT'}
        for frame in frames:
            event = frame['event']
            if (event.get('record_type') != 'EFFECT_ACCEPTED' or event.get('effect_id') in results or
                    'publication_acceptance' not in json.loads(frame['envelope'].authority_fact_bytes)):
                continue
            intended = self._exact_ref(event['intent_ref'])
            if PublicationIdentity.from_record(intended['event']) == identity:
                return True
        return False

    def read_verified(self, min_revision, expected_chain_digest=None):
        with self._lock:
            self._check_healthy()
            for frame in self._durable:
                if "envelope" in frame and not self._u04_frame_valid(frame):
                    try:
                        self.witness.deny_durable_digest_conflict(self, _boundary=_U04_BOUNDARIES['DENY'])
                    except AuthorizationDenied:
                        pass
                    self.quarantined = self.containment_only = True
                    self._health = "QUARANTINED"
                    raise Quarantined("retained U-04 envelope changed")
                if "envelope" in frame:
                    envelope = frame["envelope"]
                    status, committed = self.witness.query_transaction(envelope.transaction_id)
                    if (status != "COMMITTED" or
                            committed.reservation.frame_digest != envelope.frame_digest or
                            committed.reservation.initiator_bytes != envelope.producer_bytes or
                            committed.receipt_id != frame["receipt"].witness_receipt):
                        self.quarantined = self.containment_only = True
                        self._health = "QUARANTINED"
                        raise Quarantined("independent witness confirmation absent/conflicting")
            if min_revision > self.revision:
                raise StaleRead("authoritative minimum revision unavailable")
            if (self.witness.high_revision != self.revision or
                    self.witness.high_chain_digest != self.chain_digest):
                self.quarantined = self.containment_only = True
                raise Quarantined("witness divergence")
            if expected_chain_digest is not None and expected_chain_digest != self.chain_digest:
                raise StaleRead("chain digest mismatch")
            return {"revision": self.revision, "chain_digest": self.chain_digest,
                    "events": self.events, "taint": sorted(self._taint),
                    "consumed": sorted(self._consumed)}

    def stale_read(self, revision):
        if type(revision) is not int or revision < 0:
            raise StaleRead("stale revision")
        return {"revision": min(revision, self.revision),
                "events": self.events[:revision], "authoritative": False}

    def verified_prefix(self):
        """Read-only forensic prefix; never issues a session or repairs history.

        A corrupt suffix cannot erase independently confirmed earlier evidence.
        Unavailable W evidence is not classified as a positive contradiction.
        Callers receive copies, not writable D references.
        """
        with self.authorization_lock, self._lock:
            previous = '0' * 64
            verified = []
            if not self.witness.available:
                return {'frames': (), 'stop_reason': 'UNKNOWN', 'authorizes_execution': False}
            for revision, frame in enumerate(self._durable, 1):
                envelope = frame.get('envelope')
                if (type(envelope) is not JournalEnvelope or not self._u04_frame_valid(frame) or
                        envelope.revision != revision or envelope.predecessor_revision != revision - 1 or
                        envelope.predecessor_hash != previous or envelope.store_identity != self.identity):
                    return {'frames': tuple(verified), 'stop_reason': 'QUARANTINED', 'authorizes_execution': False}
                status, commit = self.witness.query_transaction(envelope.transaction_id)
                if status == 'PENDING':
                    return {'frames': tuple(verified), 'stop_reason': 'RECONCILABLE', 'authorizes_execution': False}
                if (status != 'COMMITTED' or commit.reservation.frame_digest != envelope.frame_digest or
                        commit.reservation.initiator_bytes != envelope.producer_bytes or
                        commit.receipt_id != frame['receipt'].witness_receipt):
                    return {'frames': tuple(verified), 'stop_reason': 'QUARANTINED', 'authorizes_execution': False}
                verified.append(copy.deepcopy(frame))
                previous = envelope.frame_digest
            return {'frames': tuple(verified), 'stop_reason':
                ('HEALTHY' if self.witness.high_revision == len(verified) and
                 self.witness.high_chain_digest == previous else 'QUARANTINED'),
                'authorizes_execution': False}

    def read_only_inspector(self, service, authorization, reader_identity):
        """Trusted local setup supplies a reader without touching D/W authority."""
        if (service is not self._authentication_service or service is None or
                reader_identity != _LOCAL_INSPECTION_READER_ID):
            raise AuthorizationDenied('pinned service and configured local reader required')
        service.verify(authorization, store_identity=self.identity, campaign_id=authorization.campaign_id)
        return OfflineReadOnlyInspector(self, service, authorization, reader_identity,
                                        _entry=_LOCAL_INSPECTION_BOUNDARY)

    def crash(self):
        # A same-thread hook is revoke-only. Exhaustive reset must occur after
        # the interrupted stack unwinds; it cannot replace its captured token.
        self._current_reconciler = self._recovery_writer = self._rp_binding = None
        self._rp_grants.clear()
        self._rp_proofs.clear()
        for destination in self._publication_destinations:
            # These two indexes are V, unlike the destination's retained C
            # bytes/claims. Revocation cannot erase an already-started effect.
            destination._source_bindings.clear()
            destination._eligible_grants.clear()
        if self._current_actor is not None:
            actor = self._current_actor
            self._execution_revoked = self._publication_prohibited = True
            self._supervisor_ready = False
            self._pending_reset = True
            try:
                self.witness.freeze_actor(actor)
            finally:
                self._current_actor = None
        self._volatile.clear()

    def simulate_rollback(self, revision):
        with self.authorization_lock, self._lock:
            if type(revision) is not int or not 0 <= revision <= self.revision:
                raise StoreError('bounded simulated rollback revision required')
            before = tuple(self._durable)
            if self._authentication_service is not None:
                self.read_verified(0)
            self._durable = self._durable[:revision]
            if self._authentication_service is not None and len(self._durable) < len(before):
                self.witness.deny_observed_rollback(self, before, _boundary=_U04_BOUNDARIES['DENY'])
            self.quarantined = self.containment_only = True

    def snapshot(self):
        return {"store_identity": self.identity, "revision": self.revision,
                "chain_digest": self.chain_digest, "taint": sorted(self._taint),
                "consumed": sorted(self._consumed)}

    def restore_snapshot(self, snapshot):
        if (type(snapshot) is not dict or snapshot.get("store_identity") != self.identity or
                snapshot.get("revision") != self.witness.high_revision or
                snapshot.get("chain_digest") != self.witness.high_chain_digest):
            self.quarantined = self.containment_only = True
            raise Quarantined("snapshot rollback or identity mismatch")
        return snapshot

    def consume(self, kind, identity):
        key = (kind, identity)
        if key in self._consumed:
            raise DuplicateEvent("identity already consumed")
        self.append_nonauthorizing(
            self.witness.current_fence, "consume-%s-%s" % (kind, identity),
            {"record_type": "CONSUMPTION",
             "consumption": {"kind": kind, "identity": identity}},
        )

    def is_consumed(self, kind, identity):
        if self._authentication_service is not None:
            for frame in self._committed_frames():
                event = frame['event']
                if event.get('consumption') == {'kind': kind, 'identity': identity}:
                    return True
                if (kind == 'slot' and event.get('operation') == 'make-slot-eligible' and
                        event.get('slot_id') == identity and self.frame_has_provenance(frame)):
                    return True
                if [kind, identity] in json.loads(frame['envelope'].authority_fact_bytes).get('consumptions', []):
                    return True
            return False
        return (kind, identity) in self._consumed

    def add_taint(self, reason):
        if type(reason) is not str or not reason:
            raise StoreError("taint reason")
        if reason in self._taint:
            return
        self.append_nonauthorizing(
            self.witness.current_fence, "taint-%d" % (self.revision + 1),
            {"record_type": "TAINT", "taint_reason": reason},
        )

    @property
    def execution_revoked(self):
        return (not self._supervisor_ready or self._execution_revoked or
                self.containment_only or bool(self._taint))

    def revoke_execution(self):
        self._execution_revoked = True

    @property
    def publication_prohibited(self):
        return not self._supervisor_ready or self._publication_prohibited

    def install_failure_latch(self, reason_code):
        if type(reason_code) is not str or not reason_code:
            reason_code = "authoritative-safety-failure"
        with self.authorization_lock:
            self._execution_revoked = True
            self._publication_prohibited = True
            self.containment_only = True
            self._taint.add(reason_code)
            self._invalidated_effects.update(self._effect_capabilities)

    @contextmanager
    def _supervisor_takeover(self):
        """One authority transition, including reconstruction and readiness.

        Refuse same-thread takeover before any shared mutation, rather than
        letting RLock reentrancy invalidate an active operation (or deadlocking
        its callback). Other threads wait for the entire protected operation,
        including result binding/state exposure or its failure prohibition.
        """
        if self._authentication_service is not None:
            raise AuthorizationDenied("U-04 operational supervisor integration unavailable")
        if self._authorization_lock.owned_by_current_thread():
            raise AuthorizationDenied("supervisor takeover cannot reenter authorization")
        with self.authorization_lock:
            self._supervisor_ready = False
            try:
                self._supervisor_generation += 1
                yield self._supervisor_generation
            except BaseException:
                self.install_failure_latch("supervisor-takeover-failure")
                raise

    def claim_supervisor(self):
        """Fence earlier generations without making a successor usable.

        Only completed PersistentSupervisor reconstruction enables authority.
        A bare claim leaves execution and publication unavailable until then.
        """
        with self._supervisor_takeover() as generation:
            return generation

    def supervisor_is_current(self, generation):
        actor = self._current_actor
        return (self._authentication_service is not None and self._supervisor_ready and
                actor is not None and type(generation) is int and generation == actor.generation and
                generation == self.witness.high_generation and actor.fence == self.witness.current_fence and
                self.witness._actors.get(self.identity) is actor)

    def bind_custodian(self, custodian):
        """Bind the single independent custodian whose registry is evidence."""
        with self._lock:
            if self._custodian is not None and self._custodian is not custodian:
                raise AuthorizationDenied("store custodian already bound")
            if self.witness._custodian is not None and self.witness._custodian is not custodian:
                raise AuthorizationDenied('witness independent custody verifier already bound')
            object.__setattr__(self, '_custodian', custodian)
            self.witness._custodian = custodian

    def bind_artifact_verifier(self, verifier):
        """Pin the actual bootstrap verification primitive for independent ports."""
        with self.authorization_lock:
            if type(verifier) is not ArtifactVerificationPrimitive:
                raise AuthorizationDenied('independent artifact verification primitive required')
            if self._artifact_verifier is not None and self._artifact_verifier is not verifier:
                raise AuthorizationDenied('artifact verification service already pinned')
            if self._authentication_service is not None:
                self._authentication_service.verify(verifier.authorization, store_identity=self.identity,
                                                     campaign_id=verifier.authorization.campaign_id)
            object.__setattr__(self, '_artifact_verifier', verifier)

    def validate_artifact_continuity(self, binding):
        authorization = self._admitted_payload()
        expected = {'core': authorization.core_manifest_digest,
                    'adapter': authorization.adapter_manifest_digest,
                    'policy': authorization.policy_digest,
                    'schema': authorization.schema_digest}
        if (self._artifact_verifier is None or binding.verifier_identity != self._artifact_verifier.identity or
                binding.authorization_digest != authorization.authorization_digest or
                self._artifact_verifier.authorization != authorization or
                binding.manifest() != expected):
            raise AuthorizationDenied('pinned original artifact verification service required')
        self._artifact_verifier.assert_continuity(binding)

    def bound_custodian(self):
        return self._custodian

    def _bind_publication_grant(self, authority, grant_id, receipt, *, actor=None):
        """Bind a consumed grant to the exact result record it produced."""
        self._require_dedicated(authority)
        with self._lock:
            if self._authentication_service is not None:
                self.require_actor(actor)
                frame = self._frame_for_receipt(receipt, receipt.event_id)
                if frame['event'].get('operation_id') != grant_id or not self.publication_record_provenanced(frame):
                    raise AuthorizationDenied('only witnessed result may populate publication view')
                result = OperationResultBinding(receipt.event_id, receipt.revision, receipt.event_digest)
                self._publication_grant_records[grant_id] = result
                return result
            grant = self._publication_grants.get(grant_id)
            if (grant is None or grant_id not in self._consumed_publication_grants or
                    grant_id in self._publication_grant_records):
                raise StoreError("publication grant result already bound")
            frame = self._frame_for_receipt(receipt, receipt.event_id
                                            if isinstance(receipt, AppendReceipt) else None)
            try:
                produced = PublicationOperationBinding.from_record(
                    self.identity, frame["event"])
            except (ContractError, KeyError, TypeError) as exc:
                raise StoreError("publication result record is not canonical") from exc
            if produced != grant.binding:
                raise StoreError("publication result differs from its grant")
            result = OperationResultBinding(receipt.event_id, receipt.revision,
                                            receipt.event_digest)
            self._publication_grant_records[grant_id] = result
            return result

    def publication_record_provenanced(self, frame, *, phase='RESULT'):
        """True only for the exact bound result of its registered, consumed,
        single-use grant: the record decodes to the grant's complete canonical
        operation binding (identity, store, grant, operation, prior state,
        window epoch, authorization, campaign, boot, closure candidate,
        generation, session, fence), the attestation is intact, and the bound
        result names this record's event ID, revision, and digest."""
        event = frame.get("event") if type(frame) is dict else None
        receipt = frame.get("receipt") if type(frame) is dict else None
        if type(event) is not dict or not isinstance(receipt, AppendReceipt):
            return False
        if self._authentication_service is not None:
            envelope = frame.get('envelope')
            if type(envelope) is not JournalEnvelope or envelope.boundary != 'EXEC' or not self._u04_frame_valid(frame):
                return False
            status, committed = self.witness.query_transaction(envelope.transaction_id)
            if status != 'COMMITTED' or committed.reservation.frame_digest != envelope.frame_digest:
                return False
            try:
                binding = PublicationOperationBinding.from_record(self.identity, event)
                facts = json.loads(envelope.authority_fact_bytes)
                producer = json.loads(envelope.producer_bytes)
                if phase == 'RESULT':
                    results = [f for f in self._durable if f['event'].get('record_type') == 'EFFECT_RESULT' and
                               f['event'].get('effect_id') == binding.grant_id]
                    if len(results) != 1:
                        return False
                    parsed = parse_effect_result_record(_u04_canonical(results[0]['event']))
                    raw = self._validated_port_observation(parsed)
                    if parsed.result_kind != 'EFFECT_PORT_RECEIPT' or raw != _u04_canonical(event):
                        return False
                    self._custodian.validate_publication_result(binding.grant_id, raw, parsed.verifier_id)
                return (facts.get('publication_grant') == {'attestation': binding.attestation_digest(), 'phase': phase} and
                        binding.session_id == producer['session_id'] and binding.fence_epoch == producer['fence'] and
                        binding.supervisor_generation == producer['generation'])
            except (ContractError, KeyError, TypeError):
                return False
        grant_id = event.get("operation_id")
        if type(grant_id) is not str:
            return False
        grant = self._publication_grants.get(grant_id)
        result = self._publication_grant_records.get(grant_id)
        if (grant is None or grant_id not in self._consumed_publication_grants or
                result is None or
                (result.event_id, result.revision, result.event_digest) !=
                (frame.get("event_id"), receipt.revision, receipt.event_digest) or
                receipt.store_identity != self.identity or
                receipt.fence_epoch != grant.fence_epoch or
                not grant.attestation_valid()):
            return False
        try:
            produced = PublicationOperationBinding.from_record(self.identity, event)
        except (ContractError, KeyError, TypeError):
            return False
        if produced != grant.binding:
            return False
        session = self._sessions.get(grant.session_id)
        return session is not None and session.fence_epoch == grant.fence_epoch

    def put_object(self, object_id, bytes_value, *, actor=None, boundary='EXEC'):
        with self.authorization_lock:
            if self._authentication_service is None:
                raise AuthorizationDenied('legacy history cannot authorize a new immutable object')
            if self._authentication_service is not None:
                if boundary not in ('EXEC', 'RESULT', 'SHUTDOWN', 'ADMIT', 'RW', 'RP'):
                    raise AuthorizationDenied('immutable object writer is unavailable in this mode')
                self.require_actor(actor, boundary)
                if boundary == 'RW':
                    self._require_recovery_writer(self._recovery_writer, actor)
                elif boundary == 'RP':
                    self._require_rp_binding(self._rp_binding, actor)
                    proof = self._rp_proofs.get(object_id)
                    if proof is None or proof[0] is not self._rp_binding or proof[2] != bytes_value:
                        raise AuthorizationDenied('RP has no generic metadata/object writer')
                    self._validate_rp_subject(proof[0], proof[1], 'QUERY')
                    receipt = parse_closed_canonical(bytes_value)
                    port = self._rp_port(self._rp_binding.authorization, receipt.get('destination_id'))
                    port.authenticate_receipt(bytes_value)
                    if object_id != 'rp-proof-' + _sha(bytes_value):
                        raise AuthorizationDenied('closed immutable destination proof object required')
                self._check_healthy()
                self.read_verified(0)
            if type(object_id) is not str or not object_id or type(bytes_value) is not bytes:
                raise StoreError("closed immutable object")
            existing = self._objects.get(object_id)
            if existing is not None and existing != bytes_value:
                raise StoreError("immutable object collision")
            self._objects[object_id] = bytes(bytes_value)
            return _sha(bytes_value)

    def read_object(self, object_id, expected_digest):
        value = self._objects.get(object_id)
        if value is None or _sha(value) != expected_digest:
            raise StoreError("immutable object readback mismatch")
        return bytes(value)

    def register_session(self, session):
        if self._authentication_service is not None:
            raise AuthorizationDenied('session registration is admission-owned')
        if not isinstance(session, FenceSession) or session.execution_live:
            raise AuthorizationDenied('legacy identity cannot register execution membership')
        previous = self._sessions.get(session.session_id)
        if previous is not None and previous != session:
            if not (previous.fence_epoch == session.fence_epoch and
                    previous.owner_identity == session.owner_identity and
                    previous.boot_ordinal == session.boot_ordinal and
                    previous.execution_live and not session.execution_live):
                raise AuthorizationDenied("session identity collision")
        self._sessions[session.session_id] = session

    def session_registered(self, session):
        if self._authentication_service is not None:
            actor = self._current_actor
            return (actor is not None and actor.execution_session is session and
                    actor.session_id == session.session_id and actor.fence == session.fence_epoch and
                    actor.mode == 'LIVE' and actor.generation == self.witness.high_generation and
                    self.witness._actors.get(self.identity) is actor)
        return isinstance(session, FenceSession) and self._sessions.get(session.session_id) == session

    def register_effect_capability(self, capability, *, _control=None):
        # Capability registration establishes durable-record provenance, so only
        # the authorization boundary may perform it.
        if _control is not _CONTROL_APPEND:
            raise AuthorizationDenied("capability registration is boundary-owned")
        if not isinstance(capability, EffectCapability):
            raise AuthorizationDenied("closed effect capability required")
        if self._authentication_service is not None:
            if self.effect_capability(capability.effect_id) != capability:
                raise AuthorizationDenied('view registration requires exact witnessed issuance')
            self.effect_intent(capability)
            self._effect_capabilities[capability.effect_id] = capability
            self._effect_status[capability.effect_id] = 'INTENT_RECORDED'
            return
        if capability.effect_id in self._effect_capabilities:
            raise AuthorizationDenied("effect capability already issued")
        if not self.supervisor_is_current(capability.supervisor_generation):
            raise AuthorizationDenied("effect capability generation is stale")
        self._effect_capabilities[capability.effect_id] = capability
        self._effect_status[capability.effect_id] = "INTENT_RECORDED"

    def effect_capability(self, effect_id):
        if self._authentication_service is not None:
            frames = [f for f in self._committed_frames()
                      if f['event'].get('effect_id') == effect_id and
                      'effect' in json.loads(f['envelope'].authority_fact_bytes)]
            if len(frames) != 1:
                raise AuthorizationDenied('unique witnessed issuance required')
            frame = frames[0]
            event, receipt = frame['event'], frame['receipt']
            fact = json.loads(frame['envelope'].authority_fact_bytes)['effect']
            return EffectCapability(fact['capability_id'], receipt.event_id, receipt.revision,
                receipt.event_digest, ArtifactBinding(**fact['artifact_binding']),
                event['authorization_digest'], event['fence_epoch'], event['session_id'],
                event['target'], event['operation'], effect_id, event['supervisor_generation'], True)
        capability = self._effect_capabilities.get(effect_id)
        if capability is None:
            raise AuthorizationDenied("authoritative effect capability absent")
        return capability

    def effect_intent(self, capability):
        with self.authorization_lock:
            if self._authentication_service is None:
                raise AuthorizationDenied('legacy history cannot authorize an execution intent')
            self.assert_healthy_authority()
            if self._authentication_service is not None:
                actor = self.require_actor(self._current_actor)
                if (self.effect_capability(capability.effect_id) != capability or
                        capability.supervisor_generation != actor.generation or
                        capability.session_id != actor.session_id or capability.fence_epoch != actor.fence):
                    raise AuthorizationDenied('historical issuance cannot confer current authority')
                if not self.witness.acknowledged_current(actor, capability.transition_event_id):
                    raise AuthorizationDenied('intent was not acknowledged in the captured incarnation')
                if self.execution_revoked:
                    raise AuthorizationDenied('execution revoked')
                return copy.deepcopy(self._durable[capability.transition_revision - 1]['event'])
            if (not isinstance(capability, EffectCapability) or
                    self._effect_capabilities.get(capability.effect_id) != capability or
                    capability.effect_id in self._invalidated_effects or
                    not self.supervisor_is_current(capability.supervisor_generation)):
                raise AuthorizationDenied("effect capability is not authoritative")
            registered = self._sessions.get(capability.session_id)
            if (self.execution_revoked or capability.fence_epoch != self.witness.current_fence or
                    registered is None or not registered.execution_live or
                    registered.fence_epoch != capability.fence_epoch or
                    capability.artifact_binding.session_id != registered.session_id or
                    capability.artifact_binding.fence_epoch != registered.fence_epoch):
                raise AuthorizationDenied("effect acceptance lost authority")
            frame = next((frame for frame in self._durable
                          if frame["event_id"] == capability.transition_event_id), None)
            if (frame is None or frame["receipt"].event_digest != capability.transition_event_digest or
                    frame["receipt"].revision != capability.transition_revision or
                    frame["event"].get("effect_id") != capability.effect_id or
                    frame["event"].get("target") != capability.target or
                    frame["event"].get("operation") != capability.operation or
                    frame["event"].get("authorization_digest") != capability.authorization_digest or
                    frame["event"].get("authorizes_execution") is not True):
                raise AuthorizationDenied("effect capability does not match durable intent")
            return copy.deepcopy(frame["event"])

    def activate_creation_grant(self, capability):
        with self.authorization_lock:
            self.effect_intent(capability)
            if self._authentication_service is not None:
                if capability.operation != 'blocked-create' or self.effect_acceptance_count(capability.effect_id):
                    raise AuthorizationDenied('current original unaccepted creation intent required')
                self._active_creation_grants.add(capability.effect_id)
                self._effect_status[capability.effect_id] = 'FIRST_DISPATCH_ACTIVE'
                return
            if (capability.operation != "blocked-create" or
                    self._effect_status.get(capability.effect_id) != "INTENT_RECORDED"):
                raise AuthorizationDenied("first dispatch is not creation eligible")
            self._active_creation_grants.add(capability.effect_id)
            self._effect_status[capability.effect_id] = "FIRST_DISPATCH_ACTIVE"

    def deactivate_creation_grant(self, capability):
        with self.authorization_lock:
            self._active_creation_grants.discard(capability.effect_id)
            if self._effect_status.get(capability.effect_id) == "FIRST_DISPATCH_ACTIVE":
                self._effect_status[capability.effect_id] = "UNRESOLVED"
                self._invalidated_effects.add(capability.effect_id)

    def creation_grant_active(self, capability):
        if self._authentication_service is not None:
            self.effect_intent(capability)
            return capability.operation == 'blocked-create' and not self.effect_acceptance_count(capability.effect_id)
        return (self._effect_status.get(capability.effect_id) == "FIRST_DISPATCH_ACTIVE" and
                capability.effect_id in self._active_creation_grants and
                self.supervisor_is_current(capability.supervisor_generation))

    def effect_status(self, capability):
        if self._authentication_service is not None:
            if self.effect_capability(capability.effect_id) != capability:
                raise AuthorizationDenied('effect identity substitution')
            if any(f['event'].get('record_type') == 'EFFECT_RESULT' and
                   f['event'].get('effect_id') == capability.effect_id for f in self._committed_frames()):
                return 'KNOWN_RESULT'
            if self.effect_acceptance_count(capability.effect_id):
                return 'ACCEPTANCE_PENDING'
            return 'INTENT_RECORDED'
        if self._effect_capabilities.get(capability.effect_id) != capability:
            raise AuthorizationDenied("authoritative effect capability absent")
        return self._effect_status.get(capability.effect_id)

    def mark_effect_unresolved(self, capability):
        with self.authorization_lock:
            if self._effect_capabilities.get(capability.effect_id) == capability:
                self._active_creation_grants.discard(capability.effect_id)
                self._effect_status[capability.effect_id] = "UNRESOLVED"
                self._invalidated_effects.add(capability.effect_id)

    def record_effect_result(self, capability, receipt, *, actor=None):
        with self.authorization_lock:
            if self._authentication_service is not None:
                actor = self.require_actor(actor, 'RESULT')
                acceptance = self._acceptance_frame(capability)
                original = self.event_receipt(capability.transition_event_id)
                raw = _u04_canonical(asdict(receipt))
                self._custodian.validate_creation_result(capability, raw, self._custodian.identity)
                existing = [f for f in self._committed_frames() if
                    f['event'].get('record_type') == 'EFFECT_RESULT' and f['event'].get('effect_id') == capability.effect_id]
                if existing:
                    known = self.effect_result(capability.effect_id)
                    if known.receipt != receipt:
                        raise AuthorizationDenied('historical result cannot be substituted')
                    return known
                object_id = 'effect-result-' + capability.effect_id
                self.put_object(object_id, raw, actor=actor, boundary='RESULT')
                accepted = acceptance['receipt']
                event = self._u04_common(actor, 'EFFECT_RESULT', 'EVIDENCE', False)
                event.update(acceptance_ref={'event_id': accepted.event_id,
                    'revision': accepted.revision, 'payload_digest': accepted.event_digest},
                    effect_id=capability.effect_id, original_producer_ref={
                        'event_id': original.event_id, 'revision': original.revision,
                        'payload_digest': original.event_digest}, result={
                            'object_id': object_id, 'sha256': _sha(raw), 'length': len(raw)},
                    result_kind='CUSTODIAN_RECEIPT', verifier_id=self._custodian.identity)
                self._commit_u04(actor, 'RESULT', event)
                return self.effect_result(capability.effect_id)
            if (self._effect_capabilities.get(capability.effect_id) != capability or
                    self._effect_status.get(capability.effect_id) != "ACCEPTANCE_PENDING"):
                raise AuthorizationDenied("effect acceptance is not awaiting a result")
            envelope = HistoricalEffectReceipt(
                capability.effect_id, capability.supervisor_generation,
                capability.transition_event_digest, receipt)
            self._effect_results[capability.effect_id] = envelope
            self._effect_status[capability.effect_id] = "KNOWN_RESULT"
            return envelope

    def effect_result(self, effect_id):
        if self._authentication_service is not None:
            capability = self.effect_capability(effect_id)
            frames = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_RESULT' and
                f['event'].get('effect_id') == effect_id]
            if len(frames) != 1:
                raise AuthorizationDenied('exact durable effect result unavailable')
            result = parse_effect_result_record(_u04_canonical(frames[0]['event']))
            raw = self.read_object(result.result.object_id, result.result.sha256)
            receipt = self._custodian.validate_creation_result(capability, raw, result.verifier_id)
            return HistoricalEffectReceipt(effect_id, capability.supervisor_generation,
                                            capability.transition_event_digest, receipt)
        envelope = self._effect_results.get(effect_id)
        capability = self._effect_capabilities.get(effect_id)
        if (envelope is None or capability is None or
                envelope.transition_event_digest != capability.transition_event_digest):
            raise AuthorizationDenied("validated historical effect result absent")
        frame = next((frame for frame in self._durable
                      if frame["event_id"] == capability.transition_event_id), None)
        if (frame is None or frame["receipt"].event_digest != envelope.transition_event_digest or
                frame["event"].get("effect_id") != effect_id):
            raise AuthorizationDenied("historical effect result lost durable provenance")
        return envelope

    def effect_acceptance_count(self, effect_id):
        if self._authentication_service is not None:
            return len([f for f in self._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_ACCEPTED' and
                f['event'].get('effect_id') == effect_id])
        return self._effect_acceptance_counts.get(effect_id, 0)

    def accept_effect(self, capability):
        with self.authorization_lock:
            if self._authentication_service is None:
                raise AuthorizationDenied('legacy records cannot accept a new execution effect')
            event = self.effect_intent(capability)
            if self._authentication_service is not None:
                actor = self.require_actor(self._current_actor)
                if capability.operation == 'blocked-create' and not self.creation_grant_active(capability):
                    raise AuthorizationDenied('active first dispatch required')
                original = self.event_receipt(capability.transition_event_id)
                accepted = self._u04_common(actor, 'EFFECT_ACCEPTED', 'EXECUTION', True)
                accepted.update(intent_ref={'event_id': original.event_id,
                    'revision': original.revision, 'payload_digest': original.event_digest},
                    effect_id=capability.effect_id,
                    capability_digest=_sha(_u04_canonical(asdict(capability))),
                    operation=capability.operation, target=capability.target,
                    consumption_id=capability.effect_id,
                    artifact_binding=asdict(capability.artifact_binding),
                    target_acceptance_identity=capability.target)
                self._commit_u04(actor, 'EXEC', accepted)
                self.require_actor(actor)
                # Acknowledgement is a current volatile capability, never
                # reconstructed from the committed acceptance alone.
                self._effect_status[capability.effect_id] = 'ACCEPTANCE_PENDING'
                self._acceptance_acks[capability.effect_id] = actor
                return event

    def effect_accepted(self, capability):
        if self._authentication_service is not None:
            return self.effect_acceptance_count(capability.effect_id) == 1
        return False

    def _acceptance_frame(self, capability):
        frames = [f for f in self._committed_frames() if
            f['event'].get('record_type') == 'EFFECT_ACCEPTED' and
            f['event'].get('effect_id') == capability.effect_id]
        if len(frames) != 1 or frames[0]['event']['capability_digest'] != _sha(
                _u04_canonical(asdict(capability))):
            raise AuthorizationDenied('unique exact witnessed acceptance required')
        return frames[0]

    def validate_initiation(self, capability):
        """Independent port check after acknowledgement, immediately before effect."""
        self.effect_intent(capability)
        acceptance = self._acceptance_frame(capability)
        if not self.witness.acknowledged_current(self._current_actor, acceptance['event_id']):
            raise AuthorizationDenied('acceptance was not acknowledged in this incarnation')
        self.validate_artifact_continuity(capability.artifact_binding)
        return self.require_actor(self._current_actor)

    def authoritative_state(self, domain, boot_ordinal):
        """Latest state label whose frame carries authorization-boundary provenance."""
        for frame in reversed(self._durable):
            event = frame["event"]
            if event.get("state_domain") != domain:
                continue
            if domain in ("boot", "attempt") and event.get("boot_ordinal") != boot_ordinal:
                continue
            if not self.frame_has_provenance(frame):
                continue
            return event.get("state")
        return None

    # ---- provenance -----------------------------------------------------

    def event_receipt(self, event_id):
        if self._authentication_service is not None:
            matches = [f['receipt'] for f in self._committed_frames() if f['event_id'] == event_id]
            return matches[0] if len(matches) == 1 else None
        return self._receipts.get(event_id)

    def frame_has_provenance(self, frame):
        """True only for a frame written by the authorization boundary for the
        exact operation that is allowed to produce its state."""
        event = frame["event"]
        if self._authentication_service is None:
            return False
        if self._authentication_service is not None:
            envelope = frame.get('envelope')
            if type(envelope) is not JournalEnvelope or not self._u04_frame_valid(frame):
                return False
            status, committed = self.witness.query_transaction(envelope.transaction_id)
            if status != 'COMMITTED' or committed.reservation.frame_digest != envelope.frame_digest:
                return False
            if envelope.boundary == 'INIT' and event.get('state') in ('AUTHORIZATION_ADMITTED', 'CAMPAIGN_ADMITTED'):
                return True
            facts = json.loads(envelope.authority_fact_bytes)
            if 'effect' not in facts:
                return False
            operation, state = event.get('operation'), event.get('state')
            schema = (GENERIC_TRANSITION_SCHEMAS.get(state) if operation == 'append-transition'
                      else DEDICATED_OPERATIONS.get(operation, {}).get(state))
            return (schema is not None and envelope.boundary == 'EXEC' and
                    envelope.producer_bytes == _u04_canonical(facts['producer']))
        state = event.get("state")
        operation = event.get("operation")
        effect_id = event.get("effect_id")
        if event.get("authorizes_execution") is not True or type(effect_id) is not str:
            return False
        if operation == "append-transition":
            if state not in GENERIC_TRANSITION_SCHEMAS or "record_type" in event:
                return False
        elif state not in DEDICATED_OPERATIONS.get(operation, {}):
            return False
        elif ("record_type" in event) != (operation == "consume-boot-activation"):
            return False
        capability = self._effect_capabilities.get(effect_id)
        return (capability is not None and
                capability.transition_event_id == frame["event_id"] and
                capability.transition_event_digest == frame["receipt"].event_digest and
                capability.transition_revision == frame["receipt"].revision and
                capability.operation == operation and
                event.get("consumption") == {"kind": "effect", "identity": effect_id})

    def provenanced_frames(self, state=None, operation=None):
        return [frame for frame in self._durable
                if (state is None or frame["event"].get("state") == state) and
                (operation is None or frame["event"].get("operation") == operation) and
                self.frame_has_provenance(frame)]

    def frame_index(self, event_id):
        for index, frame in enumerate(self._durable):
            if frame["event_id"] == event_id:
                return index
        return None

    # ---- store-owned validated evidence registries -----------------------

    @staticmethod
    def _require_dedicated(authority):
        if authority is not _DEDICATED_AUTHORITY:
            raise AuthorizationDenied("dedicated operation authority required")

    def _reset_validated_registries(self, authority):
        self._require_dedicated(authority)
        with self.authorization_lock:
            self._validated_completions = {}
            self._validated_boot_closures = {}
            self._validated_campaign_closure = None
            self._validated_boot_custody = {}

    def _register_validated_completion(self, authority, slot_id, completion_digest):
        self._require_dedicated(authority)
        with self.authorization_lock:
            frames = [frame for frame in self.provenanced_frames("ATTEMPT_COMPLETE",
                                                                 "complete-attempt")
                      if frame["event"].get("slot_id") == slot_id and
                      frame["event"].get("completion_digest") == completion_digest]
            if len(frames) != 1:
                raise AuthorizationDenied("unique provenanced completion required")
            self._validated_completions[slot_id] = {
                "slot_id": slot_id, "completion_digest": completion_digest,
                "event_id": frames[0]["event_id"],
                "event_digest": frames[0]["receipt"].event_digest,
            }

    def validated_completion(self, slot_id):
        if self._authentication_service is not None:
            self._committed_frames()
            frames = [f for f in self.provenanced_frames('ATTEMPT_COMPLETE', 'complete-attempt')
                      if f['event'].get('slot_id') == slot_id]
            if len(frames) != 1:
                return None
            frame = frames[0]
            try:
                _HistoricalEvidenceVerifier(self, self._admitted_payload())._validate_attempt_completion_record(
                    slot_id, frame['event'], require_completion_event=True)
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                return None
            return {'slot_id': slot_id, 'completion_digest': frame['event']['completion_digest'],
                    'event_id': frame['event_id'], 'event_digest': frame['receipt'].event_digest}
        record = self._validated_completions.get(slot_id)
        if record is None:
            return None
        index = self.frame_index(record["event_id"])
        if index is None:
            return None
        frame = self._durable[index]
        if (not self.frame_has_provenance(frame) or
                frame["receipt"].event_digest != record["event_digest"] or
                frame["event"].get("state") != "ATTEMPT_COMPLETE" or
                frame["event"].get("slot_id") != slot_id or
                frame["event"].get("completion_digest") != record["completion_digest"]):
            return None
        return dict(record)

    def _register_validated_boot_custody(self, authority, record):
        self._require_dedicated(authority)
        with self.authorization_lock:
            self._validated_boot_custody[record["boot_ordinal"]] = dict(record)

    def validated_boot_custody(self, boot_ordinal):
        """Custody completion re-derived from custodian evidence, or None."""
        if self._authentication_service is not None:
            frames = [f for f in self.provenanced_frames('BOOT_CUSTODY_COMPLETE',
                        'complete-boot-custody') if f['event'].get('boot_ordinal') == boot_ordinal]
            if len(frames) != 1:
                return None
            frame = frames[0]
            try:
                proof = _boot_custody_proof(self, self._admitted_payload(), boot_ordinal,
                    frame['event'], self.frame_index(frame['event_id']))
                return dict(proof, event_id=frame['event_id'], event_digest=frame['receipt'].event_digest)
            except (ContractError, StoreError, KeyError, TypeError):
                return None
        record = self._validated_boot_custody.get(boot_ordinal)
        if record is None:
            return None
        frames = [frame for frame in self.provenanced_frames(
                      "BOOT_CUSTODY_COMPLETE", "complete-boot-custody")
                  if frame["event"].get("boot_ordinal") == boot_ordinal]
        if (len(frames) != 1 or frames[0]["event_id"] != record["event_id"] or
                frames[0]["receipt"].event_digest != record["event_digest"]):
            return None
        return dict(record)

    def _register_validated_boot_closure(self, authority, boot_ordinal, event_digest):
        self._require_dedicated(authority)
        with self.authorization_lock:
            self._validated_boot_closures[boot_ordinal] = event_digest

    def validated_boot_closure(self, boot_ordinal):
        if self._authentication_service is not None:
            self._committed_frames()
            try:
                return _HistoricalEvidenceVerifier(self, self._admitted_payload())._validate_boot_closure(boot_ordinal)
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                return None
        digest = self._validated_boot_closures.get(boot_ordinal)
        if digest is None:
            return None
        frames = [frame for frame in self.provenanced_frames("BOOT_COMPLETE", "complete-boot")
                  if frame["event"].get("boot_ordinal") == boot_ordinal]
        if len(frames) != 1 or frames[0]["receipt"].event_digest != digest:
            return None
        return digest

    def _register_validated_campaign_closure(self, authority, event_digest):
        self._require_dedicated(authority)
        with self.authorization_lock:
            self._validated_campaign_closure = event_digest

    def validated_campaign_closure(self):
        if self._authentication_service is not None:
            self._committed_frames()
            try:
                return _HistoricalEvidenceVerifier(self, self._admitted_payload())._validate_campaign_closure()
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                return None
        return self._validated_campaign_closure

    def boot_identity(self, boot_ordinal):
        """Boot identity admitted by provenanced admission/activation records."""
        if boot_ordinal == 1:
            frames = self.provenanced_frames("CAMPAIGN_ADMITTED", "admit-campaign")
            return frames[-1]["event"].get("boot_id") if len(frames) == 1 else None
        if self._authentication_service is not None:
            admitted = [f for f in self._committed_frames() if
                f['event'].get('record_type') == 'ACTIVATION_ADMITTED' and
                f['event'].get('next_boot_ordinal') == boot_ordinal]
            if len(admitted) == 1:
                return admitted[0]['event']['observed_boot_id']
            return None
        for frame in self.provenanced_frames("BOOT_HANDOFF_PENDING",
                                             "consume-boot-activation"):
            event = frame["event"]
            if (event.get("activated_boot_ordinal") == boot_ordinal and
                    self.validated_boot_closure(boot_ordinal - 1) ==
                    event.get("predecessor_closure_digest")):
                return event.get("observed_boot_id")
        return None

    # ---- slot capability gate --------------------------------------------

    def _prepare_slot_grant(self, authorization, session, event):
        """Validate a dedicated eligibility request against store-owned facts."""
        slot = next((item for item in authorization.slots
                     if item.slot_id == event.get("slot_id")), None)
        if (slot is None or slot.boot_ordinal != session.boot_ordinal or
                event.get("attempt_id") != slot.attempt_id or
                event.get("spawn_token") != "spawn-" + slot.slot_id or
                type(event.get("custodian_id")) is not str or not event["custodian_id"]):
            raise AuthorizationDenied("slot eligibility identity")
        boot_id = self.boot_identity(slot.boot_ordinal)
        if boot_id is None or event.get("boot_id") != boot_id:
            raise AuthorizationDenied("slot eligibility boot identity")
        if self.is_consumed("slot", slot.slot_id) or (self._authentication_service is None and slot.slot_id in self._slot_grants):
            raise AuthorizationDenied("slot already consumed")
        custody = self.validated_boot_custody(slot.boot_ordinal)
        if (custody is None or custody["boot_id"] != boot_id or
                custody["custodian_id"] != event["custodian_id"]):
            raise AuthorizationDenied("slot eligibility requires validated boot custody")
        if slot.worker_ordinal == 1:
            if (event.get("predecessor_slot_id") is not None or
                    event.get("predecessor_completion_digest") is not None or
                    self.authoritative_state("boot", slot.boot_ordinal) !=
                    "BOOT_CUSTODY_COMPLETE"):
                raise AuthorizationDenied("first worker requires completed boot custody")
        else:
            predecessor = next((item for item in authorization.slots
                                if item.boot_ordinal == slot.boot_ordinal and
                                item.worker_ordinal == slot.worker_ordinal - 1), None)
            validated = (None if predecessor is None else
                         self.validated_completion(predecessor.slot_id))
            if (predecessor is None or validated is None or
                    event.get("predecessor_slot_id") != predecessor.slot_id or
                    event.get("predecessor_completion_digest") !=
                    validated["completion_digest"]):
                raise AuthorizationDenied("validated same-boot predecessor required")
        return {"slot_id": slot.slot_id, "attempt_id": slot.attempt_id,
                "boot_ordinal": slot.boot_ordinal, "boot_id": boot_id,
                "campaign_id": authorization.campaign_id,
                "spawn_token": event["spawn_token"],
                "custodian_id": event["custodian_id"],
                "predecessor_slot_id": event.get("predecessor_slot_id"),
                "predecessor_completion_digest": event.get("predecessor_completion_digest")}

    def _register_slot_grant(self, record, receipt, session):
        self._slot_grants[record["slot_id"]] = dict(
            record, status="ELIGIBLE", eligibility_event_id=receipt.event_id,
            eligibility_event_digest=receipt.event_digest,
            supervisor_generation=self._supervisor_generation,
            session_id=session.session_id, fence_epoch=session.fence_epoch,
            effect_id=None, launch_spec_digest=None)

    def _grant_predecessor_valid(self, grant):
        if grant["predecessor_slot_id"] is None:
            return True
        validated = self.validated_completion(grant["predecessor_slot_id"])
        return (validated is not None and validated["completion_digest"] ==
                grant["predecessor_completion_digest"])

    def _check_slot_grant_for_creation(self, authorization, session, event):
        grant = self._derived_slot_grant(event.get('slot_id'))
        if grant is None or grant["status"] != "ELIGIBLE":
            raise AuthorizationDenied("store-backed slot capability required")
        index = self.frame_index(grant["eligibility_event_id"])
        eligibility = [frame for frame in self.provenanced_frames(
                           "SLOT_SPAWN_ELIGIBLE", "make-slot-eligible")
                       if frame["event"].get("boot_ordinal") == session.boot_ordinal]
        if (index is None or not eligibility or
                eligibility[-1]["event_id"] != grant["eligibility_event_id"] or
                eligibility[-1]["receipt"].event_digest != grant["eligibility_event_digest"]):
            raise AuthorizationDenied("slot eligibility is not the current attempt")
        generation = (self.require_actor(self._current_actor).generation
                      if self._authentication_service is not None else self._supervisor_generation)
        if (grant["supervisor_generation"] != generation or
                event.get("supervisor_generation") != grant["supervisor_generation"] or
                grant["session_id"] != session.session_id or
                grant["fence_epoch"] != session.fence_epoch or
                grant["boot_ordinal"] != session.boot_ordinal):
            raise AuthorizationDenied("stale slot capability")
        if (event.get("attempt_id") != grant["attempt_id"] or
                event.get("boot_id") != grant["boot_id"] or
                event.get("boot_id") != self.boot_identity(grant["boot_ordinal"]) or
                event.get("campaign_id") != grant["campaign_id"] or
                grant["campaign_id"] != authorization.campaign_id or
                event.get("spawn_token") != grant["spawn_token"] or
                event.get("custodian_id") != grant["custodian_id"]):
            raise AuthorizationDenied("spawn intent does not match slot capability")
        if not self.is_consumed("slot", grant["slot_id"]):
            raise AuthorizationDenied("slot capability has not been consumed")
        if not self._grant_predecessor_valid(grant):
            raise AuthorizationDenied("slot predecessor is no longer validly complete")
        return grant

    def _reserve_slot_grant(self, slot_id, effect_id, launch_spec_digest):
        if self._authentication_service is not None:
            # Cache registration is derived after the actual journaled intent.
            self._slot_grants[slot_id] = self._derived_slot_grant(slot_id)
            return
        grant = self._slot_grants[slot_id]
        grant.update(status="RESERVED", effect_id=effect_id,
                     launch_spec_digest=launch_spec_digest)

    def _derived_slot_grant(self, slot_id):
        if self._authentication_service is None:
            return self._slot_grants.get(slot_id)
        eligibility = [f for f in self.provenanced_frames('SLOT_SPAWN_ELIGIBLE', 'make-slot-eligible')
                       if f['event'].get('slot_id') == slot_id]
        if len(eligibility) != 1:
            return None
        frame = eligibility[0]
        event = frame['event']
        grant = {name: event[name] for name in ('slot_id', 'attempt_id', 'boot_ordinal',
            'boot_id', 'campaign_id', 'spawn_token', 'custodian_id', 'predecessor_slot_id',
            'predecessor_completion_digest', 'supervisor_generation', 'session_id', 'fence_epoch')}
        grant.update(status='ELIGIBLE', eligibility_event_id=frame['event_id'],
            eligibility_event_digest=frame['receipt'].event_digest, effect_id=None,
            launch_spec_digest=None)
        intents = [f for f in self.provenanced_frames('SPAWN_INTENT_PERSISTED', 'blocked-create')
                   if f['event'].get('slot_id') == slot_id]
        if intents:
            if len(intents) != 1:
                raise AuthorizationDenied('multiple creation intents for one slot')
            grant.update(status='RESERVED', effect_id=intents[0]['event']['effect_id'],
                         launch_spec_digest=intents[0]['event']['launch_spec_digest'])
        return grant

    def creation_slot_grant(self, capability, token):
        """Authoritative creation-boundary check used by the custodian."""
        with self.authorization_lock:
            self.effect_intent(capability)
            grant = self._derived_slot_grant(getattr(token, "slot_id", None))
            if (grant is None or grant["status"] != "RESERVED" or
                    not isinstance(capability, EffectCapability) or
                    grant["effect_id"] != capability.effect_id or
                    grant["supervisor_generation"] != capability.supervisor_generation or
                    not self.supervisor_is_current(grant["supervisor_generation"]) or
                    grant["session_id"] != capability.session_id or
                    grant["fence_epoch"] != capability.fence_epoch or
                    grant["spawn_token"] != token.token_id or
                    grant["attempt_id"] != token.attempt_id or
                    grant["boot_id"] != token.boot_id or
                    grant["campaign_id"] != token.campaign_id or
                    grant["custodian_id"] != token.custodian_id or
                    grant["launch_spec_digest"] != token.launch_spec_digest or
                    token.supervisor_generation != grant["supervisor_generation"] or
                    not self._grant_predecessor_valid(grant)):
                raise AuthorizationDenied("creation lacks a reserved store slot capability")
            return dict(grant)


class ArtifactVerificationPrimitive:
    """Nonrecursive trust root for exact authorized execution bytes."""

    def __setattr__(self, name, value):
        if (name in ('identity', 'authorization', 'artifact_reader') and
                name in self.__dict__ and self.__dict__[name] is not value):
            raise AuthorizationDenied('artifact verification bootstrap references are pinned')
        object.__setattr__(self, name, value)

    def __init__(self, verifier_identity, authorization, artifact_reader):
        if type(verifier_identity) is not str or not verifier_identity:
            raise AuthorizationDenied("verifier identity")
        if not isinstance(authorization, Authorization):
            raise AuthorizationDenied("authorization contract")
        if not callable(artifact_reader):
            raise AuthorizationDenied("artifact reader")
        self.identity = verifier_identity
        self.authorization = authorization
        self.artifact_reader = artifact_reader
        self.root_binding_live = True
        self._sequence = 0

    @property
    def expected(self):
        return {"core": self.authorization.core_manifest_digest,
                "adapter": self.authorization.adapter_manifest_digest,
                "policy": self.authorization.policy_digest,
                "schema": self.authorization.schema_digest}

    def _read_exact(self):
        current = self.artifact_reader()
        if type(current) is not dict or set(current) != {"core", "adapter", "policy", "schema"}:
            raise AuthorizationDenied("artifact manifest structure")
        core = current["core"]
        adapter = current["adapter"]
        if (type(core) is not dict or set(core) != {"commit", "files"} or
                core["commit"] != self.authorization.core_commit or
                type(adapter) is not dict or set(adapter) != {"files"}):
            raise AuthorizationDenied("artifact commit and manifest structure")
        def manifest_digest(kind, files, commit=None):
            if (type(files) is not dict or not files or
                    any(type(path) is not str or not path or type(value) is not bytes
                        for path, value in files.items())):
                raise AuthorizationDenied("closed artifact file manifest")
            record = {"kind": kind,
                      "files": [[path, _sha(value)] for path, value in sorted(files.items())]}
            if commit is not None:
                record["commit"] = commit
            return _sha(_canonical(record))
        for name in ("policy", "schema"):
            if type(current[name]) is not bytes:
                raise AuthorizationDenied("policy/schema bytes required")
        computed = {
            "core": manifest_digest("core", core["files"], core["commit"]),
            "adapter": manifest_digest("adapter", adapter["files"]),
            "policy": _sha(current["policy"]), "schema": _sha(current["schema"]),
        }
        if computed != self.expected:
            raise AuthorizationDenied("authorized execution bytes changed")
        return computed

    def verify(self, transition, fence_epoch, session_id):
        if not self.root_binding_live:
            raise AuthorizationDenied("verification root binding lost")
        current = self._read_exact()
        self._sequence += 1
        return ArtifactBinding(
            "verification-%d" % self._sequence, self.identity,
            self.authorization.authorization_digest, transition, fence_epoch,
            session_id, current["core"], current["adapter"], current["policy"],
            current["schema"], True,
        )

    def assert_continuity(self, binding):
        if not isinstance(binding, ArtifactBinding) or not self.root_binding_live:
            raise AuthorizationDenied("artifact binding continuity lost")
        if binding.manifest() != self._read_exact():
            raise AuthorizationDenied("artifact substitution")
        return True


def _closed_payload(operation, transition, source_event, schema, trusted, authorization,
                    session):
    """Reject unknown, reserved, or authority-bearing caller fields."""
    keys = set(source_event)
    if operation == "append-transition":
        if not keys <= schema or "slot_id" not in keys or keys & TRUSTED_EVENT_FIELDS:
            raise AuthorizationDenied("closed general transition payload")
        for name, value in source_event.items():
            if name in _GENERIC_INTEGER_FIELDS:
                if type(value) is not int or value < 0:
                    raise AuthorizationDenied("closed general transition payload value")
            elif type(value) is not str or not value:
                raise AuthorizationDenied("closed general transition payload value")
        slot = next((item for item in authorization.slots
                     if item.slot_id == source_event["slot_id"]), None)
        if slot is None or slot.boot_ordinal != session.boot_ordinal:
            raise AuthorizationDenied("general transition slot binding")
        return
    if keys != schema:
        raise AuthorizationDenied("closed dedicated operation payload")
    for name in keys & TRUSTED_EVENT_FIELDS:
        if source_event[name] != trusted[name]:
            raise AuthorizationDenied("dedicated payload conflicts with trusted field")
    if operation == "consume-boot-activation" and source_event["record_type"] != "BOOT_ACTIVATION":
        raise AuthorizationDenied("boot activation record type")


def authorize_and_dispatch(store, verifier, expected_revision, current_fence,
                           session, transition, effect_specification, dispatcher,
                           interlock=None, *, _authority=None):
    """Linearize verification, CAS, capability issuance, and bound dispatch.

    ``append-transition`` is the only general operation and accepts only the
    closed ``GENERIC_TRANSITION_SCHEMAS`` allowlist.  Every other transition is
    produced exclusively by its dedicated operation, which requires the
    module-private dedicated authority and a closed payload.
    """
    if type(effect_specification) is not dict or set(effect_specification) != {
            "effect_id", "target", "operation", "event_id", "event"}:
        raise AuthorizationDenied("closed effect specification")
    domains = [domain for domain, states in STATE_DOMAINS.items() if transition in states]
    if len(domains) != 1 or domains[0] == "safety":
        raise ContractError("unknown, removed, or non-executable state")
    parse_state(domains[0], transition)
    if not callable(dispatcher):
        raise AuthorizationDenied("dispatch port absent")
    operation = effect_specification["operation"]
    if operation == "append-transition":
        if _authority is not None:
            raise AuthorizationDenied("dedicated authority cannot use the general operation")
        schema = GENERIC_TRANSITION_SCHEMAS.get(transition)
        if schema is None:
            raise AuthorizationDenied(
                "reserved transition requires its dedicated evidence-validating operation")
    elif operation in DEDICATED_OPERATIONS:
        if _authority is not _DEDICATED_AUTHORITY:
            raise AuthorizationDenied("dedicated operation authority required")
        schema = DEDICATED_OPERATIONS[operation].get(transition)
        if schema is None:
            raise AuthorizationDenied("transition is not produced by this operation")
    else:
        raise AuthorizationDenied("operation is not authorized")
    source_event = effect_specification["event"]
    if type(source_event) is not dict:
        raise AuthorizationDenied("closed transition event required")
    effect_id = effect_specification["effect_id"]
    target = effect_specification["target"]
    with store.authorization_lock:
        store.assert_healthy_authority()
        if not isinstance(session, FenceSession) or not session.execution_live:
            raise AuthorizationDenied("live execution session required")
        if not store.session_registered(session):
            raise AuthorizationDenied("registered execution session required")
        if current_fence != session.fence_epoch or current_fence != store.witness.current_fence:
            raise AuthorizationDenied("stale fence/session")
        if store.execution_revoked:
            raise AuthorizationDenied("taint or custody prohibition")
        transition_boot_ordinal = session.boot_ordinal
        if operation == "consume-boot-activation":
            transition_boot_ordinal = session.boot_ordinal - 1
        trusted = {
            "state": transition, "effect_id": effect_id, "state_domain": domains[0],
            "session_id": session.session_id, "session_owner": session.owner_identity,
            "session_live": session.execution_live, "fence_epoch": current_fence,
            "boot_ordinal": transition_boot_ordinal,
            "session_boot_ordinal": session.boot_ordinal,
            "supervisor_generation": store._supervisor_generation,
            "authorization_digest": verifier.authorization.authorization_digest,
            "campaign_id": verifier.authorization.campaign_id,
            "target": target, "operation": operation,
            "authorizes_execution": True, "dispatch_resolved": False,
            "consumption": {"kind": "effect", "identity": effect_id},
        }
        _closed_payload(operation, transition, source_event, schema, trusted,
                        verifier.authorization, session)
        if operation == "blocked-create":
            if (target != source_event["custodian_id"] or
                    not store.supervisor_is_current(source_event["supervisor_generation"])):
                raise AuthorizationDenied("blocked create operation contract")
        elif target not in (store.identity, "offline-store"):
            raise AuthorizationDenied("store transition target")
        prior = store.authoritative_state(domains[0], transition_boot_ordinal)
        allowed = TRANSITION_PREDECESSORS.get(domains[0], {}).get(transition)
        slot_grant = None
        custody_proof = None
        if operation == "append-transition":
            intents = [frame for frame in store.provenanced_frames(
                           "SPAWN_INTENT_PERSISTED", "blocked-create")
                       if frame["event"].get("boot_ordinal") == session.boot_ordinal]
            if (not intents or intents[-1]["event"].get("slot_id") != source_event["slot_id"] or
                    source_event.get("spawn_token", intents[-1]["event"].get("spawn_token")) !=
                    intents[-1]["event"].get("spawn_token")):
                raise AuthorizationDenied("observation must bind the current spawned attempt")
        elif operation in ("establish-boot-custody", "complete-boot-custody"):
            # The token is not evidence: the state-producing boundary itself
            # re-checks the custodian-issued custody evidence and identity.
            custody_proof = _boot_custody_evidence(store, verifier.authorization,
                                                   operation, source_event, trusted)
        elif operation == "make-slot-eligible":
            slot_grant = store._prepare_slot_grant(verifier.authorization, session,
                                                   source_event)
        elif operation == "blocked-create":
            store._check_slot_grant_for_creation(verifier.authorization, session,
                                                 source_event)
        elif operation == "consume-boot-activation":
            if (session.boot_ordinal < 2 or
                    source_event["activated_boot_ordinal"] != session.boot_ordinal):
                raise AuthorizationDenied("boot activation operation contract")
            allowed = ("BOOT_HANDOFF_PENDING",)
            closure = store.validated_boot_closure(transition_boot_ordinal)
            if closure is None or source_event["predecessor_closure_digest"] != closure:
                raise AuthorizationDenied("boot activation predecessor closure")
        elif operation == "finalize-boot-closure-candidate":
            required = sorted(slot.slot_id for slot in verifier.authorization.slots
                              if slot.boot_ordinal == session.boot_ordinal)
            bound = source_event["attempt_completion_digests"]
            if (type(bound) is not dict or sorted(bound) != required or
                    any((store.validated_completion(slot_id) or {}).get(
                        "completion_digest") != bound[slot_id] for slot_id in required) or
                    source_event["boot_id"] != store.boot_identity(session.boot_ordinal)):
                raise AuthorizationDenied("boot closure candidate evidence binding")
        elif operation in ("complete-boot", "complete-campaign"):
            candidate_state = ("BOOT_CLOSURE_CANDIDATE_FINALIZED"
                               if operation == "complete-boot" else
                               "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")
            candidates = [frame for frame in store.provenanced_frames(candidate_state)
                          if operation == "complete-campaign" or
                          frame["event"].get("boot_ordinal") == session.boot_ordinal]
            if (len(candidates) != 1 or
                    candidates[0]["receipt"].event_digest !=
                    source_event["candidate_event_digest"] or
                    candidates[0]["event"].get("candidate_digest") !=
                    source_event["candidate_digest"]):
                raise AuthorizationDenied("closure requires its provenanced candidate")
            if operation == "complete-boot" and (
                    source_event["boot_id"] != store.boot_identity(session.boot_ordinal)):
                raise AuthorizationDenied("boot closure identity")
            # Publication must have been performed and verified for this exact
            # finalized candidate after its finalization event.
            _closure_publication_proof(store, verifier.authorization, candidates[0],
                                       source_event["publication_manifest"],
                                       store.revision)
        elif operation == "finalize-campaign-closure-candidate":
            bound = source_event["boot_closure_digests"]
            if (type(bound) is not list or
                    bound != [store.validated_boot_closure(ordinal)
                              for ordinal in (1, 2, 3, 4)] or None in bound):
                raise AuthorizationDenied("campaign closure candidate evidence binding")
        if allowed is None or prior not in allowed:
            raise AuthorizationDenied("authoritative transition precondition")
        if store.is_consumed("effect", effect_id):
            raise AuthorizationDenied("effect capability already consumed")
        try:
            binding = verifier.verify(transition, current_fence, session.session_id)
        except Exception:
            store.install_failure_latch("authoritative-verification-failure")
            raise
        event = {name: copy.deepcopy(source_event[name]) for name in source_event}
        event.update(trusted)
        event["verification_id"] = binding.verification_id
        try:
            actor = store.actor_for_session(session)
            if expected_revision != store.revision:
                raise CASMismatch('stale expected revision')
            event['authority_class'] = 'CONTROL'
            receipt = store._commit_u04(actor, 'EXEC', event, event_id=effect_specification['event_id'],
                facts={'effect': {'capability_id': 'capability-' + effect_id,
                                  'artifact_binding': asdict(binding)}})
            capability = EffectCapability(
                "capability-" + effect_id, receipt.event_id,
                receipt.revision, receipt.event_digest, binding,
                verifier.authorization.authorization_digest, current_fence,
                session.session_id, target, operation, effect_id,
                store._supervisor_generation, True,
            )
            store.register_effect_capability(capability, _control=_CONTROL_APPEND)
            if slot_grant is not None:
                store._register_slot_grant(slot_grant, receipt, session)
            if custody_proof is not None:
                store._register_validated_boot_custody(
                    _DEDICATED_AUTHORITY, dict(custody_proof, event_id=receipt.event_id,
                                               event_digest=receipt.event_digest))
            if operation == "blocked-create":
                store._reserve_slot_grant(source_event["slot_id"], effect_id,
                                          source_event["launch_spec_digest"])
            if interlock is not None:
                interlock()
            verifier.assert_continuity(binding)
            store.assert_healthy_authority()
            if (current_fence != store.witness.current_fence or
                    not store.session_registered(session) or store.execution_revoked):
                raise AuthorizationDenied("authority changed before effect acceptance")
            if target in (store.identity, "offline-store"):
                store.accept_effect(capability)
            creation_operation = capability.operation == "blocked-create"
            if creation_operation:
                store.activate_creation_grant(capability)
            try:
                if target in (store.identity, 'offline-store'):
                    result = store._custodian.initiate_control(capability, binding, dispatcher)
                    store.record_control_effect_result(actor, capability)
                else:
                    result = dispatcher(capability, binding)
            finally:
                if creation_operation:
                    store.deactivate_creation_grant(capability)
            if not store.effect_accepted(capability):
                raise AuthorizationDenied("dispatcher did not accept bound capability")
            return result, capability
        except (DispatchUncertain, TransactionPending, LostAcknowledgement, Quarantined):
            store.revoke_execution()
            store._publication_prohibited = True
            raise
        except Exception:
            store.install_failure_latch("authoritative-mutation-failure")
            raise


class PersistentSupervisor:
    def __init__(self, store, verifier, custodian, authorization, session):
        self.store = store
        self.verifier = verifier
        self.custodian = custodian
        self.authorization = authorization
        self.session = session
        self.campaign_state = None
        self.boot_state = None
        self.attempt_state = None
        self.safety_markers = set()
        self.activation_ids = set()
        self.current_boot_id = None
        self.current_boot_ordinal = 0
        self.predecessor_closure_digest = None
        self._custody = None
        self._slot_tokens = {}
        self._slot_capabilities = {}
        self._completed_attempts = {}
        self._completed_boots = set()
        self._boot_ids = {}
        self._observed_boot_ids = set()
        self.synthetic_reap = False
        self.synthetic_residual_clearance = False
        self._finalized_candidates = {}
        self.last_lifecycle_failure = None
        self.reconstruction_violations = []
        if self.store._authorization_lock.owned_by_current_thread():
            raise AuthorizationDenied('supervisor takeover cannot reenter authorization')
        fresh = (self.store._authentication_service is not None and not self.store._durable and
                 self.store.witness.high_generation == 0 and self.store.witness.high_fence == 0)
        if not fresh:
            try:
                self.store.reset_volatile()
            except BaseException:
                # A failed replacement cannot leave the outgoing token usable.
                # Preserve the primary failure; unreadable W is only uncertainty.
                try:
                    with self.store.authorization_lock:
                        self.store.crash()
                except StoreError:
                    pass
                self.store.revoke_execution()
                self.store._publication_prohibited = self.store.containment_only = True
                raise
        with self.store.authorization_lock:
            self.store.bind_artifact_verifier(verifier)
            self.custodian.bind_authority(self.store, self.record_custodian_loss)
            self._actor = None
            if (self.store._authentication_service is not None and not self.store._durable and
                    self.store.witness.high_generation == 0 and self.store.witness.high_fence == 0):
                self._actor = self.store.begin_fresh_entry(self.store._authentication_service,
                    authorization, session.owner_identity)
                self.session = FenceSession(self._actor.fence, self._actor.session_id,
                    self._actor.owner_identity, 1, False)
            else:
                self.session = replace(session, execution_live=False)
            self._supervisor_generation = self.store.witness.high_generation
            if not fresh and self.store.health != 'HEALTHY':
                self._window_history = WindowHistory(None, 0, (), frozenset(), ('history-unavailable',))
                self.safety_markers.add('CONTAINMENT_ONLY_RECOVERY')
                self._history_violation('history-health:' + self.store.health)
                # Inspection preserves forensic bytes and cannot resurrect
                # sessions, interpret labels as authority, or allocate ENTRY.
                if self.store._authentication_service is not None:
                    inspector = self.store.read_only_inspector(self.store._authentication_service,
                        self.authorization, _LOCAL_INSPECTION_READER_ID)
                    prefix_ids = {f['event_id'] for f in inspector.snapshot()['frames']}
                else:
                    # Unauthenticated local raw inspection cannot label any
                    # frame authoritative or allocate a reader actor.
                    prefix_ids = set()
                for frame in self.store._durable:
                    event = frame['event']
                    if (_is_reserved_control_record(event) and frame['event_id'] not in prefix_ids):
                        self._history_violation('unprovenanced-reserved-record:' +
                                                str(event.get('state') or event.get('record_type')))
                return
            self._reconstruct()
            if not fresh and self.store._authentication_service is not None and self.store.health == 'HEALTHY':
                try:
                    self._actor = self.store.open_nonlive_entry(authorization, session.owner_identity)
                except (AuthorizationDenied, Quarantined):
                    self._actor = None
                if self._actor is not None:
                    self._supervisor_generation = self._actor.generation
                    self.session = FenceSession(self._actor.fence, self._actor.session_id,
                        self._actor.owner_identity, max(1, self.current_boot_ordinal), False)

    # ---- reconstruction ----------------------------------------------------

    def _history_violation(self, reason):
        self.reconstruction_violations.append(reason)

    def _classify_frame(self, frame):
        """Return True when a frame may be interpreted; record violations."""
        event = frame["event"]
        state = event.get("state")
        record_type = event.get("record_type")
        if (record_type == 'BOOT_ACTIVATION' and type(frame.get('envelope')) is JournalEnvelope and
                'activation_authentication' in json.loads(frame['envelope'].authority_fact_bytes)):
            return False
        if event.get('schema_version') == 'u04-record/v1':
            return False
        authorizing = event.get("authorizes_execution") is True
        if record_type == "PUBLICATION":
            envelope = frame.get('envelope')
            if type(envelope) is JournalEnvelope and json.loads(envelope.authority_fact_bytes).get('publication_grant', {}).get('phase') != 'RESULT':
                return False
            if (authorizing or state not in STATE_DOMAINS["publication"] or
                    "effect_id" in event or "state_domain" in event or
                    event.get("operation") not in _PUBLICATION_OPERATIONS):
                self._history_violation("malformed-publication-record")
                return False
            return True
        if record_type == "MEASUREMENT_WINDOW":
            # Interpreted only through the single validated window history,
            # which records its own violations.
            return frame["event_id"] in self._window_history.accepted_event_ids
        if state in STATE_DOMAINS["publication"]:
            self._history_violation("publication-state-outside-publication-record")
            return False
        if authorizing or state in _RESERVED_STATES or record_type in _RESERVED_RECORD_TYPES:
            if not self.store.frame_has_provenance(frame):
                self._history_violation("unprovenanced-reserved-record:%s" % (
                    state or record_type,))
                return False
        return True

    def _reconstruct(self):
        """Rebuild reducer state from witnessed history.

        A reserved label is never proof by itself: every reserved record must
        carry authorization-boundary provenance for its dedicated operation, and
        attempt, boot, activation, and campaign closure are re-derived from the
        retained evidence.  Anything that cannot be re-established fails closed.
        """
        self.store._reset_validated_registries(_DEDICATED_AUTHORITY)
        frames = list(self.store._durable)
        # One validated window history serves frame classification, the
        # current window/epoch, and publication-chain validation.  It also
        # reports pending window operations that never appended a frame.
        self._window_history = _validated_window_history(self.store, self.authorization)
        completion_frames = []
        boot_complete_frames = {}
        activation_frames = []
        failure_reasons = []
        for frame in frames:
            event = frame["event"]
            state = event.get("state")
            if event.get('record_type') == 'ACTIVATION_ADMITTED':
                self.current_boot_ordinal = event['next_boot_ordinal']
                self.current_boot_id = event['observed_boot_id']
                self._boot_ids[self.current_boot_ordinal] = self.current_boot_id
                self.activation_ids.add(event['activation_id'])
                self.boot_state = self.attempt_state = None
            try:
                if not self._classify_frame(frame):
                    continue
                reconstructed = None
                if (event.get("authorizes_execution") is True and
                        event.get("session_id") and event.get("session_owner")):
                    reconstructed = FenceSession(
                        event["fence_epoch"], event["session_id"], event["session_owner"],
                        event.get("session_boot_ordinal", event.get("boot_ordinal", 1)),
                        False)
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                self._history_violation("malformed-reserved-record")
                continue
            if reconstructed is not None:
                envelope = frame.get('envelope')
                self.store._historical_producers[frame['event_id']] = (
                    envelope.producer_bytes if type(envelope) is JournalEnvelope else _u04_canonical({
                        'legacy_historical': True, 'generation': event.get('supervisor_generation'),
                        'session_id': reconstructed.session_id, 'fence': reconstructed.fence_epoch,
                        'owner_identity': reconstructed.owner_identity}))
            try:
                if event.get("record_type") == "MEASUREMENT_WINDOW":
                    continue
                if (event.get("authorizes_execution") is not True and
                        state == "TAINTED" and type(event.get("reason")) is str and
                        event.get("reason")):
                    failure_reasons.append(event["reason"])
                if state in _STICKY_HISTORY_STATES:
                    self.safety_markers.add(state)
                if (event.get("authorizes_execution") is not True and
                        not (event.get('state') == 'CAMPAIGN_ADMITTED' and
                             self.store.frame_has_provenance(frame))):
                    continue
                if event.get("operation") == "consume-boot-activation":
                    ordinal = event["activated_boot_ordinal"]
                    activation_frames.append(frame)
                    self.activation_ids.add(event["activation_id"])
                    self.current_boot_id = event["observed_boot_id"]
                    self.current_boot_ordinal = ordinal
                    self._boot_ids[ordinal] = event["observed_boot_id"]
                    self.boot_state = None
                    self.attempt_state = None
                    continue
                if state in STATE_DOMAINS["campaign"]:
                    self.campaign_state = state
                if state in STATE_DOMAINS["boot"]:
                    self.boot_state = state
                if state in STATE_DOMAINS["attempt"]:
                    self.attempt_state = state
                if state == "CAMPAIGN_ADMITTED":
                    self.current_boot_id = event["boot_id"]
                    self.current_boot_ordinal = event.get("boot_ordinal", 1)
                    self._boot_ids[1] = event["boot_id"]
                if state == "SPAWN_INTENT_PERSISTED":
                    slot = next((item for item in self.authorization.slots
                                 if item.slot_id == event.get("slot_id")), None)
                    if slot is None:
                        self._history_violation("spawn-intent-for-unknown-slot")
                        continue
                    self._slot_tokens[slot.slot_id] = SpawnToken(
                        event["spawn_token"], self.authorization.campaign_id,
                        event["boot_id"], slot.slot_id, slot.attempt_id,
                        event["launch_spec_digest"], self.custodian.identity,
                        event["supervisor_generation"])
                if state == "ATTEMPT_COMPLETE":
                    completion_frames.append(frame)
                if state == "BOOT_COMPLETE":
                    boot_complete_frames[event["boot_ordinal"]] = frame
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                self._history_violation("malformed-reserved-record")
        self._observed_boot_ids = {boot_id for boot_id in self._boot_ids.values()}
        history = self._window_history
        for reason in history.violations:
            self._history_violation(reason)
        if self.campaign_state is not None and history.window_epoch < 1:
            # Interrupted or unprovenanced initialization is never completed
            # by reconstruction.
            self._history_violation("missing-window-history")
        # An incomplete history never falls back to an earlier outside window.
        self.store._measurement_window = history.authorizing_window
        self.store._window_epoch = history.window_epoch
        # Attempt completion: revalidate every completion against retained evidence.
        for frame in completion_frames:
            event = copy.deepcopy(frame["event"])
            slot_id = event.get("slot_id")
            try:
                self._validate_attempt_completion_record(
                    slot_id, event, require_completion_event=True)
                self.store._register_validated_completion(
                    _DEDICATED_AUTHORITY, slot_id, event["completion_digest"])
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("invalid-completion-evidence")
            else:
                self._completed_attempts[slot_id] = event
        # Boot closure, activation, and candidates are re-derived in boot order.
        for ordinal in sorted(set(boot_complete_frames) | {
                frame["event"].get("boot_ordinal") for frame in
                self.store.provenanced_frames("BOOT_CLOSURE_CANDIDATE_FINALIZED")}):
            try:
                if type(ordinal) is not int:
                    raise AuthorizationDenied("boot ordinal")
                candidate = self._validate_boot_candidate(ordinal)
                if ordinal == self.current_boot_ordinal:
                    self._finalized_candidates["boot"] = candidate
                if ordinal in boot_complete_frames:
                    digest = self._validate_boot_closure(ordinal)
                    self.store._register_validated_boot_closure(
                        _DEDICATED_AUTHORITY, ordinal, digest)
                    self._completed_boots.add(ordinal)
                    self.predecessor_closure_digest = digest
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("invalid-boot-closure:%s" % (ordinal,))
                if ordinal == self.current_boot_ordinal:
                    self._finalized_candidates.pop("boot", None)
                    self.boot_state = None
                    self.predecessor_closure_digest = None
                self._completed_boots.discard(ordinal)
        for frame in activation_frames:
            event = frame["event"]
            previous = event.get("activated_boot_ordinal", 0) - 1
            if (previous not in self._completed_boots or
                    self.store.validated_boot_closure(previous) !=
                    event.get("predecessor_closure_digest")):
                self._history_violation("activation-without-validated-closure")
        # Boot custody: provenance and legal ordering are not proof.  Re-check the
        # custodian-issued evidence behind every retained custody record.
        for frame in self.store.provenanced_frames("BOOT_CUSTODY_ESTABLISHED",
                                                   "establish-boot-custody"):
            event = frame["event"]
            ordinal = event.get("boot_ordinal")
            try:
                boot_id = self.store.boot_identity(ordinal)
                if boot_id is None or event.get("boot_id") != boot_id:
                    raise AuthorizationDenied("custody establishment boot identity")
                expected = {name: event.get(name) for name in (
                    "authorization_digest", "campaign_id", "supervisor_generation",
                    "session_id", "fence_epoch", "session_owner")}
                expected.update(boot_id=boot_id, boot_ordinal=ordinal,
                                authorization_digest=self.authorization.authorization_digest,
                                campaign_id=self.authorization.campaign_id)
                _boot_custody_attestation_digest(
                    self.store, event.get("custody_attestation"), expected)
                if self.custodian.confirms_required_custody_loss(event.get('custody_attestation')):
                    self.safety_markers.update(('CUSTODY_UNCERTAIN', 'TAINTED', 'CONTAINMENT_ONLY_RECOVERY'))
                    self.store.revoke_execution()
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("invalid-boot-custody:%s" % (ordinal,))
                if ordinal == self.current_boot_ordinal:
                    self.boot_state = None
        for frame in self.store.provenanced_frames("BOOT_CUSTODY_COMPLETE",
                                                   "complete-boot-custody"):
            event = frame["event"]
            ordinal = event.get("boot_ordinal")
            try:
                proof = _boot_custody_proof(
                    self.store, self.authorization, ordinal, event,
                    self.store.frame_index(frame["event_id"]))
                self.store._register_validated_boot_custody(
                    _DEDICATED_AUTHORITY, dict(proof, event_id=frame["event_id"],
                                               event_digest=frame["receipt"].event_digest))
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("invalid-boot-custody:%s" % (ordinal,))
                if ordinal == self.current_boot_ordinal and self.boot_state in (
                        "BOOT_CUSTODY_ESTABLISHED", "BOOT_CUSTODY_COMPLETE"):
                    self.boot_state = None
        # Publication: valid bytes prove object consistency only.  Every retained
        # publication record must be the result of its own consumed grant.
        for entries in _publication_frame_groups(self.store).values():
            try:
                _validate_publication_frames(self.store, self.authorization,
                                             [frame for _, frame in entries],
                                             require_verified=False,
                                             window_history=history)
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("unprovenanced-publication-history")
        # Started publication operations without a bound result (including
        # those that appended nothing) stay non-authorizing; reconstruction
        # never refunds, redispatches, or infers their result.
        for reason in self.store.incomplete_publication_operations():
            self._history_violation(reason)
        if self.store.provenanced_frames("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED"):
            try:
                self._finalized_candidates["campaign"] = self._validate_campaign_candidate()
                if self.campaign_state == "CAMPAIGN_COMPLETE":
                    self.store._register_validated_campaign_closure(
                        _DEDICATED_AUTHORITY, self._validate_campaign_closure())
            except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                    ValueError):
                self._history_violation("invalid-campaign-closure")
                self._finalized_candidates.pop("campaign", None)
                if self.campaign_state in ("CAMPAIGN_COMPLETE",
                                           "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED"):
                    self.campaign_state = "CAMPAIGN_ADMITTED"
        if self.store.taint:
            self.safety_markers.add("TAINTED")
        for reason in failure_reasons:
            # A durable failure record re-derives the sticky prohibition even if
            # the store's volatile latch flags were lost.
            self.safety_markers.update(("ABORTED", "TAINTED", "CONTAINMENT_ONLY_RECOVERY"))
            self.store.install_failure_latch(reason)
        if self.reconstruction_violations:
            self.safety_markers.update(("TAINTED", "CONTAINMENT_ONLY_RECOVERY"))
            self.store.install_failure_latch(
                "reconstruction-rejected:" + self.reconstruction_violations[0])
        unresolved = {
            "SPAWN_INTENT_PERSISTED", "WORKER_CREATION_IN_PROGRESS",
            "WORKER_IDENTITY_ESTABLISHED", "WORKER_IDENTITY_DURABLY_RECORDED",
            "RELEASE_ELIGIBLE", "RELEASE_INTENT", "RELEASED_OR_POSSIBLY_RELEASED",
            "CUDA_CALL_GATE_PASSED", "CLEANUP_REQUESTED", "EXIT_OBSERVED",
            "REAPING_PROVEN", "RESIDUAL_CLEARANCE_PROVEN",
        }
        if self.attempt_state in unresolved:
            self.safety_markers.update(("CUSTODY_UNCERTAIN",
                                        "CONTAINMENT_ONLY_RECOVERY"))
            self.store.revoke_execution()

    # ---- closure evidence -------------------------------------------------

    def _dedicated_events(self, state, operation=None):
        return [copy.deepcopy(frame["event"])
                for frame in self.store.provenanced_frames(state, operation)]

    def _rebuild_candidate(self, frame, kind):
        from .evidence import build_closure_candidate
        event = frame["event"]
        raw_hex = event.get("candidate_bytes")
        if event.get("candidate_kind") != kind or type(raw_hex) is not str:
            raise AuthorizationDenied("closure candidate record")
        raw = bytes.fromhex(raw_hex)
        decoded = json.loads(raw.decode("utf-8"))
        if type(decoded) is not dict or decoded.get("candidate_type") != kind:
            raise AuthorizationDenied("closure candidate bytes")
        candidate = build_closure_candidate(kind, decoded.get("payload"))
        if (candidate.bytes != raw or candidate.digest != event.get("candidate_digest") or
                list(candidate.object_digests) != event.get("object_digests")):
            raise AuthorizationDenied("closure candidate bytes do not match digest")
        return candidate, decoded["payload"]

    def _candidate_frame(self, state, boot_ordinal=None):
        frames = [frame for frame in self.store.provenanced_frames(state)
                  if boot_ordinal is None or frame["event"].get("boot_ordinal") == boot_ordinal]
        if len(frames) != 1:
            raise AuthorizationDenied("unique provenanced closure candidate required")
        return frames[0]

    def _history_clean_before(self, index):
        for frame in self.store._durable[:index]:
            event = frame["event"]
            if (event.get("record_type") == "TAINT" or
                    event.get("state") in _STICKY_HISTORY_STATES):
                raise AuthorizationDenied("intervening sticky prohibition or taint")

    def _validate_boot_candidate(self, boot_ordinal):
        frame = self._candidate_frame("BOOT_CLOSURE_CANDIDATE_FINALIZED", boot_ordinal)
        candidate, payload = self._rebuild_candidate(frame, "boot")
        event = frame["event"]
        boot_id = self._boot_ids.get(boot_ordinal)
        if (boot_id is None or payload.get("boot_id") != boot_id or
                event.get("boot_id") != boot_id):
            raise AuthorizationDenied("boot closure candidate identity")
        candidate_index = self.store.frame_index(frame["event_id"])
        required = sorted(slot.slot_id for slot in self.authorization.slots
                          if slot.boot_ordinal == boot_ordinal)
        bound = event.get("attempt_completion_digests")
        if type(bound) is not dict or sorted(bound) != required:
            raise AuthorizationDenied("boot closure candidate attempt binding")
        for slot_id in required:
            validated = self.store.validated_completion(slot_id)
            record = self._completed_attempts.get(slot_id)
            if (validated is None or record is None or
                    validated["completion_digest"] != bound[slot_id] or
                    record.get("completion_digest") != bound[slot_id] or
                    record.get("boot_id") != boot_id or
                    self.store.frame_index(validated["event_id"]) > candidate_index):
                raise AuthorizationDenied("boot closure candidate lacks validated attempts")
        return candidate

    def _validate_published_manifest(self, candidate, candidate_frame, event,
                                     completion_index):
        manifest = sorted([candidate.digest, *candidate.object_digests])
        if (event.get("publication_manifest") != manifest or
                event.get("publication_receipt_id") !=
                "publication-receipt-" + candidate.digest[:16]):
            raise AuthorizationDenied("closure publication manifest")
        # Identity and order: each chain was published for this exact finalized
        # candidate after its finalization event and verified before completion.
        _closure_publication_proof(self.store, self.authorization, candidate_frame,
                                   manifest, completion_index)

    def _validate_boot_closure(self, boot_ordinal):
        frames = [frame for frame in self.store.provenanced_frames("BOOT_COMPLETE",
                                                                   "complete-boot")
                  if frame["event"].get("boot_ordinal") == boot_ordinal]
        if len(frames) != 1:
            raise AuthorizationDenied("unique provenanced boot completion required")
        completion = frames[0]
        event = completion["event"]
        completion_index = self.store.frame_index(completion["event_id"])
        candidate_frame = self._candidate_frame("BOOT_CLOSURE_CANDIDATE_FINALIZED",
                                                boot_ordinal)
        candidate = self._validate_boot_candidate(boot_ordinal)
        if (self.store.frame_index(candidate_frame["event_id"]) > completion_index or
                event.get("candidate_digest") != candidate.digest or
                event.get("candidate_kind") != "boot" or
                event.get("candidate_event_digest") !=
                candidate_frame["receipt"].event_digest or
                event.get("boot_id") != self._boot_ids.get(boot_ordinal) or
                event.get("campaign_id") != self.authorization.campaign_id or
                event.get("authorization_digest") !=
                self.authorization.authorization_digest):
            raise AuthorizationDenied("boot completion is not bound to its candidate")
        self._validate_published_manifest(candidate, candidate_frame, event,
                                          completion_index)
        self._history_clean_before(completion_index)
        return completion["receipt"].event_digest

    def _validate_campaign_candidate(self):
        frame = self._candidate_frame("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")
        candidate, payload = self._rebuild_candidate(frame, "campaign")
        candidate_index = self.store.frame_index(frame["event_id"])
        closures = [self.store.validated_boot_closure(ordinal) for ordinal in (1, 2, 3, 4)]
        if (payload.get("campaign_id") != self.authorization.campaign_id or
                None in closures or
                frame["event"].get("boot_closure_digests") != closures or
                self._completed_boots != {1, 2, 3, 4}):
            raise AuthorizationDenied("campaign closure candidate lacks validated boots")
        for ordinal in (1, 2, 3, 4):
            boot_frames = [item for item in self.store.provenanced_frames("BOOT_COMPLETE")
                           if item["event"].get("boot_ordinal") == ordinal]
            if (len(boot_frames) != 1 or
                    self.store.frame_index(boot_frames[0]["event_id"]) > candidate_index):
                raise AuthorizationDenied("campaign candidate precedes boot closure")
        return candidate

    def _validate_campaign_closure(self):
        frames = self.store.provenanced_frames("CAMPAIGN_COMPLETE", "complete-campaign")
        if len(frames) != 1:
            raise AuthorizationDenied("unique provenanced campaign completion required")
        completion = frames[0]
        event = completion["event"]
        completion_index = self.store.frame_index(completion["event_id"])
        candidate_frame = self._candidate_frame("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")
        candidate = self._validate_campaign_candidate()
        if (self.store.frame_index(candidate_frame["event_id"]) > completion_index or
                event.get("candidate_digest") != candidate.digest or
                event.get("candidate_kind") != "campaign" or
                event.get("candidate_event_digest") !=
                candidate_frame["receipt"].event_digest or
                event.get("campaign_id") != self.authorization.campaign_id):
            raise AuthorizationDenied("campaign completion is not bound to its candidate")
        self._validate_published_manifest(candidate, candidate_frame, event,
                                          completion_index)
        self._history_clean_before(completion_index)
        return completion["receipt"].event_digest

    # ---- transitions -------------------------------------------------------

    def _ensure_session(self):
        self.store.require_actor(self._actor)
        if (not self.session.execution_live or
                not self.store.supervisor_is_current(self._supervisor_generation) or
                self.session.fence_epoch != self.store.witness.current_fence or
                not self.store.session_registered(self.session) or
                self.store.execution_revoked or
                self.safety_markers & {"TAINTED", "CUSTODY_UNCERTAIN", "ABORTED"}):
            raise AuthorizationDenied("execution session is not eligible")

    def _transition(self, domain, state, suffix, event=None,
                    dispatcher=lambda capability, binding: None, interlock=None,
                    return_capability=False):
        """General transition surface: closed allowlist and closed payloads only."""
        return self._authorized_transition(
            None, domain, state, suffix, event, dispatcher, interlock,
            return_capability, "offline-store")

    def _dedicated_transition(self, operation, domain, state, suffix, event=None,
                              dispatcher=lambda capability, binding: None, interlock=None,
                              return_capability=False, target="offline-store"):
        if operation not in DEDICATED_OPERATIONS:
            raise AuthorizationDenied("unknown dedicated operation")
        return self._authorized_transition(
            operation, domain, state, suffix, event, dispatcher, interlock,
            return_capability, target)

    def _authorized_transition(self, operation, domain, state, suffix, event, dispatcher,
                               interlock, return_capability, target):
        parse_state(domain, state)
        self._ensure_session()
        self._assert_transition_precondition(domain, state)
        spec = {"effect_id": suffix, "target": target,
                "operation": operation or "append-transition",
                "event_id": "event-" + suffix, "event": dict(event or {})}
        try:
            outcome = authorize_and_dispatch(
                self.store, self.verifier, self.store.revision, self.session.fence_epoch,
                self.session, state, spec, dispatcher, interlock=interlock,
                _authority=None if operation is None else _DEDICATED_AUTHORITY,
            )
        except (DispatchUncertain, TransactionPending, LostAcknowledgement, Quarantined):
            self.store.revoke_execution()
            self.store._publication_prohibited = True
            raise
        except Exception:
            self._contain_after_failure(
                "authoritative-verification-failure", b"",
                suppress_reporting_error=True)
            raise
        return outcome if return_capability else outcome[0]

    def _assert_transition_precondition(self, domain, state):
        if domain == "authorization":
            if state != "AUTHORIZATION_ADMITTED" or self.campaign_state is not None:
                raise AuthorizationDenied("authorization transition precondition")
            return
        if domain == "campaign":
            required = {"CAMPAIGN_ADMITTED": None,
                        "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED": "CAMPAIGN_ADMITTED",
                        "CAMPAIGN_COMPLETE": "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED"}
            if state in required and self.campaign_state != required[state]:
                raise AuthorizationDenied("campaign transition precondition")
            return
        if domain == "boot":
            required = {"BOOT_CUSTODY_ESTABLISHED": None,
                        "BOOT_CUSTODY_COMPLETE": "BOOT_CUSTODY_ESTABLISHED",
                        "BOOT_CLOSURE_CANDIDATE_FINALIZED": "BOOT_CUSTODY_COMPLETE",
                        "BOOT_COMPLETE": "BOOT_CLOSURE_CANDIDATE_FINALIZED",
                        "BOOT_HANDOFF_PENDING": "BOOT_COMPLETE"}
            if self.boot_state != required[state]:
                raise AuthorizationDenied("boot transition precondition")
            return
        if domain == "attempt":
            if self.attempt_state not in TRANSITION_PREDECESSORS["attempt"][state]:
                raise AuthorizationDenied("attempt transition precondition")
            return
        if domain == "local_evidence":
            prior = self.store.authoritative_state("local_evidence",
                                                   self.current_boot_ordinal)
            if prior not in TRANSITION_PREDECESSORS["local_evidence"][state]:
                raise AuthorizationDenied("local evidence transition precondition")

    def admit_campaign(self, boot_activation):
        if self.campaign_state is not None or self._actor is None:
            raise AuthorizationDenied('witness-authenticated fresh admission required')
        self._actor, self.session = self.store.complete_fresh_admission(
            self._actor, self.authorization, boot_activation)
        self._supervisor_generation = self._actor.generation
        self.activation_ids.add(boot_activation.activation_id)
        self.campaign_state = 'CAMPAIGN_ADMITTED'
        self.current_boot_id = boot_activation.observed_boot_id
        self.current_boot_ordinal = 1
        self._boot_ids[1] = self.current_boot_id
        self._observed_boot_ids = {self.current_boot_id}

    def establish_boot_custody(self, custody_proof, observer_isolated, watchdog_ready,
                               observer_id="isolated-observer"):
        if type(custody_proof) is not str or not custody_proof:
            raise AuthorizationDenied("custody proof")
        if type(observer_isolated) is not bool or type(watchdog_ready) is not bool:
            raise AuthorizationDenied("custody readiness booleans")
        if not observer_isolated or not watchdog_ready:
            raise AuthorizationDenied("custody readiness")
        self._ensure_session()
        attest = getattr(self.custodian, "attest_boot_custody", None)
        if not callable(attest):
            raise AuthorizationDenied("custodian cannot attest boot custody")
        try:
            attestation = attest(
                store_identity=self.store.identity,
                authorization_digest=self.authorization.authorization_digest,
                campaign_id=self.authorization.campaign_id,
                boot_id=self.current_boot_id, boot_ordinal=self.current_boot_ordinal,
                supervisor_generation=self._supervisor_generation,
                session_id=self.session.session_id,
                fence_epoch=self.session.fence_epoch, observer_id=observer_id,
                custody_proof=custody_proof, observer_isolated=observer_isolated,
                watchdog_ready=watchdog_ready)
        except ContractError as exc:
            raise AuthorizationDenied("custodian did not attest boot custody") from exc
        self._dedicated_transition("establish-boot-custody", "boot",
                                   "BOOT_CUSTODY_ESTABLISHED",
                                   "boot-%d-custody-established" % self.current_boot_ordinal,
                                   {"boot_id": self.current_boot_id,
                                    "custody_attestation": attestation.record()})
        self._custody = attestation
        self.boot_state = "BOOT_CUSTODY_ESTABLISHED"

    def complete_boot_custody(self):
        if self.boot_state != "BOOT_CUSTODY_ESTABLISHED" or self._custody is None:
            raise AuthorizationDenied("boot custody incomplete")
        established = [frame for frame in self.store.provenanced_frames(
                           "BOOT_CUSTODY_ESTABLISHED", "establish-boot-custody")
                       if frame["event"].get("boot_ordinal") == self.current_boot_ordinal]
        if len(established) != 1:
            raise AuthorizationDenied("boot custody establishment is not unique")
        self._dedicated_transition(
            "complete-boot-custody", "boot", "BOOT_CUSTODY_COMPLETE",
            "boot-%d-custody-complete" % self.current_boot_ordinal,
            {"extra_pre_spawn_baseline_ns": 0,
             "custody_established_event_digest": established[0]["receipt"].event_digest,
             "custody_attestation_digest": _sha(_canonical(self._custody.record()))})
        self.boot_state = "BOOT_CUSTODY_COMPLETE"

    def make_slot_eligible(self, slot_id):
        self._ensure_session()
        slots = {slot.slot_id: slot for slot in self.authorization.slots}
        slot = slots.get(slot_id)
        if slot is None or slot.boot_ordinal != self.current_boot_ordinal:
            raise AuthorizationDenied("wrong matrix slot")
        if self.store.is_consumed("slot", slot_id):
            raise AuthorizationDenied("slot already consumed")
        predecessor_slot_id = predecessor_digest = None
        if slot.worker_ordinal == 1:
            if self.boot_state != "BOOT_CUSTODY_COMPLETE":
                raise AuthorizationDenied("first worker requires completed boot custody")
        else:
            predecessor = next((candidate for candidate in self.authorization.slots
                                if candidate.boot_ordinal == slot.boot_ordinal and
                                candidate.worker_ordinal == slot.worker_ordinal - 1), None)
            evidence = None if predecessor is None else self._completed_attempts.get(predecessor.slot_id)
            if evidence is None or not self._authoritative_attempt_complete(predecessor.slot_id,
                                                                            evidence):
                raise AuthorizationDenied("durable same-boot predecessor evidence incomplete")
            predecessor_slot_id = predecessor.slot_id
            predecessor_digest = evidence["completion_digest"]
        # The authorization boundary re-derives the successor gate from store-owned
        # facts and registers the store-backed slot capability that creation requires.
        self._dedicated_transition(
            "make-slot-eligible", "attempt", "SLOT_SPAWN_ELIGIBLE",
            "slot-" + slot_id + "-eligible",
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "boot_id": self.current_boot_id, "spawn_token": "spawn-" + slot_id,
             "custodian_id": self.custodian.identity,
             "predecessor_slot_id": predecessor_slot_id,
             "predecessor_completion_digest": predecessor_digest})
        if self.store._authentication_service is None:
            self.store.consume("slot", slot_id)
        spawn_token = "spawn-" + slot_id
        capability = SlotCapability(
            "slot-capability-" + slot_id, self.authorization.authorization_digest,
            self.authorization.campaign_id, self.current_boot_id, slot_id,
            slot.attempt_id, spawn_token, _sha("unbound-launch:" + slot_id),
            self.session.fence_epoch, self.session.session_id,
            _sha("boot-custody" if slot.worker_ordinal == 1 else "local-predecessor"),
            "slot-effect-" + slot_id, "SLOT_SPAWN_ELIGIBLE", self.custodian.identity,
            "blocked-create", False,
        )
        self._slot_capabilities[slot_id] = capability
        self.attempt_state = "SLOT_SPAWN_ELIGIBLE"
        return capability

    def _authoritative_attempt_complete(self, slot_id, record):
        try:
            self._validate_attempt_completion_record(slot_id, record,
                                                     require_completion_event=True)
            return True
        except (AuthorizationDenied, ContractError, StoreError, KeyError, TypeError,
                ValueError):
            return False

    def _validate_attempt_completion_record(self, slot_id, record,
                                            *, require_completion_event):
        from .evidence import EvidencePipeline, canonical_core_bytes
        from tools.decision_0009.startup_characterization.controller import (
            ProtocolError, validate_attempt,
        )
        manifest_fields = _ATTEMPT_MANIFEST_FIELDS
        if type(record) is not dict or any(field not in record for field in manifest_fields):
            raise AuthorizationDenied("closed attempt completion manifest required")
        manifest = {field: copy.deepcopy(record[field]) for field in manifest_fields}
        if record.get("completion_digest") != _sha(_canonical(manifest)):
            raise AuthorizationDenied("attempt completion digest mismatch")
        slot = next((candidate for candidate in self.authorization.slots
                     if candidate.slot_id == slot_id), None)
        token = self._slot_tokens.get(slot_id)
        if (slot is None or token is None or manifest["slot_id"] != slot.slot_id or
                manifest["attempt_id"] != slot.attempt_id or
                manifest["authorization_digest"] != self.authorization.authorization_digest or
                manifest["campaign_id"] != self.authorization.campaign_id or
                manifest["boot_ordinal"] != slot.boot_ordinal or
                manifest["worker_ordinal"] != slot.worker_ordinal or
                manifest["thermal_state"] != slot.thermal_state or
                manifest["handle_order"] != slot.handle_order or
                manifest["spawn_token"] != token.token_id or
                manifest["boot_id"] != token.boot_id or
                manifest["launch_spec_digest"] != token.launch_spec_digest or
                manifest["custodian_id"] != token.custodian_id or
                manifest["supervisor_generation"] != token.supervisor_generation):
            raise AuthorizationDenied("attempt completion authority identity mismatch")
        spawn_events = [event for event in self._dedicated_events(
                            "SPAWN_INTENT_PERSISTED", "blocked-create")
                        if event.get("slot_id") == slot_id]
        if (len(spawn_events) != 1 or
                any(spawn_events[0].get(name) != manifest[name] for name in (
                    "attempt_id", "authorization_digest", "campaign_id", "boot_id",
                    "spawn_token", "launch_spec_digest", "custodian_id",
                    "supervisor_generation"))):
            raise AuthorizationDenied("completion lacks exact admitted spawn intent")
        raw = self.store.read_object(manifest["raw_object_id"], manifest["raw_digest"])
        normalized = self.store.read_object(manifest["normalized_object_id"],
                                            manifest["normalized_digest"])
        core = self.store.read_object(manifest["core_object_id"], manifest["core_digest"])
        if (manifest["raw_readback_digest"] != _sha(raw) or
                manifest["normalized_readback_digest"] != _sha(normalized) or
                manifest["core_readback_digest"] != _sha(core)):
            raise AuthorizationDenied("completion object readback mismatch")
        pipeline = EvidencePipeline(max_frame_bytes=8_388_608,
                                    max_attempt_bytes=8_388_608)
        reference = pipeline.capture(token.token_id, raw, 1, 1)
        if reference.truncated or reference.retained_length != len(raw):
            raise AuthorizationDenied("raw attempt object is incomplete")
        decoded = pipeline.decode(reference)
        try:
            validate_attempt(decoded)
        except (ProtocolError, KeyError, TypeError, ValueError) as exc:
            raise AuthorizationDenied("retained accepted-core attempt is invalid") from exc
        expected_identity = {
            "run_id": manifest["campaign_id"], "trial_id": manifest["attempt_id"],
            "boot_id": manifest["boot_id"], "boot": manifest["boot_ordinal"],
            "ordinal": manifest["worker_ordinal"], "state": manifest["thermal_state"],
            "handle_order": manifest["handle_order"], "verdict": "valid",
        }
        if any(decoded.get(name) != value for name, value in expected_identity.items()):
            raise AuthorizationDenied("retained accepted-core identity mismatch")
        canonical = canonical_core_bytes(decoded)
        if normalized != canonical or core != canonical:
            raise AuthorizationDenied("normalized and frozen core are not canonical")
        receipt = self.custodian.get_reap_receipt(token.token_id)
        if receipt is None:
            raise AuthorizationDenied("actual reap receipt absent")
        self.custodian.validate_reap_receipt(receipt)
        inspection = self.custodian.inspect_spawn(token.token_id)
        if (inspection.status != "REAPED" or inspection.possibly_live or
                manifest["reap_receipt_id"] != receipt.receipt_id or
                manifest["reap_receipt_digest"] != _sha(_canonical(receipt.__dict__))):
            raise AuthorizationDenied("reap evidence does not establish worker exit")
        residual_ids = manifest["residual_object_ids"]
        residual_digests = manifest["residual_sample_digests"]
        if (type(residual_ids) is not list or type(residual_digests) is not list or
                len(residual_ids) < 3 or len(residual_ids) != len(residual_digests) or
                manifest["residual_sample_count"] != len(residual_ids)):
            raise AuthorizationDenied("residual manifest is incomplete")
        residual_bytes = tuple(
            self.store.read_object(object_id, digest)
            for object_id, digest in zip(residual_ids, residual_digests))
        self._validate_residual_observations(
            slot, token, residual_bytes, boot_id=manifest["boot_id"])
        histories = {
            state: [event for event in self._dedicated_events(state,
                                                              "persist-local-evidence")
                    if event.get("slot_id") == slot_id and
                    event.get("attempt_id") == slot.attempt_id]
            for state in ("RAW_CAPTURED", "NORMALIZATION_BOUND",
                          "IMMUTABLE_BYTES_STORED", "READBACK_VERIFIED",
                          "ATTEMPT_EVIDENCE_FINALIZED")
        }
        if any(len(events) != 1 for events in histories.values()):
            raise AuthorizationDenied("exact local evidence history is absent")
        raw_event = histories["RAW_CAPTURED"][0]
        normalized_event = histories["NORMALIZATION_BOUND"][0]
        core_event = histories["IMMUTABLE_BYTES_STORED"][0]
        readback_event = histories["READBACK_VERIFIED"][0]
        final_event = histories["ATTEMPT_EVIDENCE_FINALIZED"][0]
        if (raw_event.get("object_id") != manifest["raw_object_id"] or
                raw_event.get("object_digest") != manifest["raw_digest"] or
                raw_event.get("retained_length") != len(raw) or
                raw_event.get("declared_length") != len(raw) or raw_event.get("truncated") or
                normalized_event.get("raw_object_id") != manifest["raw_object_id"] or
                normalized_event.get("raw_digest") != manifest["raw_digest"] or
                normalized_event.get("normalized_object_id") != manifest["normalized_object_id"] or
                normalized_event.get("normalized_digest") != manifest["normalized_digest"] or
                core_event.get("core_object_id") != manifest["core_object_id"] or
                core_event.get("core_digest") != manifest["core_digest"] or
                readback_event.get("raw_readback_digest") != manifest["raw_readback_digest"] or
                readback_event.get("normalized_readback_digest") !=
                manifest["normalized_readback_digest"] or
                readback_event.get("core_readback_digest") != manifest["core_readback_digest"] or
                final_event.get("completion_digest") != record["completion_digest"] or
                final_event.get("raw_object_id") != manifest["raw_object_id"] or
                final_event.get("normalized_object_id") != manifest["normalized_object_id"] or
                final_event.get("core_object_id") != manifest["core_object_id"]):
            raise AuthorizationDenied("local evidence history does not match manifest")
        residual_events = [event for event in self._dedicated_events(
                               "RESIDUAL_CLEARANCE_PROVEN", "persist-local-evidence")
                           if event.get("slot_id") == slot_id]
        if (len(residual_events) != 1 or
                residual_events[0].get("spawn_token") != token.token_id or
                residual_events[0].get("sample_digests") != residual_digests):
            raise AuthorizationDenied("residual clearance history mismatch")
        if require_completion_event:
            matching = [event for event in self._dedicated_events(
                            "ATTEMPT_COMPLETE", "complete-attempt")
                        if event.get("slot_id") == slot_id and
                        event.get("completion_digest") == record["completion_digest"]]
            if len(matching) != 1:
                raise AuthorizationDenied("unique authoritative completion absent")
        return manifest

    def record_local_attempt_evidence(self, slot_id, evidence):
        if not isinstance(evidence, LocalAttemptEvidence):
            raise ContractError("closed local attempt evidence")
        raise AuthorizationDenied("caller-asserted attempt evidence is not authoritative")

    def persist_local_attempt_evidence(self, slot_id, raw_bytes,
                                       residual_samples=(b"clear-1", b"clear-2", b"clear-3")):
        """Contain failures around the real raw-evidence ingestion boundary."""
        try:
            return self._persist_local_attempt_evidence(slot_id, raw_bytes,
                                                        residual_samples)
        except Exception as exc:
            forensic = raw_bytes[:1_048_576] if type(raw_bytes) is bytes else b""
            self._contain_after_failure("evidence-ingestion-failure", forensic,
                                        suppress_reporting_error=True)
            if isinstance(exc, AuthorizationDenied):
                raise
            raise AuthorizationDenied("attempt evidence ingestion rejected") from exc

    def _validate_residual_observations(self, slot, token, residual_samples,
                                        *, boot_id=None):
        from .evidence import EvidencePipeline
        required = {
            "campaign_id", "boot_id", "slot_id", "attempt_id", "spawn_token",
            "observed_ns", "allocated_bytes", "cgroup_populated", "cgroup_pids",
            "owned_descendants", "gpu_process_present", "gpu_used_bytes",
        }
        if (type(residual_samples) is not tuple or len(residual_samples) < 3 or
                any(type(item) is not bytes or not item for item in residual_samples)):
            raise AuthorizationDenied("verified residual observations required")
        pipeline = EvidencePipeline(max_frame_bytes=65_536,
                                    max_attempt_bytes=1_048_576)
        decoded_values = []
        references = []
        for sequence, raw in enumerate(residual_samples, 1):
            reference = pipeline.capture(token.token_id, raw, sequence,
                                         self.store.revision + sequence)
            value = pipeline.decode(reference)
            if type(value) is not dict or set(value) != required:
                raise AuthorizationDenied("closed residual observation required")
            if (value["campaign_id"] != self.authorization.campaign_id or
                    value["boot_id"] != (boot_id or self.current_boot_id) or
                    value["slot_id"] != slot.slot_id or
                    value["attempt_id"] != slot.attempt_id or
                    value["spawn_token"] != token.token_id):
                raise AuthorizationDenied("residual observation identity mismatch")
            if (type(value["observed_ns"]) is not int or value["observed_ns"] < 0 or
                    type(value["allocated_bytes"]) is not int or
                    value["allocated_bytes"] != 0 or
                    type(value["cgroup_populated"]) is not bool or
                    value["cgroup_populated"] or
                    type(value["cgroup_pids"]) is not list or value["cgroup_pids"] or
                    type(value["owned_descendants"]) is not list or
                    value["owned_descendants"] or
                    type(value["gpu_process_present"]) is not bool or
                    value["gpu_process_present"] or
                    type(value["gpu_used_bytes"]) is not int or
                    value["gpu_used_bytes"] != 0):
                raise AuthorizationDenied("residual observation is not clear")
            references.append(reference)
            decoded_values.append(value)
        observed = [value["observed_ns"] for value in decoded_values]
        if (observed != sorted(set(observed)) or
                observed[-1] - observed[0] < 2_000_000_000):
            raise AuthorizationDenied("residual observations are stale or insufficient")
        return tuple(zip(references, residual_samples))

    def _persist_local_attempt_evidence(self, slot_id, raw_bytes, residual_samples):
        """Derive completion solely from retained bytes and custodian-owned facts."""
        from .evidence import EvidencePipeline, canonical_core_bytes
        from tools.decision_0009.startup_characterization.controller import (
            ProtocolError, validate_attempt,
        )
        slot = next((candidate for candidate in self.authorization.slots
                     if candidate.slot_id == slot_id), None)
        token = self._slot_tokens.get(slot_id)
        if (slot is None or token is None or slot.boot_ordinal != self.current_boot_ordinal or
                self.attempt_state != "REAPING_PROVEN" or
                type(raw_bytes) is not bytes or type(residual_samples) is not tuple):
            raise AuthorizationDenied("authoritative attempt inputs absent")
        reap = self.custodian.get_reap_receipt(token.token_id)
        if reap is None:
            raise AuthorizationDenied("actual custodian reap receipt required")
        self.custodian.validate_reap_receipt(reap)
        inspection = self.custodian.inspect_spawn(token.token_id)
        if inspection.status != "REAPED" or inspection.possibly_live:
            raise AuthorizationDenied("worker remains live or unreaped")
        pipeline = EvidencePipeline(max_frame_bytes=8_388_608,
                                    max_attempt_bytes=8_388_608)
        reference = pipeline.capture(token.token_id, raw_bytes, 1, self.store.revision)
        raw_object_id = "attempt-raw-" + slot.attempt_id
        raw_digest = self.store.put_object(raw_object_id,
                                           pipeline.raw.read(reference), actor=self._actor)
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "RAW_CAPTURED", "raw-captured-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "object_id": raw_object_id, "object_digest": raw_digest,
             "declared_length": reference.declared_length,
             "retained_length": reference.retained_length,
             "truncated": reference.truncated})
        decoded = pipeline.decode(reference)
        try:
            validate_attempt(decoded)
        except (ProtocolError, KeyError, TypeError, ValueError) as exc:
            raise AuthorizationDenied("accepted-core attempt validation failed") from exc
        expected_identity = {
            "run_id": self.authorization.campaign_id,
            "trial_id": slot.attempt_id,
            "boot_id": self.current_boot_id,
            "boot": slot.boot_ordinal,
            "ordinal": slot.worker_ordinal,
            "state": slot.thermal_state,
            "handle_order": slot.handle_order,
            "verdict": "valid",
        }
        if any(decoded.get(name) != value for name, value in expected_identity.items()):
            raise AuthorizationDenied("accepted-core attempt identity mismatch")
        normalized = pipeline.normalize(reference, decoded)
        normalized_object_id = "attempt-normalized-" + slot.attempt_id
        normalized_digest = self.store.put_object(normalized_object_id,
                                                   normalized.value, actor=self._actor)
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "NORMALIZATION_BOUND", "normalization-bound-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "raw_object_id": raw_object_id, "raw_digest": raw_digest,
             "normalized_object_id": normalized_object_id,
             "normalized_digest": normalized_digest})
        core = pipeline.freeze_core(decoded, normalized)
        core_object_id = "attempt-core-" + slot.attempt_id
        core_digest = self.store.put_object(core_object_id, core.bytes, actor=self._actor)
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "IMMUTABLE_BYTES_STORED",
            "immutable-bytes-stored-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "core_object_id": core_object_id, "core_digest": core_digest})
        readback = pipeline.readback(core.digest)
        raw_readback = self.store.read_object(raw_object_id, raw_digest)
        normalized_readback = self.store.read_object(normalized_object_id,
                                                      normalized_digest)
        core_readback = self.store.read_object(core_object_id, core_digest)
        if (raw_readback != raw_bytes or normalized_readback != normalized.value or
                core_readback != core.bytes or readback != core.bytes or
                canonical_core_bytes(decoded) != core.bytes):
            raise AuthorizationDenied("raw normalized and frozen bytes diverge")
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "READBACK_VERIFIED", "readback-verified-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "raw_readback_digest": _sha(raw_readback),
             "normalized_readback_digest": _sha(normalized_readback),
             "core_readback_digest": _sha(core_readback)})
        residual_records = self._validate_residual_observations(slot, token,
                                                                 residual_samples)
        residual_object_ids = []
        residual_digests = []
        for sequence, (residual_reference, residual_raw) in enumerate(residual_records, 1):
            object_id = "attempt-residual-%s-%d" % (slot.attempt_id, sequence)
            digest = self.store.put_object(object_id, residual_raw, actor=self._actor)
            if self.store.read_object(object_id, digest) != residual_raw:
                raise AuthorizationDenied("residual readback mismatch")
            residual_object_ids.append(object_id)
            residual_digests.append(digest)
        record = {
            "slot_id": slot_id, "attempt_id": slot.attempt_id,
            "authorization_digest": self.authorization.authorization_digest,
            "campaign_id": self.authorization.campaign_id,
            "boot_id": self.current_boot_id, "boot_ordinal": slot.boot_ordinal,
            "worker_ordinal": slot.worker_ordinal,
            "thermal_state": slot.thermal_state, "handle_order": slot.handle_order,
            "spawn_token": token.token_id,
            "launch_spec_digest": token.launch_spec_digest,
            "custodian_id": token.custodian_id,
            "supervisor_generation": token.supervisor_generation,
            "raw_object_id": raw_object_id,
            "raw_digest": raw_digest, "raw_readback_digest": _sha(raw_readback),
            "normalized_object_id": normalized_object_id,
            "normalized_digest": normalized_digest,
            "normalized_readback_digest": _sha(normalized_readback),
            "core_object_id": core_object_id, "core_digest": core_digest,
            "core_readback_digest": _sha(core_readback),
            "reap_receipt_id": reap.receipt_id,
            "reap_receipt_digest": _sha(_canonical(reap.__dict__)),
            "residual_object_ids": residual_object_ids,
            "residual_sample_digests": residual_digests,
            "residual_sample_count": len(residual_digests),
        }
        record["completion_digest"] = _sha(_canonical(record))
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "ATTEMPT_EVIDENCE_FINALIZED",
            "attempt-evidence-finalized-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "completion_digest": record["completion_digest"],
             "raw_object_id": raw_object_id,
             "normalized_object_id": normalized_object_id,
             "core_object_id": core_object_id})
        self._dedicated_transition(
            "persist-local-evidence", "attempt", "RESIDUAL_CLEARANCE_PROVEN",
            "residual-clearance-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "spawn_token": token.token_id,
             "sample_digests": residual_digests, "empty_cgroup": True,
             "no_owned_descendants": True, "complete_gpu_coverage": True})
        self.attempt_state = "RESIDUAL_CLEARANCE_PROVEN"
        self._validate_attempt_completion_record(
            slot_id, record, require_completion_event=False)
        self._dedicated_transition("complete-attempt", "attempt", "ATTEMPT_COMPLETE",
                                   "attempt-complete-" + slot_id, record)
        self._validate_attempt_completion_record(
            slot_id, record, require_completion_event=True)
        self.store._register_validated_completion(
            _DEDICATED_AUTHORITY, slot_id, record["completion_digest"])
        self._completed_attempts[slot_id] = copy.deepcopy(record)
        self.attempt_state = "ATTEMPT_COMPLETE"
        return record["completion_digest"]

    def complete_worker_lifecycle(self, slot_id):
        """Authoritative contained operation over the whole post-creation lifecycle.

        Every verification, direct verifier call, custodian containment, wait/reap,
        and subsequent transition runs inside the protected region.  Any failure
        installs the sticky prohibition first, then attempts owned-worker
        containment, and only then reports diagnostics.
        """
        token = self._slot_tokens.get(slot_id)
        if token is None or self.attempt_state != "WORKER_CREATION_IN_PROGRESS":
            raise AuthorizationDenied("created worker required")
        try:
            return self._complete_worker_lifecycle(slot_id, token)
        except Exception as exc:
            self._contain_lifecycle_failure(slot_id, token, exc)
            raise

    def _complete_worker_lifecycle(self, slot_id, token):
        inspection = self.custodian.inspect_spawn(token.token_id)
        identity = inspection.process_identity
        if identity is None or not inspection.possibly_live:
            raise AuthorizationDenied("live blocked worker identity required")
        bound = {"slot_id": slot_id, "spawn_token": token.token_id}
        sequence = (
            ("WORKER_IDENTITY_ESTABLISHED", {**bound, "host_pid": identity.host_pid,
                                             "start_ticks": identity.process_start_ticks}),
            ("WORKER_IDENTITY_DURABLY_RECORDED", bound),
            ("RELEASE_ELIGIBLE", bound),
            ("RELEASE_INTENT", bound),
            ("RELEASED_OR_POSSIBLY_RELEASED", bound),
            ("CUDA_CALL_GATE_PASSED", bound),
            ("CLEANUP_REQUESTED", bound),
        )
        for state, event in sequence:
            self._dedicated_transition("worker-lifecycle", "attempt", state,
                                       state.lower() + "-" + slot_id, event)
            self.attempt_state = state
        binding = self.verifier.verify("CLEANUP_REQUESTED", self.session.fence_epoch,
                                       self.session.session_id)
        self.custodian.contain_spawn(token.token_id, "contain-capability", binding)
        self._dedicated_transition("worker-lifecycle", "attempt", "EXIT_OBSERVED",
                                   "exit-observed-" + slot_id, bound)
        self.attempt_state = "EXIT_OBSERVED"
        reap = self.custodian.wait_reap(token.token_id)
        self.custodian.validate_reap_receipt(reap)
        self._dedicated_transition("worker-lifecycle", "attempt", "REAPING_PROVEN",
                                   "reaping-proven-" + slot_id,
                                   {**bound, "reap_receipt_id": reap.receipt_id})
        self.attempt_state = "REAPING_PROVEN"
        return reap

    def _contain_lifecycle_failure(self, slot_id, token, primary):
        reason = "worker-lifecycle-failure"
        secondary = []
        # 1. Authoritative safety state first, under the authorization lock.
        try:
            with self.store.authorization_lock:
                self.safety_markers.update(("ABORTED", "TAINTED",
                                            "CONTAINMENT_ONLY_RECOVERY"))
                self.store.install_failure_latch(reason)
        except Exception as exc:
            secondary.append("latch:" + type(exc).__name__)
            self.store._execution_revoked = True
            self.store._publication_prohibited = True
            self.store.containment_only = True
            self.store._taint.add(reason)
        # 2. Owned-worker containment; never claim reap or clearance.
        try:
            inspection = self.custodian.inspect_spawn(token.token_id)
            if inspection.possibly_live:
                binding = self.store.effect_capability(
                    "spawn-intent-" + slot_id).artifact_binding
                self.custodian.contain_spawn(token.token_id, "failure-containment", binding)
        except Exception as exc:
            secondary.append("contain:" + type(exc).__name__)
        try:
            self._cleanup_existing_workers()
        except Exception as exc:
            secondary.append("cleanup:" + type(exc).__name__)
        try:
            inspection = self.custodian.inspect_spawn(token.token_id)
            receipt = self.custodian.get_reap_receipt(token.token_id)
            reaped = (inspection.status == "REAPED" and not inspection.possibly_live and
                      receipt is not None and self.custodian.validate_reap_receipt(receipt))
        except Exception as exc:
            secondary.append("inspect:" + type(exc).__name__)
            reaped = False
        if not reaped:
            self.safety_markers.add("CUSTODY_UNCERTAIN")
        # 3. Best-effort diagnostics; they cannot undo the safety state.
        self.last_lifecycle_failure = {"slot_id": slot_id,
                                       "primary": type(primary).__name__,
                                       "secondary": list(secondary)}
        try:
            self._write_failure_record(reason, b"", primary_failure=type(primary).__name__,
                                       secondary_failures=list(secondary))
        except Exception as exc:
            secondary.append("diagnostic:" + type(exc).__name__)
            self.last_lifecycle_failure["secondary"] = list(secondary)
            self.store._taint.add(reason)

    def spawn_worker(self, slot_id, launch_spec_digest, fault=None, interlock=None):
        if self.attempt_state != "SLOT_SPAWN_ELIGIBLE" or slot_id not in self._slot_capabilities:
            raise AuthorizationDenied("slot is not spawn eligible")
        capability = self._slot_capabilities[slot_id]
        if capability.consumed:
            raise AuthorizationDenied("spawn capability consumed")
        slot = next(slot for slot in self.authorization.slots if slot.slot_id == slot_id)
        token = SpawnToken(capability.spawn_token, self.authorization.campaign_id,
                           self.current_boot_id, slot_id, slot.attempt_id,
                           launch_spec_digest, self.custodian.identity,
                           self._supervisor_generation)
        intent_event_id = "event-spawn-intent-" + slot_id

        def record_durable_intent():
            # Local token/capability state follows the durable intent, never precedes it.
            if self.store.event_receipt(intent_event_id) is None:
                return False
            self._slot_tokens[slot_id] = token
            self._slot_capabilities[slot_id] = replace(
                capability, launch_spec_digest=launch_spec_digest, consumed=True)
            self.attempt_state = "SPAWN_INTENT_PERSISTED"
            return True

        def dispatch(effect_capability, binding):
            record_durable_intent()
            self.custodian.observe_store_revision(self.store.revision)
            try:
                return self.custodian.create_once(
                    token, launch_spec_digest, effect_capability, binding,
                    fault=({"crash_after_create": "ambiguous_after_create",
                            "crash_after_acceptance": "crash_after_acceptance"}.get(fault)),
                )
            except ContractError as exc:
                if fault == "crash_after_acceptance":
                    raise DispatchUncertain(
                        "effect accepted but result persistence is unresolved") from exc
                raise

        if fault == "crash_after_intent":
            if interlock is not None:
                raise ContractError("only one pre-dispatch interlock may be supplied")
            def interlock():
                raise DispatchUncertain("crash after durable spawn intent")
        try:
            receipt = self._dedicated_transition(
                "blocked-create", "attempt", "SPAWN_INTENT_PERSISTED", "spawn-intent-" + slot_id,
                {"spawn_token": token.token_id, "launch_spec_digest": launch_spec_digest,
                 "slot_id": slot_id, "attempt_id": slot.attempt_id,
                 "boot_id": self.current_boot_id,
                 "campaign_id": self.authorization.campaign_id,
                 "custodian_id": self.custodian.identity,
                 "supervisor_generation": self._supervisor_generation},
                dispatch, interlock=interlock, target=self.custodian.identity,
            )
        except DispatchUncertain:
            record_durable_intent()
            effect_capability = self.store.effect_capability("spawn-intent-" + slot_id)
            self.store.mark_effect_unresolved(effect_capability)
            self.safety_markers.update(("CUSTODY_UNCERTAIN",
                                        "CONTAINMENT_ONLY_RECOVERY"))
            self.store.install_failure_latch("unresolved-creation")
            raise
        except Exception:
            record_durable_intent()
            raise
        record_durable_intent()
        if fault == "crash_after_create":
            raise DispatchUncertain("create result lost; worker is possibly live")
        self._dedicated_transition("record-worker-creation", "attempt",
                                   "WORKER_CREATION_IN_PROGRESS", "worker-creation-" + slot_id,
                                   {"slot_id": slot_id, "spawn_token": token.token_id,
                                    "custodian_receipt": receipt.receipt_id})
        self.attempt_state = "WORKER_CREATION_IN_PROGRESS"
        return receipt

    def recover_spawn(self, slot_id):
        token = self._slot_tokens.get(slot_id)
        if token is None:
            raise AuthorizationDenied("no durable spawn intent")
        receipt = self.custodian.inspect_spawn(token.token_id)
        if receipt.status == "FAILED_NO_CHILD":
            return CustodianReceipt(
                "unresolved-" + token.token_id, self.custodian.identity,
                token.token_id, token.launch_spec_digest, "UNKNOWN", None, True)
        return receipt

    def lookup_historical_spawn_receipt(self, slot_id):
        token = self._slot_tokens.get(slot_id)
        if token is None:
            raise AuthorizationDenied("no durable spawn intent")
        envelope = self.store.effect_result("spawn-intent-" + slot_id)
        receipt = envelope.receipt
        if (receipt.spawn_token != token.token_id or
                receipt.launch_spec_digest != token.launch_spec_digest or
                envelope.supervisor_generation != token.supervisor_generation):
            raise AuthorizationDenied("historical receipt identity mismatch")
        return envelope

    def record_custodian_loss(self, lifecycle_point):
        if type(lifecycle_point) is not str or not lifecycle_point:
            raise ContractError("custodian loss point")
        self.safety_markers.update(("CUSTODY_UNCERTAIN", "TAINTED",
                                    "CONTAINMENT_ONLY_RECOVERY"))
        self.store.revoke_execution()
        reason = "custody-uncertain:" + lifecycle_point
        if self.store._authentication_service is not None:
            try:
                self.store.witness.deny_campaign(self._actor, 'CUSTODY_LOSS_PROVEN',
                    [f['envelope'] for f in self.store._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                self.store.mirror_denial(self._actor)
            except (StoreError, ContractError):
                pass
            self.store._taint.add(reason)
            return
        try:
            self.store.add_taint(reason)
            self.store.append_nonauthorizing(
                self.store.witness.current_fence,
                "custody-uncertain-%d" % (self.store.revision + 1),
                {"state": "CUSTODY_UNCERTAIN", "lifecycle_point": lifecycle_point},
            )
        except StoreError:
            self.store._taint.add(reason)

    def _cleanup_existing_workers(self):
        for slot_id, token in tuple(self._slot_tokens.items()):
            inspection = self.custodian.inspect_spawn(token.token_id)
            if not inspection.possibly_live or not self.custodian.alive:
                continue
            try:
                binding = self.custodian.original_creation_binding(token.token_id)
            except Exception:
                continue
            try:
                self.custodian.contain_spawn(
                    token.token_id, "failure-containment", binding)
            except Exception:
                continue

    def _write_failure_record(self, reason, raw_bytes, *, primary_failure=None,
                              secondary_failures=None):
        if self.store._authentication_service is None:
            self.store.add_taint(reason)
        record = {"state": "TAINTED", "reason": reason, "raw_digest": _sha(raw_bytes),
                  "raw_length": len(raw_bytes)}
        if primary_failure is not None:
            record["primary_failure"] = str(primary_failure)
            record["secondary_failures"] = [str(item) for item in secondary_failures or ()]
        if self.store._authentication_service is not None:
            record.update(authorization_digest=self.authorization.authorization_digest,
                          campaign_id=self.authorization.campaign_id, authorizes_execution=False)
            return self.store.record_original_diagnostic(self._actor, record)
        return self.store.append_nonauthorizing(
            self.store.witness.current_fence, "failure-%d" % (self.store.revision + 1),
            record,
        )

    def _contain_after_failure(self, reason, raw_bytes, *, suppress_reporting_error):
        self.safety_markers.update(("ABORTED", "TAINTED"))
        self.store.install_failure_latch(reason)
        self._cleanup_existing_workers()
        try:
            if self.store._authentication_service is not None and self._actor is not None:
                try:
                    self.store.witness.deny_campaign(self._actor, 'PUBLICATION_INTEGRITY_CONFLICT',
                        [f['envelope'] for f in self.store._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                except AuthorizationDenied:
                    pass
                else:
                    self.store.mirror_denial(self._actor)
            self._write_failure_record(reason, raw_bytes)
        except Exception:
            self.store._taint.add(reason)
            if not suppress_reporting_error:
                raise

    def record_failure(self, reason, raw_bytes):
        self.safety_markers.update(("ABORTED", "TAINTED"))
        self.store.install_failure_latch("reported-failure")
        if type(reason) is not str or type(raw_bytes) is not bytes or len(raw_bytes) > 1_048_576:
            raise ContractError("bounded failure record")
        self._contain_after_failure(reason, raw_bytes,
                                    suppress_reporting_error=False)

    def run_contained(self, operation, raw_bytes=b""):
        """Execute fallible parsing with prohibition installed before reporting."""
        if not callable(operation) or type(raw_bytes) is not bytes:
            raise ContractError("contained operation")
        try:
            return operation()
        except Exception:
            self._contain_after_failure(
                "malformed-input", raw_bytes[:1_048_576],
                suppress_reporting_error=True)
            raise

    def set_measurement_window(self, window):
        if type(window) is not str or window not in MEASUREMENT_WINDOWS:
            raise ContractError("unknown measurement window")
        self._set_measurement_window(window, initialization=None)

    def _prohibit_started_operation(self, reason):
        """Sticky prohibition for a started operation, installed while the
        authorization lock is still held.  Fallible reporting follows later."""
        self.safety_markers.update(("ABORTED", "TAINTED"))
        self.store.install_failure_latch(reason)

    def _set_measurement_window(self, window, *, initialization):
        """Validate -> register pending -> append and witness -> bind result
        -> expose the new window and epoch, all under the authorization lock."""
        started = False
        try:
            with self.store.authorization_lock:
                try:
                    self._ensure_session()
                    self.store.assert_healthy_authority()
                    history = _validated_window_history(self.store, self.authorization)
                    if not history.complete:
                        raise AuthorizationDenied(
                            "measurement-window history is incomplete or unprovenanced")
                    if initialization is None:
                        if history.window_epoch < 1:
                            raise AuthorizationDenied("measurement window is uninitialized")
                        previous = (history.window, history.window_epoch)
                    else:
                        if history.window_epoch != 0 or window != OUTSIDE_MEASURED_WINDOWS:
                            raise AuthorizationDenied("initial measurement window")
                        previous = (None, 0)
                    operation_id = self.store._next_window_operation_id(_DEDICATED_AUTHORITY, actor=self._actor)
                    transition = MeasurementWindowTransition(
                        self.store.identity, WINDOW_OPERATION, operation_id,
                        "measurement-" + operation_id, previous[0], previous[1], window,
                        previous[1] + 1, self.authorization.authorization_digest,
                        self.authorization.campaign_id, self._supervisor_generation,
                        self.session.session_id, self.session.fence_epoch)
                    # Mark started: register the exact operation as pending.
                    started = True
                    self.store._register_window_operation(
                        _DEDICATED_AUTHORITY, transition, initialization=initialization, actor=self._actor)
                    receipt = self.store._append_window_result(_DEDICATED_AUTHORITY,
                                                               transition, actor=self._actor)
                    self.store._bind_window_result(_DEDICATED_AUTHORITY,
                                                   transition.operation_id, receipt, actor=self._actor)
                    self.store._measurement_window = transition.window
                    self.store._window_epoch = transition.window_epoch
                except BaseException:
                    if started:
                        # A started, unbound transition leaves the window
                        # indeterminate; it never falls back to an earlier one.
                        self.store._measurement_window = None
                        self._prohibit_started_operation("measurement-window-failure")
                    raise
        except (TransactionPending, LostAcknowledgement, Quarantined):
            self.store.revoke_execution()
            self.store._publication_prohibited = True
            raise
        except StoreError:
            self._contain_after_failure(
                "measurement-window-failure", b"", suppress_reporting_error=True)
            raise
        except Exception:
            if started:
                self._contain_after_failure(
                    "measurement-window-failure", b"", suppress_reporting_error=True)
            raise

    @property
    def current_window(self):
        return self.store._measurement_window

    @property
    def window_epoch(self):
        return self.store._window_epoch

    def publication_binding(self):
        return (self._supervisor_generation, self.session.session_id,
                self.session.fence_epoch,
                self.authorization.authorization_digest,
                self.authorization.campaign_id)

    def _assert_publication_binding(self, binding, *, mutation):
        """Current authority for a publication operation.

        For mutation, returns the validated window history; the current window
        and epoch must come from it, be complete, and be outside measurement."""
        expected = (self._supervisor_generation, self.session.session_id,
                    self.session.fence_epoch,
                    self.authorization.authorization_digest,
                    self.authorization.campaign_id)
        if not mutation:
            if binding != expected:
                raise AuthorizationDenied('foreign historical reader binding')
            self.store.validate_admitted_authorization(self.authorization)
            return None
        if (binding != expected or
                not self.store.supervisor_is_current(self._supervisor_generation) or
                self.session.fence_epoch != self.store.witness.current_fence or
                not self.store.session_registered(self.session)):
            raise AuthorizationDenied("stale or foreign publication authority")
        if not mutation:
            return None
        self._ensure_session()
        if self.store.publication_prohibited:
            raise AuthorizationDenied("publication promotion is prohibited")
        history = _validated_window_history(self.store, self.authorization)
        if not history.complete:
            raise AuthorizationDenied("measurement-window provenance is incomplete")
        if history.window_epoch < 1:
            raise AuthorizationDenied("authoritative measurement window is absent")
        if history.window != OUTSIDE_MEASURED_WINDOWS:
            raise AuthorizationDenied("publication prohibited during measured window")
        return history

    @staticmethod
    def _publication_identity(intent):
        """Canonical identity of a publication intent; its source bytes must
        match the digest and length."""
        from .evidence import PublicationIntent
        if not isinstance(intent, PublicationIntent):
            raise AuthorizationDenied("closed publication intent required")
        try:
            identity = PublicationIdentity(intent.intent_id, intent.destination,
                                           intent.object_key, intent.object_digest,
                                           intent.length)
            identity.verify_source(intent.bytes)
        except ContractError as exc:
            raise AuthorizationDenied("publication intent does not match its identity") from exc
        return identity

    @staticmethod
    def _publication_source_object_id(intent):
        return "publication-source-" + intent.intent_id

    @staticmethod
    def _publication_written_object_id(intent):
        return "publication-written-" + intent.intent_id

    @staticmethod
    def _is_publication_record(event):
        return _is_publication_record(event)

    def _publication_candidate_binding(self):
        """Event digest of the closure candidate finalized in the current
        lifecycle, or None.  Publication records carry it so that closure can
        prove a publication was performed for that exact candidate."""
        frames = self.store.provenanced_frames("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
                                               "finalize-campaign-closure-candidate")
        if not frames:
            frames = [frame for frame in self.store.provenanced_frames(
                          "BOOT_CLOSURE_CANDIDATE_FINALIZED",
                          "finalize-boot-closure-candidate")
                      if frame["event"].get("boot_ordinal") == self.current_boot_ordinal]
        return frames[-1]["receipt"].event_digest if frames else None

    def _publication_events(self, identity):
        """Validated retained chain of exactly this publication identity."""
        entries = _publication_frame_groups(self.store).get(
            (identity.destination, identity.object_key), [])
        if not entries:
            return []
        events = self._validate_publication_chain([frame for _, frame in entries],
                                                  require_verified=False)
        if PublicationIdentity.from_record(events[0]) != identity:
            raise AuthorizationDenied("publication intent identity changed")
        return events

    def _publication_lifecycle(self, grant_id, operation, identity, window_epoch):
        """The complete canonical operation binding current conditions permit.

        Issuance builds the grant from it; consumption requires the presented
        grant to equal it exactly, before anything is consumed or mutated."""
        events = self._publication_events(identity)
        prior = events[-1].get("state") if events else None
        try:
            return PublicationOperationBinding(
                identity, self.store.identity, grant_id, operation, prior, window_epoch,
                self.authorization.authorization_digest, self.authorization.campaign_id,
                self.current_boot_id, self.current_boot_ordinal,
                self._publication_candidate_binding(), self._supervisor_generation,
                self.session.session_id, self.session.fence_epoch)
        except ContractError as exc:
            raise AuthorizationDenied("publication transition precondition") from exc

    def issue_publication_grant(self, binding, operation, intent):
        if type(operation) is not str or operation not in _PUBLICATION_OPERATIONS:
            raise AuthorizationDenied("closed publication operation required")
        identity = self._publication_identity(intent)
        with self.store.authorization_lock:
            history = self._assert_publication_binding(binding, mutation=True)
            self.store.assert_healthy_authority()
            grant_id = self.store._next_publication_grant_id(_DEDICATED_AUTHORITY, actor=self._actor)
            request = self._publication_lifecycle(grant_id, operation, identity,
                                                  history.window_epoch)
            grant = PublicationOperationGrant(request,
                                              _publication_grant_attestation(request))
            return self.store._register_publication_grant(_DEDICATED_AUTHORITY, grant, actor=self._actor)

    def perform_publication(self, binding, grant, intent, payload=None,
                            interlock=None):
        from .contracts import PublicationReceipt
        from .evidence import PublicationIntent
        if (not isinstance(grant, PublicationOperationGrant) or
                not isinstance(intent, PublicationIntent) or
                (interlock is not None and not callable(interlock))):
            raise AuthorizationDenied("closed publication operation required")
        identity = self._publication_identity(intent)
        started = False
        try:
            with self.store.authorization_lock:
                try:
                    # Validate the complete grant and current conditions.
                    self._assert_publication_binding(binding, mutation=True)
                    if interlock is not None:
                        interlock()
                    history = self._assert_publication_binding(binding, mutation=True)
                    self.store.assert_healthy_authority()
                    request = grant.binding
                    self.store._publication_issuance(grant, self._actor)
                    if (self.store.publication_grant_consumed(request.grant_id) or
                            not grant.attestation_valid() or
                            grant.attestation != _publication_grant_attestation(request)):
                        raise AuthorizationDenied(
                            "publication operation grant is stale or foreign")
                    if request.identity != identity:
                        raise AuthorizationDenied(
                            "publication grant is bound to another publication identity")
                    current = self._publication_lifecycle(
                        request.grant_id, request.operation, identity,
                        history.window_epoch)
                    if current != request:
                        raise AuthorizationDenied(
                            "publication grant is bound to another lifecycle point")
                    events = self._publication_events(identity)
                    operation = request.operation
                    if operation == "intent":
                        if payload != intent.bytes:
                            raise AuthorizationDenied("publication source bytes mismatch")
                    elif operation == "write":
                        if type(payload) is not bytes:
                            raise AuthorizationDenied("publication write bytes required")
                    elif payload is not None:
                        raise AuthorizationDenied("unexpected %s payload" % operation)
                    # Consume, then perform the bounded modeled object operation.
                    started = True
                    self.store._consume_publication_grant(_DEDICATED_AUTHORITY, grant, actor=self._actor)
                    event = request.record_fields()
                    result = request.state
                    if operation == "intent":
                        source_id = self._publication_source_object_id(intent)
                        event["source_object_id"] = source_id
                        event["source_digest"] = _sha(payload)
                        result = intent
                    elif operation == "create":
                        event["reservation_id"] = "reservation-" + request.grant_id
                    elif operation == "write":
                        object_id = self._publication_written_object_id(intent)
                        written_digest = _sha(payload)
                        event.update({"written_object_id": object_id,
                                      "written_digest": written_digest,
                                      "written_length": len(payload),
                                      "write_revision": self.store.revision + 1})
                    elif operation == "durable":
                        written = events[-1]
                        self.store.read_object(written["written_object_id"],
                                               written["written_digest"])
                        event.update({"written_object_id": written["written_object_id"],
                                      "written_digest": written["written_digest"],
                                      "write_revision": written["write_revision"],
                                      "durability_ack_id": "durable-" + request.grant_id})
                    elif operation == "verify":
                        durable = events[-1]
                        readback = self.store.read_object(
                            durable["written_object_id"], durable["written_digest"])
                        try:
                            identity.verify_source(readback)
                        except ContractError as exc:
                            raise AuthorizationDenied(
                                "publication readback differs from intent") from exc
                        if readback != intent.bytes:
                            raise AuthorizationDenied(
                                "publication readback differs from intent")
                        event.update({"written_object_id": durable["written_object_id"],
                                      "written_digest": durable["written_digest"],
                                      "write_revision": durable["write_revision"],
                                      "durability_ack_id": durable["durability_ack_id"],
                                      "readback_digest": _sha(readback),
                                      "verification_id": "readback-" + request.grant_id})
                        result = PublicationReceipt(
                            "publication-receipt-" + identity.object_digest[:16],
                            identity.destination, identity.object_key,
                            identity.object_digest, identity.length,
                            "PUBLICATION_VERIFIED", _sha(readback))
                    # Freeze exact issuance/consumption before any modeled
                    # object effect. The provisional payload is not a result.
                    provisional = self.store._commit_u04(self._actor, 'EXEC', event,
                        facts={'publication_grant': {'attestation': grant.attestation, 'phase': 'INTENT'}})
                    artifact = self.verifier.verify(request.state, self._actor.fence, self._actor.session_id)
                    accepted = self.store._u04_common(self._actor, 'EFFECT_ACCEPTED', 'EXECUTION', True)
                    accepted.update(intent_ref={'event_id': provisional.event_id,
                        'revision': provisional.revision, 'payload_digest': provisional.event_digest},
                        effect_id=grant.grant_id, capability_digest=_sha(_u04_canonical(asdict(grant))),
                        operation=request.operation, target=request.identity.destination,
                        consumption_id=grant.grant_id, artifact_binding=asdict(artifact),
                        target_acceptance_identity=request.identity.destination)
                    self.store._commit_u04(self._actor, 'EXEC', accepted,
                        facts={'publication_acceptance': request.grant_id})
                    self.store.require_actor(self._actor)
                    self.store._acceptance_acks[request.grant_id] = self._actor
                    self.verifier.assert_continuity(artifact)
                    event = self.custodian.initiate_publication(self._actor, grant, event, payload)
                    # Append and witness the exact result, then bind it.
                    appended = self.store._append_publication_result(
                        _DEDICATED_AUTHORITY, grant,
                        "publication-%s-%d" % (operation, self.store.revision + 1), event, actor=self._actor)
                    self.store.record_publication_effect_result(self._actor, grant)
                    if self.custodian.confirms_publication_conflict(event):
                        self.store.witness.deny_campaign(self._actor, 'PUBLICATION_INTEGRITY_CONFLICT',
                            [f['envelope'] for f in self.store._committed_frames()], _boundary=_U04_BOUNDARIES['DENY'])
                        self.store.mirror_denial(self._actor)
                        raise AuthorizationDenied('independently completed publication conflicts with intended bytes')
                    self.store._bind_publication_grant(_DEDICATED_AUTHORITY,
                                                       request.grant_id, appended, actor=self._actor)
                    return result
                except BaseException as exc:
                    if started:
                        self._prohibit_started_operation(
                            "publication-authority-failure" if isinstance(exc, StoreError)
                            else "publication-mutation-failure")
                    raise
        except (TransactionPending, LostAcknowledgement, Quarantined):
            self.store.revoke_execution()
            self.store._publication_prohibited = True
            raise
        except StoreError:
            if started:
                self._contain_after_failure(
                    "publication-authority-failure", b"", suppress_reporting_error=True)
            raise
        except Exception:
            if started:
                self._contain_after_failure(
                    "publication-mutation-failure", b"", suppress_reporting_error=True)
            raise

    def publication_snapshot(self, binding):
        """Read-only view built only from validated publication chains."""
        self._assert_publication_binding(binding, mutation=False)
        history = _validated_window_history(self.store, self.authorization)
        indexed = []
        for entries in _publication_frame_groups(self.store).values():
            events = self._validate_publication_chain([frame for _, frame in entries],
                                                      require_verified=False,
                                                      window_history=history)
            indexed.extend(zip([index for index, _ in entries], events))
        records = []
        for _, event in sorted(indexed, key=lambda item: item[0]):
            record = copy.deepcopy(event)
            if event.get("state") == "PUBLICATION_INTENT":
                record["source_bytes"] = self.store.read_object(
                    event["source_object_id"], event["source_digest"])
            elif event.get("state") == "PUBLICATION_WRITTEN":
                record["written_bytes"] = self.store.read_object(
                    event["written_object_id"], event["written_digest"])
            records.append(record)
        return records

    def authorize_publication(self, state, intent):
        raise AuthorizationDenied(
            "publication state labels are not an authoritative operation")

    def _validate_publication_chain(self, frames, *, require_verified, window_history=None):
        return _validate_publication_frames(self.store, self.authorization, frames,
                                            require_verified=require_verified,
                                            window_history=window_history)

    def _verify_publication_receipts(self, candidate, receipts, candidate_frame=None):
        from .contracts import PublicationReceipt
        values = (receipts,) if isinstance(receipts, PublicationReceipt) else receipts
        if type(values) is not tuple:
            raise AuthorizationDenied("closed publication receipt manifest required")
        groups = _publication_frame_groups(self.store)
        for receipt in values:
            if not isinstance(receipt, PublicationReceipt):
                raise AuthorizationDenied("verified publication receipt required")
            entries = groups.get((receipt.destination, receipt.object_key), [])
            try:
                events = self._validate_publication_chain(
                    [frame for _, frame in entries], require_verified=True)
            except (AuthorizationDenied, StoreError) as exc:
                raise AuthorizationDenied(
                    "publication receipt lacks authoritative verification") from exc
            verified = events[-1]
            identity = PublicationIdentity.from_record(verified)
            if (identity.destination != receipt.destination or
                    identity.object_key != receipt.object_key or
                    identity.object_digest != receipt.object_digest or
                    identity.length != receipt.length or
                    verified.get("readback_digest") != receipt.readback_digest):
                raise AuthorizationDenied("publication receipt lacks authoritative verification")
            if candidate_frame is not None and not _publication_bound_to_candidate(
                    self.store, self.authorization, candidate_frame, entries,
                    self.store.revision):
                raise AuthorizationDenied(
                    "publication receipt was not produced for the finalized candidate")
        return values

    def finalize_boot_closure_candidate(self, payload):
        from .evidence import build_closure_candidate
        required_slots = sorted(slot.slot_id for slot in self.authorization.slots
                                if slot.boot_ordinal == self.current_boot_ordinal)
        if (set(self._completed_attempts) & set(required_slots)) != set(required_slots):
            raise AuthorizationDenied("all three local boot attempts must be valid")
        if type(payload) is not dict or payload.get("boot_id") != self.current_boot_id:
            raise AuthorizationDenied("boot closure candidate must bind the current boot")
        bound = {}
        for slot_id in required_slots:
            validated = self.store.validated_completion(slot_id)
            if (validated is None or validated["completion_digest"] !=
                    self._completed_attempts[slot_id].get("completion_digest")):
                raise AuthorizationDenied("boot attempt completion is not store-validated")
            bound[slot_id] = validated["completion_digest"]
        candidate = build_closure_candidate("boot", payload)
        self._dedicated_transition(
            "finalize-boot-closure-candidate", "boot", "BOOT_CLOSURE_CANDIDATE_FINALIZED",
            "boot-%d-closure-candidate" % self.current_boot_ordinal,
            {"candidate_digest": candidate.digest,
             "candidate_kind": candidate.kind,
             "candidate_bytes": candidate.bytes.hex(),
             "object_digests": list(candidate.object_digests),
             "boot_id": self.current_boot_id,
             "attempt_completion_digests": bound},
        )
        self._finalized_candidates["boot"] = candidate
        self.boot_state = "BOOT_CLOSURE_CANDIDATE_FINALIZED"
        return candidate

    def _closure_payload(self, candidate, publication_receipt, candidate_state,
                         boot_ordinal=None):
        from .evidence import complete_closure
        try:
            closure = complete_closure(candidate, publication_receipt, self.store.revision,
                                       self.session.fence_epoch, bool(self.store.taint))
        except Exception as exc:
            raise AuthorizationDenied("closure evidence rejected") from exc
        candidate_frame = self._candidate_frame(candidate_state, boot_ordinal)
        return {"candidate_digest": closure["candidate_digest"],
                "candidate_kind": closure["candidate_kind"],
                "candidate_event_digest": candidate_frame["receipt"].event_digest,
                "publication_receipt_id": closure["publication_receipt_id"],
                "publication_manifest": closure["publication_manifest"],
                "closure_revision": closure["revision"]}

    def complete_boot(self, candidate, publication_receipt):
        if self.boot_state != "BOOT_CLOSURE_CANDIDATE_FINALIZED":
            raise AuthorizationDenied("boot closure candidate not finalized")
        if self._finalized_candidates.get("boot") != candidate:
            raise AuthorizationDenied("exact finalized boot candidate required")
        publication_receipt = self._verify_publication_receipts(
            candidate, publication_receipt,
            self._candidate_frame("BOOT_CLOSURE_CANDIDATE_FINALIZED",
                                  self.current_boot_ordinal))
        validated_candidate = self._validate_boot_candidate(self.current_boot_ordinal)
        if validated_candidate != candidate:
            raise AuthorizationDenied("boot candidate evidence changed")
        payload = self._closure_payload(candidate, publication_receipt,
                                        "BOOT_CLOSURE_CANDIDATE_FINALIZED",
                                        self.current_boot_ordinal)
        payload["boot_id"] = self.current_boot_id
        self._dedicated_transition(
            "complete-boot", "boot", "BOOT_COMPLETE",
            "boot-%d-complete" % self.current_boot_ordinal, payload,
        )
        try:
            digest_value = self._validate_boot_closure(self.current_boot_ordinal)
            self.store._register_validated_boot_closure(
                _DEDICATED_AUTHORITY, self.current_boot_ordinal, digest_value)
        except Exception:
            self._contain_after_failure("boot-closure-validation-failure", b"",
                                        suppress_reporting_error=True)
            raise
        self.predecessor_closure_digest = digest_value
        self.boot_state = "BOOT_COMPLETE"
        self._completed_boots.add(self.current_boot_ordinal)
        return self.predecessor_closure_digest

    def finalize_campaign_closure_candidate(self, payload):
        from .evidence import build_closure_candidate
        if self._completed_boots != {1, 2, 3, 4}:
            raise AuthorizationDenied("all four boots must be complete")
        closures = [self.store.validated_boot_closure(ordinal) for ordinal in (1, 2, 3, 4)]
        if None in closures:
            raise AuthorizationDenied("all four boot closures must be store-validated")
        if (type(payload) is not dict or
                payload.get("campaign_id") != self.authorization.campaign_id):
            raise AuthorizationDenied("campaign closure candidate must bind the campaign")
        candidate = build_closure_candidate("campaign", payload)
        self._dedicated_transition(
            "finalize-campaign-closure-candidate", "campaign",
            "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
            "campaign-closure-candidate", {"candidate_digest": candidate.digest,
                                            "candidate_kind": candidate.kind,
                                            "candidate_bytes": candidate.bytes.hex(),
                                            "object_digests": list(candidate.object_digests),
                                            "boot_closure_digests": closures},
        )
        self._finalized_candidates["campaign"] = candidate
        self.campaign_state = "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED"
        return candidate

    def complete_campaign(self, candidate, publication_receipt):
        if self.campaign_state != "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED":
            raise AuthorizationDenied("campaign closure candidate not finalized")
        if self._finalized_candidates.get("campaign") != candidate:
            raise AuthorizationDenied("exact finalized campaign candidate required")
        publication_receipt = self._verify_publication_receipts(
            candidate, publication_receipt,
            self._candidate_frame("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED"))
        if self._validate_campaign_candidate() != candidate:
            raise AuthorizationDenied("campaign candidate evidence changed")
        payload = self._closure_payload(candidate, publication_receipt,
                                        "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")
        self._dedicated_transition("complete-campaign", "campaign", "CAMPAIGN_COMPLETE",
                                   "campaign-complete", payload)
        try:
            self.store._register_validated_campaign_closure(
                _DEDICATED_AUTHORITY, self._validate_campaign_closure())
        except Exception:
            self._contain_after_failure("campaign-closure-validation-failure", b"",
                                        suppress_reporting_error=True)
            raise
        self.campaign_state = "CAMPAIGN_COMPLETE"

    def begin_boot_handoff(self, next_ordinal):
        if self.boot_state != "BOOT_COMPLETE" or next_ordinal != self.current_boot_ordinal + 1:
            raise AuthorizationDenied("boot handoff")
        if (self.store.validated_boot_closure(self.current_boot_ordinal) is None or
                self.store.validated_boot_closure(self.current_boot_ordinal) !=
                self.predecessor_closure_digest):
            raise AuthorizationDenied("boot handoff requires validated boot closure")
        self._dedicated_transition("begin-boot-handoff", "boot", "BOOT_HANDOFF_PENDING",
                                   "boot-%d-handoff" % self.current_boot_ordinal)
        self.boot_state = "BOOT_HANDOFF_PENDING"
        self._actor = self.store.witness.change_mode(self._actor, 'SHUTDOWN_ONLY', _boundary=_U04_BOUNDARIES['EXEC'])
        self.store._current_actor = self._actor
        self.store._entry_mode = 'SHUTDOWN_ONLY'
        self.session = replace(self.session, execution_live=False)
        self.store._sessions[self.session.session_id] = self.session

    def commit_planned_shutdown(self, fault=None):
        return self.store.commit_shutdown(self._actor, self.authorization, fault=fault)

    def activate_next_boot(self, activation):
        actor, fresh_session = self.store.admit_next_boot(self.authorization, activation,
                                                         self.session.owner_identity)
        self._actor, self.session = actor, fresh_session
        self._supervisor_generation = actor.generation
        self.activation_ids.add(activation.activation_id)
        self.current_boot_ordinal = activation.boot_ordinal
        self.current_boot_id = activation.observed_boot_id
        self._boot_ids[self.current_boot_ordinal] = self.current_boot_id
        self._observed_boot_ids.add(self.current_boot_id)
        self.boot_state = self.attempt_state = self._custody = None


class _HistoricalEvidenceVerifier:
    """Ephemeral derived view shared by lower store checks and historical readers.

    Every member is a B service reference or V/D historical view. No actor,
    opaque session, live registration, writer, or dispatch method is exposed.
    A retained completion/closure dictionary can never supply authority here.
    """
    def __init__(self, store, authorization):
        self.store, self.authorization, self.custodian = store, authorization, store._custodian
        store._committed_frames()
        self._boot_ids = {ordinal: store.boot_identity(ordinal) for ordinal in (1, 2, 3, 4)}
        self.current_boot_id = None
        self._slot_tokens = {}
        for frame in store.provenanced_frames('SPAWN_INTENT_PERSISTED', 'blocked-create'):
            event = frame['event']
            slot_id = event['slot_id']
            if slot_id in self._slot_tokens:
                raise AuthorizationDenied('multiple original spawn identities for one slot')
            self._slot_tokens[slot_id] = SpawnToken(event['spawn_token'], event['campaign_id'],
                event['boot_id'], slot_id, event['attempt_id'], event['launch_spec_digest'],
                event['custodian_id'], event['supervisor_generation'])
        self._completed_attempts = {f['event']['slot_id']: f['event'] for f in
            store.provenanced_frames('ATTEMPT_COMPLETE', 'complete-attempt')}
        self._completed_boots = {f['event']['boot_ordinal'] for f in
            store.provenanced_frames('BOOT_COMPLETE', 'complete-boot')}

    _dedicated_events = PersistentSupervisor._dedicated_events
    _candidate_frame = PersistentSupervisor._candidate_frame
    _rebuild_candidate = PersistentSupervisor._rebuild_candidate
    _history_clean_before = PersistentSupervisor._history_clean_before
    _validate_residual_observations = PersistentSupervisor._validate_residual_observations
    _validate_attempt_completion_record = PersistentSupervisor._validate_attempt_completion_record
    _validate_boot_candidate = PersistentSupervisor._validate_boot_candidate
    _validate_published_manifest = PersistentSupervisor._validate_published_manifest
    _validate_boot_closure = PersistentSupervisor._validate_boot_closure
    _validate_campaign_candidate = PersistentSupervisor._validate_campaign_candidate
    _validate_campaign_closure = PersistentSupervisor._validate_campaign_closure
