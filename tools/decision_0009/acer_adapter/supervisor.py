"""Persistent offline reducer, durable-store model, and effect authorization.

Everything in this module is an in-memory failure model.  No default live-effect
implementation exists.  Callers must inject offline dispatch functions.
"""

from dataclasses import dataclass, replace
from contextlib import contextmanager
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


class AuthorizationDenied(ContractError):
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
        transition = store._window_operations[event["operation_id"]]
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
    for operation_id in sorted(store._window_operations):
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

    def acquire_fence(self, owner, fail=False):
        with self._lock:
            self.high_fence += 1
            epoch = self.high_fence
            if not fail:
                self.current_fence = epoch
            return epoch

    def reserve(self, revision, chain_digest):
        if not self.available:
            raise Quarantined("witness unavailable")
        if revision != self.high_revision + 1 or revision in self.pending:
            self.quarantined = True
            raise Quarantined("witness revision divergence")
        self.pending[revision] = chain_digest
        return "reservation-%d-%s" % (revision, chain_digest[:12])

    def commit(self, revision, chain_digest):
        if self.pending.get(revision) != chain_digest:
            self.quarantined = True
            raise Quarantined("witness reservation mismatch")
        self.pending.pop(revision)
        self.high_revision = revision
        self.high_chain_digest = chain_digest
        return "witness-%d-%s" % (revision, chain_digest[:12])


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
        return False


class OfflineDurableStore:
    """Append-only framed-journal model with independent witness semantics."""

    def __init__(self, identity, witness):
        self.identity = identity
        self.witness = witness
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
                self.quarantined = self.containment_only = True
                raise Quarantined("journal ahead of witness")
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

    def _next_window_operation_id(self, authority):
        self._require_dedicated(authority)
        with self._lock:
            return "window-operation-%d" % (self._window_operation_sequence + 1)

    def _register_window_operation(self, authority, transition, initialization=None):
        """Mark a window operation started: register its exact transition as
        pending before anything is appended."""
        self._require_dedicated(authority)
        with self._lock:
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

    def _append_window_result(self, authority, transition, fault=None):
        """Append and witness the exact record of a pending window operation."""
        self._require_dedicated(authority)
        with self._lock:
            if (not isinstance(transition, MeasurementWindowTransition) or
                    self._window_operations.get(transition.operation_id) != transition or
                    transition.operation_id in self._window_results):
                raise StoreError("measurement-window operation is not pending")
            return self._append_control(self.revision, transition.fence_epoch,
                                        transition.event_id, transition.record(),
                                        fault=fault)

    def _bind_window_result(self, authority, operation_id, receipt):
        """Bind a pending window operation to the exact record it produced."""
        self._require_dedicated(authority)
        with self._lock:
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

    def _next_publication_grant_id(self, authority):
        self._require_dedicated(authority)
        with self._lock:
            return "publication-grant-%d" % (self._publication_grant_sequence + 1)

    def _register_publication_grant(self, authority, grant):
        self._require_dedicated(authority)
        with self._lock:
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
        return grant_id in self._consumed_publication_grants

    def _consume_publication_grant(self, authority, grant):
        """Mark a publication operation started.  Consumption is never
        refunded; a consumed grant without a bound result prohibits promotion."""
        self._require_dedicated(authority)
        with self._lock:
            if (self._publication_grants.get(grant.grant_id) != grant or
                    grant.grant_id in self._consumed_publication_grants):
                raise StoreError("publication grant is not registered and unused")
            self._consumed_publication_grants.add(grant.grant_id)

    def _append_publication_result(self, authority, grant, event_id, event):
        """Append and witness the exact result record of a consumed grant."""
        self._require_dedicated(authority)
        with self._lock:
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

    def read_verified(self, min_revision, expected_chain_digest=None):
        with self._lock:
            self._check_healthy()
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

    def crash(self):
        self._volatile.clear()

    def simulate_rollback(self, revision):
        with self._lock:
            self._durable = self._durable[:revision]
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
        return (self._supervisor_ready and type(generation) is int and
                generation == self._supervisor_generation)

    def bind_custodian(self, custodian):
        """Bind the single independent custodian whose registry is evidence."""
        with self._lock:
            if self._custodian is not None and self._custodian is not custodian:
                raise AuthorizationDenied("store custodian already bound")
            self._custodian = custodian

    def bound_custodian(self):
        return self._custodian

    def _bind_publication_grant(self, authority, grant_id, receipt):
        """Bind a consumed grant to the exact result record it produced."""
        self._require_dedicated(authority)
        with self._lock:
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

    def publication_record_provenanced(self, frame):
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

    def put_object(self, object_id, bytes_value):
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
        if not isinstance(session, FenceSession):
            raise AuthorizationDenied("closed execution session required")
        previous = self._sessions.get(session.session_id)
        if previous is not None and previous != session:
            if not (previous.fence_epoch == session.fence_epoch and
                    previous.owner_identity == session.owner_identity and
                    previous.boot_ordinal == session.boot_ordinal and
                    previous.execution_live and not session.execution_live):
                raise AuthorizationDenied("session identity collision")
        self._sessions[session.session_id] = session

    def session_registered(self, session):
        return isinstance(session, FenceSession) and self._sessions.get(session.session_id) == session

    def register_effect_capability(self, capability, *, _control=None):
        # Capability registration establishes durable-record provenance, so only
        # the authorization boundary may perform it.
        if _control is not _CONTROL_APPEND:
            raise AuthorizationDenied("capability registration is boundary-owned")
        if not isinstance(capability, EffectCapability):
            raise AuthorizationDenied("closed effect capability required")
        if capability.effect_id in self._effect_capabilities:
            raise AuthorizationDenied("effect capability already issued")
        if not self.supervisor_is_current(capability.supervisor_generation):
            raise AuthorizationDenied("effect capability generation is stale")
        self._effect_capabilities[capability.effect_id] = capability
        self._effect_status[capability.effect_id] = "INTENT_RECORDED"

    def effect_capability(self, effect_id):
        capability = self._effect_capabilities.get(effect_id)
        if capability is None:
            raise AuthorizationDenied("authoritative effect capability absent")
        return capability

    def effect_intent(self, capability):
        with self.authorization_lock:
            self.assert_healthy_authority()
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
        return (self._effect_status.get(capability.effect_id) == "FIRST_DISPATCH_ACTIVE" and
                capability.effect_id in self._active_creation_grants and
                self.supervisor_is_current(capability.supervisor_generation))

    def effect_status(self, capability):
        if self._effect_capabilities.get(capability.effect_id) != capability:
            raise AuthorizationDenied("authoritative effect capability absent")
        return self._effect_status.get(capability.effect_id)

    def mark_effect_unresolved(self, capability):
        with self.authorization_lock:
            if self._effect_capabilities.get(capability.effect_id) == capability:
                self._active_creation_grants.discard(capability.effect_id)
                self._effect_status[capability.effect_id] = "UNRESOLVED"
                self._invalidated_effects.add(capability.effect_id)

    def record_effect_result(self, capability, receipt):
        with self.authorization_lock:
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
        return self._effect_acceptance_counts.get(effect_id, 0)

    def accept_effect(self, capability):
        with self.authorization_lock:
            event = self.effect_intent(capability)
            if capability.effect_id in self._accepted_effects:
                raise AuthorizationDenied("effect capability already accepted")
            if (capability.operation == "blocked-create" and
                    not self.creation_grant_active(capability)):
                raise AuthorizationDenied("active first-dispatch grant required")
            self._accepted_effects.add(capability.effect_id)
            self._effect_status[capability.effect_id] = (
                "ACCEPTANCE_PENDING" if capability.operation == "blocked-create"
                else "EFFECT_ACCEPTED")
            self._effect_acceptance_counts[capability.effect_id] = (
                self._effect_acceptance_counts.get(capability.effect_id, 0) + 1)
            return event

    def effect_accepted(self, capability):
        return capability.effect_id in self._accepted_effects

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
        return self._receipts.get(event_id)

    def frame_has_provenance(self, frame):
        """True only for a frame written by the authorization boundary for the
        exact operation that is allowed to produce its state."""
        event = frame["event"]
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
        return self._validated_campaign_closure

    def boot_identity(self, boot_ordinal):
        """Boot identity admitted by provenanced admission/activation records."""
        if boot_ordinal == 1:
            frames = self.provenanced_frames("CAMPAIGN_ADMITTED", "admit-campaign")
            return frames[-1]["event"].get("boot_id") if len(frames) == 1 else None
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
        if self.is_consumed("slot", slot.slot_id) or slot.slot_id in self._slot_grants:
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
        grant = self._slot_grants.get(event.get("slot_id"))
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
        if (grant["supervisor_generation"] != self._supervisor_generation or
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
        grant = self._slot_grants[slot_id]
        grant.update(status="RESERVED", effect_id=effect_id,
                     launch_spec_digest=launch_spec_digest)

    def creation_slot_grant(self, capability, token):
        """Authoritative creation-boundary check used by the custodian."""
        with self.authorization_lock:
            grant = self._slot_grants.get(getattr(token, "slot_id", None))
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
            receipt = store._append_control(expected_revision, current_fence,
                                            effect_specification["event_id"], event)
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
                result = dispatcher(capability, binding)
            finally:
                if creation_operation:
                    store.deactivate_creation_grant(capability)
            if not store.effect_accepted(capability):
                raise AuthorizationDenied("dispatcher did not accept bound capability")
            return result, capability
        except DispatchUncertain:
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
        with self.store._supervisor_takeover() as generation:
            self._supervisor_generation = generation
            self.store.register_session(session)
            self.custodian.bind_authority(self.store, self.record_custodian_loss)
            self._reconstruct()
            # Replay may have installed sticky prohibitions; readiness never
            # clears them, and historical provenance is not a current-generation
            # check. No successor authority is usable during partial replay.
            self.store._supervisor_ready = True

    # ---- reconstruction ----------------------------------------------------

    def _history_violation(self, reason):
        self.reconstruction_violations.append(reason)

    def _classify_frame(self, frame):
        """Return True when a frame may be interpreted; record violations."""
        event = frame["event"]
        state = event.get("state")
        record_type = event.get("record_type")
        authorizing = event.get("authorizes_execution") is True
        if record_type == "PUBLICATION":
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
            try:
                if not self._classify_frame(frame):
                    continue
                reconstructed = None
                if (event.get("authorizes_execution") is True and
                        event.get("session_id") and event.get("session_owner")):
                    reconstructed = FenceSession(
                        event["fence_epoch"], event["session_id"], event["session_owner"],
                        event.get("session_boot_ordinal", event.get("boot_ordinal", 1)),
                        event.get("session_live", True))
            except (ContractError, StoreError, KeyError, TypeError, ValueError):
                self._history_violation("malformed-reserved-record")
                continue
            if reconstructed is not None:
                existing = self.store._sessions.get(reconstructed.session_id)
                if existing is None:
                    self.store.register_session(reconstructed)
                elif (existing.fence_epoch != reconstructed.fence_epoch or
                      existing.owner_identity != reconstructed.owner_identity or
                      existing.boot_ordinal != reconstructed.boot_ordinal):
                    raise AuthorizationDenied("durable session identity collision")
            try:
                if event.get("record_type") == "MEASUREMENT_WINDOW":
                    continue
                if (event.get("authorizes_execution") is not True and
                        state == "TAINTED" and type(event.get("reason")) is str and
                        event.get("reason")):
                    failure_reasons.append(event["reason"])
                if state in _STICKY_HISTORY_STATES:
                    self.safety_markers.add(state)
                if event.get("authorizes_execution") is not True:
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
        except DispatchUncertain:
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
        if self.campaign_state is not None:
            raise ContractError("campaign authorization replay")
        if not isinstance(boot_activation, BootActivation) or boot_activation.boot_ordinal != 1:
            raise AuthorizationDenied("initial boot activation")
        if boot_activation.authorization_digest != self.authorization.authorization_digest:
            raise AuthorizationDenied("activation authorization digest")
        # Initialization eligibility is established before any admission write
        # and is usable only within this call.
        initialization = self.store._begin_window_initialization(_DEDICATED_AUTHORITY)
        if initialization is None:
            raise AuthorizationDenied(
                "campaign admission requires a fresh, uninitialized store")
        try:
            self._dedicated_transition("admit-authorization", "authorization",
                                       "AUTHORIZATION_ADMITTED", "authorization-admitted")
            self.store.consume("authorization", self.authorization.authorization_id)
            self._dedicated_transition("admit-campaign", "campaign", "CAMPAIGN_ADMITTED",
                                       "campaign-admitted",
                                       {"boot_id": boot_activation.observed_boot_id,
                                        "activation_id": boot_activation.activation_id})
            self.store.consume("boot_activation", boot_activation.activation_id)
            self.activation_ids.add(boot_activation.activation_id)
            self.campaign_state = "CAMPAIGN_ADMITTED"
            self.current_boot_id = boot_activation.observed_boot_id
            self.current_boot_ordinal = 1
            self._boot_ids[1] = boot_activation.observed_boot_id
            self._observed_boot_ids = {boot_activation.observed_boot_id}
            self._set_measurement_window(OUTSIDE_MEASURED_WINDOWS,
                                         initialization=initialization)
        finally:
            self.store._end_window_initialization(_DEDICATED_AUTHORITY, initialization)

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
                                           pipeline.raw.read(reference))
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
                                                   normalized.value)
        self._dedicated_transition(
            "persist-local-evidence", "local_evidence", "NORMALIZATION_BOUND", "normalization-bound-" + slot_id,
            {"slot_id": slot_id, "attempt_id": slot.attempt_id,
             "raw_object_id": raw_object_id, "raw_digest": raw_digest,
             "normalized_object_id": normalized_object_id,
             "normalized_digest": normalized_digest})
        core = pipeline.freeze_core(decoded, normalized)
        core_object_id = "attempt-core-" + slot.attempt_id
        core_digest = self.store.put_object(core_object_id, core.bytes)
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
            digest = self.store.put_object(object_id, residual_raw)
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
                capability = self.store.effect_capability("spawn-intent-" + slot_id)
                binding = capability.artifact_binding
            except Exception:
                continue
            try:
                self.custodian.contain_spawn(
                    token.token_id, "failure-containment", binding)
            except Exception:
                continue

    def _write_failure_record(self, reason, raw_bytes, *, primary_failure=None,
                              secondary_failures=None):
        self.store.add_taint(reason)
        record = {"state": "TAINTED", "reason": reason, "raw_digest": _sha(raw_bytes),
                  "raw_length": len(raw_bytes)}
        if primary_failure is not None:
            record["primary_failure"] = str(primary_failure)
            record["secondary_failures"] = [str(item) for item in secondary_failures or ()]
        return self.store.append_nonauthorizing(
            self.store.witness.current_fence, "failure-%d" % (self.store.revision + 1),
            record,
        )

    def _contain_after_failure(self, reason, raw_bytes, *, suppress_reporting_error):
        self.safety_markers.update(("ABORTED", "TAINTED"))
        self.store.install_failure_latch(reason)
        self._cleanup_existing_workers()
        try:
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
                    if ((self.store._measurement_window, self.store._window_epoch) !=
                            previous):
                        raise AuthorizationDenied(
                            "exposed measurement window diverges from its history")
                    operation_id = self.store._next_window_operation_id(_DEDICATED_AUTHORITY)
                    transition = MeasurementWindowTransition(
                        self.store.identity, WINDOW_OPERATION, operation_id,
                        "measurement-" + operation_id, previous[0], previous[1], window,
                        previous[1] + 1, self.authorization.authorization_digest,
                        self.authorization.campaign_id, self._supervisor_generation,
                        self.session.session_id, self.session.fence_epoch)
                    # Mark started: register the exact operation as pending.
                    started = True
                    self.store._register_window_operation(
                        _DEDICATED_AUTHORITY, transition, initialization=initialization)
                    receipt = self.store._append_window_result(_DEDICATED_AUTHORITY,
                                                               transition)
                    self.store._bind_window_result(_DEDICATED_AUTHORITY,
                                                   transition.operation_id, receipt)
                    self.store._measurement_window = transition.window
                    self.store._window_epoch = transition.window_epoch
                except BaseException:
                    if started:
                        # A started, unbound transition leaves the window
                        # indeterminate; it never falls back to an earlier one.
                        self.store._measurement_window = None
                        self._prohibit_started_operation("measurement-window-failure")
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
        if ((self.store._measurement_window, self.store._window_epoch) !=
                (history.window, history.window_epoch)):
            raise AuthorizationDenied("exposed measurement window diverges from its history")
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
            grant_id = self.store._next_publication_grant_id(_DEDICATED_AUTHORITY)
            request = self._publication_lifecycle(grant_id, operation, identity,
                                                  history.window_epoch)
            grant = PublicationOperationGrant(request,
                                              _publication_grant_attestation(request))
            return self.store._register_publication_grant(_DEDICATED_AUTHORITY, grant)

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
                    if (self.store._publication_grants.get(request.grant_id) != grant or
                            self.store.publication_grant_consumed(request.grant_id) or
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
                    self.store._consume_publication_grant(_DEDICATED_AUTHORITY, grant)
                    event = request.record_fields()
                    result = request.state
                    if operation == "intent":
                        source_id = self._publication_source_object_id(intent)
                        event["source_object_id"] = source_id
                        event["source_digest"] = self.store.put_object(source_id, payload)
                        result = intent
                    elif operation == "create":
                        event["reservation_id"] = "reservation-" + request.grant_id
                    elif operation == "write":
                        object_id = self._publication_written_object_id(intent)
                        written_digest = self.store.put_object(object_id, payload)
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
                    # Append and witness the exact result, then bind it.
                    appended = self.store._append_publication_result(
                        _DEDICATED_AUTHORITY, grant,
                        "publication-%s-%d" % (operation, self.store.revision + 1), event)
                    self.store._bind_publication_grant(_DEDICATED_AUTHORITY,
                                                       request.grant_id, appended)
                    return result
                except BaseException as exc:
                    if started:
                        self._prohibit_started_operation(
                            "publication-authority-failure" if isinstance(exc, StoreError)
                            else "publication-mutation-failure")
                    raise
        except StoreError:
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
        self.session = replace(self.session, execution_live=False)
        self.store.register_session(self.session)

    def activate_next_boot(self, activation):
        if not isinstance(activation, BootActivation) or self.boot_state != "BOOT_HANDOFF_PENDING":
            raise AuthorizationDenied("fresh boot activation required")
        expected = self.current_boot_ordinal + 1
        if (activation.boot_ordinal != expected or
                activation.authorization_digest != self.authorization.authorization_digest or
                activation.predecessor_closure_digest != self.predecessor_closure_digest or
                activation.activation_id in self.activation_ids):
            raise AuthorizationDenied("wrong or replayed boot activation")
        if self.store.taint or self.store.execution_revoked:
            raise AuthorizationDenied("tainted campaign")
        if activation.observed_boot_id in self._observed_boot_ids:
            raise AuthorizationDenied("observed boot ID was already used")
        # Boot activation re-checks the full closure evidence that makes the
        # predecessor BOOT_COMPLETE authoritative; the label alone is not proof.
        closure = self._validate_boot_closure(self.current_boot_ordinal)
        if (closure != activation.predecessor_closure_digest or
                self.store.validated_boot_closure(self.current_boot_ordinal) != closure):
            raise AuthorizationDenied("boot activation predecessor closure evidence")
        fresh_epoch = self.store.acquire_fence(self.session.owner_identity)
        fresh_session = FenceSession(fresh_epoch,
                                     "session-boot-%d" % expected,
                                     self.session.owner_identity, expected, True)
        self.store.register_session(fresh_session)
        spec = {
            "effect_id": "boot-activation-" + activation.activation_id,
            "target": "offline-store", "operation": "consume-boot-activation",
            "event_id": "event-boot-activation-" + activation.activation_id,
            "event": {"record_type": "BOOT_ACTIVATION", "activation_id": activation.activation_id,
                      "activated_boot_ordinal": expected,
                      "observed_boot_id": activation.observed_boot_id,
                      "predecessor_closure_digest": activation.predecessor_closure_digest},
        }
        authorize_and_dispatch(
            self.store, self.verifier, self.store.revision, fresh_session.fence_epoch,
            fresh_session, "BOOT_HANDOFF_PENDING", spec,
            lambda capability, binding: None, _authority=_DEDICATED_AUTHORITY,
        )
        self.store.consume("boot_activation", activation.activation_id)
        self.activation_ids.add(activation.activation_id)
        self.current_boot_ordinal = expected
        self.current_boot_id = activation.observed_boot_id
        self._boot_ids[expected] = activation.observed_boot_id
        self._observed_boot_ids.add(activation.observed_boot_id)
        self.session = fresh_session
        self.boot_state = None
        self.attempt_state = None
        self._custody = None
