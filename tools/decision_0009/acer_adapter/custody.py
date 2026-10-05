"""Offline custodian model for Decision 0009.

The classes here simulate ownership and failure semantics.  They never create a
real process, send a signal, touch a cgroup, or call a host/vendor API.
"""

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import threading
import uuid
import copy
from contextlib import contextmanager, nullcontext

from .contracts import (
    ArtifactBinding, CustodianReceipt, CustodyError, EffectCapability,
    ProcessIdentity, ReapReceipt, SpawnToken,
    ImmutableObjectReference, parse_effect_port_receipt, ContractError,
    closed_canonical_bytes, parse_closed_canonical, survivor_digest,
    validate_survivor_descriptor, validate_survivor_trigger, _closed_dataclass_record,
)


class ContainmentUnavailable(CustodyError):
    pass


@dataclass(frozen=True)
class ContainmentEvidence:
    evidence_id: str
    actor_identity: str
    spawn_token: str
    action: str
    target_pid: int
    target_start_ticks: int
    custody_uncertain: bool


@dataclass(frozen=True)
class SurvivorTransfer:
    transfer_id: str
    source_custodian: str
    survivor_identity: str
    spawn_token: str
    process_identity: ProcessIdentity
    authority_digest: str
    fence_epoch: int
    session_id: str
    artifact_binding: ArtifactBinding
    recovery_capability_digest: str


@dataclass(frozen=True)
class BootCustodyAttestation:
    """Custodian-issued boot custody evidence.

    It names the live custodian bound to the authoritative store, that
    custodian's ready watchdog, and a separately identified isolated observer,
    and it is bound to the exact store, authorization, campaign, boot, supervisor
    generation, session, and fence.  The custodian registry retains it, so the
    custody-state boundary and reconstruction can re-check it.
    """
    attestation_id: str
    custodian_id: str
    watchdog_id: str
    observer_id: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    boot_id: str
    boot_ordinal: int
    supervisor_generation: int
    session_id: str
    fence_epoch: int
    custody_proof_digest: str
    observer_isolated: bool
    watchdog_ready: bool

    def record(self):
        return asdict(self)


@dataclass(frozen=True)
class QuiescenceAcknowledgement:
    acknowledgement_id: str
    custodian_id: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    generation: int
    incarnation_id: str
    session_id: str
    fence: int
    predecessor_ordinal: int
    predecessor_boot_id: str
    next_ordinal: int
    handoff_digest: str
    closure_digest: str
    publication_digest: str
    bundle_digest: str


@dataclass(frozen=True)
class LowerFenceAcknowledgement:
    acknowledgement_id: str
    custodian_id: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    generation: int
    incarnation_id: str
    fence: int
    revoked_fences: tuple


@dataclass
class _Worker:
    token: SpawnToken
    identity: ProcessIdentity
    status: str = "BLOCKED"
    possibly_live: bool = True
    released: bool = False
    contained: bool = False
    reaped: bool = False
    receipt: CustodianReceipt = None
    reap_receipt: ReapReceipt = None
    # Actual target-side C retention; loss cannot authorize a replacement port.
    _domain_handle: object = None
    _domain_ever_bound: bool = False


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OfflineCustodian:
    """Independent-lifetime fake with a durable token registry."""

    def __init__(self, identity, *, containment_factory=None):
        if type(identity) is not str or not identity:
            raise CustodyError("custodian identity")
        self.identity = identity
        self._registry = {}
        self._create_counts = {}
        self._lock = threading.Lock()
        self.alive = True
        self.current_store_revision = 0
        self.first_create_observed_store_revision = None
        self._store = None
        self._loss_callback = None
        self._boot_custody = {}
        self._quiescence = {}
        self._fence_acknowledgements = {}
        self._revoked_through = 0
        self._transfers = {}
        self._creation_receipts = {}
        self._creation_bindings = {}
        self._publication_receipts = {}
        self._publication_counts = {}
        self._control_receipts = {}
        self._control_counts = {}
        self._effect_port_receipts = {}
        self._loss_evidence = ()
        self._containment_factory = containment_factory
        if containment_factory is not None:
            containment_factory._bind_source(self)

    def attest_quiescence(self, actor, predecessor_ordinal, predecessor_boot_id,
                          next_ordinal, handoff_digest, closure_digest,
                          publication_digest, bundle_digest):
        with self._lock:
            self._ensure_live()
            self._store.require_actor(actor, 'SHUTDOWN')
            if any(w.possibly_live or not w.reaped for w in self._registry.values()):
                raise CustodyError('independent ownership registry is not quiescent')
            if self._store.open_execution_effects():
                raise CustodyError('pending effect obligation prevents shutdown')
            ack = QuiescenceAcknowledgement('quiescence-' + actor.incarnation_id,
                self.identity, actor.store_identity, actor.authorization_digest, actor.campaign_id,
                actor.generation, actor.incarnation_id, actor.session_id, actor.fence,
                predecessor_ordinal, predecessor_boot_id, next_ordinal, handoff_digest,
                closure_digest, publication_digest, bundle_digest)
            self._quiescence[ack.acknowledgement_id] = ack
            self._revoked_through = max(self._revoked_through, actor.fence)
            return ack

    def validate_quiescence(self, raw):
        try:
            record = QuiescenceAcknowledgement(**json.loads(raw))
        except (TypeError, ValueError) as exc:
            raise CustodyError('closed quiescence acknowledgement') from exc
        if self._quiescence.get(record.acknowledgement_id) != record:
            raise CustodyError('quiescence acknowledgement lacks independent provenance')
        return record

    def revoke_all_lower_fences(self, actor):
        with self._lock:
            self._ensure_live()
            self._store.require_actor(actor, 'ADMIT')
            if any(w.possibly_live or not w.reaped for w in self._registry.values()):
                raise CustodyError('lower-fence ownership is not quiescent')
            self._revoked_through = max(self._revoked_through, actor.fence - 1)
            ack = LowerFenceAcknowledgement('lower-fences-' + actor.incarnation_id,
                self.identity, actor.store_identity, actor.authorization_digest, actor.campaign_id,
                actor.generation, actor.incarnation_id, actor.fence, tuple(range(1, actor.fence)))
            self._fence_acknowledgements[ack.acknowledgement_id] = ack
            return ack

    def validate_lower_fences(self, raw, actor):
        try:
            value = json.loads(raw)
            value['revoked_fences'] = tuple(value['revoked_fences'])
            ack = LowerFenceAcknowledgement(**value)
        except (TypeError, ValueError, KeyError) as exc:
            raise CustodyError('closed lower-fence acknowledgement') from exc
        if (self._fence_acknowledgements.get(ack.acknowledgement_id) != ack or
                ack.store_identity != actor.store_identity or ack.authorization_digest != actor.authorization_digest or
                ack.campaign_id != actor.campaign_id or ack.generation != actor.generation or
                ack.incarnation_id != actor.incarnation_id or ack.fence != actor.fence or
                ack.revoked_fences != tuple(range(1, actor.fence)) or self._revoked_through < actor.fence - 1):
            raise CustodyError('all-lower-fence revocation proof mismatch')
        return ack

    @property
    def watchdog_identity(self):
        return self.identity + "/watchdog"

    def bind_authority(self, store, loss_callback):
        if store is None or not callable(loss_callback):
            raise CustodyError("custodian authority binding")
        if self._store is not None and self._store is not store:
            raise CustodyError("custodian authority already bound")
        bind_custodian = getattr(store, "bind_custodian", None)
        if callable(bind_custodian):
            try:
                bind_custodian(self)
            except Exception as exc:
                raise CustodyError("store is bound to another custodian") from exc
        self._store = store
        self._loss_callback = loss_callback

    def attest_boot_custody(self, *, store_identity, authorization_digest, campaign_id,
                            boot_id, boot_ordinal, supervisor_generation, session_id,
                            fence_epoch, observer_id, custody_proof, observer_isolated,
                            watchdog_ready):
        """Issue and retain boot custody evidence for the bound store."""
        if self._store is None or getattr(self._store, "identity", None) != store_identity:
            raise CustodyError("custody attestation requires the bound authoritative store")
        self._ensure_live()
        if self._store._authentication_service is not None:
            actor = self._store.require_actor(self._store._current_actor)
            if (supervisor_generation != actor.generation or session_id != actor.session_id or
                    fence_epoch != actor.fence or authorization_digest != actor.authorization_digest or
                    campaign_id != actor.campaign_id):
                raise CustodyError('custody attestation requires independently current identity')
        if observer_isolated is not True or watchdog_ready is not True:
            raise CustodyError("custody readiness")
        for value in (store_identity, authorization_digest, campaign_id, boot_id,
                      session_id, observer_id, custody_proof):
            if type(value) is not str or not value:
                raise CustodyError("custody attestation identity")
        for value in (boot_ordinal, supervisor_generation, fence_epoch):
            if type(value) is not int or value < 1:
                raise CustodyError("custody attestation identity")
        if observer_id in (self.identity, self.watchdog_identity):
            raise CustodyError("observer is not isolated from custody")
        fields = {
            "custodian_id": self.identity, "watchdog_id": self.watchdog_identity,
            "observer_id": observer_id, "store_identity": store_identity,
            "authorization_digest": authorization_digest, "campaign_id": campaign_id,
            "boot_id": boot_id, "boot_ordinal": boot_ordinal,
            "supervisor_generation": supervisor_generation, "session_id": session_id,
            "fence_epoch": fence_epoch, "custody_proof_digest": _digest(custody_proof),
            "observer_isolated": True, "watchdog_ready": True,
        }
        attestation_id = "boot-custody-" + _digest(
            json.dumps(fields, sort_keys=True, separators=(",", ":")))[:24]
        attestation = BootCustodyAttestation(attestation_id=attestation_id, **fields)
        with self._lock:
            existing = self._boot_custody.get(attestation_id)
            if existing is not None and existing != attestation:
                raise CustodyError("custody attestation collision")
            self._boot_custody[attestation_id] = attestation
        return attestation

    def boot_custody_attestation(self, attestation_id):
        return self._boot_custody.get(attestation_id)

    def observe_store_revision(self, revision):
        if type(revision) is not int or revision < 0:
            raise CustodyError("store revision")
        self.current_store_revision = revision

    def _ensure_live(self):
        if self._containment_factory is not None:
            self._containment_factory._require_original_source_lifetime(self)
        if not self.alive:
            raise ContainmentUnavailable("custodian ownership is unavailable")

    def create_once(self, token, launch_spec_digest, consumed_capability_receipt,
                    artifact_binding, fault=None):
        if self._store is None:
            raise CustodyError("authoritative durable store binding required")
        if not isinstance(token, SpawnToken) or token.custodian_id != self.identity:
            raise CustodyError("spawn token custodian")
        if not isinstance(consumed_capability_receipt, EffectCapability):
            raise CustodyError("consumed capability receipt")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("fresh artifact binding required")
        if (not consumed_capability_receipt.consumed or
                consumed_capability_receipt.target != self.identity or
                consumed_capability_receipt.operation != "blocked-create" or
                consumed_capability_receipt.artifact_binding != artifact_binding or
                consumed_capability_receipt.fence_epoch != artifact_binding.fence_epoch or
                consumed_capability_receipt.session_id != artifact_binding.session_id or
                consumed_capability_receipt.supervisor_generation !=
                token.supervisor_generation):
            raise CustodyError("capability is not bound to this durable create")
        self._ensure_live()
        with self._store.authorization_lock:
            if consumed_capability_receipt.fence_epoch <= self._revoked_through:
                raise CustodyError('custodian independently revoked this execution fence')
            try:
                intent = self._store.effect_intent(consumed_capability_receipt)
            except Exception as exc:
                raise CustodyError("healthy witnessed effect intent required") from exc
            if (intent.get("state") != "SPAWN_INTENT_PERSISTED" or
                    intent.get("spawn_token") != token.token_id or
                    intent.get("campaign_id") != token.campaign_id or
                    intent.get("boot_id") != token.boot_id or
                    intent.get("slot_id") != token.slot_id or
                    intent.get("attempt_id") != token.attempt_id or
                    intent.get("custodian_id") != token.custodian_id or
                    intent.get("launch_spec_digest") != token.launch_spec_digest or
                    intent.get("launch_spec_digest") != launch_spec_digest or
                    intent.get("session_id") != consumed_capability_receipt.session_id or
                    intent.get("fence_epoch") != consumed_capability_receipt.fence_epoch or
                    intent.get("supervisor_generation") != token.supervisor_generation or
                    intent.get("authorization_digest") !=
                    consumed_capability_receipt.authorization_digest):
                raise CustodyError("durable spawn intent does not bind complete token identity")
            # The successor invariant is enforced here, at the authoritative
            # mutation boundary: a store-backed slot capability reserved for exactly
            # this effect (slot, attempt, boot, campaign, predecessor, generation,
            # token, launch spec, custodian) must exist.  A label is never enough.
            try:
                self._store.creation_slot_grant(consumed_capability_receipt, token)
            except Exception as exc:
                raise CustodyError("reserved store slot capability required") from exc
            status = self._store.effect_status(consumed_capability_receipt)
            if status == "KNOWN_RESULT":
                envelope = self._store.effect_result(
                    consumed_capability_receipt.effect_id)
                existing = self._registry.get(token.token_id)
                if (existing is None or existing.token != token or
                        self._creation_receipts.get(token.token_id) != envelope.receipt):
                    raise CustodyError("known result lacks exact custodian registry evidence")
                return envelope.receipt
            if status in ("UNRESOLVED", "ACCEPTANCE_PENDING"):
                raise CustodyError("unresolved effect cannot create")
            if not self._store.creation_grant_active(consumed_capability_receipt):
                raise CustodyError("active first-dispatch creation grant required")
            if launch_spec_digest != token.launch_spec_digest:
                raise CustodyError("launch specification mismatch")
            with self._lock:
                existing = self._registry.get(token.token_id)
                if existing is not None:
                    raise CustodyError("unregistered existing effect is ambiguous")
                try:
                    accepted = self._store.accept_effect(consumed_capability_receipt)
                except Exception as exc:
                    raise CustodyError("capability was not accepted by authoritative store") from exc
                if accepted != intent:
                    raise CustodyError("accepted effect intent changed")
                if fault == "crash_after_acceptance":
                    self._store.mark_effect_unresolved(consumed_capability_receipt)
                    raise CustodyError("accepted effect result is unresolved")
                initiation_actor = self._store.validate_initiation(consumed_capability_receipt)
                self._create_counts[token.token_id] = 1
                if self.first_create_observed_store_revision is None:
                    self.first_create_observed_store_revision = self.current_store_revision
                ordinal = len(self._registry) + 1
                pid = 10_000 + ordinal
                process = ProcessIdentity(
                    host_id="offline-host", boot_id=token.boot_id, host_pid=pid,
                    pid_namespace="offline-pidns", namespace_pid=1,
                    process_start_ticks=50_000 + ordinal,
                    executable_path="/offline/blocked-worker", executable_device=1,
                    executable_inode=100 + ordinal,
                    executable_digest=_digest("offline-worker"),
                    cgroup_path="/offline/workers/" + token.token_id,
                    cgroup_device=1, cgroup_inode=200 + ordinal,
                    cgroup_members=(pid,), custodian_id=self.identity,
                    spawn_token=token.token_id,
                    gpu_uuid="GPU-beba5a2f-9130-d279-5639-9ffda0d4e464", alive=True,
                )
                status = "UNKNOWN" if fault == "ambiguous_after_create" else "BLOCKED"
                receipt = CustodianReceipt(
                    receipt_id="create-" + token.token_id, custodian_id=self.identity,
                    spawn_token=token.token_id, launch_spec_digest=launch_spec_digest,
                    status=status, process_identity=process, possibly_live=True,
                )
                self._registry[token.token_id] = _Worker(token, process, status=status,
                                                          receipt=receipt)
                self._creation_receipts[token.token_id] = receipt
                self._creation_bindings[token.token_id] = artifact_binding
                try:
                    self._store.record_effect_result(consumed_capability_receipt,
                                                     receipt, actor=initiation_actor)
                except Exception:
                    self._store.mark_effect_unresolved(consumed_capability_receipt)
                    raise
                return receipt

    def validate_creation_result(self, capability, raw_bytes, verifier_id):
        """Compare exact original receipt bytes to independent C-domain history."""
        if verifier_id != self.identity or type(raw_bytes) is not bytes:
            raise CustodyError('independent result verifier identity')
        intent = self._store._durable[capability.transition_revision - 1]['event']
        worker = self._registry.get(intent.get('spawn_token'))
        if (worker is None or worker.token.supervisor_generation != capability.supervisor_generation or
                worker.token.launch_spec_digest != intent.get('launch_spec_digest')):
            raise CustodyError('exact independent creation history unavailable')
        original = self._creation_receipts.get(worker.token.token_id)
        if original is None:
            raise CustodyError('original immutable creation observation unavailable')
        expected = (json.dumps(asdict(original), sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
        if raw_bytes != expected:
            raise CustodyError('result differs from independently retained receipt')
        return original

    def original_creation_binding(self, spawn_token):
        """Independent C evidence permits containment during journal outages."""
        binding = self._creation_bindings.get(spawn_token)
        if spawn_token not in self._registry or binding is None:
            raise CustodyError('original creation binding unavailable')
        return binding

    def initiate_publication(self, actor, grant, planned, payload):
        """Independent offline effect port; never executes a real destination write."""
        self._ensure_live()
        with self._store.authorization_lock, self._lock:
            self._store.validate_publication_initiation(actor, grant, planned)
            acceptance = next(f for f in self._store._committed_frames() if
                f['event'].get('record_type') == 'EFFECT_ACCEPTED' and f['event'].get('effect_id') == grant.grant_id)
            if grant.grant_id in self._publication_counts:
                raise CustodyError('an initiated publication may only be queried')
            request = grant.binding
            event = request.record_fields()
            from .supervisor import _publication_frame_groups, _validate_publication_frames, _sha
            previous = _publication_frame_groups(self._store).get(
                (request.identity.destination, request.identity.object_key), [])
            events = (_validate_publication_frames(self._store, self._store._admitted_payload(),
                [f for _, f in previous], require_verified=False) if previous else [])
            operation = request.operation
            if operation == 'intent':
                request.identity.verify_source(payload)
                event.update(source_object_id=planned.get('source_object_id'), source_digest=_sha(payload))
            elif operation == 'create':
                event['reservation_id'] = 'reservation-' + request.grant_id
            elif operation == 'write':
                if type(payload) is not bytes:
                    raise CustodyError('exact publication bytes required')
                event.update(written_object_id=planned.get('written_object_id'), written_digest=_sha(payload),
                    written_length=len(payload), write_revision=planned.get('write_revision'))
            elif operation == 'durable':
                old = events[-1]
                self._store.read_object(old['written_object_id'], old['written_digest'])
                event.update(written_object_id=old['written_object_id'], written_digest=old['written_digest'],
                    write_revision=old['write_revision'], durability_ack_id='durable-' + request.grant_id)
            elif operation == 'verify':
                old = events[-1]
                raw = self._store.read_object(old['written_object_id'], old['written_digest'])
                request.identity.verify_source(raw)
                event.update(written_object_id=old['written_object_id'], written_digest=old['written_digest'],
                    write_revision=old['write_revision'], durability_ack_id=old['durability_ack_id'],
                    readback_digest=_sha(raw), verification_id='readback-' + request.grant_id)
            else:
                raise CustodyError('closed offline publication operation required')
            if event != planned:
                raise CustodyError('independently observed publication binding differs from request')
            # No counters or modeled object effects advance before this second
            # currentness check, immediately before independent initiation.
            self._store.validate_publication_initiation(actor, grant, planned)
            self._publication_counts[grant.grant_id] = 1
            if operation == 'intent':
                self._store.put_object(event['source_object_id'], payload, actor=actor)
            elif operation == 'write':
                self._store.put_object(event['written_object_id'], payload, actor=actor)
                event['write_revision'] = self._store.revision + 1
            raw = (json.dumps(event, sort_keys=True, separators=(',', ':'),
                              ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
            self._publication_receipts[grant.grant_id] = raw
            self._observe_effect_port(acceptance, request.identity.destination, raw)
            return event

    def _observe_effect_port(self, acceptance, target_id, observation):
        from .supervisor import _u04_canonical, _sha
        producer = json.loads(acceptance['envelope'].producer_bytes)
        effect_id = acceptance['event']['effect_id']
        record = {'effect_id': effect_id, 'acceptance_ref': self._store._reference(acceptance['receipt']),
            'target_id': target_id, 'original_generation': producer['generation'],
            'original_incarnation_id': producer['incarnation_id'], 'original_session_id': producer['session_id'],
            'original_fence': producer['fence'], 'result_object': {
                'object_id': 'port-observation-' + effect_id, 'sha256': _sha(observation), 'length': len(observation)}}
        record['port_attestation'] = _sha(_u04_canonical({'custodian_id': self.identity, 'receipt': record}))
        raw = _u04_canonical(record)
        parse_effect_port_receipt(raw)
        self._effect_port_receipts[effect_id] = raw

    def effect_port_receipt_bytes(self, effect_id):
        raw = self._effect_port_receipts.get(effect_id)
        if raw is None:
            raise CustodyError('independent complete effect port receipt unavailable')
        return raw

    def validate_effect_port_receipt(self, effect_id, raw, verifier_id):
        if verifier_id != self.identity or self._effect_port_receipts.get(effect_id) != raw:
            raise CustodyError('effect port receipt lacks independent original provenance')
        parsed = parse_effect_port_receipt(raw)
        if parsed.effect_id != effect_id:
            raise CustodyError('independent port receipt effect substitution')
        return parsed

    def port_observation_bytes(self, receipt):
        from .supervisor import _sha
        raw = (self._publication_receipts.get(receipt.effect_id) if receipt.effect_id in self._publication_counts
               else self._control_receipts.get(receipt.effect_id))
        if (raw is None or receipt.result_object != ImmutableObjectReference(
                'port-observation-' + receipt.effect_id, _sha(raw), len(raw))):
            raise CustodyError('independent port observation missing or substituted')
        return raw

    def publication_result_bytes(self, effect_id):
        raw = self._publication_receipts.get(effect_id)
        if raw is None:
            raise CustodyError('independent exact publication result unavailable')
        return raw

    def validate_publication_result(self, effect_id, raw, verifier_id):
        if (verifier_id != self.identity or type(raw) is not bytes or
                self._publication_counts.get(effect_id) != 1 or
                self._publication_receipts.get(effect_id) != raw):
            raise CustodyError('publication result lacks exact independent observation')
        return json.loads(raw)

    def confirms_publication_conflict(self, intended):
        """Only a completed independent receipt proves a stable byte conflict."""
        if type(intended) is not dict or intended.get('operation') != 'write':
            return False
        effect_id = intended.get('operation_id')
        raw = self._publication_receipts.get(effect_id)
        if raw is None or self._publication_counts.get(effect_id) != 1:
            return False
        observed = json.loads(raw)
        from .contracts import PublicationOperationBinding
        try:
            expected = PublicationOperationBinding.from_record(self._store.identity, intended)
            actual = PublicationOperationBinding.from_record(self._store.identity, observed)
        except Exception:
            return False
        return (expected == actual and (observed['written_digest'] != expected.identity.object_digest or
                                      observed['written_length'] != expected.identity.length))

    def initiate_control(self, capability, binding, dispatcher):
        """Observe one bounded offline callback after independent acceptance checks."""
        self._ensure_live()
        with self._store.authorization_lock, self._lock:
            return self._initiate_control_guarded(capability,binding,dispatcher)

    def _initiate_control_guarded(self,capability,binding,dispatcher):
        if (capability.artifact_binding != binding or capability.effect_id in self._control_counts or
                capability.operation == 'blocked-create' or capability.target not in (self._store.identity, 'offline-store')):
            raise CustodyError('exact fresh original control binding required before any port effect')
        if self._containment_factory is not None:
            self._containment_factory._original_control_port(self,capability,binding)
        with nullcontext():
            self._store.validate_initiation(capability)
            if (capability.operation == 'blocked-create' or capability.target not in (self._store.identity, 'offline-store') or
                    capability.artifact_binding != binding or capability.effect_id in self._control_counts):
                raise CustodyError('exact fresh offline control initiation required')
            self._store.validate_initiation(capability)
            acceptance = self._store._acceptance_frame(capability)
            self._control_counts[capability.effect_id] = 1
            value = dispatcher(capability, binding)
            from .supervisor import _u04_canonical
            raw = _u04_canonical({'effect_id': capability.effect_id,
                'operation': capability.operation, 'transition': binding.transition,
                'intent_event_id': capability.transition_event_id,
                'intent_digest': capability.transition_event_digest})
            self._control_receipts[capability.effect_id] = raw
            self._observe_effect_port(acceptance, capability.target, raw)
            return value

    def control_result_bytes(self, effect_id):
        raw = self._control_receipts.get(effect_id)
        if raw is None:
            raise CustodyError('independent original control observation unavailable')
        return raw

    def validate_control_result(self, capability, raw, verifier_id):
        if (verifier_id != self.identity or type(raw) is not bytes or
                self._control_counts.get(capability.effect_id) != 1 or
                self._control_receipts.get(capability.effect_id) != raw):
            raise CustodyError('control result lacks original independent observation')
        result = json.loads(raw)
        if (set(result) != {'effect_id', 'operation', 'transition', 'intent_event_id', 'intent_digest'} or
                result['effect_id'] != capability.effect_id or result['operation'] != capability.operation or
                result['transition'] != capability.artifact_binding.transition or
                result['intent_event_id'] != capability.transition_event_id or result['intent_digest'] != capability.transition_event_digest):
            raise CustodyError('independent result producer substitution')
        return result

    def inspect_spawn(self, spawn_token):
        if type(spawn_token) is not str:
            raise CustodyError("spawn token")
        worker = self._registry.get(spawn_token)
        if worker is None:
            return CustodianReceipt("inspect-absent-" + spawn_token, self.identity,
                                    spawn_token, _digest("absent"), "FAILED_NO_CHILD",
                                    None, False)
        return CustodianReceipt(
            "inspect-" + spawn_token, self.identity, spawn_token,
            worker.token.launch_spec_digest, worker.status, worker.identity,
            worker.possibly_live,
        )

    def establish_survivor_containment(self, spawn_token, actor, *, fault=None):
        if self._containment_factory is None:
            raise ContainmentUnavailable('trusted independent factory is unavailable')
        return self._containment_factory._establish(self, spawn_token, actor, fault=fault)

    def validate_recovery_supplement(self, parent, event, raw):
        if self._containment_factory is None:
            raise CustodyError('independent recovery evidence source unavailable')
        return self._containment_factory._validate_report(self, parent, event, raw)

    def observe_failure_envelope(self, parent_ref, failure_code, raw_object_refs=()):
        if self._containment_factory is None:
            raise CustodyError('independent bounded failure observer unavailable')
        return self._containment_factory._observe_failure_envelope(self,parent_ref,failure_code,raw_object_refs)

    def validate_containment_obligation(self, event):
        if self._containment_factory is None:
            raise CustodyError('independent containment operation unavailable')
        return self._containment_factory._validate_obligation(event)

    def contain_spawn(self, spawn_token, recovery_capability, artifact_binding):
        self._ensure_live()
        if type(recovery_capability) is not str or not recovery_capability:
            raise CustodyError("recovery capability")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("containment artifact binding")
        if self._containment_factory is not None:
            return self._containment_factory._contain_original(self, spawn_token, artifact_binding)
        with self._lock:
            worker = self._registry.get(spawn_token)
            if worker is None:
                raise ContainmentUnavailable("token-owned survivor unavailable")
            worker.contained = True
            worker.status = "EXITED"
            worker.possibly_live = False
            worker.identity = replace(worker.identity, alive=False)
            worker.receipt = CustodianReceipt(
                "contained-" + spawn_token, self.identity, spawn_token,
                worker.token.launch_spec_digest, "EXITED", worker.identity, False,
            )
            return ContainmentEvidence(
                "contain-" + spawn_token, self.identity, spawn_token, "CONTAIN",
                worker.identity.host_pid, worker.identity.process_start_ticks, False,
            )

    def watchdog_supervisor_lost(self, spawn_token, artifact_binding):
        return self.contain_spawn(spawn_token, "watchdog-containment", artifact_binding)

    def wait_reap(self, spawn_token):
        self._ensure_live()
        with self._lock:
            worker = self._registry.get(spawn_token)
            if worker is None or worker.status != "EXITED":
                raise CustodyError("actual exited child required before wait")
            if worker.reap_receipt is None:
                worker.reaped = True
                worker.status = "REAPED"
                worker.reap_receipt = ReapReceipt(
                    "reap-" + spawn_token, self.identity, spawn_token,
                    worker.identity.host_pid, worker.identity.process_start_ticks,
                    1, True,
                )
            if self._containment_factory is not None:
                self._containment_factory._retain_reap(self,worker.reap_receipt)
            return worker.reap_receipt

    def get_reap_receipt(self, spawn_token):
        worker = self._registry.get(spawn_token)
        return None if worker is None else worker.reap_receipt

    def validate_reap_receipt(self, receipt):
        if not isinstance(receipt, ReapReceipt):
            raise CustodyError("reap receipt type")
        worker = self._registry.get(receipt.spawn_token)
        if worker is None and self._containment_factory is not None:
            return self._containment_factory._validate_archived_reap(self,receipt)
        if (worker is None or worker.reap_receipt != receipt or
                receipt.custodian_id != self.identity or not worker.reaped):
            raise CustodyError("reap receipt does not match custodian registry")
        return True

    def export_survivor_ownership(self, spawn_token, survivor,
                                  recovery_capability="contain-capability"):
        if self._store is None:
            raise ContainmentUnavailable('original store binding unavailable')
        with self._store.authorization_lock:
            return self._export_survivor_ownership(spawn_token, survivor, recovery_capability)

    def _export_survivor_ownership(self, spawn_token, survivor, recovery_capability):
        self._ensure_live()
        worker = self._registry.get(spawn_token)
        if worker is None:
            raise ContainmentUnavailable("worker absent")
        if not isinstance(survivor, OfflineSurvivor) or not survivor.alive:
            raise ContainmentUnavailable("separate survivor unavailable")
        authority = _digest(survivor.authority)
        if self._store is None or type(recovery_capability) is not str or not recovery_capability:
            raise ContainmentUnavailable("authoritative survivor transfer unavailable")
        actor = self._store.require_actor(self._store._current_actor)
        session = actor.execution_session
        if session is None:
            raise ContainmentUnavailable('opaque current execution session required')
        self._store.actor_for_session(session)
        self._store.validate_artifact_continuity(survivor.artifact_binding)
        self._store.require_actor(actor)
        transfer = SurvivorTransfer(
            "transfer-" + spawn_token, self.identity, survivor.identity, spawn_token,
            worker.identity, authority, self._store.witness.current_fence,
            session.session_id, survivor.artifact_binding,
            _digest(recovery_capability),
        )
        artifact_digest = _digest(repr(transfer.artifact_binding))
        record = {"record_type": "SURVIVOR_TRANSFER", "transfer_id": transfer.transfer_id,
             "source_custodian": transfer.source_custodian,
             "survivor_identity": transfer.survivor_identity,
             "spawn_token": transfer.spawn_token,
             "host_pid": transfer.process_identity.host_pid,
             "process_start_ticks": transfer.process_identity.process_start_ticks,
             "authority_digest": transfer.authority_digest,
             "artifact_digest": artifact_digest,
             "recovery_capability_digest": transfer.recovery_capability_digest,
             "fence_epoch": transfer.fence_epoch, "session_id": transfer.session_id}
        self._transfers[transfer.transfer_id] = record
        if self._store._authentication_service is not None:
            actor = self._store.actor_for_session(session)
            self._store.record_original_diagnostic(actor, record)
        else:
            self._store.append_nonauthorizing(transfer.fence_epoch,
                "survivor-transfer-%s-%d" % (spawn_token, self._store.revision + 1), record)
        survivor.register_transfer(transfer, self._store)
        return transfer

    def validate_transfer_record(self, record):
        if self._transfers.get(record.get('transfer_id')) != record:
            raise CustodyError('survivor transfer lacks independent exact provenance')
        return True

    def die(self):
        guard=self._containment_factory.lock if self._containment_factory is not None else nullcontext()
        with guard:
            if not self.alive:return
            self._loss_evidence=tuple(sorted(self._boot_custody))
            self.alive=False
        if self._loss_callback is not None:
            if self._containment_factory is None:
                self._loss_callback('custodian-death')
            else:
                with guard: guard.defer(lambda:self._loss_callback('custodian-death'))

    def confirms_required_custody_loss(self, attestation_record):
        """Positive independent invalidation, never an unanswered observation."""
        if self._containment_factory is not None and self._containment_factory._confirms_required_loss(self,attestation_record):
            return True
        if self.alive or type(attestation_record) is not dict:
            return False
        attestation = self._boot_custody.get(attestation_record.get('attestation_id'))
        return (attestation is not None and attestation.attestation_id in self._loss_evidence and
                attestation.record() == attestation_record)

    def underlying_create_count(self, spawn_token):
        return self._create_counts.get(spawn_token, 0)

    def underlying_create_count_for_all(self):
        return sum(self._create_counts.values())


class OfflineSurvivor:
    """Separate fake actor; possession and authority are explicit."""

    def __init__(self, identity, authority, artifact_binding):
        if type(identity) is not str or type(authority) is not str:
            raise CustodyError("survivor identity/authority")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("survivor artifact binding")
        self.identity = identity
        self.authority = authority
        self.artifact_binding = artifact_binding
        self.alive = True
        self._acted = set()
        self._transfers = {}
        self._store = None

    def register_transfer(self, transfer, store):
        if not isinstance(transfer, SurvivorTransfer) or store is None:
            raise ContainmentUnavailable("authoritative transfer registration")
        self._store = store
        self._transfers[transfer.transfer_id] = transfer

    def contain_transferred(self, transfer, recovery_capability):
        raise ContainmentUnavailable('legacy survivor descriptors cannot create a live B gate')


@dataclass(frozen=True, eq=False)
class _SurvivorEndpoint:
    incarnation: tuple
    credential: object

    def __reduce__(self):
        raise TypeError('survivor endpoint is nonserializable')


@dataclass(frozen=True, eq=False)
class _ProtectedContainmentInvocation:
    factory: object
    entry: object
    endpoint: object
    trigger_id: object
    channel: object
    consume: object
    source: object
    binding: object

    def __reduce__(self):
        raise TypeError('protected containment invocation cannot escape its stack')


class _CustodyExclusion:
    """C exclusion with revoke-only nested loss and post-unlock propagation."""
    def __init__(self):
        self._mutex=threading.RLock()
        self._local=threading.local()
        self._deferred=[]

    def owned_by_current_thread(self):return getattr(self._local,'depth',0)>0
    def __enter__(self):
        self._mutex.acquire();self._local.depth=getattr(self._local,'depth',0)+1
        return self
    def defer(self,callback):
        if not self.owned_by_current_thread():raise CustodyError('C-owned deferred loss required')
        self._deferred.append(callback)
    def __exit__(self,*args):
        self._local.depth-=1
        callbacks=tuple(self._deferred) if self._local.depth==0 else ()
        if callbacks:self._deferred.clear()
        self._mutex.release()
        for callback in callbacks:callback()


class _TokenDomainPort:
    """Independently retained actual token-domain handle; never a PID lookup."""
    def __init__(self, worker, source):
        if worker._domain_ever_bound or worker._domain_handle is not None:
            raise ContainmentUnavailable('actual worker domain cannot be rebound')
        worker._domain_ever_bound = True
        worker._domain_handle = self
        self.lock = threading.RLock()
        self.worker = worker
        self.source = source
        self.original_identity = worker.identity
        self.domain_id = 'token-domain-' + worker.token.token_id
        self.sealed = False
        self.claim = None
        self.started = False
        self.initiations = 0
        self.teardowns = 0
        self.handle_live = True
        self.readable = True
        self._pending_invocation = None
        self.releases = 0
        self.delegation = None

    def target_valid(self):
        return (self.worker._domain_ever_bound and self.worker._domain_handle is self and
            self.handle_live and self.readable and self.worker.token.token_id ==
            self.original_identity.spawn_token and replace(self.worker.identity, alive=True) ==
            replace(self.original_identity, alive=True))

    def _initiate(self, actor_id, operation_id, *, invocation=None):
        if invocation is None or self._pending_invocation is not invocation:
            raise ContainmentUnavailable('unexported current protected port invocation required')
        if type(invocation) is not _ProtectedContainmentInvocation:
            raise ContainmentUnavailable('authenticated bounded native invocation required')
        invocation.factory._validate_native_invocation(self,invocation,actor_id,operation_id)
        if not self.target_valid() or self.started or self.claim != (actor_id, operation_id):
            raise ContainmentUnavailable('exact claimed non-reusable domain initiation required')
        self.started = True
        self.initiations += 1
        self.teardowns += 1
        self.worker.contained = True
        self.worker.status = 'IN_PROGRESS'

    def _observe_exit(self):
        if not self.started:raise ContainmentUnavailable('no initiated containment to observe')
        self.worker.status = 'EXITED'
        self.worker.possibly_live = False
        self.worker.identity = replace(self.worker.identity, alive=False)
        self.worker.receipt = CustodianReceipt('contained-' + self.worker.token.token_id,
            self.source.identity, self.worker.token.token_id, self.worker.token.launch_spec_digest,
            'EXITED', self.worker.identity, False)


class _IndependentTriggerArchive:
    """C verifier/archive, separate from supervisor, source, and live survivor."""
    def __init__(self, verifier_id, producer_channel):
        self.identity = verifier_id
        self.channel = producer_channel
        self.entries = {}
        self.duplicates = {}
        self.uses = {}
        self.available = True
        self.sequence = 0
        self.evidence_sequence = 0
        self.request_sequence = 0
        self.delegations = {}
        self.observations = {}
        self.validations = {}
        self.deliveries = []


class OfflineContainmentFactory:
    """Trusted bootstrap-only C service for accepted B's deterministic model.

    Public methods inspect or request exact original cleanup. No public method
    receives a survivor credential, submits loss evidence, or dispatches a trigger.
    Terminal transitions originate in the independent prebound lifecycle source.
    """
    ESTABLISH_STAGES = ('reserved', 'descriptor_persisted', 'delegation_committed',
        'handle_prepared', 'evidence_retained', 'exposed', 'acknowledged')

    def __init__(self, identity, artifact_verifier, lifecycle_port, *, reader_endpoint=None):
        if type(identity) is not str or not identity or lifecycle_port is None:
            raise CustodyError('trusted factory and lifecycle bindings required')
        self.identity = identity
        self.epoch = uuid.uuid4().hex
        self.lock = _CustodyExclusion()
        lifecycle_port.bind_authority_exclusion(self.lock)
        self._reader_endpoint = object() if reader_endpoint is None else reader_endpoint
        self._artifact_verifier = artifact_verifier
        self._lifecycle_port = lifecycle_port
        self._source = None
        self._source_binding = None
        self._observer_channel = object()
        self._cleanup_channel = object()
        self._verifier = _IndependentTriggerArchive(identity+':independent-verifier', self._observer_channel)
        self._entries = {}
        self._tokens = {}
        self._endpoints = {}
        self._domains = {}
        self._incarnation = 0
        self._lost_sources = set()
        self._lost_supervisors = set()
        self._lost_ownership = set()
        self._reap_history = {}
        self._diagnostic_history = {}
        self._fault = None
        self._admitted_authorization = artifact_verifier.authorization

    def _bind_source(self, source):
        with self.lock:
            if self._source is not None or source._store is not None:
                raise CustodyError('factory/source setup is one-shot before runtime')
            self._source = source
            self._source_binding = self._lifecycle_port.bind_lifetime(source)
            self._lifecycle_port.subscribe(source,self._source_binding,self._observer_channel,self._source_terminal_observed)

    def _require_original_source_lifetime(self,source):
        with self.lock:
            if (source is not self._source or source._containment_factory is not self or not source.alive or
                    source in self._lost_sources or self._lifecycle_port.read_event(source,self._source_binding) is not None):
                raise ContainmentUnavailable('exact continuously live original custody endpoint required')

    def _source_terminal_observed(self):
        with self.lock:
            try:event=self._lifecycle_port.read_event(self._source,self._source_binding)
            except RuntimeError:return
            if event is not None:
                self._lost_sources.add(self._source)
                self._source.die()

    @staticmethod
    def _incarnation_record(d):
        return [d['factory_identity'],d['factory_epoch'],d['survivor_incarnation_number']]

    @classmethod
    def _actor_id(cls,d):
        return '/survivor/' + survivor_digest('b-survivor-incarnation/v1', cls._incarnation_record(d))

    def _assert_artifact(self, binding):
        if self._admitted_authorization is None or self._artifact_verifier.authorization != self._admitted_authorization:
            raise ContainmentUnavailable('original admitted implementation binding unavailable')
        if binding.verifier_identity != self._artifact_verifier.identity or binding.authorization_digest != self._admitted_authorization.authorization_digest:
            raise ContainmentUnavailable('original implementation verifier substitution')
        self._artifact_verifier.assert_continuity(binding)

    def _original_current(self, source, actor):
        store=source._store
        if source is not self._source or source._containment_factory is not self or not source.alive or source in self._lost_sources:
            raise ContainmentUnavailable('original custody binding lost')
        if self._lifecycle_port.read_event(source,self._source_binding) is not None:
            raise ContainmentUnavailable('positive original custody terminal evidence')
        actor_binding=self._lifecycle_port.bind_lifetime(actor)
        if self._lifecycle_port.read_event(actor,actor_binding) is not None:
            raise ContainmentUnavailable('positive original controller terminal evidence')
        store.require_actor(actor,'HISTORY')
        if actor.mode != 'LIVE' or actor in self._lost_supervisors:
            raise ContainmentUnavailable('original live controller required')
        store.assert_healthy_authority()
        store.read_verified(0)
        return store

    def _establish(self, source, token_id, actor, *, fault=None):
        store=source._store
        if store is None: raise ContainmentUnavailable('bound original store required')
        with store.authorization_lock:
            self._original_current(source,actor)
            store.require_actor(actor)
            authorization=store._admitted_payload()
            if store._artifact_verifier is not self._artifact_verifier:
                raise ContainmentUnavailable('trusted pinned factory implementation required')
            self._admitted_authorization=authorization
            worker=source._registry.get(token_id)
            if worker is None or worker.token.supervisor_generation != actor.generation or not worker.possibly_live:
                raise ContainmentUnavailable('exact already-created live original worker required')
            acceptance=[f for f in store._committed_frames() if f['event'].get('record_type')=='EFFECT_ACCEPTED'
                and f['event'].get('effect_id')=='spawn-intent-'+worker.token.slot_id]
            if len(acceptance)!=1:raise ContainmentUnavailable('original creation acceptance required')
            result=store.effect_result(acceptance[0]['event']['effect_id'])
            result_frames=[f for f in store._committed_frames() if f['event'].get('record_type')=='EFFECT_RESULT'
                and f['event'].get('effect_id')==acceptance[0]['event']['effect_id']]
            if len(result_frames)!=1:raise ContainmentUnavailable('exact original creation result required')
            creation_object=result_frames[0]['event']['result']
            created=source._creation_receipts.get(token_id)
            if result.receipt != created or created.process_identity != worker.identity:
                raise ContainmentUnavailable('exact independent original creation provenance required')
            binding=source.original_creation_binding(token_id)
            self._assert_artifact(binding)
            with self.lock:
                prior_domain=self._domains.get(token_id)
                if token_id in self._tokens or prior_domain is not None and prior_domain.delegation is not None:
                    raise ContainmentUnavailable('delegation reservation cannot be reused')
                self._incarnation+=1
                n=self._incarnation
                delegation='delegation-'+survivor_digest('b-survivor-delegation/v1',[self.identity,self.epoch,n,token_id])
                endpoint=_SurvivorEndpoint((self.identity,self.epoch,n),object())
                domain=self._actual_domain(worker,source)
                domain.delegation=delegation
                entry={'descriptor':None,'descriptor_bytes':None,'stage':'reserved','endpoint':endpoint,
                    'exposed':False,'revoked':False,'closure':None,'operation':{'state':'READY','consume':None},
                    'domain':domain,'actor':actor,'source':source,'binding':binding,
                    'supervisor_binding':self._lifecycle_port.bind_lifetime(actor),'source_binding':self._source_binding,
                    'receipt':None,'receipt_bytes':None,'observations':{},'transfer_ref':None,
                    'survivor_binding':self._lifecycle_port.bind_lifetime(endpoint),
                    'ownership_subject':(source,token_id),
                    'ownership_binding':self._lifecycle_port.bind_lifetime((source,token_id))}
                self._tokens[token_id]=delegation;self._entries[delegation]=entry
                if fault=='reserved':raise ContainmentUnavailable('fault after permanent identity reservation')
                desc={'schema_version':'b-survivor-binding/v1','delegation_id':delegation,
                    'capability_id':survivor_digest('b-survivor-capability-id/v1',[self.identity,self.epoch,n]),
                    'store_identity':store.identity,'authorization_digest':actor.authorization_digest,
                    'campaign_id':actor.campaign_id,'source_custodian_id':source.identity,
                    'source_custodian_incarnation':self._source_binding[0],
                    'spawn_token':asdict(worker.token),'original_ownership_ref':store._reference(acceptance[0]['receipt']),
                    'original_creation_receipt':copy.deepcopy(creation_object),
                    'process_identity':asdict(worker.identity),'handle_domain_id':domain.domain_id,
                    'factory_identity':self.identity,'factory_epoch':self.epoch,'survivor_incarnation_number':n,
                    'original_generation':actor.generation,'original_incarnation_id':actor.incarnation_id,
                    'original_session_id':actor.session_id,'original_fence':actor.fence,
                    'artifact_binding':asdict(binding),'containment_port_id':self.identity+':token-domain-port',
                    'evidence_verifier_id':self._verifier.identity,'operation_id':'pending',
                    'action':'CONTAIN_TOKEN_DOMAIN','may_wait':False,'authorizes_execution':False}
                desc['operation_id']=survivor_digest('b-survivor-operation/v1', [delegation,
                    self._incarnation_record(desc),desc['spawn_token'],
                    survivor_digest('b-survivor-target/v1',desc['process_identity']),desc['action']])
                raw=closed_canonical_bytes(desc);desc=validate_survivor_descriptor(raw)
                entry['descriptor']=desc;entry['descriptor_bytes']=raw
            digest=survivor_digest('b-survivor-descriptor/v1',desc)
            obj_id='survivor-descriptor-'+digest
            store.put_object(obj_id,raw,actor=actor)
            if store.read_object(obj_id,_digest(raw.decode('utf-8'))) != raw:
                raise ContainmentUnavailable('descriptor exact readback required')
            entry['stage']='descriptor_persisted'
            if fault=='descriptor_persisted':raise ContainmentUnavailable('fault after descriptor persistence')
            record={'record_type':'SURVIVOR_TRANSFER','transfer_id':delegation,'source_custodian':source.identity,
                'survivor_identity':self._actor_id(desc),'spawn_token':token_id,'host_pid':worker.identity.host_pid,
                'process_start_ticks':worker.identity.process_start_ticks,'authority_digest':digest,
                'artifact_digest':_digest(repr(binding)),
                'recovery_capability_digest':survivor_digest('b-survivor-capability/v1',[digest,desc['capability_id']]),
                'fence_epoch':actor.fence,'session_id':actor.session_id}
            source._transfers[delegation]=copy.deepcopy(record)
            receipt=store.record_original_diagnostic(actor,record)
            frame=store._exact_ref(store._reference(receipt))
            status,checkpoint=store.witness.query_transaction(receipt.event_id)
            if status!='COMMITTED' or checkpoint.completion_mode!='ORIGIN' or not store.witness.acknowledged_current(actor,receipt.event_id):
                raise ContainmentUnavailable('original acknowledged delegation required')
            entry['transfer_ref']=store._reference(receipt);entry['stage']='delegation_committed'
            if fault=='delegation_committed':raise ContainmentUnavailable('fault after delegation commit')
            self._original_current(source,actor)
            with self.lock,domain.lock:
                self._assert_artifact(binding)
                if not domain.target_valid():raise ContainmentUnavailable('actual independent target handle required')
                self._lifecycle_port.subscribe(actor,entry['supervisor_binding'],self._observer_channel,
                    lambda:self._observe_loss(delegation,actor))
                self._lifecycle_port.subscribe(source,entry['source_binding'],self._observer_channel,
                    lambda:self._observe_loss(delegation,source))
                self._lifecycle_port.subscribe(endpoint,entry['survivor_binding'],self._observer_channel,
                    lambda:self._revoke_endpoint(entry))
                self._lifecycle_port.subscribe(entry['ownership_subject'],entry['ownership_binding'],self._observer_channel,
                    lambda:self._observe_loss(delegation,entry['ownership_subject']))
                entry['stage']='handle_prepared'
                if fault=='handle_prepared':raise ContainmentUnavailable('fault after handle preparation')
                # Independently owned immutable C copies, never references into V caches.
                closure={'descriptor_bytes':bytes(raw),'transfer_bytes':bytes(frame['bytes']),
                    'checkpoint':copy.deepcopy(checkpoint),'creation_bytes':bytes(store._object_proof(desc['original_creation_receipt'])),
                    'acceptance_bytes':bytes(acceptance[0]['bytes']),'registration':(entry['supervisor_binding'],entry['source_binding']),
                    'handle':domain,'endpoint':endpoint,'artifact':binding,
                    'boot_custody':tuple(a.record() for a in source._boot_custody.values() if a.boot_id==worker.token.boot_id)}
                entry['closure']=closure;entry['stage']='evidence_retained'
                self._verifier.delegations[delegation]={
                    'entry':entry,'endpoint':endpoint,'handle':domain,
                    'bytes':tuple(closure[k] for k in ('descriptor_bytes','transfer_bytes','creation_bytes','acceptance_bytes')),
                    'registration':closure['registration'],'boot_custody':closed_canonical_bytes(closure['boot_custody']),
                    'checkpoint':copy.deepcopy(checkpoint),'artifact':binding}
                if fault=='evidence_retained':raise ContainmentUnavailable('fault before authority exposure')
                self._original_current(source,actor)
                store.require_actor(actor)
                if (self._lifecycle_port.read_event(actor,entry['supervisor_binding']) is not None or
                        self._lifecycle_port.read_event(source,entry['source_binding']) is not None or
                        self._lifecycle_port.read_event(endpoint,entry['survivor_binding']) is not None or entry['revoked']):
                    raise ContainmentUnavailable('loss before exposure cannot be recovered')
                self._assert_artifact(binding)
                if not domain.target_valid():raise ContainmentUnavailable('handle lost before exposure')
                self._original_current(source,actor);store.require_actor(actor)
                if (self._lifecycle_port.read_event(entry['ownership_subject'],entry['ownership_binding']) is not None or
                        entry['revoked'] or self._lifecycle_port.read_event(endpoint,entry['survivor_binding']) is not None or
                        self._lifecycle_port.read_event(actor,entry['supervisor_binding']) is not None or
                        self._lifecycle_port.read_event(source,entry['source_binding']) is not None):
                    raise ContainmentUnavailable('lifetime loss won before exposure')
                entry['exposed']=True;self._endpoints[endpoint]=entry
                entry['stage']='exposed'
                if fault=='exposed':raise ContainmentUnavailable('exposure acknowledgement lost')
                entry['stage']='acknowledged'
            if fault=='acknowledged':raise ContainmentUnavailable('establishment response lost')
            return copy.deepcopy(desc)

    def _revoke_endpoint(self,entry):
        with self.lock,entry['domain'].lock:
            if self._lifecycle_port.read_event(entry['endpoint'],entry['survivor_binding']) is not None:
                entry['revoked']=True
                self._endpoints.pop(entry['endpoint'],None)

    def _live_guard(self, entry, endpoint):
        d=entry['descriptor'];closure=entry['closure'];domain=entry['domain']
        if (self._source._containment_factory is not self or not entry['exposed'] or entry['revoked'] or self._endpoints.get(endpoint) is not entry or
                entry['endpoint'] is not endpoint or closure is None or closure['endpoint'] is not endpoint or
                closure['handle'] is not domain or closure['descriptor_bytes']!=entry['descriptor_bytes'] or
                closed_canonical_bytes(d)!=entry['descriptor_bytes'] or
                closure['checkpoint'].completion_mode!='ORIGIN' or not self._verifier.available or
                not domain.target_valid()):
            raise ContainmentUnavailable('exact continuously live survivor and independent closure required')
        proof=self._verifier.delegations.get(d['delegation_id'])
        if (proof is None or proof['entry'] is not entry or proof['endpoint'] is not endpoint or
                proof['handle'] is not domain or domain.delegation!=d['delegation_id'] or
                self._domains.get(d['spawn_token']['token_id']) is not domain or
                proof['bytes']!=tuple(closure[k] for k in ('descriptor_bytes','transfer_bytes','creation_bytes','acceptance_bytes')) or
                proof['checkpoint']!=closure['checkpoint'] or proof['artifact']!=closure['artifact'] or
                proof['registration']!=closure['registration'] or
                proof['boot_custody']!=closed_canonical_bytes(closure['boot_custody'])):
            raise ContainmentUnavailable('complete independent retained delegation proof required')
        self._assert_artifact(entry['binding'])
        # Trusted continuity checks may observe revoke-only lifetime loss. Repeat
        # actual endpoint/target checks after that observation, under C/port.
        if (not self._artifact_verifier.root_binding_live or entry['revoked'] or
                self._endpoints.get(endpoint) is not entry or not domain.target_valid() or
                self._lifecycle_port.read_event(endpoint,entry['survivor_binding']) is not None):
            raise ContainmentUnavailable('survivor loss won before physical initiation')
        return d,domain

    def _observe_loss(self, delegation, subject):
        entry=self._entries.get(delegation)
        if entry is None or entry['descriptor'] is None:return
        with self.lock:
            source=entry['source'];actor=entry['actor']
            binding=entry['supervisor_binding'] if subject is actor else entry['ownership_binding'] if subject==entry['ownership_subject'] else entry['source_binding']
            try:event=self._lifecycle_port.read_event(subject,binding)
            except RuntimeError:return
            if event is None or subject not in (source,actor,entry['ownership_subject']):return
            if subject is actor:
                self._lost_supervisors.add(actor);kind='SUPERVISOR_TERMINAL'
                facts=dict(event,original_generation=actor.generation,original_incarnation_id=actor.incarnation_id,
                    original_session_id=actor.session_id,original_fence=actor.fence)
            elif subject==entry['ownership_subject']:
                self._lost_ownership.add(subject);kind='REQUIRED_OWNERSHIP_INVALIDATED'
                facts=dict(event,source_custodian_id=source.identity,
                    source_custodian_incarnation=entry['descriptor']['source_custodian_incarnation'],
                    original_ownership_ref=entry['descriptor']['original_ownership_ref'])
            else:
                self._lost_sources.add(source);kind='CUSTODIAN_TERMINAL'
                facts=dict(event,source_custodian_id=source.identity,
                    source_custodian_incarnation=entry['descriptor']['source_custodian_incarnation'],
                    original_ownership_ref=entry['descriptor']['original_ownership_ref'])
            trigger=self._retain_trigger(entry,kind,facts,self._observer_channel)
            if trigger is not None:
                try: entry['last_delivery_status']=self._deliver(entry,trigger,self._observer_channel,entry['endpoint'])
                except (ContractError,RuntimeError):entry['last_delivery_status']='AUTHORITY_UNAVAILABLE'
        # Queue propagation under C and run it only after the outermost C/port
        # exclusions release, including same-thread revoke-only fault callbacks.
        with self.lock:
            self.lock.defer(lambda:self._propagate_observed_loss(entry,subject))

    def _propagate_observed_loss(self,entry,subject):
        source=entry['source'];actor=entry['actor']
        if subject is source:source.die()
        elif subject==entry['ownership_subject']:
            if source._loss_callback is not None:source._loss_callback('required-ownership-invalidated')
        elif source._store._current_actor is actor:
            try:source._store.crash()
            except RuntimeError:pass

    def _retain_trigger(self,entry,kind,facts,channel):
        archive=self._verifier;d=entry['descriptor']
        if not archive.available or (channel is not self._observer_channel and channel is not self._cleanup_channel):return None
        key=(d['operation_id'],kind,closed_canonical_bytes(facts))
        previous=archive.duplicates.get(key)
        if previous is not None:return previous
        archive.sequence+=1;n=archive.sequence
        archive.evidence_sequence+=1;en=archive.evidence_sequence
        producer=self._incarnation_record(d)+['ORIGINAL_CLEANUP_BOUNDARY' if kind=='ORIGINAL_CLEANUP_REQUEST' else 'LIFECYCLE_OBSERVER']
        evidence={'schema_version':'b-survivor-trigger-evidence/v1',
            'evidence_id':survivor_digest('b-survivor-evidence-id/v1',[producer,self.epoch,en]),
            'evidence_sequence':en,'producer_id':producer,'producer_epoch':self.epoch,'observer_id':producer,
            'verifier_id':archive.identity,'descriptor_digest':survivor_digest('b-survivor-descriptor/v1',d),
            'operation_id':d['operation_id'],'event_kind':kind,'facts':copy.deepcopy(facts),'authorizes_execution':False}
        trigger={k:copy.deepcopy(d[k]) for k in ('store_identity','campaign_id','authorization_digest','spawn_token',
            'delegation_id','operation_id','source_custodian_id','source_custodian_incarnation',
            'original_generation','original_incarnation_id','original_session_id','original_fence')}
        trigger.update(schema_version='b-survivor-trigger/v1',trigger_id=survivor_digest('b-survivor-trigger-id/v1',[producer,self.epoch,n]),
            trigger_type={'SUPERVISOR_TERMINAL':'SUPERVISOR_LOSS','CUSTODIAN_TERMINAL':'CUSTODIAN_LOSS',
                'REQUIRED_OWNERSHIP_INVALIDATED':'CUSTODIAN_LOSS','ORIGINAL_CLEANUP_REQUEST':'ORIGINAL_CLEANUP'}[kind],
            target_identity_digest=survivor_digest('b-survivor-target/v1',d['process_identity']),
            descriptor_digest=evidence['descriptor_digest'],survivor_incarnation=self._incarnation_record(d),
            producer_id=producer,producer_epoch=self.epoch,trigger_sequence=n,observer_id=producer,
            verifier_id=archive.identity,evidence_id=evidence['evidence_id'],evidence_sequence=en,
            evidence_digest=survivor_digest('b-survivor-trigger-evidence/v1',evidence),authorizes_execution=False)
        tr,er=closed_canonical_bytes(trigger),closed_canonical_bytes(evidence)
        validate_survivor_trigger(tr,er,entry['descriptor_bytes'])
        archive.entries[trigger['trigger_id']]={'trigger':tr,'evidence':er,'entry':entry,'channel':channel,'facts':copy.deepcopy(facts)}
        archive.duplicates[key]=trigger['trigger_id']
        return trigger['trigger_id']

    def _validate_trigger(self,entry,trigger_id,channel):
        archive=self._verifier
        if not archive.available:raise ContainmentUnavailable('trigger provenance unavailable')
        item=archive.entries.get(trigger_id)
        if item is None or item['entry'] is not entry or item['channel'] is not channel:
            raise ContainmentUnavailable('registered producer and independently retained trigger required')
        t,e=validate_survivor_trigger(item['trigger'],item['evidence'],entry['descriptor_bytes'])
        if t['trigger_type']=='ORIGINAL_CLEANUP':
            self._validate_cleanup(entry,item['facts'])
        else:
            subject=entry['actor'] if t['trigger_type']=='SUPERVISOR_LOSS' else entry['ownership_subject'] if e['event_kind']=='REQUIRED_OWNERSHIP_INVALIDATED' else entry['source']
            binding=entry['supervisor_binding'] if subject is entry['actor'] else entry['ownership_binding'] if subject==entry['ownership_subject'] else entry['source_binding']
            actual=self._lifecycle_port.read_event(subject,binding)
            if actual is None or any(item['facts'].get(k)!=v for k,v in actual.items()):
                raise ContainmentUnavailable('exact independent positive lifecycle event required')
        archive.validations.setdefault(trigger_id,(item['trigger'],item['evidence'],channel))
        return t,item

    def _deliver(self,entry,trigger_id,channel,endpoint):
        with self.lock:
            before=copy.deepcopy(entry.get('operation'))
            try:
                status=self._deliver_guarded(entry,trigger_id,channel,endpoint)
            except (ContractError,RuntimeError):
                status='TRIGGER_REJECTED'
                raise
            finally:
                self._verifier.deliveries.append((trigger_id,before,copy.deepcopy(entry.get('operation')),
                    locals().get('status','OUTCOME_UNKNOWN'),entry['domain'].initiations,entry['domain'].teardowns))
            return status

    def _deliver_guarded(self,entry,trigger_id,channel,endpoint):
        with self.lock,entry['domain'].lock:
            t,item=self._validate_trigger(entry,trigger_id,channel)
            if t['trigger_type']=='ORIGINAL_CLEANUP':self._original_current(entry['source'],entry['actor'])
            d,domain=self._live_guard(entry,endpoint)
            op=entry.get('operation')
            if (op is None or not domain.readable or op['state']=='READY' and
                    (domain.started and domain.claim is None or
                     domain.claim is not None and domain.claim[0]!=entry['source'].identity or
                     any(use[2]==d['operation_id'] for use in self._verifier.uses.values()))):
                entry['operation']=None
                return 'OUTCOME_UNKNOWN'
            if op['state']=='RESULT_AVAILABLE':return 'EXISTING_RESULT'
            if op['state']!='READY':return 'ALREADY_CLAIMED' if op['state']=='CLAIMED' else 'OUTCOME_UNKNOWN'
            if trigger_id in self._verifier.uses:return 'OUTCOME_UNKNOWN'
            if self._fault in ('before_prepare','before_commit','before_claim'):return 'VALIDATED_NOT_CLAIMED'
            if self._fault=='prepare_ambiguous':
                entry['operation']=None;domain.sealed=True;domain.claim=(self._actor_id(d),d['operation_id'])
                return 'OUTCOME_UNKNOWN'
            if entry['revoked'] or self._endpoints.get(endpoint) is not entry or not domain.target_valid():
                raise ContainmentUnavailable('current gate and target required at atomic claim')
            consume=(trigger_id,survivor_digest('b-survivor-trigger-bytes/v1',t),d['operation_id'],tuple(self._incarnation_record(d)))
            # One atomic publication; no committed consumed-but-READY state.
            entry['operation']={'state':'CLAIMED','consume':consume}
            self._verifier.uses[trigger_id]=consume
            domain.sealed=True
            if domain.claim is not None:
                entry['operation']['joined_source']=domain.claim
                if domain.started:
                    original=self._verifier.observations.get((domain.worker.receipt or CustodianReceipt(
                        'missing',entry['source'].identity,d['spawn_token']['token_id'],d['spawn_token']['launch_spec_digest'],
                        'UNKNOWN',domain.worker.identity,True)).receipt_id)
                    if original is not None and original.get('original_source'):
                        entry['receipt_bytes']=original['bytes'];entry['receipt']=parse_closed_canonical(original['bytes'])
                        entry['operation']['state']='RESULT_AVAILABLE'
                    else:self._observe_result(entry,domain.claim[0])
                return 'ALREADY_CLAIMED'
            domain.claim=(self._actor_id(d),d['operation_id'])
            if self._fault in ('after_claim','after_commit','before_initiation'):return 'ALREADY_CLAIMED'
            self._live_guard(entry,endpoint)
            self._validate_trigger(entry,trigger_id,channel)
            if t['trigger_type']=='ORIGINAL_CLEANUP':self._original_current(entry['source'],entry['actor'])
            self._live_guard(entry,endpoint)
            # Only this protected invocation may initiate its newly claimed operation.
            if not domain.worker.possibly_live:
                self._observe_result(entry,self._actor_id(d),observation_only=True)
                return 'EXISTING_RESULT'
            if self._verifier.uses.get(trigger_id)!=consume:
                raise ContainmentUnavailable('exact atomic consumption proof required at initiation')
            invocation=_ProtectedContainmentInvocation(self,entry,endpoint,trigger_id,channel,consume,None,entry['binding'])
            domain._pending_invocation=invocation
            try:domain._initiate(self._actor_id(d),d['operation_id'],invocation=invocation)
            finally:domain._pending_invocation=None
            entry['operation']['state']='STARTED'
            if self._fault=='after_initiation':
                self._observe_result(entry,self._actor_id(d),status_override='IN_PROGRESS')
                return 'OUTCOME_UNKNOWN'
            domain._observe_exit()
            self._observe_result(entry,self._actor_id(d))
            if self._fault=='result_before_response':return 'OUTCOME_UNKNOWN'
            return 'EXISTING_RESULT'

    def _validate_native_invocation(self,domain,invocation,actor_id,operation_id):
        if not self.lock.owned_by_current_thread() or self._domains.get(domain.worker.token.token_id) is not domain:
            raise ContainmentUnavailable('actual C-owned domain required at native port')
        if invocation.source is not None:
            source=invocation.source
            self._assert_original_containment(domain,invocation.binding)
            if (source is not self._source or source._containment_factory is not self or
                    not source.alive or source in self._lost_sources or
                    (source,domain.worker.token.token_id) in self._lost_ownership or
                    actor_id!=source.identity or operation_id!='original-containment-'+domain.worker.token.token_id):
                raise ContainmentUnavailable('current exact original containment endpoint required')
            return
        entry=invocation.entry
        if (entry is None or entry['domain'] is not domain or actor_id!=self._actor_id(entry['descriptor']) or
                operation_id!=entry['descriptor']['operation_id'] or
                (entry.get('operation') or {}).get('state')!='CLAIMED' or
                (entry.get('operation') or {}).get('consume')!=invocation.consume or
                self._verifier.uses.get(invocation.trigger_id)!=invocation.consume):
            raise ContainmentUnavailable('exact native authenticated consume/claim required')
        t,_=self._validate_trigger(entry,invocation.trigger_id,invocation.channel)
        if t['trigger_type']=='ORIGINAL_CLEANUP':self._original_current(entry['source'],entry['actor'])
        self._live_guard(entry,invocation.endpoint)

    def _observe_result(self,entry,actual_actor,observation_only=False,*,status_override=None):
        d=entry['descriptor'];domain=entry['domain'];archive=self._verifier
        if not archive.available or not domain.target_valid():return
        sequence=len(entry['observations'])+1
        status='EXITED' if not domain.worker.possibly_live and not domain.worker.identity.alive else 'IN_PROGRESS' if domain.started else 'UNKNOWN'
        if status_override is not None:status=status_override
        fields={'custodian_id':d['source_custodian_id'],'spawn_token':d['spawn_token']['token_id'],
            'launch_spec_digest':d['spawn_token']['launch_spec_digest'],'status':status,
            'process_identity':asdict(domain.worker.identity),'possibly_live':status!='EXITED'}
        digest=survivor_digest('b-survivor-receipt/v1',[survivor_digest('b-survivor-descriptor/v1',d),actual_actor,
            archive.identity,sequence,fields])
        receipt=dict(fields,receipt_id='/survivor-observation/'+d['operation_id']+'/'+str(sequence)+'/'+digest)
        receipt=parse_closed_canonical(closed_canonical_bytes(receipt))
        parsed=dict(receipt,process_identity=_closed_dataclass_record(receipt['process_identity'],ProcessIdentity))
        CustodianReceipt(**parsed)
        raw=closed_canonical_bytes(receipt)
        entry['observations'][receipt['receipt_id']]={'bytes':raw,'actor':actual_actor,'verifier':archive.identity,
            'sequence':sequence,'observation_only':observation_only,'consume':(entry.get('operation') or {}).get('consume'),
            'initiated':domain.started and not observation_only,'domain_claim':domain.claim}
        archive.observations[receipt['receipt_id']]=entry['observations'][receipt['receipt_id']]
        entry['receipt']=receipt;entry['receipt_bytes']=raw
        if status=='EXITED' and entry.get('operation') is not None and entry['operation'].get('consume') is not None:
            entry['operation']['state']='RESULT_AVAILABLE'

    def request_original_cleanup(self,source,actor,delegation_id,failure_ref):
        entry=self._entries.get(delegation_id)
        if entry is None or entry['source'] is not source:raise ContainmentUnavailable('exact original subject required')
        store=source._store
        with store.authorization_lock:
            self._original_current(source,actor)
            if entry['actor'] is not actor:raise ContainmentUnavailable('replacement cannot request original cleanup')
            with self.lock:
                self._verifier.request_sequence+=1;n=self._verifier.request_sequence
                d=entry['descriptor'];producer=self._incarnation_record(d)+['ORIGINAL_CLEANUP_BOUNDARY']
                facts={'request_id':survivor_digest('b-survivor-cleanup-request/v1',[producer,self.epoch,n]),
                    'request_sequence':n,'failure_ref':copy.deepcopy(failure_ref),
                    'failure_payload_digest':failure_ref['payload_digest'],'original_generation':actor.generation,
                    'original_incarnation_id':actor.incarnation_id,'original_session_id':actor.session_id,
                    'original_fence':actor.fence,'requested_action':'CONTAIN_TOKEN_DOMAIN'}
                self._validate_cleanup(entry,facts)
                trigger=self._retain_trigger(entry,'ORIGINAL_CLEANUP_REQUEST',facts,self._cleanup_channel)
                if trigger is None:raise ContainmentUnavailable('independent cleanup verifier unavailable')
                return self._deliver(entry,trigger,self._cleanup_channel,entry['endpoint'])

    def _validate_cleanup(self,entry,facts):
        actor=entry['actor'];source=entry['source'];store=self._original_current(source,actor)
        failure=store._exact_ref(facts['failure_ref'])
        _,commit=store.witness.query_transaction(failure['event_id'])
        if (failure['event'].get('state')!='TAINTED' or failure['envelope'].boundary!='HISTORY' or
                commit.completion_mode!='ORIGIN' or json.loads(failure['envelope'].producer_bytes)!=actor.producer() or
                facts['failure_payload_digest']!=failure['receipt'].event_digest):
            raise ContainmentUnavailable('exact ORIGIN original failure diagnostic required')

    def _assert_original_containment(self,domain,binding):
        # Accepted A cleanup uses the already-admitted original ownership bytes,
        # including after the verifier detects substitution. S has a separate
        # fresh continuity guard; this is no new delegation or execution right.
        self._require_original_source_lifetime(domain.source)
        original=domain.source.original_creation_binding(domain.worker.token.token_id)
        if (not isinstance(binding,ArtifactBinding) or binding.manifest()!=original.manifest() or
                binding.authorization_digest!=original.authorization_digest or
                binding.verifier_identity!=original.verifier_identity):
            raise ContainmentUnavailable('exact original admitted cleanup binding required')

    def _actual_domain(self,worker,source):
        if not self.lock.owned_by_current_thread():
            raise ContainmentUnavailable('C exclusion required for actual target binding')
        domain=self._domains.get(worker.token.token_id)
        if domain is not None:
            if (domain.worker is not worker or domain.source is not source or
                    not worker._domain_ever_bound or worker._domain_handle is not domain):
                raise ContainmentUnavailable('exact permanent target-side binding required')
            return domain
        if worker._domain_ever_bound or worker._domain_handle is not None:
            raise ContainmentUnavailable('actual domain registry unavailable; cannot recreate')
        domain=_TokenDomainPort(worker,source)
        self._domains[worker.token.token_id]=domain
        return domain

    def _contain_original(self,source,token_id,binding):
        with self.lock:
            if source is not self._source or source._containment_factory is not self or not source.alive or source in self._lost_sources:
                raise ContainmentUnavailable('surviving original ownership required')
            worker=source._registry.get(token_id)
            if worker is None:raise ContainmentUnavailable('exact token-owned domain unavailable')
            domain=self._actual_domain(worker,source)
            with domain.lock:
                self._assert_original_containment(domain,binding)
                if not domain.target_valid():raise ContainmentUnavailable('original target handle lost')
                if not source.alive or source in self._lost_sources or (source,token_id) in self._lost_ownership:
                    raise ContainmentUnavailable('original custody loss won before containment')
                domain.sealed=True
                if domain.claim is None:
                    domain.claim=(source.identity,'original-containment-'+token_id)
                    invocation=_ProtectedContainmentInvocation(self,None,None,None,None,None,source,binding)
                    domain._pending_invocation=invocation
                    try:domain._initiate(*domain.claim,invocation=invocation)
                    finally:domain._pending_invocation=None
                    domain._observe_exit()
                    self._verifier.observations[domain.worker.receipt.receipt_id]={
                        'bytes':closed_canonical_bytes(asdict(domain.worker.receipt)), 'actor':source.identity,
                        'verifier':source.identity,'original_source':True,'domain_claim':domain.claim,'domain':domain}
                if not domain.started:
                    raise ContainmentUnavailable('accepted operation has no initiation observation; query only')
                return ContainmentEvidence('contain-'+token_id,domain.claim[0],token_id,'CONTAIN',
                    domain.worker.identity.host_pid,domain.worker.identity.process_start_ticks,False)

    def _release_guard(self,source,actor,token_id):
        if source is not self._source or source._containment_factory is not self:
            raise ContainmentUnavailable('exact original source required')
        domain=self._domains.get(token_id)
        if domain is None:
            raise ContainmentUnavailable('actual release domain unavailable')
        if domain.sealed:
            raise ContainmentUnavailable('containment irreversibly sealed this token domain')
        source._store.require_actor(actor)
        if not source.alive or source in self._lost_sources:
            raise ContainmentUnavailable('original required custody lost')
        if (source,token_id) in self._lost_ownership:
            raise ContainmentUnavailable('exact required ownership binding invalidated')
        if domain is not None and (not domain.target_valid() or not domain.worker.possibly_live or not domain.worker.identity.alive):
            raise ContainmentUnavailable('release target identity unavailable')

    def _original_control_port(self,source,capability,binding):
        store=source._store
        actor=store.validate_initiation(capability)
        intent=store.effect_intent(capability)
        token_id=intent.get('spawn_token')
        with self.lock:
            if token_id is None and binding.transition in ('RELEASE_ELIGIBLE','RELEASE_INTENT','RELEASED_OR_POSSIBLY_RELEASED'):
                # Accepted A slot-only control history still names one actual
                # original owned worker; no supervisor V or PID reconstruction.
                owned=[w for w in source._registry.values() if
                    w.token.slot_id==intent.get('slot_id') and w.token.campaign_id==actor.campaign_id and
                    w.token.supervisor_generation==actor.generation and w.token.custodian_id==source.identity]
                if len(owned)!=1:
                    raise ContainmentUnavailable('exact original slot-owned release target required')
                token_id=owned[0].token.token_id
            domain=self._domains.get(token_id)
            if domain is None and token_id in source._registry:
                domain=self._actual_domain(source._registry[token_id],source)
            with domain.lock if domain is not None else nullcontext():
                if binding.transition in ('RELEASE_ELIGIBLE','RELEASE_INTENT','RELEASED_OR_POSSIBLY_RELEASED'):
                    self._release_guard(source,actor,token_id)
                    self._assert_artifact(binding)
                    self._release_guard(source,actor,token_id)
                    store.validate_initiation(capability)
                    if binding.transition=='RELEASED_OR_POSSIBLY_RELEASED' and domain is not None:
                        if domain.worker.released:raise ContainmentUnavailable('RELEASE cannot repeat')
                        domain.worker.released=True
                        domain.releases+=1
        # The original generic control dispatcher follows outside C/port locks;
        # the token-domain RELEASE effect has already linearized above.

    def _confirms_required_loss(self,source,attestation):
        with self.lock:
            for entry in self._entries.values():
                proof=self._verifier.delegations.get(entry['descriptor']['delegation_id']) if entry['descriptor'] is not None else None
                if (source is self._source and proof is not None and attestation in parse_closed_canonical(proof['boot_custody']) and
                        (source in self._lost_sources or entry['ownership_subject'] in self._lost_ownership)):
                    return True
            return False

    def _check_reader(self,reader):
        if self._source is None or self._source._containment_factory is not self:
            raise ContainmentUnavailable('original pinned reader service required')
        if reader is self._reader_endpoint:return
        store=self._source._store
        if store is None:raise ContainmentUnavailable('authenticated inspector required')
        with store.authorization_lock:store._require_recovery_writer(reader)

    def inspect(self,delegation_id, *, reader=None):
        self._check_reader(reader)
        with self.lock:
            entry=self._entries.get(delegation_id)
            if entry is None:raise ContainmentUnavailable('unknown original delegation')
            domain=entry['domain'];op=entry.get('operation')
            return {'stage':entry['stage'],'exposed':entry['exposed'] and not entry['revoked'],
                'operation_state':'UNKNOWN' if op is None or not domain.readable else op['state'],
                'consume':None if op is None else copy.deepcopy(op['consume']),
                'physical_initiations':domain.initiations,'teardowns':domain.teardowns,'domain_sealed':domain.sealed,
                'receipt':copy.deepcopy(entry['receipt']),'receipt_bytes':entry['receipt_bytes'],
                'transfer_ref':copy.deepcopy(entry['transfer_ref'])}

    def observe_current_outcome(self,delegation_id, *, reader=None):
        """Read-only independent observation; never claims or resumes a call."""
        self._check_reader(reader)
        with self.lock:
            entry=self._entries.get(delegation_id)
            if entry is None:raise ContainmentUnavailable('unknown original delegation')
            with entry['domain'].lock:
                op=entry.get('operation')
                if op is not None and op['state'] not in ('READY','RESULT_AVAILABLE'):
                    actor=(entry['domain'].claim or (self._actor_id(entry['descriptor']),))[0]
                    if actor==self._actor_id(entry['descriptor']):self._live_guard(entry,entry['endpoint'])
                    elif not entry['source'].alive:raise ContainmentUnavailable('original observer lifetime lost')
                    self._observe_result(entry,actor,observation_only=True)
        return self.inspect(delegation_id,reader=reader)

    def inspect_trigger(self,delegation_id,raw, *, reader=None):
        self._check_reader(reader)
        with self.lock:
            entry=self._entries.get(delegation_id)
            if entry is None:return 'TRIGGER_REJECTED'
            try:
                t=parse_closed_canonical(raw);item=self._verifier.entries.get(t.get('trigger_id'))
                if item is None:return 'TRIGGER_UNAVAILABLE'
                if item['entry'] is not entry or item['trigger']!=raw:return 'TRIGGER_REJECTED'
                self._validate_trigger(entry,t['trigger_id'],item['channel'])
                op=entry.get('operation')
                return 'OUTCOME_UNKNOWN' if op is None else 'EXISTING_RESULT' if op['state']=='RESULT_AVAILABLE' else 'ALREADY_CLAIMED' if op['state']=='CLAIMED' else 'VALIDATED_NOT_CLAIMED' if op['state']=='READY' else 'OUTCOME_UNKNOWN'
            except (ContractError,RuntimeError,TypeError,KeyError):return 'TRIGGER_REJECTED'

    def _retain_reap(self,source,receipt):
        with self.lock:
            worker=source._registry.get(receipt.spawn_token)
            if (source is not self._source or not source.alive or worker is None or not worker.reaped or
                    worker.reap_receipt!=receipt or receipt.custodian_id!=source.identity):
                raise CustodyError('actual original parent wait receipt required')
            self._reap_history[receipt.receipt_id]=closed_canonical_bytes(asdict(receipt))

    def _validate_archived_reap(self,source,receipt):
        with self.lock:
            if (not self._verifier.available or source is not self._source or
                    self._reap_history.get(receipt.receipt_id)!=closed_canonical_bytes(asdict(receipt))):
                raise CustodyError('independently archived original parent wait unavailable')
            return True

    def _report_owner(self,source,parent,token_id):
        entry=self._entries.get(parent['event'].get('transfer_id'))
        if entry is not None:
            if (entry['transfer_ref']!=source._store._reference(parent['receipt']) or
                    entry['descriptor']['spawn_token']['token_id']!=token_id or entry['closure'] is None):
                raise CustodyError('exact original Owner/delegation required')
            return entry['descriptor']['process_identity']
        domain=self._domains.get(token_id)
        if (domain is None or parent['event'].get('record_type')!='EFFECT_ACCEPTED' or
                parent['event'].get('operation')!='blocked-create' or parent['event'].get('target')!=source.identity):
            raise CustodyError('original accepted ownership proof required')
        intent=source._store._exact_ref(parent['event']['intent_ref'])['event']
        if (intent.get('spawn_token')!=token_id or intent.get('custodian_id')!=source.identity or
                intent.get('launch_spec_digest')!=domain.worker.token.launch_spec_digest):
            raise CustodyError('exact original process/token ownership required')
        return parse_closed_canonical(closed_canonical_bytes(asdict(domain.original_identity)))

    def _validate_report(self,source,parent,event,raw):
        with self.lock:
            return self._validate_report_guarded(source,parent,event,raw)

    def _validate_report_guarded(self,source,parent,event,raw):
        kind=event['supplement_kind']
        if kind=='CONTAINMENT_EVIDENCE':
            receipt=parse_closed_canonical(raw)
            observation=self._verifier.observations.get(receipt.get('receipt_id'))
            if observation is not None and observation.get('original_source'):
                identity=self._report_owner(source,parent,receipt.get('spawn_token'))
                if (not self._verifier.available or observation['bytes']!=raw or
                        event['source_id']!=source.identity or event['verifier_id']!=source.identity or
                        observation['domain_claim'][0]!=source.identity or
                        replace(_closed_dataclass_record(receipt['process_identity'],ProcessIdentity),alive=True)!=
                        replace(_closed_dataclass_record(identity,ProcessIdentity),alive=True)):
                    raise CustodyError('exact original containment/Owner observation required')
                return True
            entry=self._entries.get(parent['event'].get('transfer_id'))
            if entry is None or parent['event'].get('authority_digest')!=survivor_digest('b-survivor-descriptor/v1',entry['descriptor']):
                raise CustodyError('exact original delegation parent required')
            proof=self._verifier.delegations.get(entry['descriptor']['delegation_id'])
            if (proof is None or proof['entry'] is not entry or proof['bytes'][0]!=entry['descriptor_bytes'] or
                    closed_canonical_bytes(entry['descriptor'])!=entry['descriptor_bytes'] or
                    proof['bytes'][1]!=parent['bytes'] or
                    proof['bytes'][2]!=source._store._object_proof(entry['descriptor']['original_creation_receipt']) or
                    proof['bytes'][3]!=source._store._exact_ref(entry['descriptor']['original_ownership_ref'])['bytes']):
                raise CustodyError('full original Owner/creation/delegation report closure required')
            if (not self._verifier.available or observation is None or observation['bytes']!=raw or
                    observation['actor']!=event['source_id'] or observation['verifier']!=event['verifier_id'] or
                    event['source_id'] not in (self._actor_id(entry['descriptor']),source.identity) or
                    receipt.get('status') not in ('IN_PROGRESS','UNKNOWN','EXITED')):
                raise CustodyError('exact survivor actor and independent existing receipt required')
            _closed_dataclass_record(receipt['process_identity'],ProcessIdentity)
            if (set(receipt)!=set(CustodianReceipt.__dataclass_fields__) or
                    receipt['spawn_token']!=entry['descriptor']['spawn_token']['token_id'] or
                    receipt['custodian_id']!=source.identity or
                    receipt['possibly_live'] is not (receipt['status']!='EXITED') or
                    replace(_closed_dataclass_record(receipt['process_identity'],ProcessIdentity),alive=True)!=
                    replace(_closed_dataclass_record(entry['descriptor']['process_identity'],ProcessIdentity),alive=True)):
                raise CustodyError('closed survivor receipt/target/liveness binding required')
            if observation['initiated'] and (observation['consume'] is None or
                    self._verifier.uses.get(observation['consume'][0])!=observation['consume'] or
                    observation['consume'][2]!=entry['descriptor']['operation_id'] or
                    observation['domain_claim']!=(event['source_id'],entry['descriptor']['operation_id'])):
                raise CustodyError('no fabricated survivor initiation claim')
        elif kind=='REAP_EVIDENCE':
            value=parse_closed_canonical(raw)
            if set(value)!=set(ReapReceipt.__dataclass_fields__):raise CustodyError('closed reap receipt')
            receipt=ReapReceipt(**value)
            if event['source_id']!=source.identity or event['verifier_id']!=source.identity:
                raise CustodyError('survivor wait/reap unavailable')
            identity=self._report_owner(source,parent,receipt.spawn_token)
            if receipt.host_pid!=identity['host_pid'] or receipt.process_start_ticks!=identity['process_start_ticks']:
                raise CustodyError('reap process incarnation substitution')
            source.validate_reap_receipt(receipt)
        elif kind=='FAILURE_ENVELOPE':
            value=parse_closed_canonical(raw)
            observation=self._diagnostic_history.get(hashlib.sha256(raw).hexdigest())
            if (observation is None or observation['bytes']!=raw or not self._verifier.available or
                    observation['parent_ref']!=source._store._reference(parent['receipt']) or
                    event['source_id']!=source.identity or event['verifier_id']!=self._verifier.identity):
                raise CustodyError('exact bounded independently observed original failure required')
            self._validate_failure_envelope(source,parent,value)
        else:raise CustodyError('independent permitted supplement provenance unavailable')
        return True

    def _validate_failure_envelope(self,source,parent,value):
        from .contracts import RECOVERY_OBLIGATION_REASONS
        reasons=set().union(*RECOVERY_OBLIGATION_REASONS.values())
        if (type(value) is not dict or set(value)!={'failure_code','source_refs','raw_object_refs'} or
                value['failure_code'] not in reasons or type(value['source_refs']) is not list or
                type(value['raw_object_refs']) is not list or not 1<=len(value['source_refs'])<=16 or
                len(value['raw_object_refs'])>16 or parent['event'].get('state')!='TAINTED' or
                parent['event'].get('reason')!=value['failure_code'] or
                source._store._reference(parent['receipt']) not in value['source_refs']):
            raise CustodyError('closed bounded failure code and actual diagnostic references required')
        for ref in value['source_refs']:source._store._exact_ref(ref)
        objects=[source._store._object_proof(ref) for ref in value['raw_object_refs']]
        if sum(map(len,objects))>65536:raise CustodyError('bounded failure raw evidence required')
        if parent['event']['raw_length']:
            if (len(objects)!=1 or len(objects[0])!=parent['event']['raw_length'] or
                    hashlib.sha256(objects[0]).hexdigest()!=parent['event']['raw_digest']):
                raise CustodyError('exact retained original raw failure object required')
        elif objects:raise CustodyError('empty original raw failure cannot acquire different objects')

    def _observe_failure_envelope(self,source,parent_ref,failure_code,raw_object_refs):
        store=source._store
        with store.authorization_lock:
            actor=store._current_actor;self._original_current(source,actor)
            parent=store._exact_ref(parent_ref)
            _,checkpoint=store.witness.query_transaction(parent['event_id'])
            if (parent['envelope'].boundary!='HISTORY' or checkpoint.completion_mode!='ORIGIN' or
                    parent['envelope'].producer_bytes!=closed_canonical_bytes(actor.producer())):
                raise CustodyError('exact original ORIGIN diagnostic observer required')
            value={'failure_code':failure_code,'source_refs':[copy.deepcopy(parent_ref)],
                'raw_object_refs':copy.deepcopy(list(raw_object_refs))}
            self._validate_failure_envelope(source,parent,value)
            raw=closed_canonical_bytes(value)
            with self.lock:
                self._original_current(source,actor)
                self._diagnostic_history[hashlib.sha256(raw).hexdigest()]={'bytes':raw,'parent_ref':copy.deepcopy(parent_ref)}
            return raw

    def _validate_unavailability_obligation(self,event):
        target=event['target_ref']
        entries=[e for e in self._entries.values() if e['transfer_ref']==target['subject_ref']]
        if len(entries)!=1:raise CustodyError('exact real delegation for unavailable containment evidence required')
        entry=entries[0];d=entry['descriptor'];domain=entry['domain']
        if (target['subject_state']!='KNOWN' or entry['transfer_ref'] not in event['subject_refs'] or
                d['original_ownership_ref'] not in event['subject_refs'] or target['evidence_state']!='UNAVAILABLE'):
            raise CustodyError('truthful unavailable original Owner/delegation required')
        reason=event['reason_code'];valid=False
        if event['kind']=='CONTAINMENT_UNAVAILABLE' and target['kind']=='CUSTODIAN' and target['identity']==self._source.identity:
            if reason=='CUSTODIAN_UNAVAILABLE':valid=self._source in self._lost_sources
            elif reason=='OWNERSHIP_UNPROVEN':valid=entry['ownership_subject'] in self._lost_ownership
            elif reason=='CAPABILITY_MISMATCH':valid=not entry['exposed'] or entry['revoked'] or self._endpoints.get(entry['endpoint']) is not entry
            elif reason=='TARGET_IDENTITY_MISMATCH':valid=not domain.target_valid()
            elif reason=='REAP_UNPROVEN':valid=not domain.worker.reaped
            elif reason=='ARTIFACT_MISMATCH':
                try:self._assert_artifact(entry['binding'])
                except (CustodyError,RuntimeError):valid=True
        elif event['kind']=='EVIDENCE_SERIALIZATION_FAILED' and target['kind']=='LOCAL_EVIDENCE':
            known={self._verifier.identity}
            known.update(parse_closed_canonical(i['evidence'])['evidence_id'] for i in self._verifier.entries.values() if i['entry'] is entry)
            if target['identity'] in known:
                if reason=='SOURCE_UNAVAILABLE':valid=not self._verifier.available or not self._lifecycle_port.available
                elif reason=='SOURCE_PROVENANCE_MISMATCH':valid=self._verifier.delegations.get(d['delegation_id']) is None
        if not valid:raise CustodyError('unavailability reason must describe an actual registered source condition')
        return True

    def _validate_obligation(self,event):
        with self.lock:
            target=event['target_ref']
            if target['kind'] in ('CUSTODIAN','LOCAL_EVIDENCE'):
                return self._validate_unavailability_obligation(event)
            found=[e for e in self._entries.values() if e['descriptor'] is not None and
                e['descriptor']['operation_id']==target['identity']]
            if len(found)!=1:raise CustodyError('exact independent existing containment operation required')
            entry=found[0];domain=entry['domain'];op=entry.get('operation')
            if (target['kind']!='EFFECT' or target['subject_state']!='KNOWN' or
                    target['subject_ref']!=entry['transfer_ref'] or
                    entry['transfer_ref'] not in event['subject_refs'] or
                    entry['descriptor']['original_ownership_ref'] not in event['subject_refs']):
                raise CustodyError('real original ownership and delegation obligation references required')
            accepted=[use for use in self._verifier.uses.values() if use[2]==target['identity']]
            if len(accepted)!=1 or event['kind']!='EFFECT_RESULT_UNRESOLVED':
                raise CustodyError('unresolved independently accepted containment operation required')
            if target['evidence_state']=='AVAILABLE':
                raw=self._source._store._object_proof(target['evidence_ref'])
                if not any(o['bytes']==raw for o in entry['observations'].values()):
                    raise CustodyError('exact permitted containment observation object required')
            reason=event['reason_code']
            if reason=='ACCEPTED_NOT_STARTED':
                valid=(op is not None and op['state']=='CLAIMED' and domain.readable and
                    domain.target_valid() and not domain.started and op['consume']==accepted[0])
            elif reason=='OUTCOME_UNKNOWN':
                valid=(op is None or not domain.readable or op['state'] in ('CLAIMED','STARTED','UNKNOWN'))
            elif reason=='RESULT_UNAVAILABLE':
                valid=(op is not None and op['state']=='RESULT_AVAILABLE' and
                    (not self._verifier.available or entry['receipt_bytes'] is None))
            else:
                observation=self._verifier.observations.get((entry.get('receipt') or {}).get('receipt_id'))
                valid=(op is not None and op['state']=='RESULT_AVAILABLE' and observation is not None and
                    observation['bytes']!=entry['receipt_bytes'])
            if not valid:raise CustodyError('reason must describe actual independently observed unresolved state')
            return True
