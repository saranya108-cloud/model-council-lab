"""Offline custodian model for Decision 0009.

The classes here simulate ownership and failure semantics.  They never create a
real process, send a signal, touch a cgroup, or call a host/vendor API.
"""

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import threading

from .contracts import (
    ArtifactBinding, CustodianReceipt, CustodyError, EffectCapability,
    ProcessIdentity, ReapReceipt, SpawnToken,
    ImmutableObjectReference, parse_effect_port_receipt,
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


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OfflineCustodian:
    """Independent-lifetime fake with a durable token registry."""

    def __init__(self, identity):
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

    def contain_spawn(self, spawn_token, recovery_capability, artifact_binding):
        self._ensure_live()
        if type(recovery_capability) is not str or not recovery_capability:
            raise CustodyError("recovery capability")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("containment artifact binding")
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
            return worker.reap_receipt

    def get_reap_receipt(self, spawn_token):
        worker = self._registry.get(spawn_token)
        return None if worker is None else worker.reap_receipt

    def validate_reap_receipt(self, receipt):
        if not isinstance(receipt, ReapReceipt):
            raise CustodyError("reap receipt type")
        worker = self._registry.get(receipt.spawn_token)
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
        if not self.alive:
            return
        self._loss_evidence = tuple(sorted(self._boot_custody))
        self.alive = False
        if self._loss_callback is not None:
            self._loss_callback("custodian-death")

    def confirms_required_custody_loss(self, attestation_record):
        """Positive independent invalidation, never an unanswered observation."""
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
        if not self.alive or not isinstance(transfer, SurvivorTransfer):
            raise ContainmentUnavailable("survivor unavailable")
        if transfer.survivor_identity != self.identity:
            raise ContainmentUnavailable("survivor has no ownership rights")
        if transfer.authority_digest != _digest(self.authority):
            raise ContainmentUnavailable("survivor authority does not match transfer")
        if type(recovery_capability) is not str or not recovery_capability:
            raise CustodyError("survivor recovery capability")
        if (self._store is None or self._transfers.get(transfer.transfer_id) != transfer or
                transfer.artifact_binding != self.artifact_binding or
                transfer.fence_epoch != self._store.witness.current_fence or
                transfer.recovery_capability_digest != _digest(recovery_capability) or
                transfer.process_identity.spawn_token != transfer.spawn_token):
            raise ContainmentUnavailable("forged, stale, or unauthorized survivor transfer")
        try:
            frames = [frame for frame in self._store._committed_frames()
                      if frame['event'].get('record_type') == 'SURVIVOR_TRANSFER' and
                      frame['event'].get('transfer_id') == transfer.transfer_id]
            if len(frames) != 1 or frames[0]['envelope'].boundary != 'HISTORY':
                raise ContainmentUnavailable('original witnessed transfer unavailable')
            frame = frames[0]
            producer = json.loads(frame['envelope'].producer_bytes)
            custodian = self._store._custodian
            authorization = self._store._admitted_payload()
            if (custodian is None or custodian.identity != transfer.source_custodian or
                    frame['envelope'].store_identity != self._store.identity or
                    frame['envelope'].authorization_digest != transfer.artifact_binding.authorization_digest or
                    frame['envelope'].campaign_id != authorization.campaign_id or
                    frame['envelope'].authorization_digest != authorization.authorization_digest or
                    producer['session_id'] != transfer.session_id or
                    producer['fence'] != transfer.fence_epoch or
                    transfer.artifact_binding.session_id != transfer.session_id or
                    transfer.artifact_binding.fence_epoch != transfer.fence_epoch):
                raise ContainmentUnavailable('exact original transfer producer required')
            custodian.validate_transfer_record(frame['event'])
            authoritative = [frame['event']]
        except (CustodyError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            raise ContainmentUnavailable('independent original transfer proof unavailable') from exc
        if (len(authoritative) != 1 or
                authoritative[0].get("source_custodian") != transfer.source_custodian or
                authoritative[0].get("survivor_identity") != transfer.survivor_identity or
                authoritative[0].get("spawn_token") != transfer.spawn_token or
                authoritative[0].get("host_pid") != transfer.process_identity.host_pid or
                authoritative[0].get("process_start_ticks") !=
                transfer.process_identity.process_start_ticks or
                authoritative[0].get("authority_digest") != transfer.authority_digest or
                authoritative[0].get("artifact_digest") !=
                _digest(repr(transfer.artifact_binding)) or
                authoritative[0].get("recovery_capability_digest") !=
                transfer.recovery_capability_digest):
            raise ContainmentUnavailable("survivor transfer does not match durable ownership record")
        if transfer.spawn_token in self._acted:
            raise CustodyError("survivor action already performed")
        self._acted.add(transfer.spawn_token)
        return ContainmentEvidence(
            "survivor-contain-" + transfer.spawn_token, self.identity,
            transfer.spawn_token, "CONTAIN", transfer.process_identity.host_pid,
            transfer.process_identity.process_start_ticks, True,
        )
