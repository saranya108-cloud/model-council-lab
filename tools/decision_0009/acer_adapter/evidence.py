"""Offline evidence, attribution, and immutable-publication models."""

from dataclasses import dataclass
import hashlib
import json
import copy
import threading

from .contracts import (
    ClosureCandidate, ContractError, EvidenceObject, GPUAttribution,
    ProcessIdentity, PublicationReceipt,
)


class EvidenceError(ValueError):
    pass


from .supervisor import AuthorizationDenied


class PublicationAuthorityDenied(EvidenceError, AuthorizationDenied):
    pass


class AttributionUnavailable(EvidenceError):
    pass


class PublicationAcknowledgementLost(EvidenceError):
    def __init__(self, receipt):
        super().__init__("publication verification acknowledgement lost")
        self.receipt = receipt


DESTINATION_FIELD_DOMAINS = {
    'port_identity': 'B', 'destination_id': 'B', '_producers': 'B/C', '_store': 'B', '_lock': 'B',
    'available': 'C', 'readback_available': 'C', '_sources': 'C', '_subjects': 'C',
    '_objects': 'C', '_operations': 'C', '_receipts': 'C', '_exclusions': 'C',
    '_claims': 'C', '_grant_results': 'C', '_counts': 'C', '_reserved_subjects': 'C',
    '_source_bindings': 'V', '_eligible_grants': 'V',
}


class OfflinePublicationDestination:
    """Independent deterministic C-domain destination, provisioned before entry.

    Registry bytes, writer exclusions, operation claims and receipts belong to
    this service; neither the controller's cache nor D reconstructs them.
    Producer instances are pinned setup references, not runtime identity names.
    This class performs no filesystem, network or process operation.
    """

    def __setattr__(self, name, value):
        if name in ('port_identity', 'destination_id', '_producers', '_store') and name in self.__dict__:
            if name != '_store' or self.__dict__[name] is not None:
                if self.__dict__[name] is not value:
                    raise PublicationAuthorityDenied('destination bootstrap identity is pinned')
        object.__setattr__(self, name, value)

    def __init__(self, port_identity, destination_id, *, producers=()):
        from .contracts import _string
        _string('port_identity', port_identity)
        _string('destination_id', destination_id)
        self.port_identity = port_identity
        self.destination_id = destination_id
        self._producers = tuple(producers)
        if (len({p[0] for p in self._producers}) != len(self._producers) or
                any(type(p[0]) is not str or type(p[1]) is not EvidencePipeline for p in self._producers)):
            raise EvidenceError('exact setup producer instances required')
        self._store = None
        self._lock = threading.RLock()
        self.available = True
        self.readback_available = True
        self._subjects = {}
        self._sources = {}
        self._objects = {}
        self._operations = {}
        self._receipts = {}
        self._exclusions = {}
        self._claims = set()
        self._grant_results = {}
        self._eligible_grants = {}
        self._counts = {}
        self._source_bindings = {}
        self._reserved_subjects = set()

    def bind_store(self, store):
        with self._lock:
            if self._store is not None or store._durable or store.witness.high_generation:
                raise PublicationAuthorityDenied('destination setup must precede runtime entry')
            self._store = store

    @staticmethod
    def operation_id(subject, operation):
        from .contracts import closed_canonical_bytes
        operation = 'CONTENT' if operation in ('ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT') else operation
        return 'rp-operation-' + _sha(closed_canonical_bytes([
            subject['original_intent_ref'], subject['destination_id'], subject['object_key'],
            subject['source_object'], operation]))

    def _known(self, original_ref, key):
        subject = self._subjects.get(key)
        if subject is None or subject['original_intent_ref'] != original_ref:
            raise PublicationAuthorityDenied('independent original destination provenance unavailable')
        return subject

    def bind_original_source(self, actor, intent, proof):
        with self._store.authorization_lock, self._lock:
            self._store.require_actor(actor)
            self._store.assert_healthy_authority()
            if type(proof) is not tuple or len(proof) != 2:
                raise PublicationAuthorityDenied('actual original producer proof required')
            producer, obj = proof
            auth = self._store._admitted_payload()
            from .contracts import PublicationIdentity
            PublicationIdentity(intent.intent_id, intent.destination, intent.object_key, intent.object_digest, intent.length)
            if (not any(p is self for p in self._store._publication_destinations) or
                    not any(r.destination_id == self.destination_id and r.object_key == intent.object_key
                            for r in auth.object_rules)):
                raise PublicationAuthorityDenied('exact configured source destination/object required')
            names = [name for name, registered in self._producers if registered is producer and
                     name in auth.evidence_source_ids]
            if (len(names) != 1 or type(obj) is not EvidenceObject or
                    producer._objects.get(obj.digest) is not obj or obj.bytes != intent.bytes or
                    obj.digest != intent.object_digest or obj.length != intent.length or
                    intent.destination != self.destination_id):
                raise PublicationAuthorityDenied('copied source identity or matching bytes is insufficient')
            binding = (actor, producer, obj, names[0])
            old = self._source_bindings.get(intent.intent_id)
            if old is not None and old != binding:
                raise PublicationAuthorityDenied('original source binding is immutable')
            self._source_bindings[intent.intent_id] = binding

    def observe_original(self, actor, grant, planned, payload):
        """Called by the original port only after exact EXEC acceptance/ack."""
        store = self._store
        with store.authorization_lock, self._lock:
            original = store.validate_publication_initiation(actor, grant, planned)
            if (not any(p is self for p in store._publication_destinations) or
                    grant.grant_id in self._counts or not self.available or
                    grant.binding.identity.destination != self.destination_id):
                raise PublicationAuthorityDenied('original destination unavailable')
            request = grant.binding
            key = request.identity.object_key
            op = request.operation
            if key in self._exclusions:
                raise PublicationAuthorityDenied('original writer independently excluded')
            if op == 'intent':
                if key in self._reserved_subjects:
                    raise PublicationAuthorityDenied('independent original object identity already reserved')
                request.identity.verify_source(payload)
                auth = store._admitted_payload()
                bound = self._source_bindings.get(request.identity.intent_id)
                producers = []
                if bound is not None:
                    producer_actor, producer, produced, identity = bound
                    if (producer_actor is not actor or producer._objects.get(produced.digest) is not produced or
                            produced.bytes != payload or identity not in auth.evidence_source_ids):
                        raise PublicationAuthorityDenied('original production binding differs from accepted source')
                    producers.append((identity, producer))
                # Missing source provenance remains missing. Normal publication
                # can retain its original behavior, but RP cannot retrofit it.
                rules = [r for r in auth.object_rules if
                         r.destination_id == self.destination_id and r.object_key == key]
                source = {'object_id': planned['source_object_id'], 'sha256': _sha(payload), 'length': len(payload)}
                subject = dict(original_intent_ref=store._reference(original['receipt']),
                    subject_id=rules[0].subject_id if len(rules) == 1 else None,
                    evidence_kind=rules[0].evidence_kind if len(rules) == 1 else None,
                    producer_refs=[store._reference(original['receipt'])], source_object=source,
                    destination_id=self.destination_id, object_key=key,
                    source_bytes=bytes(payload), producers=tuple(producers),
                    authorization_digest=actor.authorization_digest, campaign_id=actor.campaign_id,
                    boot_id=request.boot_id, original_owner=request.identity.intent_id,
                    original_create_ref=None)
                self._subjects[key] = subject
                self._sources[key] = dict(subject)
                self._source_bindings.pop(request.identity.intent_id, None)
                self._reserved_subjects.add(key)
                for operation in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                    self._operations[self.operation_id(subject, operation)] = {'status': 'NOT_STARTED', 'result': None}
            else:
                subject = self._subjects.get(key)
                if subject is None or subject['original_owner'] != request.identity.intent_id:
                    raise PublicationAuthorityDenied('original destination intent unavailable')
                obj = self._objects.get(key)
                if op == 'create':
                    if obj is not None:
                        raise PublicationAuthorityDenied('destination exclusive create collision')
                    self._objects[key] = {'owner': subject['original_owner'], 'bytes': b'',
                        'object_durable': False, 'namespace_durable': False, 'written': False}
                    subject['original_create_ref'] = store._reference(original['receipt'])
                elif op == 'write':
                    operation = self._operations.get(self.operation_id(subject, 'ENSURE_EXACT_OBJECT'))
                    if obj is None or obj['written'] or operation is None or operation['status'] != 'NOT_STARTED':
                        raise PublicationAuthorityDenied('original content write may not restart')
                    operation['status'] = 'COMPLETE'
                    obj['bytes'], obj['written'] = bytes(payload), True
                elif op == 'durable':
                    if obj is None or not obj['written']:
                        raise PublicationAuthorityDenied('destination bytes not independently written')
                    obj['object_durable'] = obj['namespace_durable'] = True
                elif op == 'verify':
                    if (obj is None or obj['bytes'] != subject['source_bytes'] or
                            not obj['object_durable'] or not obj['namespace_durable'] or not self.readback_available):
                        raise PublicationAuthorityDenied('independent original destination verification failed')
                else:
                    raise PublicationAuthorityDenied('closed original publication operation')
            self._counts[grant.grant_id] = self._counts.get(grant.grant_id, 0) + 1

    def source(self, original_ref, key):
        with self._lock:
            if self._store is None or not any(p is self for p in self._store._publication_destinations):
                raise PublicationAuthorityDenied('exact pinned source/destination instance required')
            s = self._sources.get(key)
            if s is None or s['original_intent_ref'] != original_ref:
                raise PublicationAuthorityDenied('original production proof unavailable')
            if not s['producers']:
                raise PublicationAuthorityDenied('independent original source unavailable')
            if not all(p.has_original_bytes(s['source_bytes']) for _, p in s['producers']):
                raise PublicationAuthorityDenied('original producer bytes unavailable')
            return {k: copy.deepcopy(v) for k, v in s.items()
                    if k != 'producers'}

    def _supplement_never_registered(self, subject, source):
        """Prove first registration from available C facts and committed D history.

        Called with both locks held. An absent reservation marker alone says
        nothing about prior registration or acceptance of the logical operation.
        """
        key = subject['object_key']
        operations = {self.operation_id(source, op) for op in (
            'ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT')}
        if (not self.available or key in self._reserved_subjects or
                any(key in registry for registry in (
                    self._subjects, self._sources, self._objects, self._exclusions)) or
                any(op in registry for op in operations for registry in (
                    self._operations, self._eligible_grants)) or
                any(fact[0]['object_key'] == key for fact in self._receipts.values())):
            return False
        for frame in self._store._committed_frames():
            event = frame['event']
            if (event.get('destination_id') != self.destination_id or
                    event.get('object_key') != key):
                continue
            # Acceptance is immutable no-freshness evidence even when every
            # destination fact is lost. A retained destination result also
            # proves registration; an unavailable query without a receipt does not.
            if (event.get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' or
                    event.get('record_type') == 'RECOVERY_PUBLICATION_VERIFIED' or
                    event.get('record_type') == 'RECOVERY_PUBLICATION_RESULT' and
                    event.get('destination_receipt') is not None):
                return False
        return True

    def register_supplement(self, binding, subject, intent_ref):
        store = self._store
        with store.authorization_lock, self._lock:
            actor = store._require_rp_binding(binding)
            port, source = store._validate_rp_subject(binding, subject, 'QUERY')
            committed = store._exact_ref(intent_ref)
            if (port is not self or not self.available or
                    committed['event'].get('record_type') != 'RECOVERY_PUBLICATION_INTENT' or
                    any(committed['event'].get(k) != v for k, v in subject.items()) or
                    not store.witness.acknowledged_current(actor, committed['event_id'])):
                raise PublicationAuthorityDenied('exact acknowledged supplement intent required')
            key = subject['object_key']
            if key in self._reserved_subjects:
                return
            if not self._supplement_never_registered(subject, source):
                # Query will report registry loss. Do not reconstruct C facts
                # or reset an existing operation, including NOT_STARTED.
                return
            self._reserved_subjects.add(key)
            self._subjects[key] = dict(source, producers=())
            for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                self._operations[self.operation_id(source, op)] = {'status': 'NOT_STARTED', 'result': None}

    def exclude_original_writers(self, binding, subject):
        store = self._store
        with store.authorization_lock, self._lock:
            port, _ = store._validate_rp_subject(binding, subject, 'QUERY')
            if port is not self:
                raise PublicationAuthorityDenied('copied destination cannot exclude writers')
            s = self._known(subject['original_intent_ref'], subject['object_key'])
            if not self.available:
                raise PublicationAuthorityDenied('destination registry unavailable')
            if (subject.get('original_or_supplement') == 'SUPPLEMENT' and
                    subject['object_key'] not in self._reserved_subjects):
                return s
            # Every original call and RP claim shares this lock. An uncertain
            # claim may still settle; exclusion cannot convert it to no-start.
            self._exclusions[subject['object_key']] = binding.actor.fence
            self._eligible_grants[subject['logical_operation_id']] = None
            return s

    def observe(self, binding, subject):
        from .contracts import closed_canonical_bytes, validate_destination_receipt
        store = self._store
        with store.authorization_lock, self._lock:
            port, _ = store._validate_rp_subject(binding, subject, 'QUERY')
            if port is not self:
                raise PublicationAuthorityDenied('exact pinned destination query port required')
            if not self.available:
                return None, 'DESTINATION_REGISTRY_UNAVAILABLE'
            if (subject.get('original_or_supplement') == 'SUPPLEMENT' and
                    subject['object_key'] not in self._reserved_subjects):
                return None, 'DESTINATION_REGISTRY_UNAVAILABLE'
            if subject['object_key'] not in self._subjects:
                return None, 'DESTINATION_REGISTRY_UNAVAILABLE'
            s = self._known(subject['original_intent_ref'], subject['object_key'])
            operation = self._operations.get(subject['logical_operation_id'])
            content = self._operations.get(self.operation_id(s, 'ENSURE_EXACT_OBJECT'))
            if operation is None or content is None:
                return None, 'DESTINATION_REGISTRY_UNAVAILABLE'
            obj = self._objects.get(subject['object_key'])
            if obj is not None and not self.readback_available:
                return None, 'READBACK_UNAVAILABLE'
            excluded = self._exclusions.get(subject['object_key']) == binding.actor.fence
            related = [self._operations.get(self.operation_id(s, op)) for op in (
                'ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT')]
            uncertain = (any(p is None or p['status'] in ('CLAIMED', 'IN_FLIGHT', 'UNKNOWN') for p in related) or
                         operation is None or content is None or
                         operation['status'] in ('CLAIMED', 'IN_FLIGHT', 'UNKNOWN') or
                         content['status'] in ('CLAIMED', 'IN_FLIGHT', 'UNKNOWN') or not excluded or
                         obj is not None and obj['owner'] is None or
                         obj is None and content['status'] != 'NOT_STARTED')
            status = 'UNKNOWN' if uncertain else operation['status']
            outcome, reason = 'UNKNOWN', 'OUTCOME_UNKNOWN'
            if not uncertain:
                if obj is None:
                    outcome, reason = 'ABSENT_PROVEN', None
                elif obj['owner'] != s['original_owner']:
                    outcome, reason = 'OWNER_CONFLICT', 'RESERVATION_OWNER_MISMATCH'
                elif obj['bytes'] == s['source_bytes']:
                    if obj['object_durable'] and obj['namespace_durable']:
                        outcome, reason = 'DURABILITY_ESTABLISHED', None
                        prior = operation.get('result')
                        if prior is not None and json.loads(prior)['outcome'] == 'VERIFIED':
                            outcome = 'VERIFIED'
                    else:
                        outcome, reason = 'EXACT_PRESENT', None
                elif obj['bytes'] == b'' and not obj['written'] and s['original_create_ref'] is not None:
                    outcome, reason = 'OWNED_EMPTY_RESERVED', None
                elif obj['bytes'] == b'' and not obj['written']:
                    outcome, reason = 'UNKNOWN', 'INTENT_UNPROVEN'
                elif 0 < len(obj['bytes']) < len(s['source_bytes']):
                    outcome, reason = 'PARTIAL', 'PARTIAL_OBJECT'
                else:
                    outcome, reason = 'CONTENT_CONFLICT', 'CONTENT_MISMATCH'
            receipt = dict(port_identity=self.port_identity, destination_id=self.destination_id,
                object_key=subject['object_key'], original_intent_ref=subject['original_intent_ref'],
                authorization_digest=s['authorization_digest'], campaign_id=s['campaign_id'],
                reservation_owner_id=None if obj is None or uncertain else obj['owner'],
                logical_operation_id=subject['logical_operation_id'], operation_status=status,
                bytes_digest=None if obj is None or uncertain else _sha(obj['bytes']),
                length=None if obj is None or uncertain else len(obj['bytes']),
                writer_fence=binding.actor.fence, outcome=outcome,
                object_durable=bool(obj is not None and obj['object_durable']),
                namespace_durable=bool(obj is not None and obj['namespace_durable']))
            receipt['port_attestation'] = _sha(closed_canonical_bytes(receipt))
            validate_destination_receipt(receipt)
            raw = closed_canonical_bytes(receipt)
            self._receipts[raw] = (copy.deepcopy(receipt), None if obj is None else bytes(obj['bytes']), reason)
            return raw, reason

    def authenticate_receipt(self, raw):
        from .contracts import validate_destination_receipt, parse_closed_canonical
        with self._lock:
            if self._store is None or not any(p is self for p in self._store._publication_destinations):
                raise PublicationAuthorityDenied('exact original retained receipt service required')
            retained = self._receipts.get(raw)
            if retained is None or retained[0] != validate_destination_receipt(parse_closed_canonical(raw)):
                raise PublicationAuthorityDenied('receipt not independently retained by original port')
            return copy.deepcopy(retained[0]), retained[1]

    def observation_reason(self, raw):
        with self._lock:
            self.authenticate_receipt(raw)
            return self._receipts[raw][2]

    def validate_precondition(self, binding, subject, operation):
        store = self._store
        with store.authorization_lock, self._lock:
            port, source = store._validate_rp_subject(binding, subject, operation)
            if port is not self:
                raise PublicationAuthorityDenied('exact pinned destination precondition port required')
            # A first child source is authenticated by its existing B supplement.
            # Namespace truth remains C-owned; a lost prior registration is never fresh.
            if (subject.get('original_or_supplement') == 'SUPPLEMENT' and
                    subject['object_key'] not in self._reserved_subjects):
                if (operation != 'ENSURE_EXACT_OBJECT' or
                        not self._supplement_never_registered(subject, source)):
                    raise PublicationAuthorityDenied('supplement destination registry unavailable: query only')
                return source
            s = self._known(subject['original_intent_ref'], subject['object_key'])
            state = self._operations.get(subject['logical_operation_id'])
            content = self._operations.get(self.operation_id(s, 'ENSURE_EXACT_OBJECT'))
            obj = self._objects.get(subject['object_key'])
            if not self.available or state is None or content is None:
                raise PublicationAuthorityDenied('destination operation registry unavailable')
            related = [self._operations.get(self.operation_id(s, op)) for op in (
                'ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT')]
            if any(p is None or p['status'] in ('CLAIMED', 'IN_FLIGHT', 'UNKNOWN') for p in related):
                raise PublicationAuthorityDenied('unknown or initiated destination operation: query only')
            if operation in ('ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT'):
                if state['status'] != 'NOT_STARTED':
                    raise PublicationAuthorityDenied('content write cannot restart')
                if operation == 'ENSURE_EXACT_OBJECT':
                    if obj is not None:
                        raise PublicationAuthorityDenied('exact absent key required')
                elif (obj is None or obj['bytes'] != b'' or obj['written'] or
                        obj['owner'] != s['original_owner'] or s['original_create_ref'] is None or
                        len(s['source_bytes']) == 0 or not self.readback_available):
                    raise PublicationAuthorityDenied('exact original unused owned-empty reservation required')
            elif operation in ('ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                if obj is None or obj['owner'] != s['original_owner'] or obj['bytes'] != s['source_bytes']:
                    raise PublicationAuthorityDenied('exact original owned destination bytes required')
                if operation == 'VERIFY_EXACT_OBJECT' and (not obj['object_durable'] or
                        not obj['namespace_durable'] or not self.readback_available):
                    raise PublicationAuthorityDenied('independent readback and both durability proofs required')
            else:
                raise PublicationAuthorityDenied('closed recovery destination operation required')
            return s

    def initiate_recovery(self, grant, *, fault=None):
        from .contracts import closed_canonical_bytes, validate_destination_receipt
        store = self._store
        with store.authorization_lock, self._lock:
            actor, payload, subject, port, source, accepted_ref = store.validate_rp_initiation(grant)
            if port is not self:
                raise PublicationAuthorityDenied('destination port substitution')
            self.validate_precondition(grant.binding, subject, payload['operation'])
            if self._exclusions.get(subject['object_key']) != actor.fence:
                raise PublicationAuthorityDenied('all original writers must be excluded before claim')
            if self._eligible_grants.get(subject['logical_operation_id']) != payload['grant_id']:
                raise PublicationAuthorityDenied('prior recovery writer independently revoked')
            if payload['consumption_id'] in self._claims:
                raise PublicationAuthorityDenied('single-use destination grant already claimed')
            store.require_actor(actor, 'RP')
            store.assert_healthy_authority()
            if fault == 'before_claim':
                raise PublicationAcknowledgementLost(accepted_ref)
            state = self._operations[subject['logical_operation_id']]
            self._claims.add(payload['consumption_id'])
            state['status'] = 'CLAIMED'
            if fault == 'after_claim':
                raise PublicationAcknowledgementLost(accepted_ref)
            state['status'] = 'IN_FLIGHT'
            self._counts[payload['grant_id']] = 1
            if fault == 'after_initiation':
                raise PublicationAcknowledgementLost(accepted_ref)
            op, key = payload['operation'], subject['object_key']
            if op == 'ENSURE_EXACT_OBJECT':
                self._objects[key] = {'owner': source['original_owner'], 'bytes': bytes(source['source_bytes']),
                    'written': True, 'object_durable': False, 'namespace_durable': False}
            elif op == 'CONTINUE_RESERVED_EXACT':
                self._objects[key]['bytes'] = bytes(source['source_bytes'])
                self._objects[key]['written'] = True
            elif op == 'ESTABLISH_DURABILITY':
                self._objects[key]['object_durable'] = True
                if fault == 'after_object_durability':
                    raise PublicationAcknowledgementLost(accepted_ref)
                self._objects[key]['namespace_durable'] = True
            if fault in ('after_bytes', 'after_namespace_durability', 'before_readback'):
                raise PublicationAcknowledgementLost(accepted_ref)
            state['status'] = 'COMPLETE'
            raw, reason = self.observe(grant.binding, subject)
            if op == 'VERIFY_EXACT_OBJECT':
                receipt = json.loads(raw)
                receipt['outcome'] = 'VERIFIED'
                receipt.pop('port_attestation')
                receipt['port_attestation'] = _sha(closed_canonical_bytes(receipt))
                validate_destination_receipt(receipt)
                raw = closed_canonical_bytes(receipt)
                self._receipts[raw] = (copy.deepcopy(receipt), bytes(self._objects[key]['bytes']), None)
            state['result'] = raw
            self._grant_results[payload['grant_id']] = (raw, reason)
            if fault == 'after_readback':
                raise PublicationAcknowledgementLost(accepted_ref)
            return raw, reason

    def arm_recovery_grant(self, grant):
        with self._store.authorization_lock, self._lock:
            actor, payload, subject, port, _, _ = self._store.validate_rp_initiation(grant)
            if port is not self or self._exclusions.get(subject['object_key']) != actor.fence:
                raise PublicationAuthorityDenied('exact excluded destination port required')
            self.validate_precondition(grant.binding, subject, payload['operation'])
            self._eligible_grants[subject['logical_operation_id']] = payload['grant_id']


def _sha(value):
    if type(value) is str:
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def canonical_core_bytes(value):
    try:
        _validate_shape(value)
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvidenceError("core evidence serialization failed") from exc


@dataclass(frozen=True)
class RawReference:
    object_id: str
    source_identity: str
    sequence: int
    received_ns: int
    declared_length: int
    retained_length: int
    retained_digest: str
    truncated: bool


@dataclass(frozen=True)
class NormalizedReference:
    raw_object_id: str
    raw_digest: str
    source_identity: str
    acquisition_sequence: int
    normalization_policy_digest: str
    value: bytes


@dataclass(frozen=True)
class PublicationIntent:
    intent_id: str
    destination: str
    object_key: str
    object_digest: str
    length: int
    bytes: bytes


class BoundedRawJournal:
    def __init__(self, max_frame_bytes=1_048_576, max_attempt_bytes=268_435_456):
        if (type(max_frame_bytes) is not int or type(max_attempt_bytes) is not int or
                max_frame_bytes < 1 or max_attempt_bytes < max_frame_bytes):
            raise EvidenceError("raw evidence bounds")
        self.max_frame_bytes = max_frame_bytes
        self.max_attempt_bytes = max_attempt_bytes
        self._bytes = {}
        self._retained = 0

    def capture(self, source_identity, raw, sequence, received_ns, declared_length=None):
        if (type(source_identity) is not str or type(raw) is not bytes or
                type(sequence) is not int or type(received_ns) is not int or
                sequence < 1 or received_ns < 0):
            raise EvidenceError("raw acquisition record")
        declared = len(raw) if declared_length is None else declared_length
        if type(declared) is not int or declared < len(raw):
            raise EvidenceError("declared frame length")
        remaining = self.max_attempt_bytes - self._retained
        retained = raw[:min(self.max_frame_bytes, max(0, remaining))]
        if not retained and raw:
            raise EvidenceError("raw evidence capacity exhausted")
        object_id = "raw-%d" % sequence
        if object_id in self._bytes:
            raise EvidenceError("raw acquisition sequence reused")
        self._bytes[object_id] = retained
        self._retained += len(retained)
        return RawReference(object_id, source_identity, sequence, received_ns,
                            declared, len(retained), _sha(retained),
                            len(retained) != declared)

    def read(self, reference):
        raw = self._bytes.get(reference.object_id)
        if raw is None or _sha(raw) != reference.retained_digest:
            raise EvidenceError("raw evidence readback mismatch")
        return raw


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def _validate_shape(value, depth=0):
    if depth > 32:
        raise EvidenceError("decoded nesting limit")
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise EvidenceError("invalid Unicode scalar value") from exc
        if len(encoded) > 65_536:
            raise EvidenceError("decoded string limit")
    elif type(value) in (list, tuple):
        if len(value) > 4_096:
            raise EvidenceError("decoded array limit")
        for item in value:
            _validate_shape(item, depth + 1)
    elif type(value) is dict:
        if len(value) > 4_096:
            raise EvidenceError("decoded object limit")
        for key, item in value.items():
            if type(key) is not str:
                raise EvidenceError("non-string key")
            _validate_shape(key, depth + 1)
            _validate_shape(item, depth + 1)
    elif type(value) is int:
        if value.bit_length() > 13_621:
            raise EvidenceError("decoded integer limit")
    elif value is not None and type(value) is not bool:
        raise EvidenceError("unsupported decoded value")


class EvidencePipeline:
    """Raw bytes -> normalized sidecar -> exact immutable core bytes."""

    def __init__(self, max_frame_bytes=1_048_576, max_attempt_bytes=268_435_456,
                 normalization_policy_digest=None):
        self.raw = BoundedRawJournal(max_frame_bytes, max_attempt_bytes)
        self.normalization_policy_digest = normalization_policy_digest or _sha("acer-normalization-v1")
        self._objects = {}

    def capture(self, *args, **kwargs):
        return self.raw.capture(*args, **kwargs)

    def decode(self, reference):
        if reference.truncated:
            raise EvidenceError("truncated raw frame is not decodable evidence")
        raw = self.raw.read(reference)
        try:
            text = raw.decode("utf-8", errors="strict")
            value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs,
                               parse_int=lambda value: int(value) if len(value.lstrip("-")) <= 4096
                               else (_ for _ in ()).throw(EvidenceError("decoded integer limit")),
                               parse_float=lambda value: (_ for _ in ()).throw(
                                   EvidenceError("floats are not accepted")),
                               parse_constant=lambda value: (_ for _ in ()).throw(
                                   EvidenceError("nonfinite values are not accepted")))
        except EvidenceError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise EvidenceError("malformed raw bytes") from exc
        _validate_shape(value)
        return value

    def normalize(self, reference, value):
        if type(value) is not dict:
            raise EvidenceError("normalized core input must be a closed mapping")
        _validate_shape(value)
        decoded = self.decode(reference)
        normalized_bytes = canonical_core_bytes(value)
        if canonical_core_bytes(decoded) != normalized_bytes:
            raise EvidenceError("normalized value does not correspond to retained raw bytes")
        return NormalizedReference(
            reference.object_id, reference.retained_digest,
            reference.source_identity, reference.sequence,
            self.normalization_policy_digest, normalized_bytes,
        )

    def freeze_core(self, value, normalized_reference):
        if not isinstance(normalized_reference, NormalizedReference):
            raise EvidenceError("normalization binding required")
        encoded = canonical_core_bytes(value)
        raw = self.raw._bytes.get(normalized_reference.raw_object_id)
        if (type(normalized_reference.value) is not bytes or raw is None or
                _sha(raw) != normalized_reference.raw_digest or
                canonical_core_bytes(self.decode(RawReference(
                    normalized_reference.raw_object_id,
                    normalized_reference.source_identity,
                    normalized_reference.acquisition_sequence, 0, len(raw), len(raw),
                    normalized_reference.raw_digest, False))) != normalized_reference.value or
                encoded != normalized_reference.value):
            raise EvidenceError("frozen core bytes do not match normalized input")
        digest = _sha(encoded)
        existing = self._objects.get(digest)
        if existing is not None and existing.bytes != encoded:
            raise EvidenceError("immutable digest collision")
        obj = EvidenceObject("core-" + digest[:16], digest, len(encoded), encoded)
        self._objects[digest] = obj
        return obj

    def freeze_raw(self, reference):
        """Retain exact original raw evidence; never label it normalized core."""
        raw = self.raw.read(reference)
        if reference.truncated:
            raise EvidenceError('truncated source cannot establish exact intended bytes')
        digest = _sha(raw)
        obj = self._objects.get(digest)
        if obj is None:
            obj = EvidenceObject('raw-' + digest[:16], digest, len(raw), raw)
            self._objects[digest] = obj
        if obj.bytes != raw:
            raise EvidenceError('original raw digest collision')
        return obj

    def readback(self, digest):
        obj = self._objects.get(digest)
        if obj is None or _sha(obj.bytes) != obj.digest:
            raise EvidenceError("local immutable readback failed")
        return obj.bytes

    def has_original_bytes(self, raw):
        """Pinned producer inspection, not a digest-only authority lookup."""
        return (type(raw) is bytes and
                any(value.bytes == raw for value in self._objects.values()))


def _same_incarnation(left, right):
    fields = (
        "host_id", "boot_id", "host_pid", "pid_namespace", "namespace_pid",
        "process_start_ticks", "executable_path", "executable_device",
        "executable_inode", "executable_digest", "cgroup_path", "cgroup_device",
        "cgroup_inode", "cgroup_members", "custodian_id", "spawn_token", "gpu_uuid",
    )
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def normalize_gpu_attribution(pre_identity, query, post_identity):
    """F8 exact worker attribution; unavailable observations raise explicitly."""
    if not isinstance(pre_identity, ProcessIdentity) or not isinstance(post_identity, ProcessIdentity):
        raise AttributionUnavailable("closed identity brackets required")
    if not pre_identity.alive or not post_identity.alive:
        raise AttributionUnavailable("worker exit during query")
    if not _same_incarnation(pre_identity, post_identity):
        raise AttributionUnavailable("PID, namespace, cgroup, executable, or GPU identity changed")
    if pre_identity.cgroup_members != (pre_identity.host_pid,):
        raise AttributionUnavailable("unaccounted helper or child in admitted worker cgroup")
    required = {"entries", "complete", "gpu_uuid", "api_families", "api_identity",
                "api_version", "error", "pre_observed_ns", "start_ns", "end_ns",
                "post_observed_ns", "received_ns", "pid_namespace", "namespace_pid",
                "cgroup_path", "domain_members"}
    if type(query) is not dict or set(query) != required:
        raise AttributionUnavailable("closed GPU query record required")
    if (type(query["complete"]) is not bool or not query["complete"] or
            query["error"] is not None):
        raise AttributionUnavailable("GPU accounting unavailable or partial")
    if query["gpu_uuid"] != pre_identity.gpu_uuid:
        raise AttributionUnavailable("wrong GPU UUID")
    if (query["pid_namespace"] != pre_identity.pid_namespace or
            query["namespace_pid"] != pre_identity.namespace_pid or
            query["cgroup_path"] != pre_identity.cgroup_path or
            query["domain_members"] != pre_identity.cgroup_members):
        raise AttributionUnavailable("namespace translation or admitted membership mismatch")
    if (type(query["api_families"]) is not tuple or
            set(query["api_families"]) != {"nvml-compute", "nvml-graphics"} or
            type(query["entries"]) is not tuple or
            type(query["api_identity"]) is not str or not query["api_identity"] or
            type(query["api_version"]) is not str or not query["api_version"] or
            any(type(query[name]) is not int for name in
                ("pre_observed_ns", "start_ns", "end_ns", "post_observed_ns", "received_ns")) or
            not (query["pre_observed_ns"] <= query["start_ns"] <= query["end_ns"] <=
                 query["post_observed_ns"] <= query["received_ns"])):
        raise AttributionUnavailable("GPU API coverage or query bracket")
    matches = []
    for entry in query["entries"]:
        if type(entry) is not dict or set(entry) != {
                "host_pid", "start_ticks", "gpu_uuid", "context_id", "used_bytes"}:
            raise AttributionUnavailable("malformed GPU accounting entry")
        if entry["host_pid"] == pre_identity.host_pid:
            if (entry["start_ticks"] != pre_identity.process_start_ticks or
                    entry["gpu_uuid"] != pre_identity.gpu_uuid):
                raise AttributionUnavailable("PID reuse or GPU identity conflict")
            if type(entry["context_id"]) is not str or not entry["context_id"]:
                raise AttributionUnavailable("context identity unavailable")
            if type(entry["used_bytes"]) is not int or entry["used_bytes"] < 0:
                raise AttributionUnavailable("accounting sentinel or unsupported field")
            matches.append(entry)
        else:
            raise AttributionUnavailable("unaccounted helper or child in worker domain")
    if not matches:
        raise AttributionUnavailable("exact worker accounting absent")
    unique = {(entry["context_id"], entry["used_bytes"]) for entry in matches}
    if len(unique) != 1:
        raise AttributionUnavailable("multiple or conflicting worker accounting entries")
    _, used_bytes = next(iter(unique))
    return GPUAttribution(True, used_bytes, None, len(query["entries"]),
                          pre_identity.gpu_uuid, pre_identity.host_pid,
                          pre_identity.process_start_ticks)


def enforce_f5_mapping(expected, observed):
    families = {"libcudart", "libcublasLt", "libcublas", "libcuda"}
    if type(expected) is not dict or type(observed) is not dict:
        raise AttributionUnavailable("mapping proof structures")
    if set(expected) != families or set(observed) != families:
        raise AttributionUnavailable("mapping families must be exact")
    for family in families:
        if (type(observed[family]) is not str or not observed[family] or
                observed[family] != expected[family]):
            raise AttributionUnavailable("observed mapping proof unavailable or mismatched")
    return True


class ImmutablePublication:
    """Lifecycle-bound exclusive publication with explicit durability states."""

    def __init__(self, authority=None):
        if (authority is None or not callable(getattr(authority, "publication_binding", None)) or
                not callable(getattr(authority, "perform_publication", None)) or
                not callable(getattr(authority, "publication_snapshot", None))):
            raise EvidenceError("authoritative publication supervisor required")
        self._intents = {}
        self._objects = {}
        self._durable = set()
        self._receipts = {}
        self._states = {}
        self._authority = authority
        self._authority_binding = authority.publication_binding()
        try:
            self._restore(authority.publication_snapshot(self._authority_binding))
        except AuthorizationDenied as exc:
            raise PublicationAuthorityDenied('publication history is not independently verified') from exc
        except RuntimeError as exc:
            raise EvidenceError('publication history unavailable') from exc

    def _restore(self, records):
        if type(records) is not list:
            raise EvidenceError("authoritative publication snapshot required")
        self._intents = {}
        self._objects = {}
        self._durable = set()
        self._receipts = {}
        self._states = {}
        for record in records:
            if type(record) is not dict:
                raise EvidenceError("malformed publication snapshot")
            state = record.get("state")
            key = (record.get("destination"), record.get("object_key"))
            if state == "PUBLICATION_INTENT":
                source = record.get("source_bytes")
                if (type(source) is not bytes or len(source) != record.get("length") or
                        _sha(source) != record.get("object_digest")):
                    raise EvidenceError("publication source reconstruction failed")
                intent = PublicationIntent(
                    record["intent_id"], key[0], key[1], record["object_digest"],
                    record["length"], source)
                prior = self._intents.get(key)
                if prior is not None and prior != intent:
                    raise EvidenceError("publication intent reconstruction collision")
                self._intents[key] = intent
                continue
            intent = self._intents.get(key)
            if intent is None or record.get("intent_id") != intent.intent_id:
                raise EvidenceError("publication transition lacks exact intent")
            if state == "EXCLUSIVE_CREATE":
                if self._states.get(key) is not None:
                    raise EvidenceError("exclusive reservation reconstruction failed")
                self._states[key] = "RESERVED"
            elif state == "PUBLICATION_WRITTEN":
                if self._states.get(key) != "RESERVED" or type(record.get("written_bytes")) is not bytes:
                    raise EvidenceError("written publication reconstruction failed")
                self._objects[key] = record["written_bytes"]
                self._states[key] = "WRITTEN"
            elif state == "DURABLE_BYTES":
                if self._states.get(key) != "WRITTEN" or key not in self._objects:
                    raise EvidenceError("durable publication reconstruction failed")
                self._durable.add(key)
                self._states[key] = "DURABLE"
            elif state == "PUBLICATION_VERIFIED":
                if (self._states.get(key) != "DURABLE" or key not in self._durable or
                        self._objects.get(key) != intent.bytes):
                    raise EvidenceError("verified publication reconstruction failed")
                receipt = PublicationReceipt(
                    "publication-receipt-" + intent.object_digest[:16],
                    intent.destination, intent.object_key, intent.object_digest,
                    intent.length, "PUBLICATION_VERIFIED", intent.object_digest)
                self._receipts[key] = receipt
                self._states[key] = "VERIFIED"
            else:
                raise EvidenceError("unknown publication reconstruction state")

    def _operate(self, operation, intent, interlock=None, payload=None):
        try:
            grant = self._authority.issue_publication_grant(
                self._authority_binding, operation, intent)
            result = self._authority.perform_publication(
                self._authority_binding, grant, intent, payload=payload,
                interlock=interlock)
            self._restore(self._authority.publication_snapshot(
                self._authority_binding))
            return result
        except AuthorizationDenied as exc:
            raise PublicationAuthorityDenied('publication authority rejected operation') from exc
        except (ContractError, RuntimeError) as exc:
            raise EvidenceError("publication authority rejected operation") from exc

    def _require_intent(self, intent):
        if not isinstance(intent, PublicationIntent):
            raise EvidenceError("authorized publication intent required")
        key = (intent.destination, intent.object_key)
        if self._intents.get(key) != intent:
            raise EvidenceError("authorized publication intent required")
        return key

    def intent(self, destination, object_key, bytes_value, interlock=None, *, source_proof=None):
        if type(destination) is not str or type(object_key) is not str or type(bytes_value) is not bytes:
            raise EvidenceError("publication intent")
        digest = _sha(bytes_value)
        identity = _sha(destination + "\0" + object_key + "\0" + digest)
        intent = PublicationIntent("publish-" + identity[:16], destination, object_key,
                                   digest, len(bytes_value), bytes_value)
        previous = self._intents.get((destination, object_key))
        if previous is not None and previous != intent:
            raise EvidenceError("publication intent collision")
        if previous is not None:
            return previous
        if source_proof is not None:
            authority = self._authority
            with authority.store.authorization_lock:
                authority._assert_publication_binding(self._authority_binding, mutation=True)
                port = authority.store._rp_port(authority.authorization, destination)
                port.bind_original_source(authority._actor, intent, source_proof)
        self._operate("intent", intent, interlock=interlock,
                      payload=bytes_value)
        return intent

    def exclusive_create(self, intent, interlock=None):
        key = self._require_intent(intent)
        if key in self._states:
            raise EvidenceError("exclusive object already exists")
        return self._operate("create", intent, interlock=interlock)

    def write(self, intent, bytes_value, allow_partial=False, interlock=None):
        key = self._require_intent(intent)
        if self._states.get(key) != "RESERVED":
            raise EvidenceError("exclusive create required")
        if not allow_partial and bytes_value != intent.bytes:
            raise EvidenceError("publication bytes differ from intent")
        return self._operate("write", intent, interlock=interlock,
                             payload=bytes_value)

    def make_durable(self, intent, interlock=None):
        key = self._require_intent(intent)
        if self._states.get(key) != "WRITTEN" or key not in self._objects:
            raise EvidenceError("written publication required")
        return self._operate("durable", intent, interlock=interlock)

    def write_durable(self, intent, bytes_value, allow_partial=False):
        self.write(intent, bytes_value, allow_partial=allow_partial)
        return self.make_durable(intent)

    def verify(self, intent, lose_ack=False, interlock=None):
        key = self._require_intent(intent)
        if key not in self._durable or self._states.get(key) != "DURABLE":
            raise EvidenceError("durable publication acknowledgement missing")
        readback = self._objects.get(key)
        if readback != intent.bytes or _sha(readback) != intent.object_digest:
            raise EvidenceError("external publication readback mismatch")
        receipt = self._operate("verify", intent, interlock=interlock)
        if lose_ack:
            raise PublicationAcknowledgementLost(receipt)
        return receipt

    def reconcile(self, intent, interlock=None):
        key = self._require_intent(intent)
        try:
            self._restore(self._authority.publication_snapshot(
                self._authority_binding))
        except (ContractError, RuntimeError) as exc:
            raise EvidenceError("publication authority rejected reconciliation") from exc
        if self._authority.store.publication_outcome_unknown(self._authority._publication_identity(intent)):
            return 'UNKNOWN'
        if key in self._receipts:
            return self._receipts[key]
        return self._states.get(key, "INTENT")


class PublicationScheduler:
    MEASURED_WINDOWS = frozenset(("MEASURED_PREPARATION", "DWELL", "RESIDUAL_CLEARANCE"))

    def schedule(self, window, publication_operation):
        if window in self.MEASURED_WINDOWS:
            raise EvidenceError("external publication prohibited during measured window")
        if window != "OUTSIDE_MEASURED_WINDOWS":
            raise EvidenceError("unknown scheduling window")
        return publication_operation


def build_closure_candidate(kind, payload):
    if kind not in ("boot", "campaign") or type(payload) is not dict:
        raise EvidenceError("closure candidate")
    forbidden = {"BOOT_COMPLETE", "CAMPAIGN_COMPLETE", "publication_receipt"}
    _validate_shape(payload)
    encoded_payload = canonical_core_bytes(payload)
    if any(name.encode("utf-8") in encoded_payload for name in forbidden):
        raise EvidenceError("closure candidate circularity")
    object_values = payload.get("objects")
    if type(object_values) not in (list, tuple) or not object_values:
        raise EvidenceError("closure object manifest")
    object_digests = tuple(_sha(canonical_core_bytes(value)) for value in object_values)
    record = {"candidate_type": kind, "payload": payload,
              "object_digests": list(object_digests)}
    encoded = canonical_core_bytes(record)
    return ClosureCandidate(kind, _sha(encoded), encoded, object_digests)


def complete_closure(candidate, publication_receipt, revision, fence_epoch, tainted):
    if not isinstance(candidate, ClosureCandidate):
        raise EvidenceError("persisted closure candidate required")
    receipts = (publication_receipt,) if isinstance(publication_receipt, PublicationReceipt) else publication_receipt
    if (type(receipts) is not tuple or
            any(not isinstance(receipt, PublicationReceipt) for receipt in receipts)):
        raise EvidenceError("verified publication receipts required")
    if type(revision) is not int or type(fence_epoch) is not int or type(tainted) is not bool:
        raise EvidenceError("closure revision/fence/taint types")
    if tainted:
        raise EvidenceError("intervening taint prevents closure")
    digests = [receipt.object_digest for receipt in receipts]
    required = [candidate.digest, *candidate.object_digests]
    if len(digests) != len(required) or sorted(digests) != sorted(required):
        raise EvidenceError("publication receipts do not cover exact candidate manifest")
    candidate_receipt = next(receipt for receipt in receipts
                             if receipt.object_digest == candidate.digest)
    return {"state": "BOOT_COMPLETE" if candidate.kind == "boot" else "CAMPAIGN_COMPLETE",
            "candidate_digest": candidate.digest,
            "candidate_kind": candidate.kind,
            "publication_receipt_id": candidate_receipt.receipt_id,
            "publication_manifest": sorted(digests),
            "revision": revision, "fence_epoch": fence_epoch}
