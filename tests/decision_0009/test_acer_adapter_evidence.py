import json
import unittest
import copy


class CheckpointCClosedContractTests(unittest.TestCase):
    def test_destination_receipt_rejects_unknown_keys_and_unproven_owner(self):
        from tools.decision_0009.acer_adapter.contracts import validate_destination_receipt, ContractError
        from acer_adapter_fakes import digest
        receipt = dict(port_identity='port-1', destination_id='destination', object_key='evidence/a',
            original_intent_ref=dict(event_id='intent', revision=1, payload_digest=digest('intent')),
            authorization_digest=digest('approval'), campaign_id='campaign-1',
            reservation_owner_id='original-owner', logical_operation_id='write-1',
            operation_status='NOT_STARTED', bytes_digest=digest(''), length=0,
            writer_fence=2, outcome='OWNED_EMPTY_RESERVED', object_durable=False,
            namespace_durable=False, port_attestation=digest('receipt'))
        self.assertEqual(validate_destination_receipt(receipt), receipt)
        for changes in ({'reservation_owner_id': None}, {'length': None},
                        {'operation_status': 'READY'}, {'extra': True}):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                validate_destination_receipt(dict(receipt, **changes))

class CheckpointCIntegrationTests(unittest.TestCase):
    def world(self, *, empty=False, source_proof=True, configure=None, chair_service_factory=None,
              separate_supplement_destination=False):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.contracts import DestinationRule, ObjectRule, SupplementRule, authorization_digest
        from tools.decision_0009.acer_adapter.evidence import OfflinePublicationDestination
        pipeline = EvidencePipeline(max_frame_bytes=8_388_608)
        value = {'campaign_id': 'campaign-1', 'failure': 'offline-test'}
        raw = b'' if empty else canonical_core_bytes(value)
        captured = pipeline.capture('test-source', raw, 1, 1)
        obj = pipeline.freeze_raw(captured) if empty else pipeline.freeze_core(value, pipeline.normalize(captured, value))
        port = OfflinePublicationDestination('destination-port-1', 'destination',
                                            producers=(('normalizer-1', pipeline),))
        destinations = (port,)
        if separate_supplement_destination:
            destinations += (OfflinePublicationDestination('supplement-port', 'supplement-destination'),)
        def setup(auth):
            auth = replace(auth, destination_rules=(DestinationRule('dest-rule', 'destination',
                'destination-port-1', 'evidence', 'OBJECT_AND_NAMESPACE', 'ALL_LOWER_WRITERS'),),
                object_rules=(ObjectRule('object-rule', 'campaign-1', 'FAILURE_EVIDENCE',
                                         'destination', 'evidence/failure'),),
                supplement_rules=(SupplementRule('supplement-rule', 'destination', 'evidence',
                    ('FAILURE_EVIDENCE',), ('PUBLICATION_READBACK',), 'RECOVERY_SUPPLEMENT_V1'),))
            if separate_supplement_destination:
                auth = replace(auth, destination_rules=auth.destination_rules + (
                    DestinationRule('supplement-dest-rule', 'supplement-destination', 'supplement-port',
                                    'supplements', 'OBJECT_AND_NAMESPACE', 'ALL_LOWER_WRITERS'),),
                    supplement_rules=(SupplementRule('supplement-rule', 'supplement-destination', 'supplements',
                        ('FAILURE_EVIDENCE',), ('PUBLICATION_READBACK',), 'RECOVERY_SUPPLEMENT_V1'),))
            if configure is not None:
                auth = configure(auth)
            return replace(auth, authorization_digest=authorization_digest(auth)), destinations
        supervisor, _, custodian = make_supervisor(publication_setup=setup, chair_service_factory=chair_service_factory)
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent('destination', 'evidence/failure', obj.bytes,
                                  source_proof=(pipeline, obj) if source_proof else None)
        return supervisor, custodian, publisher, intent, port

    def test_original_destination_records_actual_owned_empty_and_written_bytes(self):
        supervisor, _, publisher, intent, port = self.world()
        self.assertNotIn(intent.object_key, port._objects)
        publisher.exclusive_create(intent)
        self.assertEqual(port._objects[intent.object_key]['bytes'], b'')
        publisher.write_durable(intent, intent.bytes)
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
        self.assertTrue(port._objects[intent.object_key]['namespace_durable'])
        self.assertEqual(publisher.verify(intent).object_digest, intent.object_digest)

    def test_recovery_binding_never_reuses_normal_execution_authority(self):
        supervisor, _, _, _, _ = self.world()
        method = getattr(supervisor.store, 'recovery_publication_binding', None)
        self.assertTrue(callable(method), 'dedicated RP authority required')
        with self.assertRaises(AuthorizationDenied):
            method(supervisor._actor, supervisor.authorization)

    def recover(self, supervisor):
        store = supervisor.store
        store.reset_volatile()
        actor = store.open_nonlive_entry(supervisor.authorization, 'recovery-reader-1')
        return store.recovery_publication_binding(actor, supervisor.authorization)

    def original_ref(self, supervisor):
        return supervisor.store._reference(next(f['receipt'] for f in supervisor.store._committed_frames()
            if f['event'].get('operation') == 'intent' and
            supervisor.store.publication_record_provenanced(f, phase='INTENT')))

    def test_absent_original_recovers_once_then_durability_and_verification(self):
        supervisor, _, _, intent, port = self.world()
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        for operation in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = store.recovery_publication_subject(binding, original, operation)
            receipt = store.perform_recovery_publication(binding, subject, operation)
        self.assertEqual(store._exact_ref(store._reference(receipt))['event']['record_type'],
                         'RECOVERY_PUBLICATION_VERIFIED')
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        before = (store.revision, len(store._objects), dict(port._counts))
        with self.assertRaises(AuthorizationDenied):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(before, (store.revision, len(store._objects), dict(port._counts)))
        self.assertFalse(binding.actor.execution_live)

    def test_original_owned_empty_continues_once_and_old_binding_dies(self):
        supervisor, _, publisher, intent, port = self.world()
        publisher.exclusive_create(intent)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = supervisor.store.recovery_publication_subject(binding, original, 'CONTINUE_RESERVED_EXACT')
        supervisor.store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT')
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
        old_grant = next(iter(supervisor.store._rp_grants.values()))
        self.recover(supervisor)
        with self.assertRaises(AuthorizationDenied):
            port.initiate_recovery(old_grant)

    def test_empty_final_payload_verifies_without_content_write(self):
        supervisor, _, publisher, intent, port = self.world(empty=True)
        publisher.exclusive_create(intent)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        initial = dict(port._counts)
        for op in ('ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = supervisor.store.recovery_publication_subject(binding, original, op)
            supervisor.store.perform_recovery_publication(binding, subject, op)
        self.assertEqual(port._objects[intent.object_key]['bytes'], b'')
        self.assertFalse(port._objects[intent.object_key]['written'])
        self.assertEqual(len(port._counts) - len(initial), 2)
        subject = supervisor.store.recovery_publication_subject(binding, original, 'CONTINUE_RESERVED_EXACT')
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT')

    def test_matching_source_bytes_without_actual_original_producer_binding_deny(self):
        supervisor, _, _, _, _ = self.world(source_proof=False)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        before = (supervisor.store.revision, dict(supervisor.store._objects))
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(before, (supervisor.store.revision, dict(supervisor.store._objects)))

    def test_committed_readback_supplement_publishes_only_its_derived_child(self):
        supervisor, _, _, intent, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = store.recovery_publication_subject(binding, original, op)
            verified = store.perform_recovery_publication(binding, subject, op)
        record = store._exact_ref(store._reference(verified))['event']
        parent = record['result_refs'][0]
        raw = store._object_proof(record['independent_readback'])
        rw = store.recovery_writer_binding(binding.actor)
        supplement = store.record_recovery_supplement(rw, parent_ref=parent,
            supplement_kind='PUBLICATION_READBACK', evidence_bytes=raw,
            source_id=port.port_identity, verifier_id=port.port_identity)
        method = getattr(store, 'recovery_supplement_subject', None)
        self.assertTrue(callable(method), 'committed supplement publication branch required')
        subject = method(binding, original, store._reference(supplement), 'ENSURE_EXACT_OBJECT',
                         policy_rule_id='supplement-rule')
        store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(port._objects[subject['object_key']]['bytes'], raw)
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)

    def supplement_world(self, *, separate=False):
        supervisor, _, publisher, intent, original_port = self.world(
            separate_supplement_destination=separate)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, intent.bytes)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
        verified = store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
        event = store._exact_ref(store._reference(verified))['event']
        raw = store._object_proof(event['independent_readback'])
        supplement = store.record_recovery_supplement(store.recovery_writer_binding(binding.actor),
            parent_ref=event['result_refs'][0], supplement_kind='PUBLICATION_READBACK',
            evidence_bytes=raw, source_id=original_port.port_identity,
            verifier_id=original_port.port_identity)
        child = store.recovery_supplement_subject(binding, original, store._reference(supplement),
            'ENSURE_EXACT_OBJECT', policy_rule_id='supplement-rule')
        destination = store._publication_destinations[-1]
        return store, binding, child, destination, original_port, intent

    def supplement_facts(self, port, child):
        # Capture the affected C facts without copying pinned producer instances.
        key = child['object_key']
        return copy.deepcopy(dict(subject=port._subjects.get(key), source=port._sources.get(key),
            object=port._objects.get(key), operations=port._operations, receipts=port._receipts,
            exclusions=port._exclusions, claims=port._claims, counts=port._counts,
            grant_results=port._grant_results, reserved=port._reserved_subjects,
            eligible=port._eligible_grants))

    def check_supplement_registry_loss(self, retained, states=('CLAIMED', 'IN_FLIGHT', 'COMPLETE')):
        faults = {'NOT_STARTED': 'before_claim', 'CLAIMED': 'after_claim',
                  'IN_FLIGHT': 'after_initiation', 'UNKNOWN': 'after_initiation'}
        for separate in (False, True):
            for status in states:
                with self.subTest(retained=retained, status=status, separate=separate):
                    store, binding, child, port, original_port, intent = self.supplement_world(separate=separate)
                    if status == 'COMPLETE':
                        store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT')
                    else:
                        with self.assertRaises(PublicationAcknowledgementLost):
                            store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT',
                                fault_at='destination', fault=faults[status])
                    operation_id = child['logical_operation_id']
                    old_grant = next(g for g in store._rp_grants.values()
                                     if json.loads(g.canonical_bytes)['logical_operation_id'] == operation_id)
                    if status == 'UNKNOWN':
                        port._operations[operation_id]['status'] = 'UNKNOWN'
                    self.assertEqual(port._operations[operation_id]['status'], status)
                    accepted = [f['event'] for f in store._committed_frames()
                        if f['event'].get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' and
                        f['event'].get('logical_operation_id') == operation_id]
                    self.assertEqual(len(accepted), 1)
                    key = child['object_key']
                    port._objects.pop(key, None)
                    port._reserved_subjects.remove(key)
                    if retained not in ('subject', 'both'):
                        port._subjects.pop(key)
                    if retained not in ('operation', 'both'):
                        for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                            port._operations.pop(port.operation_id(child, op))
                    if retained == 'journal':
                        # Erase all remaining child C evidence, leaving only the
                        # exact committed acceptance in D as the no-freshness proof.
                        port._exclusions.pop(key, None)
                        port._eligible_grants.pop(operation_id, None)
                        port._claims.discard(accepted[0]['consumption_id'])
                        port._counts.pop(accepted[0]['grant_id'], None)
                        port._grant_results.pop(accepted[0]['grant_id'], None)
                        port._receipts = {raw: fact for raw, fact in port._receipts.items()
                                          if fact[0]['object_key'] != key}
                    before = self.supplement_facts(port, child)
                    grants = dict(store._rp_grants)
                    observed = store.query_recovery_publication(binding, child)
                    self.assertEqual(self.supplement_facts(port, child), before)
                    event = store._exact_ref(store._reference(observed))['event']
                    self.assertEqual((event['outcome'], event['reason_code']),
                                     ('UNKNOWN', 'DESTINATION_REGISTRY_UNAVAILABLE'))
                    with self.assertRaises(AuthorizationDenied):
                        store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT')
                    with self.assertRaises(AuthorizationDenied):
                        port.initiate_recovery(old_grant)
                    self.assertEqual(self.supplement_facts(port, child), before)
                    self.assertEqual(store._rp_grants, grants)
                    after = [f['event'] for f in store._committed_frames()
                        if f['event'].get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' and
                        f['event'].get('logical_operation_id') == operation_id]
                    self.assertEqual(after, accepted)
                    self.assertNotIn(key, port._objects)
                    self.assertEqual(original_port._objects[intent.object_key]['bytes'], intent.bytes)

    def test_supplement_registry_loss_retained_subject_absent_bytes(self):
        self.check_supplement_registry_loss('subject')

    def test_supplement_registry_loss_retained_operation_absent_bytes(self):
        self.check_supplement_registry_loss('operation')

    def test_supplement_registry_loss_retained_both_absent_bytes(self):
        self.check_supplement_registry_loss('both')

    def test_supplement_registry_loss_committed_acceptance_only_absent_bytes(self):
        self.check_supplement_registry_loss('journal')

    def test_supplement_registry_loss_unknown_and_accepted_unstarted_are_query_only(self):
        self.check_supplement_registry_loss('operation', ('UNKNOWN', 'NOT_STARTED'))

    def test_register_supplement_never_overwrites_retained_operation_records(self):
        for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            for status in ('NOT_STARTED', 'CLAIMED', 'IN_FLIGHT', 'COMPLETE', 'UNKNOWN'):
                with self.subTest(operation=op, status=status):
                    store, binding, child, port, _, _ = self.supplement_world(separate=True)
                    port.available = False
                    store.query_recovery_publication(binding, child)
                    committed = next(f for f in reversed(list(store._committed_frames()))
                        if f['event'].get('record_type') == 'RECOVERY_PUBLICATION_INTENT' and
                        f['event'].get('logical_operation_id') == child['logical_operation_id'])
                    port.available = True
                    port._operations[port.operation_id(child, op)] = {'status': status, 'result': None}
                    before = self.supplement_facts(port, child)
                    port.register_supplement(binding, child, store._reference(committed['receipt']))
                    self.assertEqual(self.supplement_facts(port, child), before)

    def test_supplement_registry_loss_positive_never_registered_control(self):
        for separate in (False, True):
            with self.subTest(separate=separate):
                store, binding, child, port, original_port, intent = self.supplement_world(separate=separate)
                key = child['object_key']
                self.assertNotIn(key, port._reserved_subjects)
                self.assertNotIn(key, port._subjects)
                self.assertNotIn(child['logical_operation_id'], port._operations)
                self.assertFalse(any(f['event'].get('logical_operation_id') == child['logical_operation_id']
                    for f in store._committed_frames()))
                queried = store.query_recovery_publication(binding, child)
                self.assertEqual(store._exact_ref(store._reference(queried))['event']['outcome'], 'ABSENT_PROVEN')
                store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT')
                self.assertEqual(port._operations[child['logical_operation_id']]['status'], 'COMPLETE')
                self.assertEqual(port._objects[key]['bytes'], store._object_proof(child['source_object']))
                for operation in ('ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                    followup = store.recovery_supplement_subject(binding, child['original_intent_ref'],
                        child['supplement_ref'], operation, policy_rule_id='supplement-rule')
                    receipt = store.perform_recovery_publication(binding, followup, operation)
                self.assertEqual(store._exact_ref(store._reference(receipt))['event']['record_type'],
                                 'RECOVERY_PUBLICATION_VERIFIED')
                self.assertEqual(original_port._objects[intent.object_key]['bytes'], intent.bytes)

    def test_continuation_observations_preserve_conflicts_and_unknown_precedence(self):
        cases = ('absent', 'owned-empty', 'written', 'durable', 'partial', 'wrong',
                 'wrong-owner', 'unknown-owner', 'unproven-empty', 'in-flight-partial',
                 'unknown-operation', 'registry-loss', 'destination-loss')
        expected = ('ABSENT_PROVEN', 'OWNED_EMPTY_RESERVED', 'EXACT_PRESENT', 'DURABILITY_ESTABLISHED',
                    'PARTIAL', 'CONTENT_CONFLICT', 'OWNER_CONFLICT', 'UNKNOWN', 'UNKNOWN',
                    'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN')
        for case, outcome in zip(cases, expected):
            with self.subTest(case=case):
                supervisor, _, publisher, intent, port = self.world()
                original = self.original_ref(supervisor)
                if case != 'absent':
                    publisher.exclusive_create(intent)
                if case in ('written', 'durable'):
                    publisher.write(intent, intent.bytes)
                    if case == 'durable':
                        publisher.make_durable(intent)
                obj = port._objects.get(intent.object_key)
                if case in ('partial', 'in-flight-partial'):
                    obj['bytes'], obj['written'] = intent.bytes[:3], True
                if case == 'wrong':
                    obj['bytes'], obj['written'] = b'x' * len(intent.bytes), True
                if case == 'wrong-owner':
                    obj['owner'] = 'other-original-owner'
                if case == 'unknown-owner':
                    obj['owner'] = None
                if case == 'unproven-empty':
                    port._subjects[intent.object_key]['original_create_ref'] = None
                content = port.operation_id(port._subjects[intent.object_key], 'ENSURE_EXACT_OBJECT')
                if case in ('in-flight-partial', 'unknown-operation'):
                    port._operations[content]['status'] = 'IN_FLIGHT' if case == 'in-flight-partial' else 'UNKNOWN'
                if case == 'registry-loss':
                    port._operations.clear()
                if case == 'destination-loss':
                    port.available = False
                binding = self.recover(supervisor)
                subject = supervisor.store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                before = copy.deepcopy(port._objects)
                result = supervisor.store.query_recovery_publication(binding, subject)
                event = supervisor.store._exact_ref(supervisor.store._reference(result))['event']
                self.assertEqual(event['outcome'], outcome)
                self.assertEqual(port._objects, before)
                self.assertEqual(supervisor.store._independent_rp_conflict(event),
                                 outcome in ('PARTIAL', 'CONTENT_CONFLICT', 'OWNER_CONFLICT'))

    def test_recovery_permission_and_substitution_requests_have_zero_mutation(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.contracts import ContractError
        for op, permission in (('ENSURE_EXACT_OBJECT', 'WRITE_EXACT'),
                              ('CONTINUE_RESERVED_EXACT', 'WRITE_EXACT'),
                              ('ESTABLISH_DURABILITY', 'ESTABLISH_DURABILITY'),
                              ('VERIFY_EXACT_OBJECT', 'VERIFY_EXACT')):
            with self.subTest(operation=op):
                supervisor, _, _, _, port = self.world(configure=lambda a: replace(a,
                    evidence_operations=tuple(p for p in a.evidence_operations if p != permission)))
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                before = (supervisor.store.revision, dict(supervisor.store._objects), copy.deepcopy(port._objects))
                with self.assertRaises(ContractError):
                    supervisor.store.recovery_publication_subject(binding, original, op)
                self.assertEqual(before, (supervisor.store.revision, dict(supervisor.store._objects), port._objects))
        supervisor, _, _, _, port = self.world()
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        for field, wrong in (('subject_id', 'boot-2'), ('destination_id', 'other'),
                             ('object_key', 'evidence/other'), ('logical_operation_id', 'other'),
                             ('policy_rule_id', 'other'), ('original_or_supplement', 'SUPPLEMENT'),
                             ('producer_refs', []),
                             ('source_object', dict(subject['source_object'], sha256='0' * 64)),
                             ('source_object', dict(subject['source_object'], length=subject['source_object']['length'] + 1)),
                             ('extra', 'unknown')):
            bad = dict(subject, **{field: wrong})
            before = (store.revision, dict(store._objects), copy.deepcopy(port._objects), dict(port._exclusions))
            with self.subTest(field=field), self.assertRaises((ContractError, KeyError, TypeError)):
                store.perform_recovery_publication(binding, bad, 'ENSURE_EXACT_OBJECT')
            self.assertEqual(before, (store.revision, dict(store._objects), port._objects, port._exclusions))

    def test_all_four_rp_records_use_the_eight_journal_crash_windows(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        stages = ('before_reservation', 'reservation_response_lost', 'reserved_before_frame',
            'frame_before_readback', 'readback_mismatch', 'readback_unavailable',
            'validated_before_commit', 'commit_before_ack')
        for record in ('intent', 'accepted', 'result', 'verified'):
            for stage in stages:
                with self.subTest(record=record, stage=stage):
                    supervisor, _, publisher, intent, port = self.world()
                    if record == 'verified':
                        publisher.exclusive_create(intent)
                        publisher.write_durable(intent, intent.bytes)
                    original = self.original_ref(supervisor)
                    binding = self.recover(supervisor)
                    store = supervisor.store
                    op = 'VERIFY_EXACT_OBJECT' if record == 'verified' else 'ENSURE_EXACT_OBJECT'
                    subject = store.recovery_publication_subject(binding, original, op)
                    before = dict(port._counts)
                    with self.assertRaises(StoreError):
                        store.perform_recovery_publication(binding, subject, op, fault_at=record, fault=stage)
                    self.assertEqual(len(port._counts) - len(before), int(record in ('result', 'verified')))
                    if stage in ('frame_before_readback', 'validated_before_commit'):
                        retained = store._durable[-1]['bytes']
                        for interrupted in ('before_commit', 'lost_ack'):
                            with self.subTest(reconciliation=interrupted), self.assertRaises(StoreError):
                                store.reconcile_pending(store._authentication_service, supervisor.authorization,
                                                        fault=interrupted)
                        reconciled = store.reconcile_pending(store._authentication_service, supervisor.authorization)
                        self.assertEqual(store._durable[-1]['bytes'], retained)
                        self.assertEqual(store.witness.query_transaction(reconciled.event_id)[1].completion_mode,
                                         'RECOVERY_RECONCILE')
                        self.assertIsNone(store._rp_binding)
                        self.assertEqual(len(port._counts) - len(before), int(record in ('result', 'verified')))

    def test_destination_crash_claim_start_bytes_and_result_never_replay(self):
        stages = ('before_claim', 'after_claim', 'after_initiation', 'after_bytes', 'after_readback')
        for stage in stages:
            with self.subTest(stage=stage):
                supervisor, _, _, intent, port = self.world()
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                with self.assertRaises(PublicationAcknowledgementLost):
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT',
                        fault_at='destination', fault=stage)
                old = next(iter(store._rp_grants.values()))
                binding = self.recover(supervisor)
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                with self.assertRaises(AuthorizationDenied):
                    port.initiate_recovery(old)
                result = store.query_recovery_publication(binding, subject)
                outcome = store._exact_ref(store._reference(result))['event']['outcome']
                self.assertEqual(outcome, 'ABSENT_PROVEN' if stage == 'before_claim' else
                                 'EXACT_PRESENT' if stage == 'after_readback' else 'UNKNOWN')
                if stage == 'before_claim':
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                    self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
                else:
                    before = (store.revision, dict(store._objects), dict(port._counts))
                    with self.assertRaises(AuthorizationDenied):
                        store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                    self.assertEqual(before, (store.revision, dict(store._objects), dict(port._counts)))

    def test_quarantine_and_unavailable_witness_do_not_append_or_publish(self):
        for health in ('quarantine', 'witness-unavailable', 'reconcilable', 'unknown'):
            with self.subTest(health=health):
                supervisor, _, _, _, port = self.world()
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                if health == 'quarantine':
                    store.quarantined = True
                elif health == 'witness-unavailable':
                    store.witness.available = False
                else:
                    rw = store.recovery_writer_binding(binding.actor)
                    with self.assertRaises(RuntimeError):
                        store.record_recovery_entry(rw, fault='frame_before_readback' if health == 'reconcilable'
                                                    else 'readback_unavailable')
                before = (store.revision, dict(store._objects), copy.deepcopy(port._objects), dict(port._counts))
                with self.assertRaises((AuthorizationDenied, RuntimeError)):
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                self.assertEqual(before, (store.revision, dict(store._objects), port._objects, port._counts))

    def test_invalid_bindings_receipts_and_generic_lower_writer_cannot_mutate(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes, ContractError
        supervisor, _, _, _, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        for bad in (copy.copy(binding), replace(binding, actor=replace(binding.actor)),
                    replace(binding, authorization=replace(binding.authorization, authenticated=False))):
            before = (store.revision, dict(store._objects), dict(port._counts))
            with self.subTest(binding=type(bad).__name__), self.assertRaises(AuthorizationDenied):
                store.perform_recovery_publication(bad, subject, 'ENSURE_EXACT_OBJECT')
            self.assertEqual(before, (store.revision, dict(store._objects), port._counts))
        result = store.query_recovery_publication(binding, subject)
        observation = store._exact_ref(store._reference(result))['event']
        raw = store._object_proof(observation['destination_receipt'])
        altered = dict(json.loads(raw), object_key='evidence/forged')
        with self.assertRaises(AuthorizationDenied):
            port.authenticate_receipt(closed_canonical_bytes(altered))
        before = (store.revision, dict(store._objects))
        with self.assertRaises(AuthorizationDenied):
            store.put_object('rp-proof-' + __import__('hashlib').sha256(raw).hexdigest(), raw,
                             actor=binding.actor, boundary='RP')
        self.assertEqual(before, (store.revision, dict(store._objects)))
        rw = store.recovery_writer_binding(binding.actor)
        for change in ({'reason_code': 'PARTIAL_OBJECT'}, {'kind': 'EFFECT_RESULT_UNRESOLVED'},
                       {'target_ref': dict(kind='DESTINATION', identity='forged-port', destination_id='destination',
                            object_key='evidence/failure', subject_ref=original, subject_state='KNOWN',
                            evidence_ref=observation['destination_receipt'], evidence_state='AVAILABLE')}):
            args = dict(obligation_id='false-obligation', kind='PUBLICATION_UNVERIFIED', reason_code='OUTCOME_UNKNOWN',
                subject_refs=[original, store._reference(result)], target_ref=dict(kind='DESTINATION',
                    identity=port.port_identity, destination_id=port.destination_id, object_key=subject['object_key'],
                    subject_ref=original, subject_state='KNOWN', evidence_ref=observation['destination_receipt'],
                    evidence_state='AVAILABLE'))
            args.update(change)
            with self.subTest(change=change), self.assertRaises(ContractError):
                store.record_recovery_obligation(rw, **args)
            self.assertEqual(before, (store.revision, dict(store._objects)))

    def test_durability_boundaries_and_verified_history_do_not_restart(self):
        for stage in ('after_object_durability', 'after_namespace_durability', 'before_readback', 'after_readback'):
            with self.subTest(stage=stage):
                supervisor, _, publisher, intent, port = self.world()
                publisher.exclusive_create(intent)
                publisher.write(intent, intent.bytes)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ESTABLISH_DURABILITY')
                with self.assertRaises(PublicationAcknowledgementLost):
                    store.perform_recovery_publication(binding, subject, 'ESTABLISH_DURABILITY',
                        fault_at='destination', fault=stage)
                binding = self.recover(supervisor)
                before = dict(port._counts)
                subject = store.recovery_publication_subject(binding, original, 'ESTABLISH_DURABILITY')
                result = store.query_recovery_publication(binding, subject)
                self.assertEqual(store._exact_ref(store._reference(result))['event']['outcome'],
                                 'DURABILITY_ESTABLISHED' if stage == 'after_readback' else 'UNKNOWN')
                self.assertEqual(port._counts, before)
        supervisor, _, _, _, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = store.recovery_publication_subject(binding, original, op)
            verified = store.perform_recovery_publication(binding, subject, op)
        binding = self.recover(supervisor)
        before = (store.revision, dict(port._counts))
        subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
        self.assertEqual(store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT'), verified)
        self.assertEqual(before, (store.revision, port._counts))

    def test_another_valid_approval_is_not_the_original_admitted_rp_authority(self):
        from dataclasses import replace
        from acer_adapter_fakes import offline_chair_service
        from tools.decision_0009.acer_adapter.contracts import authorization_digest
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthorizationVerifier
        alternate = []
        def enrolled(auth):
            other = replace(auth, authorization_id='second-valid-approval', nonce='second-valid-nonce')
            other = replace(other, authorization_digest=authorization_digest(other))
            alternate.append(other)
            first, second = offline_chair_service(auth), offline_chair_service(other)
            return OfflineChairAuthorizationVerifier(replace(first.root,
                approvals=first.root.approvals + second.root.approvals))
        supervisor, _, _, _, port = self.world(chair_service_factory=enrolled)
        binding = self.recover(supervisor)
        store = supervisor.store
        self.assertEqual(store._authentication_service.verify(alternate[0], store_identity=store.identity,
            campaign_id=supervisor.authorization.campaign_id).authorization_id, 'second-valid-approval')
        before = (store.revision, dict(store._objects), dict(port._counts))
        with self.assertRaises(AuthorizationDenied):
            store.recovery_publication_binding(binding.actor, alternate[0])
        self.assertEqual(before, (store.revision, dict(store._objects), port._counts))

    def test_operations_need_only_their_own_permission_plus_observation(self):
        from dataclasses import replace
        for operation in ('ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            with self.subTest(operation=operation):
                permission = 'WRITE_EXACT' if operation in ('ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT') else (
                    'ESTABLISH_DURABILITY' if operation == 'ESTABLISH_DURABILITY' else 'VERIFY_EXACT')
                supervisor, _, publisher, intent, port = self.world(configure=lambda a: replace(a,
                    evidence_operations=tuple(p for p in a.evidence_operations if p in (permission, 'VERIFY_EXACT'))))
                if operation != 'ENSURE_EXACT_OBJECT':
                    publisher.exclusive_create(intent)
                if operation in ('ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                    publisher.write(intent, intent.bytes)
                if operation == 'VERIFY_EXACT_OBJECT':
                    publisher.make_durable(intent)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                subject = supervisor.store.recovery_publication_subject(binding, original, operation)
                self.assertTrue(supervisor.store.perform_recovery_publication(binding, subject, operation).durable)

    def test_wrong_publisher_and_false_recovery_flag_cannot_issue_rp(self):
        from dataclasses import replace
        for change in ({'recovery_publisher_ids': ('other-reader',)}, {'exact_byte_recovery_authorized': False}):
            with self.subTest(change=change):
                supervisor, _, _, _, port = self.world(configure=lambda a: replace(a, **change))
                store = supervisor.store
                store.reset_volatile()
                actor = store.open_nonlive_entry(supervisor.authorization, 'recovery-reader-1')
                before = (store.revision, dict(store._objects), dict(port._counts))
                with self.assertRaises(AuthorizationDenied):
                    store.recovery_publication_binding(actor, supervisor.authorization)
                self.assertEqual(before, (store.revision, dict(store._objects), port._counts))

    def test_readback_loss_records_unknown_and_never_rewrites_completed_bytes(self):
        for originally_written in (False, True):
            with self.subTest(originally_written=originally_written):
                supervisor, _, publisher, intent, port = self.world()
                if originally_written:
                    publisher.exclusive_create(intent)
                    publisher.write_durable(intent, intent.bytes)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                port.readback_available = False
                if originally_written:
                    result = store.query_recovery_publication(binding, subject)
                else:
                    result = store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                event = store._exact_ref(store._reference(result))['event']
                self.assertEqual((event['outcome'], event['reason_code'], event['destination_receipt']),
                                 ('UNKNOWN', 'READBACK_UNAVAILABLE', None))
                self.assertFalse(store._independent_rp_conflict(event))
                before = dict(port._counts)
                port.readback_available = True
                binding = self.recover(supervisor)
                with self.assertRaises(AuthorizationDenied):
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                self.assertEqual(port._counts, before)
                self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)

    def test_query_only_permission_and_each_supplement_permission_overlay(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.contracts import ContractError
        supervisor, _, _, _, port = self.world(configure=lambda a: replace(a,
            evidence_operations=('VERIFY_EXACT',)))
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'QUERY')
        counts = dict(port._counts)
        observed = store.query_recovery_publication(binding, subject)
        self.assertEqual(store._exact_ref(store._reference(observed))['event']['outcome'], 'ABSENT_PROVEN')
        self.assertEqual(port._counts, counts)
        self.assertFalse(store._rp_grants)
        for op in ('ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT', 'ESTABLISH_DURABILITY'):
            with self.subTest(operation=op), self.assertRaises(ContractError):
                store.perform_recovery_publication(binding, subject, op)
        supervisor, _, publisher, intent, port = self.world(configure=lambda a: replace(a,
            evidence_operations=tuple(p for p in a.evidence_operations if p != 'PUBLISH_RECOVERY_SUPPLEMENT')))
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, intent.bytes)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
        verified = store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
        event = store._exact_ref(store._reference(verified))['event']
        supplement = store.record_recovery_supplement(store.recovery_writer_binding(binding.actor),
            parent_ref=event['result_refs'][0], supplement_kind='PUBLICATION_READBACK',
            evidence_bytes=store._object_proof(event['independent_readback']),
            source_id=port.port_identity, verifier_id=port.port_identity)
        before = (store.revision, dict(store._objects), dict(port._counts))
        for op in ('QUERY', 'ENSURE_EXACT_OBJECT', 'CONTINUE_RESERVED_EXACT',
                   'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            with self.subTest(supplement_operation=op), self.assertRaises(ContractError):
                store.recovery_supplement_subject(binding, original, store._reference(supplement), op,
                                                 policy_rule_id='supplement-rule')
            self.assertEqual(before, (store.revision, dict(store._objects), port._counts))

    def test_exact_original_intent_producer_and_port_cannot_be_substituted(self):
        from tools.decision_0009.acer_adapter.contracts import ContractError
        supervisor, _, publisher, intent, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = store.recovery_publication_subject(binding, original, 'QUERY')
        aliases = [store._reference(f['receipt']) for f in store._committed_frames()
                   if f['event'].get('record_type') == 'PUBLICATION' and
                   store._reference(f['receipt']) != original]
        for ref in aliases:
            before = store.revision
            with self.subTest(reference=ref['event_id']), self.assertRaises(AuthorizationDenied):
                store.query_recovery_publication(binding, dict(subject, original_intent_ref=ref))
            self.assertEqual(store.revision, before)
        clone = copy.copy(port)
        before = (store.revision, dict(store._objects), copy.deepcopy(port._objects), dict(port._exclusions))
        for action in (lambda: clone.observe(binding, subject),
                       lambda: clone.exclude_original_writers(binding, subject),
                       lambda: clone.validate_precondition(binding, subject, 'ENSURE_EXACT_OBJECT')):
            with self.assertRaises(AuthorizationDenied): action()
            self.assertEqual(before, (store.revision, dict(store._objects), port._objects, port._exclusions))
        subject_bad = dict(subject, source_object=dict(subject['source_object'], object_id='other-source'))
        with self.assertRaises(ContractError): store.query_recovery_publication(binding, subject_bad)
        port._producers[0][1]._objects.clear()
        with self.assertRaises(AuthorizationDenied): store.query_recovery_publication(binding, subject)
        self.assertEqual(before, (store.revision, dict(store._objects), port._objects, port._exclusions))

    def test_direct_result_writer_rejects_false_unknown_reason_and_wrong_proofs(self):
        from tools.decision_0009.acer_adapter.contracts import ContractError, validate_rp_record
        supervisor, _, _, _, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = store.recovery_publication_subject(binding, original, 'QUERY')
        port._operations[subject['logical_operation_id']]['status'] = 'UNKNOWN'
        result = store.query_recovery_publication(binding, subject)
        historical = store._exact_ref(store._reference(result))['event']
        event = dict(historical, **store._u04_common(binding.actor,
            'RECOVERY_PUBLICATION_RESULT', 'EVIDENCE', False))
        before = (store.revision, dict(store._objects), dict(store.witness.pending))
        for changes in ({'reason_code': 'AUTHORIZATION_MISSING'}, {'destination_receipt': None},
                        {'query_or_grant': 'GRANT'}, {'outcome': 'PARTIAL', 'reason_code': 'PARTIAL_OBJECT'},
                        {'extra': True}):
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                store._commit_u04(binding.actor, 'RP', dict(event, **changes))
        self.assertEqual(before, (store.revision, dict(store._objects), dict(store.witness.pending)))
        # A genuinely issued, previously unpersisted receipt cannot be used to
        # sneak an immutable object write ahead of full result validation.
        port._operations[subject['logical_operation_id']]['status'] = 'NOT_STARTED'
        raw, reason = port.observe(binding, subject)
        for bad_reason, bad_acceptance in (('OUTCOME_UNKNOWN', None), (reason, original)):
            with self.subTest(lower_result_reason=bad_reason), self.assertRaises(ContractError):
                store._record_rp_result(binding, subject, raw, bad_reason, bad_acceptance)
            self.assertEqual(before, (store.revision, dict(store._objects), dict(store.witness.pending)))
        for kind in ('RECOVERY_PUBLICATION_INTENT', 'RECOVERY_PUBLICATION_RESULT'):
            actual = next(f['event'] for f in store._committed_frames() if f['event'].get('record_type') == kind)
            for changes in ({'extra': True}, {'authorizes_execution': True}, {'authority_class': 'CONTROL'},
                            {'producer_refs': []}, {'source_object': None}):
                with self.subTest(record=kind, changes=changes), self.assertRaises(ContractError):
                    validate_rp_record(dict(actual, **changes))

    def test_completed_write_missing_object_and_other_unknown_writer_are_not_absence(self):
        for lost in ('object', 'other-operation'):
            with self.subTest(lost=lost):
                supervisor, _, publisher, intent, port = self.world()
                if lost == 'object':
                    publisher.exclusive_create(intent)
                    publisher.write(intent, intent.bytes)
                    port._objects.clear()
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                if lost == 'other-operation':
                    key = port.operation_id(port._subjects[intent.object_key], 'ESTABLISH_DURABILITY')
                    port._operations[key]['status'] = 'UNKNOWN'
                result = store.query_recovery_publication(binding, subject)
                self.assertEqual(store._exact_ref(store._reference(result))['event']['outcome'], 'UNKNOWN')
                before = (store.revision, dict(store._objects), dict(port._counts))
                with self.assertRaises(AuthorizationDenied):
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                self.assertEqual(before, (store.revision, dict(store._objects), port._counts))

    def test_destination_authorization_failure_requires_actual_original_target(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.contracts import ContractError
        for reason, change in (('AUTHORIZATION_MISSING', {'exact_byte_recovery_authorized': False}),
                               ('DESTINATION_UNAUTHORIZED', {'object_rules': ()})):
            with self.subTest(reason=reason):
                supervisor, _, _, intent, port = self.world(source_proof=False,
                    configure=lambda a: replace(a, **change))
                store = supervisor.store
                original = self.original_ref(supervisor)
                store.reset_volatile()
                actor = store.open_nonlive_entry(supervisor.authorization, 'recovery-reader-1')
                rw = store.recovery_writer_binding(actor)
                target = dict(kind='DESTINATION', identity=port.port_identity,
                    destination_id=port.destination_id, object_key=intent.object_key,
                    subject_ref=original, subject_state='KNOWN', evidence_ref=None, evidence_state='UNAVAILABLE')
                before = (store.revision, dict(store._objects), dict(port._counts))
                for altered in ({'object_key': 'evidence/unrelated'}, {'identity': 'forged-port'},
                                {'subject_state': 'UNKNOWN', 'subject_ref': None}):
                    with self.subTest(altered=altered), self.assertRaises(ContractError):
                        store.record_recovery_obligation(rw, obligation_id='authorization-failure',
                            kind='PUBLICATION_UNVERIFIED', reason_code=reason, subject_refs=[original],
                            target_ref=dict(target, **altered))
                    self.assertEqual(before, (store.revision, dict(store._objects), port._counts))
                result = store.record_recovery_obligation(rw, obligation_id='authorization-failure',
                    kind='PUBLICATION_UNVERIFIED', reason_code=reason, subject_refs=[original], target_ref=target)
                self.assertTrue(result.durable)
                self.assertEqual(port._counts, before[2])

    def test_competing_publishers_and_reset_orders_have_one_or_zero_initiations(self):
        import threading
        for order in ('competing', 'operation-first', 'loss-first'):
            with self.subTest(order=order):
                supervisor, _, _, _, port = self.world()
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                initial = dict(port._counts)
                entered, proceed = threading.Event(), threading.Event()
                errors = []
                def publish():
                    try: store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                    except AuthorizationDenied as exc: errors.append(exc)
                def run(action):
                    thread = threading.Thread(target=action, daemon=True)
                    thread.start()
                    return thread
                if order == 'loss-first':
                    store.reset_volatile()
                    threads = [run(publish)]
                else:
                    original_initiate = port.initiate_recovery
                    def paused(*args, **kwargs):
                        entered.set()
                        self.assertTrue(proceed.wait(5))
                        return original_initiate(*args, **kwargs)
                    port.initiate_recovery = paused
                    first = run(publish)
                    self.assertTrue(entered.wait(5))
                    second = run(publish if order == 'competing' else store.reset_volatile)
                    proceed.set()
                    threads = [first, second]
                for thread in threads: thread.join(5)
                self.assertFalse(any(t.is_alive() for t in threads))
                self.assertEqual(len(port._counts) - len(initial), int(order != 'loss-first'))
                self.assertEqual(len(errors), int(order != 'operation-first'))

    def test_reentrant_loss_at_final_precondition_and_superseded_grant_deny(self):
        for loss in ('freeze', 'reset', 'new-intent'):
            with self.subTest(loss=loss):
                supervisor, _, _, _, port = self.world()
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                with self.assertRaises(PublicationAcknowledgementLost):
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT',
                        fault_at='destination', fault='before_claim')
                old = next(iter(store._rp_grants.values()))
                if loss == 'new-intent':
                    store.query_recovery_publication(binding, subject)
                else:
                    validate = port.validate_precondition
                    def interrupted(*args, **kwargs):
                        result = validate(*args, **kwargs)
                        if loss == 'freeze': store.witness.freeze_actor(binding.actor)
                        else: store.reset_volatile()
                        return result
                    port.validate_precondition = interrupted
                before = (dict(port._counts), copy.deepcopy(port._objects), set(port._claims))
                with self.assertRaises((AuthorizationDenied, RuntimeError)):
                    port.initiate_recovery(old)
                self.assertEqual(before, (port._counts, port._objects, port._claims))

    def test_destination_settles_started_bytes_after_controller_loss_without_restart(self):
        supervisor, _, _, intent, port = self.world()
        store = supervisor.store
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        with self.assertRaises(PublicationAcknowledgementLost):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT',
                fault_at='destination', fault='after_bytes')
        store.reset_volatile()
        counts = dict(port._counts)
        # Trusted deterministic destination driver settles its *already started*
        # operation. It neither reconstructs bytes nor creates a new claim.
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
        operation = port._operations[subject['logical_operation_id']]
        self.assertEqual(operation['status'], 'IN_FLIGHT')
        operation['status'] = 'COMPLETE'
        actor = store.open_nonlive_entry(supervisor.authorization, 'recovery-reader-1')
        binding = store.recovery_publication_binding(actor, supervisor.authorization)
        result = store.query_recovery_publication(binding, subject)
        self.assertEqual(store._exact_ref(store._reference(result))['event']['outcome'], 'EXACT_PRESENT')
        with self.assertRaises(AuthorizationDenied):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(port._counts, counts)

    def test_publication_and_survivor_lifetimes_do_not_replace_custody_or_consumption(self):
        from acer_adapter_fakes import b_lifetimes, b_reader, digest
        for loss in ('origin', 'survivor', 'destination', 'witness'):
            with self.subTest(loss=loss):
                supervisor, custodian, _, _, port = self.world()
                supervisor.make_slot_eligible('slot-1-1')
                created = supervisor.spawn_worker('slot-1-1', digest('c-coexistence'))
                descriptor = custodian.establish_survivor_containment(created.spawn_token, supervisor._actor)
                factory = custodian._containment_factory
                lifetimes = b_lifetimes(custodian)
                entry = factory._entries[descriptor['delegation_id']]
                if loss == 'survivor': lifetimes.terminate(entry['endpoint'])
                if loss == 'origin': lifetimes.terminate(custodian)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                if loss == 'destination': port.available = False
                if loss == 'witness': store.witness.available = False
                prior = factory.inspect(descriptor['delegation_id'], reader=b_reader(factory))
                creates = custodian.underlying_create_count_for_all()
                subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT') if loss != 'witness' else None
                if loss in ('destination', 'witness'):
                    with self.assertRaises((AuthorizationDenied, RuntimeError)):
                        store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                else:
                    store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
                after = factory.inspect(descriptor['delegation_id'], reader=b_reader(factory))
                self.assertEqual(after, prior)
                self.assertEqual(custodian.underlying_create_count_for_all(), creates)
                self.assertFalse(binding.actor.execution_live)
                if loss in ('destination', 'witness'):
                    lifetimes.terminate(custodian)
                    self.assertEqual(factory.inspect(descriptor['delegation_id'],
                        reader=b_reader(factory))['physical_initiations'], 1)

    def test_destination_registry_loss_and_reset_domains_never_rebuild_authority(self):
        from tools.decision_0009.acer_adapter.evidence import DESTINATION_FIELD_DOMAINS
        from tools.decision_0009.acer_adapter.supervisor import STORE_FIELD_DOMAINS
        supervisor, _, _, _, port = self.world()
        store = supervisor.store
        self.assertEqual(set(vars(store)), set(STORE_FIELD_DOMAINS))
        self.assertEqual(set(vars(port)), set(DESTINATION_FIELD_DOMAINS))
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        with self.assertRaises(PublicationAcknowledgementLost):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT',
                fault_at='destination', fault='before_claim')
        old = next(iter(store._rp_grants.values()))
        retained = {k: copy.deepcopy(v) for k, v in vars(port).items()
                    if DESTINATION_FIELD_DOMAINS[k] == 'C' and k not in ('_sources', '_subjects')}
        binding = self.recover(supervisor)
        self.assertFalse(port._eligible_grants)
        self.assertFalse(port._source_bindings)
        self.assertFalse(store._rp_grants)
        self.assertFalse(store._rp_proofs)
        for key, value in retained.items(): self.assertEqual(getattr(port, key), value)
        with self.assertRaises(AuthorizationDenied): port.arm_recovery_grant(old)
        port._subjects.clear()
        result = store.query_recovery_publication(binding, subject)
        event = store._exact_ref(store._reference(result))['event']
        self.assertEqual((event['outcome'], event['reason_code']), ('UNKNOWN', 'DESTINATION_REGISTRY_UNAVAILABLE'))
        before = (store.revision, dict(store._objects), dict(port._counts))
        with self.assertRaises(AuthorizationDenied):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(before, (store.revision, dict(store._objects), port._counts))

    def test_owned_empty_single_variable_denials_and_readback_prevalidation(self):
        for change in ('owner', 'started', 'marker', 'partial', 'readback'):
            with self.subTest(change=change):
                supervisor, _, publisher, intent, port = self.world()
                publisher.exclusive_create(intent)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'CONTINUE_RESERVED_EXACT')
                obj = port._objects[intent.object_key]
                if change == 'owner': obj['owner'] = 'wrong-owner'
                if change == 'started': port._operations[subject['logical_operation_id']]['status'] = 'IN_FLIGHT'
                if change == 'marker': obj['written'] = True
                if change == 'partial': obj['bytes'] = intent.bytes[:1]
                if change == 'readback': port.readback_available = False
                before = (store.revision, dict(store._objects), copy.deepcopy(port._objects),
                          dict(port._counts), set(port._claims), dict(port._exclusions))
                with self.assertRaises(AuthorizationDenied):
                    store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT')
                self.assertEqual(before, (store.revision, dict(store._objects), port._objects,
                                          port._counts, port._claims, port._exclusions))

    def test_attempt_source_requires_actual_completed_subject(self):
        from dataclasses import replace
        from acer_adapter_fakes import digest, core_attempt_bytes, residual_observations
        from tools.decision_0009.acer_adapter.contracts import ObjectRule
        for subject_id in ('attempt-1-1', 'attempt-1-2'):
            with self.subTest(subject=subject_id):
                supervisor, _, publisher, _, port = self.world(configure=lambda a: replace(a,
                    object_rules=a.object_rules + (ObjectRule('attempt-rule', subject_id,
                        'ATTEMPT_EVIDENCE', 'destination', 'evidence/attempt'),)))
                supervisor.make_slot_eligible('slot-1-1')
                supervisor.spawn_worker('slot-1-1', digest('launch-slot-1-1'))
                supervisor.complete_worker_lifecycle('slot-1-1')
                raw = core_attempt_bytes(supervisor.authorization.slots[0])
                supervisor.persist_local_attempt_evidence('slot-1-1', raw, residual_observations())
                pipeline = port._producers[0][1]
                obj = pipeline.freeze_raw(pipeline.capture('original-source', raw, 2, 2))
                publisher.intent('destination', 'evidence/attempt', raw, source_proof=(pipeline, obj))
                original = port._subjects['evidence/attempt']['original_intent_ref']
                binding = self.recover(supervisor)
                store = supervisor.store
                if subject_id == 'attempt-1-1':
                    subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                    self.assertTrue(store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT').durable)
                else:
                    before = (store.revision, dict(port._counts))
                    with self.assertRaises(AuthorizationDenied):
                        store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
                    self.assertEqual(before, (store.revision, port._counts))

    def test_supplement_independent_destination_loss_and_false_readback_producers(self):
        from tools.decision_0009.acer_adapter.contracts import ContractError
        supervisor, _, publisher, intent, port = self.world(separate_supplement_destination=True)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, intent.bytes)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
        verified = store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
        event = store._exact_ref(store._reference(verified))['event']
        rw = store.recovery_writer_binding(binding.actor)
        args = dict(parent_ref=event['result_refs'][0], supplement_kind='PUBLICATION_READBACK',
            evidence_bytes=store._object_proof(event['independent_readback']),
            source_id=port.port_identity, verifier_id=port.port_identity)
        before = (store.revision, dict(store._objects))
        for change in ({'source_id': 'normalizer-1'}, {'verifier_id': 'supplement-port'},
                       {'parent_ref': original}, {'evidence_bytes': b'{}\n'}):
            with self.subTest(change=tuple(change)), self.assertRaises(ContractError):
                store.record_recovery_supplement(rw, **dict(args, **change))
            self.assertEqual(before, (store.revision, dict(store._objects)))
        supplement = store.record_recovery_supplement(rw, **args)
        child = store.recovery_supplement_subject(binding, original, store._reference(supplement),
            'ENSURE_EXACT_OBJECT', policy_rule_id='supplement-rule')
        destination = store._publication_destinations[1]
        destination.available = False
        observed = store.query_recovery_publication(binding, child)
        self.assertEqual(store._exact_ref(store._reference(observed))['event']['outcome'], 'UNKNOWN')
        self.assertFalse(destination._objects)
        destination.available = True
        self.assertTrue(store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT').durable)
        self.assertEqual(destination._objects[child['object_key']]['bytes'], args['evidence_bytes'])
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)
        counts = dict(destination._counts)
        destination._subjects.clear()
        observed = store.query_recovery_publication(binding, child)
        self.assertEqual(store._exact_ref(store._reference(observed))['event']['outcome'], 'UNKNOWN')
        with self.assertRaises(AuthorizationDenied):
            store.perform_recovery_publication(binding, child, 'ENSURE_EXACT_OBJECT')
        self.assertEqual(destination._counts, counts)
        # Historical RW reporting is not an attempt to recreate an RP binding.
        store.reset_volatile()
        actor = store.open_nonlive_entry(supervisor.authorization, 'historical-report-reader')
        self.assertIsNone(store._rp_binding)
        rw = store.recovery_writer_binding(actor)
        report = store.record_recovery_obligation(rw, obligation_id='historical-child-registry-loss',
            kind='PUBLICATION_UNVERIFIED', reason_code='DESTINATION_REGISTRY_UNAVAILABLE',
            subject_refs=[original, store._reference(observed)],
            target_ref=dict(kind='DESTINATION', identity=destination.port_identity,
                destination_id=destination.destination_id, object_key=child['object_key'],
                subject_ref=original, subject_state='KNOWN', evidence_ref=None, evidence_state='UNAVAILABLE'))
        self.assertTrue(report.durable)
        self.assertIsNone(store._rp_binding)
        self.assertEqual(destination._counts, counts)

    def test_actual_supervisor_reconstruction_keeps_rp_history_nonexecuting(self):
        supervisor, custodian, publisher, intent, port = self.world()
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = store.recovery_publication_subject(binding, original, op)
            store.perform_recovery_publication(binding, subject, op)
        grant = next(iter(store._rp_grants.values()))
        counts, creates = dict(port._counts), custodian.underlying_create_count_for_all()
        restarted = PersistentSupervisor(store, supervisor.verifier, custodian,
                                         supervisor.authorization, supervisor.session)
        self.assertIsNone(store._rp_binding)
        self.assertFalse(store._rp_grants)
        self.assertFalse(store._rp_proofs)
        self.assertEqual(port._counts, counts)
        self.assertEqual(custodian.underlying_create_count_for_all(), creates)
        self.assertIsNone(store.validated_campaign_closure())
        with self.assertRaises(AuthorizationDenied): port.initiate_recovery(grant)
        with self.assertRaises(AuthorizationDenied): restarted.make_slot_eligible('slot-1-1')
        with self.assertRaises((AuthorizationDenied, EvidenceError)): publisher.exclusive_create(intent)
        self.assertEqual(port._objects[intent.object_key]['bytes'], intent.bytes)

    def test_four_closed_record_shapes_reject_extra_authority_and_null_discriminators(self):
        from tools.decision_0009.acer_adapter.contracts import ContractError, validate_rp_record
        supervisor, _, publisher, intent, _ = self.world()
        publisher.exclusive_create(intent)
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        for op in ('CONTINUE_RESERVED_EXACT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
            subject = store.recovery_publication_subject(binding, original, op)
            store.perform_recovery_publication(binding, subject, op)
        specific = {
            'RECOVERY_PUBLICATION_INTENT': ({'supplement_ref': original}, {'original_or_supplement': 'SUPPLEMENT'}),
            'RECOVERY_PUBLICATION_ACCEPTED': ({'continuation_owner_receipt': None},
                {'previous_result_ref': original}, {'operation': 'WRITE'}, {'consumption_id': None}),
            'RECOVERY_PUBLICATION_RESULT': ({'acceptance_ref': None}, {'query_or_grant': 'QUERY'},
                {'destination_receipt': None}, {'reason_code': 'OUTCOME_UNKNOWN'}),
            'RECOVERY_PUBLICATION_VERIFIED': ({'result_refs': []}, {'namespace_ack': None},
                {'durability_receipt': None}, {'independent_readback': None}),
        }
        for kind, changes in specific.items():
            event = next(f['event'] for f in store._committed_frames() if f['event'].get('record_type') == kind)
            self.assertEqual(validate_rp_record(event), event)
            for bad in (*changes, {'arbitrary_metadata': {}}, {'authorizes_execution': True},
                        {'schema_version': 'u04-record/v2'}, {'authority_class': 'EXECUTION'}):
                with self.subTest(kind=kind, change=tuple(bad)), self.assertRaises(ContractError):
                    validate_rp_record(dict(event, **bad))

    def test_exact_bytes_require_each_durability_and_readback_proof(self):
        for missing in ('object_durable', 'namespace_durable', 'readback_available'):
            with self.subTest(missing=missing):
                supervisor, _, publisher, intent, port = self.world()
                publisher.exclusive_create(intent)
                publisher.write_durable(intent, intent.bytes)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                if missing == 'readback_available': port.readback_available = False
                else: port._objects[intent.object_key][missing] = False
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
                before = (store.revision, dict(store._objects), dict(port._counts), set(port._claims))
                with self.assertRaises(AuthorizationDenied):
                    store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
                self.assertEqual(before, (store.revision, dict(store._objects), port._counts, port._claims))

    def test_copied_original_producer_and_recovery_grant_never_become_capabilities(self):
        supervisor, _, _, intent, port = self.world()
        producer = port._producers[0][1]
        obj = producer._objects[intent.object_digest]
        before = (supervisor.store.revision, dict(port._source_bindings), dict(port._counts))
        with self.assertRaises(AuthorizationDenied):
            port.bind_original_source(supervisor._actor, intent, (copy.copy(producer), obj))
        self.assertEqual(before, (supervisor.store.revision, port._source_bindings, port._counts))
        original = self.original_ref(supervisor)
        binding = self.recover(supervisor)
        store = supervisor.store
        subject = store.recovery_publication_subject(binding, original, 'ENSURE_EXACT_OBJECT')
        with self.assertRaises(PublicationAcknowledgementLost):
            store.perform_recovery_publication(binding, subject, 'ENSURE_EXACT_OBJECT',
                fault_at='destination', fault='before_claim')
        grant = next(iter(store._rp_grants.values()))
        before = (store.revision, dict(store._objects), dict(port._counts), set(port._claims))
        for action in (lambda: port.initiate_recovery(copy.copy(grant)),
                       lambda: port.arm_recovery_grant(copy.copy(grant)),
                       lambda: copy.copy(port).initiate_recovery(grant)):
            with self.assertRaises(AuthorizationDenied): action()
            self.assertEqual(before, (store.revision, dict(store._objects), port._counts, port._claims))

    def test_owned_empty_ack_loss_queries_same_marker_and_replaces_only_not_started(self):
        for stage in ('before_claim', 'after_claim', 'after_initiation', 'after_bytes', 'after_readback'):
            with self.subTest(stage=stage):
                supervisor, _, publisher, intent, port = self.world()
                publisher.exclusive_create(intent)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'CONTINUE_RESERVED_EXACT')
                owner = port._objects[intent.object_key]['owner']
                initial = dict(port._counts)
                with self.assertRaises(PublicationAcknowledgementLost):
                    store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT',
                        fault_at='destination', fault=stage)
                old = next(iter(store._rp_grants.values()))
                binding = self.recover(supervisor)
                observation = store.query_recovery_publication(binding, subject)
                event = store._exact_ref(store._reference(observation))['event']
                self.assertEqual(event['outcome'], 'OWNED_EMPTY_RESERVED' if stage == 'before_claim'
                    else 'EXACT_PRESENT' if stage == 'after_readback' else 'UNKNOWN')
                if stage == 'before_claim':
                    store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT')
                else:
                    before = store.revision
                    with self.assertRaises(AuthorizationDenied):
                        store.perform_recovery_publication(binding, subject, 'CONTINUE_RESERVED_EXACT')
                    self.assertEqual(store.revision, before)
                with self.assertRaises(AuthorizationDenied): port.initiate_recovery(old)
                self.assertLessEqual(len(port._counts) - len(initial), 1)
                self.assertEqual(port._objects[intent.object_key]['owner'], owner)

    def test_lost_verification_response_reconciles_verified_record_without_replaying_effect(self):
        for stage in ('before_claim', 'after_claim', 'after_initiation', 'before_readback', 'after_readback'):
            with self.subTest(stage=stage):
                supervisor, _, publisher, intent, port = self.world()
                publisher.exclusive_create(intent)
                publisher.write_durable(intent, intent.bytes)
                original = self.original_ref(supervisor)
                binding = self.recover(supervisor)
                store = supervisor.store
                subject = store.recovery_publication_subject(binding, original, 'VERIFY_EXACT_OBJECT')
                with self.assertRaises(PublicationAcknowledgementLost):
                    store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT',
                        fault_at='destination', fault=stage)
                counts = dict(port._counts)
                binding = self.recover(supervisor)
                if stage in ('before_claim', 'after_readback'):
                    verified = store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
                    self.assertEqual(store._exact_ref(store._reference(verified))['event']['record_type'],
                                     'RECOVERY_PUBLICATION_VERIFIED')
                    self.assertEqual(len(port._counts) - len(counts), int(stage == 'before_claim'))
                    before = (store.revision, dict(port._counts))
                    self.assertEqual(store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT'), verified)
                    self.assertEqual(before, (store.revision, port._counts))
                else:
                    result = store.query_recovery_publication(binding, subject)
                    self.assertEqual(store._exact_ref(store._reference(result))['event']['outcome'], 'UNKNOWN')
                    with self.assertRaises(AuthorizationDenied):
                        store.perform_recovery_publication(binding, subject, 'VERIFY_EXACT_OBJECT')
                    self.assertEqual(port._counts, counts)

class CheckpointCTerminalTests(unittest.TestCase):
    world = CheckpointCIntegrationTests.world
    original_ref = CheckpointCIntegrationTests.original_ref
    recover = CheckpointCIntegrationTests.recover

    def test_completed_campaign_allows_terminal_rp_without_new_closure_or_execution(self):
        from dataclasses import replace
        from unittest.mock import patch
        from acer_adapter_fakes import activation
        from test_acer_adapter_supervisor import SupervisorTests
        from tools.decision_0009.acer_adapter.contracts import ObjectRule
        def policies(auth):
            return replace(auth, object_rules=auth.object_rules + (
                ObjectRule('boot-rule', 'boot-1', 'BOOT_CLOSURE_EVIDENCE', 'destination', 'evidence/boot'),
                ObjectRule('attempt-rule', 'attempt-1-1', 'ATTEMPT_EVIDENCE', 'destination', 'evidence/attempt'),
                ObjectRule('campaign-rule', 'campaign-1', 'CAMPAIGN_EVIDENCE', 'destination', 'evidence/campaign')))
        supervisor, custodian, publisher, _, port = self.world(configure=policies)
        original = self.original_ref(supervisor)
        originals = [original]
        pipeline = port._producers[0][1]
        def retain_original(key, raw):
            captured = pipeline.capture('original-source', raw, len(originals) + 1, len(originals) + 1)
            obj = pipeline.freeze_raw(captured)
            intent = ImmutablePublication(supervisor).intent('destination', key, obj.bytes, source_proof=(pipeline, obj))
            originals.append(port._subjects[intent.object_key]['original_intent_ref'])
        finalize_boot = supervisor.finalize_boot_closure_candidate
        boot_sources = []
        def boot_candidate(*args, **kwargs):
            candidate = finalize_boot(*args, **kwargs)
            if supervisor.current_boot_id == 'boot-1': boot_sources.append(candidate.bytes)
            return candidate
        finalize_campaign = supervisor.finalize_campaign_closure_candidate
        def campaign_candidate(*args, **kwargs):
            candidate = finalize_campaign(*args, **kwargs)
            # Evidence subject boot-1 remains boot-1 even when the authorized
            # original publisher runs in boot-4. Producer boot is a different fact.
            retain_original('evidence/boot', boot_sources[0])
            retain_original('evidence/campaign', candidate.bytes)
            return candidate
        persist_attempt = supervisor.persist_local_attempt_evidence
        def attempt(*args, **kwargs):
            result = persist_attempt(*args, **kwargs)
            if args[0] == 'slot-1-1': retain_original('evidence/attempt', args[1])
            return result
        supervisor.finalize_boot_closure_candidate = boot_candidate
        supervisor.finalize_campaign_closure_candidate = campaign_candidate
        supervisor.persist_local_attempt_evidence = attempt
        control = SupervisorTests('test_campaign_candidate_publication_precedes_campaign_completion')
        control.make_supervisor = lambda: (supervisor, None, custodian)
        def authorized_activation(*args, **kwargs):
            return replace(activation(*args, **kwargs),
                           authorization_digest=supervisor.authorization.authorization_digest)
        with patch('test_acer_adapter_supervisor.activation', side_effect=authorized_activation):
            control.test_campaign_candidate_publication_precedes_campaign_completion()
        store = supervisor.store
        closure = store.validated_campaign_closure()
        creates = custodian.underlying_create_count_for_all()
        binding = self.recover(supervisor)
        self.assertEqual(binding.actor.mode, 'TERMINAL')
        self.assertIsNone(store.witness.denial(binding.actor))
        self.assertEqual(len(originals), 4)
        for original in originals:
            for op in ('ENSURE_EXACT_OBJECT', 'ESTABLISH_DURABILITY', 'VERIFY_EXACT_OBJECT'):
                with self.subTest(original=original['event_id'], operation=op):
                    subject = store.recovery_publication_subject(binding, original, op)
                    self.assertTrue(store.perform_recovery_publication(binding, subject, op).durable)
        self.assertEqual(store.validated_campaign_closure(), closure)
        self.assertIsNone(store.witness.denial(binding.actor))
        self.assertEqual(custodian.underlying_create_count_for_all(), creates)
        self.assertFalse(binding.actor.execution_live)
        # This terminal world begins without a loss latch, so C's conflict
        # trigger can be tested independently of the accepted B boot-loss latch.
        key = 'evidence/failure'
        source = port._subjects[key]
        port._objects[key]['bytes'] = b'x' * len(source['source_bytes'])
        content = port._operations[port.operation_id(source, 'ENSURE_EXACT_OBJECT')]
        subject = store.recovery_publication_subject(binding, originals[0], 'QUERY')
        content['status'] = 'UNKNOWN'
        unknown = store.query_recovery_publication(binding, subject)
        self.assertEqual(store._exact_ref(store._reference(unknown))['event']['outcome'], 'UNKNOWN')
        self.assertIsNone(store.witness.denial(binding.actor))
        content['status'] = 'COMPLETE'
        deny = store.witness.deny_campaign
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        for stage in ('before-latch', 'after-latch', 'mirror'):
            with self.subTest(conflict_fault=stage):
                def interrupted(*args, **kwargs):
                    if stage == 'after-latch': deny(*args, **kwargs)
                    raise StoreError('injected latch acknowledgement loss')
                if stage != 'mirror':
                    with patch.object(store.witness, 'deny_campaign', side_effect=interrupted), self.assertRaises(StoreError):
                        store.query_recovery_publication(binding, subject)
                else:
                    with patch.object(store, 'mirror_denial', side_effect=StoreError('injected mirror failure')), self.assertRaises(StoreError):
                        store.query_recovery_publication(binding, subject)
                denial = store.witness.denial(binding.actor)
                self.assertEqual(None if denial is None else denial[0],
                    None if stage == 'before-latch' else 'PUBLICATION_INTEGRITY_CONFLICT')
        binding = self.recover(supervisor)
        store.query_recovery_publication(binding, subject)
        self.assertEqual(store.witness.denial(binding.actor)[0], 'PUBLICATION_INTEGRITY_CONFLICT')
        self.assertEqual(store.validated_campaign_closure(), closure)
        self.assertEqual(custodian.underlying_create_count_for_all(), creates)


from tools.decision_0009.acer_adapter.evidence import (
    BoundedRawJournal, EvidenceError, EvidencePipeline, ImmutablePublication,
    PublicationAcknowledgementLost, PublicationScheduler,
    build_closure_candidate, canonical_core_bytes, complete_closure,
)
from tools.decision_0009.acer_adapter.contracts import PublicationReceipt
from tools.decision_0009.acer_adapter.supervisor import (
    AuthorizationDenied, PersistentSupervisor,
)
from acer_adapter_fakes import make_supervisor, inject_untrusted_record


def _append_unprovenanced(store, fence_epoch, event_id, event):
    """Low-level fixture seam: retain a deliberately unprovenanced,
    nonauthorizing record through the store's control plumbing."""
    record = dict(event)
    record["authorizes_execution"] = False
    return inject_untrusted_record(store, fence_epoch, event_id, record)


class EvidenceTests(unittest.TestCase):
    def test_three_layers_preserve_raw_cross_reference_and_exact_core_bytes(self):
        pipeline = EvidencePipeline(max_frame_bytes=128, max_attempt_bytes=1024)
        raw = b'{"available":true,"used_bytes":7}'
        reference = pipeline.capture("gpu", raw, 1, 10)
        normalized = pipeline.normalize(reference, {"available": True, "used_bytes": 7})
        frozen = pipeline.freeze_core({"available": True, "used_bytes": 7}, normalized)
        self.assertEqual(frozen.bytes, b'{"available":true,"used_bytes":7}\n')
        self.assertEqual(pipeline.readback(frozen.digest), frozen.bytes)

    def test_normalization_and_freeze_require_exact_raw_correspondence(self):
        pipeline = EvidencePipeline()
        reference = pipeline.capture("gpu", b'{"used_bytes":7}', 1, 1)
        decoded = pipeline.decode(reference)
        with self.assertRaises(EvidenceError):
            pipeline.normalize(reference, {"used_bytes": 8})
        normalized = pipeline.normalize(reference, decoded)
        with self.assertRaises(EvidenceError):
            pipeline.freeze_core({"used_bytes": 8}, normalized)

    def test_malformed_raw_bytes_and_parser_serialization_failures_are_bounded(self):
        pipeline = EvidencePipeline(max_frame_bytes=8, max_attempt_bytes=16)
        reference = pipeline.capture("transport", b"not-json-and-too-long", 1, 1)
        self.assertTrue(reference.truncated)
        with self.assertRaises(EvidenceError):
            pipeline.decode(reference)
        with self.assertRaises(EvidenceError):
            canonical_core_bytes({"bad": float("nan")})

    def test_all_malformed_classes_fail_closed(self):
        nested = b"[" * 34 + b"0" + b"]" * 34
        cases = (
            b"\xff", b'{"a":1,"a":2}', nested,
            ('{"value":"%s"}' % ("x" * 65_537)).encode("utf-8"),
            ('{"value":%s}' % ("9" * 4097)).encode("ascii"),
            b'{"unterminated":',
        )
        for index, raw in enumerate(cases, 1):
            pipeline = EvidencePipeline(max_frame_bytes=len(raw) + 1,
                                        max_attempt_bytes=len(raw) + 1)
            reference = pipeline.capture("malformed", raw, index, index)
            with self.subTest(index=index), self.assertRaises(EvidenceError):
                pipeline.decode(reference)
        with self.assertRaises(EvidenceError):
            canonical_core_bytes({"surrogate": "\ud800"})
        with self.assertRaises(EvidenceError):
            canonical_core_bytes({1: "non-string-key"})

    def test_publication_is_exclusive_immutable_and_exactly_reconcilable(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("destination", "object", b"abc")
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, b"abc")
        receipt = publisher.verify(intent)
        self.assertEqual(receipt.state, "PUBLICATION_VERIFIED")
        self.assertEqual(publisher.reconcile(intent), receipt)
        with self.assertRaises(EvidenceError):
            publisher.intent("destination", "object", b"xyz")

    def test_lost_publication_ack_reconciles_only_the_exact_object(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("destination", "object", b"abc")
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, b"abc")
        with self.assertRaises(PublicationAcknowledgementLost) as lost:
            publisher.verify(intent, lose_ack=True)
        self.assertEqual(publisher.reconcile(intent), lost.exception.receipt)

    def test_publication_is_prohibited_during_measured_windows(self):
        scheduler = PublicationScheduler()
        for window in ("MEASURED_PREPARATION", "DWELL", "RESIDUAL_CLEARANCE"):
            with self.subTest(window=window), self.assertRaises(EvidenceError):
                scheduler.schedule(window, "publication-intent")
        self.assertEqual(scheduler.schedule("OUTSIDE_MEASURED_WINDOWS", "publication-intent"),
                         "publication-intent")

    def test_boot_and_campaign_candidates_exclude_future_completion_events(self):
        for kind, complete_state in (("boot", "BOOT_COMPLETE"), ("campaign", "CAMPAIGN_COMPLETE")):
            candidate = build_closure_candidate(kind, {"identity": kind, "objects": ["a"]})
            decoded = json.loads(candidate.bytes)
            self.assertNotIn(complete_state, candidate.bytes.decode("utf-8"))
            supervisor, _, _ = make_supervisor()
            publisher = ImmutablePublication(supervisor)
            intent = publisher.intent("dest", kind, candidate.bytes)
            publisher.exclusive_create(intent)
            publisher.write_durable(intent, candidate.bytes)
            receipts = [publisher.verify(intent)]
            object_bytes = canonical_core_bytes("a")
            object_intent = publisher.intent("dest", kind + "-object", object_bytes)
            publisher.exclusive_create(object_intent)
            publisher.write_durable(object_intent, object_bytes)
            receipts.append(publisher.verify(object_intent))
            closure = complete_closure(candidate, tuple(receipts), revision=9,
                                       fence_epoch=3, tainted=False)
            self.assertEqual(closure["state"], complete_state)
            self.assertEqual(closure["candidate_digest"], candidate.digest)

    def test_publication_readback_failure_or_intervening_taint_prevents_closure(self):
        candidate = build_closure_candidate("boot", {"identity": "boot-1", "objects": ["a"]})
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "boot", candidate.bytes)
        publisher.exclusive_create(intent)
        with self.assertRaises(EvidenceError):
            publisher.write_durable(intent, b"corrupt", allow_partial=True)
        with self.assertRaises(EvidenceError):
            publisher.verify(intent)
        good_supervisor, _, _ = make_supervisor()
        good = ImmutablePublication(good_supervisor)
        intent = good.intent("dest", "boot", candidate.bytes)
        good.exclusive_create(intent)
        good.write_durable(intent, candidate.bytes)
        receipts = [good.verify(intent)]
        object_bytes = canonical_core_bytes("a")
        object_intent = good.intent("dest", "boot-object", object_bytes)
        good.exclusive_create(object_intent)
        good.write_durable(object_intent, object_bytes)
        receipts.append(good.verify(object_intent))
        with self.assertRaises(EvidenceError):
            complete_closure(candidate, tuple(receipts), 1, 1, tainted=True)

    def test_verified_empty_object_cannot_be_overwritten(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "empty", b"")
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, b"")
        publisher.verify(intent)
        with self.assertRaises(EvidenceError):
            publisher.write_durable(intent, b"replacement", allow_partial=True)

    def test_unregistered_or_altered_intent_cannot_operate(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "object", b"abc")
        altered = intent.__class__(intent.intent_id, intent.destination, intent.object_key,
                                   intent.object_digest, intent.length, b"xyz")
        for operation in (publisher.exclusive_create,
                          lambda value: publisher.write_durable(value, b"abc"),
                          publisher.verify):
            with self.subTest(operation=operation), self.assertRaises(EvidenceError):
                operation(altered)

    def test_every_publication_operation_consults_authoritative_window(self):
        windows = ("MEASURED_PREPARATION", "DWELL", "RESIDUAL_CLEARANCE")
        for window in windows:
            with self.subTest(window=window, operation="intent"):
                authority, _, _ = make_supervisor()
                publisher = ImmutablePublication(authority)
                authority.set_measurement_window(window)
                with self.assertRaises(EvidenceError):
                    publisher.intent("dest", "key", b"value")
            for operation in ("create", "write", "verify"):
                authority, _, _ = make_supervisor()
                publisher = ImmutablePublication(authority)
                intent = publisher.intent("dest", operation, b"value")
                if operation in ("write", "verify"):
                    publisher.exclusive_create(intent)
                if operation == "verify":
                    publisher.write_durable(intent, b"value")
                authority.set_measurement_window(window)
                call = {"create": lambda: publisher.exclusive_create(intent),
                        "write": lambda: publisher.write_durable(intent, b"value"),
                        "verify": lambda: publisher.verify(intent)}[operation]
                with self.subTest(window=window, operation=operation), self.assertRaises(EvidenceError):
                    call()
            authority, _, _ = make_supervisor()
            publisher = ImmutablePublication(authority)
            intent = publisher.intent("dest", "reconcile-" + window.lower(), b"value")
            publisher.exclusive_create(intent)
            authority.set_measurement_window(window)
            self.assertEqual(publisher.reconcile(intent), "RESERVED")

    def test_publication_transition_race_rechecks_before_mutation(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        with self.assertRaises(EvidenceError):
            publisher.intent(
                "dest", "raced", b"value",
                interlock=lambda: supervisor.set_measurement_window("MEASURED_PREPARATION"))

    def test_normalized_mutation_cannot_diverge_from_retained_raw_bytes(self):
        pipeline = EvidencePipeline()
        reference = pipeline.capture("gpu", b'{"used_bytes":7}', 1, 1)
        decoded = pipeline.decode(reference)
        normalized = pipeline.normalize(reference, decoded)
        with self.assertRaises(TypeError):
            normalized.value[0] = 0
        self.assertEqual(pipeline.freeze_core(decoded, normalized).bytes,
                         b'{"used_bytes":7}\n')

    def test_unbound_publication_is_rejected(self):
        with self.assertRaises(EvidenceError):
            ImmutablePublication()

    def test_publisher_becomes_stale_when_supervisor_is_reconstructed(self):
        supervisor, _, custodian = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        PersistentSupervisor(supervisor.store, supervisor.verifier, custodian,
                             supervisor.authorization, supervisor.session)
        with self.assertRaises(EvidenceError):
            publisher.intent("dest", "stale", b"value")

    def test_window_change_after_publication_authorization_prevents_mutation(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "raced-create", b"value")
        with self.assertRaises(EvidenceError):
            publisher.exclusive_create(
                intent, interlock=lambda: supervisor.set_measurement_window("DWELL"))
        self.assertNotIn((intent.destination, intent.object_key), publisher._states)

    def test_written_but_not_durable_state_recovers_without_verification(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "written", b"value")
        publisher.exclusive_create(intent)
        publisher.write(intent, b"value")
        self.assertEqual(publisher._states[("dest", "written")], "WRITTEN")
        with self.assertRaises(EvidenceError):
            publisher.verify(intent)
        self.assertEqual(publisher.reconcile(intent), "WRITTEN")
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, supervisor.custodian,
            supervisor.authorization, supervisor.session)
        recovered = ImmutablePublication(restarted)
        self.assertEqual(recovered.reconcile(intent), "WRITTEN")
        before = (restarted.store.revision, dict(restarted.store._objects))
        with self.assertRaises(EvidenceError):
            recovered.make_durable(intent)
        self.assertEqual((restarted.store.revision, dict(restarted.store._objects)), before)
        live, _, _ = make_supervisor()
        positive = ImmutablePublication(live)
        original = positive.intent('dest', 'uninterrupted-written', b'value')
        positive.exclusive_create(original)
        positive.write(original, b'value')
        positive.make_durable(original)
        self.assertEqual(positive.verify(original).state, 'PUBLICATION_VERIFIED')

    def test_each_publication_state_reconstructs_without_promotion(self):
        for target, expected in (("RESERVED", "RESERVED"),
                                 ("WRITTEN", "WRITTEN"),
                                 ("DURABLE", "DURABLE"),
                                 ("VERIFIED", "PUBLICATION_VERIFIED")):
            supervisor, _, custodian = make_supervisor()
            publisher = ImmutablePublication(supervisor)
            intent = publisher.intent("dest", "state-" + target.lower(), b"value")
            publisher.exclusive_create(intent)
            if target in ("WRITTEN", "DURABLE", "VERIFIED"):
                publisher.write(intent, b"value")
            if target in ("DURABLE", "VERIFIED"):
                publisher.make_durable(intent)
            if target == "VERIFIED":
                publisher.verify(intent)
            restarted = PersistentSupervisor(
                supervisor.store, supervisor.verifier, custodian,
                supervisor.authorization, supervisor.session)
            recovered = ImmutablePublication(restarted)
            reconciled = recovered.reconcile(intent)
            if target == "VERIFIED":
                self.assertEqual(reconciled.state, expected)
            else:
                self.assertEqual(reconciled, expected)
                self.assertNotIn((intent.destination, intent.object_key),
                                 recovered._receipts)

    def test_caller_cannot_advance_publication_by_presenting_state_labels(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "label-injection", b"value")
        for state in ("EXCLUSIVE_CREATE", "PUBLICATION_WRITTEN",
                      "DURABLE_BYTES", "PUBLICATION_VERIFIED"):
            with self.subTest(state=state), self.assertRaises(AuthorizationDenied):
                supervisor.authorize_publication(state, intent)
        self.assertEqual(publisher.reconcile(intent), "INTENT")

    def test_publication_grants_are_store_owned_single_use_and_window_epoch_bound(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "epoch", b"value")
        binding = supervisor.publication_binding()
        old = supervisor.issue_publication_grant(binding, "create", intent)
        original_epoch = old.window_epoch
        supervisor.set_measurement_window("DWELL")
        supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        self.assertGreater(supervisor.window_epoch, original_epoch)
        with self.assertRaises(AuthorizationDenied):
            supervisor.perform_publication(binding, old, intent)
        fresh = supervisor.issue_publication_grant(binding, "create", intent)
        copied = copy.copy(fresh)
        supervisor.perform_publication(binding, fresh, intent)
        with self.assertRaises(AuthorizationDenied):
            supervisor.perform_publication(binding, copied, intent)

    def test_restart_during_measured_window_cannot_promote_publication(self):
        supervisor, _, custodian = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "measured-restart", b"value")
        publisher.exclusive_create(intent)
        supervisor.set_measurement_window("DWELL")
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertEqual(restarted.current_window, "DWELL")
        self.assertEqual(restarted.window_epoch, supervisor.window_epoch)
        recovered = ImmutablePublication(restarted)
        with self.assertRaises(EvidenceError):
            recovered.write(intent, b"value")

    def test_label_only_publication_history_and_fabricated_receipt_cannot_close(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "label-only", b"value")
        source = next(event for event in supervisor.store.events
                      if event.get("record_type") == "PUBLICATION" and
                      event.get("intent_id") == intent.intent_id)
        prior = "PUBLICATION_INTENT"
        for operation, state in (("create", "EXCLUSIVE_CREATE"),
                                 ("write", "PUBLICATION_WRITTEN"),
                                 ("durable", "DURABLE_BYTES"),
                                 ("verify", "PUBLICATION_VERIFIED")):
            injected = dict(source)
            injected.update({"state": state, "operation": operation,
                             "operation_id": "injected-" + operation,
                             "prior_state": prior})
            _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
                                  "label-only-" + operation, injected)
            prior = state
        receipt = PublicationReceipt(
            "fabricated-receipt", intent.destination, intent.object_key,
            intent.object_digest, intent.length, "PUBLICATION_VERIFIED",
            intent.object_digest)
        with self.assertRaises(AuthorizationDenied):
            supervisor._verify_publication_receipts(None, receipt)
        with self.assertRaises((EvidenceError, AuthorizationDenied)):
            ImmutablePublication(supervisor)

    def test_foreign_durability_and_readback_evidence_are_rejected(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "foreign-durable", b"value")
        publisher.exclusive_create(intent)
        publisher.write(intent, b"value")
        written = next(event for event in reversed(supervisor.store.events)
                       if event.get("state") == "PUBLICATION_WRITTEN")
        foreign = dict(written)
        foreign.update({"state": "DURABLE_BYTES", "operation": "durable",
                        "operation_id": "foreign-durable-operation",
                        "prior_state": "PUBLICATION_WRITTEN",
                        "written_digest": "f" * 64,
                        "durability_ack_id": "foreign-ack"})
        _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
                              "foreign-durability", foreign)
        with self.assertRaises((EvidenceError, AuthorizationDenied)):
            ImmutablePublication(supervisor)

        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "foreign-readback", b"value")
        publisher.exclusive_create(intent)
        publisher.write(intent, b"value")
        publisher.make_durable(intent)
        durable = next(event for event in reversed(supervisor.store.events)
                       if event.get("state") == "DURABLE_BYTES")
        foreign = dict(durable)
        foreign.update({"state": "PUBLICATION_VERIFIED", "operation": "verify",
                        "operation_id": "foreign-readback-operation",
                        "prior_state": "DURABLE_BYTES",
                        "readback_digest": "e" * 64,
                        "verification_id": "foreign-readback"})
        _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
                              "foreign-readback", foreign)
        with self.assertRaises((EvidenceError, AuthorizationDenied)):
            ImmutablePublication(supervisor)

    def test_pending_publication_can_resume_with_new_grant_after_allowed_rollover(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "pending-rollover", b"value")
        supervisor.set_measurement_window("DWELL")
        supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        publisher.exclusive_create(intent)
        publisher.write(intent, b"value")
        publisher.make_durable(intent)
        self.assertEqual(publisher.verify(intent).state, "PUBLICATION_VERIFIED")

    def test_restart_stale_grant_copied_supervisor_and_old_generation_cannot_mutate(self):
        supervisor, _, custodian = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "restart-stale", b"value")
        binding = supervisor.publication_binding()
        stale_grant = supervisor.issue_publication_grant(binding, "create", intent)
        alias = copy.copy(supervisor)
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        for authority in (supervisor, alias):
            with self.subTest(authority=authority), self.assertRaises(AuthorizationDenied):
                authority.perform_publication(binding, stale_grant, intent)
        recovered = ImmutablePublication(restarted)
        with self.assertRaises(EvidenceError):
            recovered.exclusive_create(intent)
        reservations = [event for event in _result_events(supervisor.store)
                        if event.get("record_type") == "PUBLICATION" and
                        event.get("state") == "EXCLUSIVE_CREATE" and
                        event.get("intent_id") == intent.intent_id]
        self.assertEqual(len(reservations), 0)


# ---------------------------------------------------------------------------
# Decision 0009 bounded consolidation: publication integration through the
# canonical publication identity and the validated measurement-window history.
# Field inventories are literal.
# ---------------------------------------------------------------------------

from dataclasses import replace as _replace
import hashlib

from tools.decision_0009.acer_adapter.contracts import PublicationIdentity
from tools.decision_0009.acer_adapter.custody import OfflineCustodian
from tools.decision_0009.acer_adapter.evidence import PublicationIntent
from tools.decision_0009.acer_adapter.supervisor import (
    ArtifactVerificationPrimitive, OfflineDurableStore, OfflineWitness, StoreError,
)
from acer_adapter_fakes import (MutableArtifacts, activation, u04_authorization,
                               offline_chair_service, offline_activation_service, session)


def _result_events(store):
    from tools.decision_0009.acer_adapter.supervisor import _publication_frame_groups
    return [frame['event'] for entries in _publication_frame_groups(store).values()
            for _, frame in entries]

IDENTITY_FIELDS = ("intent_id", "destination", "object_key", "object_digest", "length")
OPERATIONS = ("intent", "create", "write", "durable", "verify")
PUBLISHER_STATE_BEFORE = {"intent": None, "create": "INTENT", "write": "RESERVED",
                          "durable": "WRITTEN", "verify": "DURABLE"}


def _restart(supervisor):
    return PersistentSupervisor(supervisor.store, supervisor.verifier,
                                supervisor.custodian, supervisor.authorization,
                                supervisor.session)


def _publisher_step(publisher, operation, intent, value=b"value"):
    return {"intent": lambda: publisher.intent(intent.destination, intent.object_key, value),
            "create": lambda: publisher.exclusive_create(intent),
            "write": lambda: publisher.write(intent, value),
            "durable": lambda: publisher.make_durable(intent),
            "verify": lambda: publisher.verify(intent)}[operation]()


def _publisher_advance(publisher, key, before_operation, value=b"value"):
    intent = publisher.intent("dest", key, value)
    for operation in OPERATIONS[1:OPERATIONS.index(before_operation)]:
        _publisher_step(publisher, operation, intent, value)
    return intent


def _substituted(intent):
    other = intent.bytes.upper()  # same length, different digest
    assert other != intent.bytes and len(other) == len(intent.bytes)
    values = {
        "intent_id": _replace(intent, intent_id="publish-substituted"),
        "destination": _replace(intent, destination="dest-substituted"),
        "object_key": _replace(intent, object_key="key-substituted"),
        "object_digest": PublicationIntent(intent.intent_id, intent.destination,
                                           intent.object_key,
                                           hashlib.sha256(other).hexdigest(),
                                           len(other), other),
        "length": _replace(intent, length=intent.length + 1),
    }
    assert tuple(values) == IDENTITY_FIELDS
    return values


class ConsolidatedPublicationIntegrationTests(unittest.TestCase):
    def test_independent_completed_wrong_bytes_trigger_exact_integrity_denial(self):
        supervisor, _, custodian = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent('dest', 'stable-conflict', b'expected')
        publisher.exclusive_create(intent)
        with self.assertRaises(EvidenceError):
            publisher.write(intent, b'different', allow_partial=True)
        self.assertEqual(supervisor.store.witness.denial(supervisor._actor)[0],
                         'PUBLICATION_INTEGRITY_CONFLICT')
        self.assertTrue(custodian._publication_counts)

    def test_identity_substitutions_are_rejected_for_every_operation_before_consumption(self):
        for operation in OPERATIONS:
            supervisor, _, _ = make_supervisor()
            store = supervisor.store
            publisher = ImmutablePublication(supervisor)
            key = "integration-" + operation
            if operation == "intent":
                value = b"value"
                digest_value = hashlib.sha256(value).hexdigest()
                intent = PublicationIntent("publish-integration", "dest", key,
                                           digest_value, len(value), value)
            else:
                intent = _publisher_advance(publisher, key, operation)
            binding = supervisor.publication_binding()
            grant = supervisor.issue_publication_grant(binding, operation, intent)
            for field, substituted in _substituted(intent).items():
                with self.subTest(operation=operation, field=field):
                    before = (store.revision, set(store._consumed_publication_grants),
                              dict(store._objects))
                    if operation != "intent":
                        with self.assertRaises(EvidenceError):
                            _publisher_step(publisher, operation, substituted)
                    with self.assertRaises(AuthorizationDenied):
                        supervisor.perform_publication(
                            binding, grant, substituted,
                            payload=substituted.bytes if operation in ("intent", "write")
                            else None)
                    self.assertEqual((store.revision, set(store._consumed_publication_grants),
                                      dict(store._objects)), before)
                    self.assertFalse(store.publication_prohibited)
            # Valid control: the exact identity performs with the same grant, and
            # the publisher continues through verification.
            supervisor.perform_publication(
                binding, grant, intent,
                payload=intent.bytes if operation in ("intent", "write") else None)
            publisher = ImmutablePublication(supervisor)
            for later in OPERATIONS[OPERATIONS.index(operation) + 1:]:
                _publisher_step(publisher, later, intent, intent.bytes)
            self.assertEqual(publisher.reconcile(intent).state, "PUBLICATION_VERIFIED")
            records = [event for event in _result_events(store)
                       if event.get("record_type") == "PUBLICATION" and
                       event.get("object_key") == key]
            self.assertEqual(len(records), 5)
            self.assertEqual({PublicationIdentity.from_record(event) for event in records},
                             {PublicationIdentity(intent.intent_id, "dest", key,
                                                  intent.object_digest, intent.length)})

    def test_initial_window_gates_publication(self):
        artifacts = MutableArtifacts()
        auth = u04_authorization(artifacts)
        store = OfflineDurableStore("store-1", OfflineWitness("witness-1"),
            chair_verifier=offline_chair_service(auth), activation_verifier=offline_activation_service(auth))
        verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
        supervisor = PersistentSupervisor(store, verifier, OfflineCustodian("custodian-1"),
                                          auth, session())
        with self.assertRaises((EvidenceError, AuthorizationDenied)):
            ImmutablePublication(supervisor)
        self.assertEqual(store.revision, 1)
        # Interrupted admission: the campaign is admitted but the initial
        # window never registers a result.
        commit = store._commit_u04
        def interrupted(actor, boundary, event, **kwargs):
            if boundary == 'INIT' and event.get('record_type') == 'MEASUREMENT_WINDOW':
                raise StoreError('interrupted before initial window transaction')
            return commit(actor, boundary, event, **kwargs)
        store._commit_u04 = interrupted
        with self.assertRaises(StoreError):
            supervisor.admit_campaign(activation())
        del store._commit_u04
        restarted = _restart(supervisor)
        with self.assertRaises(EvidenceError):
            ImmutablePublication(restarted).intent("dest", "interrupted", b"value")
        # Valid control: legitimate first admission of a fresh store.
        admitted, _, _ = make_supervisor()
        receipt_publisher = ImmutablePublication(admitted)
        intent = receipt_publisher.intent("dest", "initialized", b"value")
        receipt_publisher.exclusive_create(intent)
        receipt_publisher.write_durable(intent, b"value")
        self.assertEqual(receipt_publisher.verify(intent).state, "PUBLICATION_VERIFIED")

    def test_interrupted_result_registration_blocks_promotion_and_restart_recovery(self):
        for operation in ("create", "write", "durable", "verify"):
            with self.subTest(operation=operation):
                supervisor, _, _ = make_supervisor()
                store = supervisor.store
                publisher = ImmutablePublication(supervisor)
                intent = _publisher_advance(publisher, "unbound-" + operation, operation)

                commit = store._commit_u04
                def interrupted(actor, boundary, event, **kwargs):
                    if event.get('record_type') == 'PUBLICATION' and kwargs.get('facts', {}).get('publication_grant', {}).get('phase') == 'RESULT':
                        raise StoreError('interrupted before durable observed result')
                    return commit(actor, boundary, event, **kwargs)
                store._commit_u04 = interrupted
                try:
                    with self.assertRaises(EvidenceError):
                        _publisher_step(publisher, operation, intent)
                finally:
                    del store._commit_u04
                self.assertTrue(store.publication_prohibited)
                self.assertEqual(publisher.reconcile(intent), 'UNKNOWN')
                store.crash()
                restarted = _restart(supervisor)
                self.assertIn("consumed-publication-grant-without-result",
                              restarted.reconstruction_violations)
                # The accepted effect remains unresolved. Existing exact
                # earlier history is readable; no new mutation is authorized.
                recovered = ImmutablePublication(restarted)
                with self.assertRaises(EvidenceError):
                    _publisher_step(recovered, operation, intent)
                receipt = PublicationReceipt(
                    "publication-receipt-" + intent.object_digest[:16], intent.destination,
                    intent.object_key, intent.object_digest, intent.length,
                    "PUBLICATION_VERIFIED", intent.object_digest)
                with self.assertRaises(AuthorizationDenied):
                    restarted._verify_publication_receipts(None, receipt)

    def test_valid_intermediate_history_reconciles_and_fresh_grants_continue_after_restart(self):
        for state, next_operation in (("RESERVED", "write"), ("WRITTEN", "durable"),
                                      ("DURABLE", "verify")):
            with self.subTest(state=state):
                supervisor, _, _ = make_supervisor()
                publisher = ImmutablePublication(supervisor)
                intent = _publisher_advance(publisher, "resume-" + state.lower(),
                                            next_operation)
                self.assertEqual(publisher.reconcile(intent), state)
                supervisor.store.crash()
                restarted = _restart(supervisor)
                self.assertEqual(restarted.reconstruction_violations, [])
                recovered = ImmutablePublication(restarted)
                self.assertEqual(recovered.reconcile(intent), state)
                with self.assertRaises(EvidenceError):
                    _publisher_step(recovered, next_operation, intent)
                self.assertEqual(recovered.reconcile(intent), state)
                supervisor.store.crash()
                again = _restart(restarted)
                self.assertEqual(again.reconstruction_violations, [])
                self.assertEqual(ImmutablePublication(again).reconcile(intent), state)
                states = [event["state"] for event in _result_events(again.store)
                          if event.get("record_type") == "PUBLICATION" and
                          event.get("intent_id") == intent.intent_id]
                expected = ['PUBLICATION_INTENT', 'EXCLUSIVE_CREATE', 'PUBLICATION_WRITTEN',
                            'DURABLE_BYTES', 'PUBLICATION_VERIFIED']
                self.assertEqual(states, expected[:OPERATIONS.index(next_operation)])
                live, _, _ = make_supervisor()
                positive = ImmutablePublication(live)
                original = _publisher_advance(positive, 'live-' + state.lower(), next_operation)
                for operation in OPERATIONS[OPERATIONS.index(next_operation):]:
                    _publisher_step(positive, operation, original)
                self.assertEqual(positive.reconcile(original).state, 'PUBLICATION_VERIFIED')

    def test_outside_dwell_outside_restart_resumes_only_at_final_window_epoch(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "window-cycle", b"value")
        supervisor.set_measurement_window("DWELL")
        with self.assertRaises(EvidenceError):
            publisher.exclusive_create(intent)
        supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        supervisor.store.crash()
        restarted = _restart(supervisor)
        self.assertEqual((restarted.current_window, restarted.window_epoch),
                         ("OUTSIDE_MEASURED_WINDOWS", 3))
        recovered = ImmutablePublication(restarted)
        with self.assertRaises(EvidenceError):
            recovered.exclusive_create(intent)
        epochs = [event["window_epoch"] for event in _result_events(restarted.store)
                  if event.get("record_type") == "PUBLICATION"]
        self.assertEqual(epochs, [1])
        live, _, _ = make_supervisor()
        positive = ImmutablePublication(live)
        original = positive.intent('dest', 'live-window-cycle', b'value')
        live.set_measurement_window('DWELL')
        live.set_measurement_window('OUTSIDE_MEASURED_WINDOWS')
        positive.exclusive_create(original)
        positive.write_durable(original, b'value')
        self.assertEqual(positive.verify(original).state, 'PUBLICATION_VERIFIED')
        self.assertEqual([e['window_epoch'] for e in _result_events(live.store)], [1, 3, 3, 3, 3])
