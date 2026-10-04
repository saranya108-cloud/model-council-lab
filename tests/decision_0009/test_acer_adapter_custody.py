import dataclasses
import threading
import unittest

from tools.decision_0009.acer_adapter.custody import (
    ContainmentUnavailable, OfflineCustodian, OfflineSurvivor,
)
from tools.decision_0009.acer_adapter.contracts import CustodyError
from tools.decision_0009.acer_adapter.supervisor import DispatchUncertain
from acer_adapter_fakes import (
    artifact_binding, consumed_create_capability, digest, make_supervisor, spawn_token,
)


U04_COMMIT_STAGES = (
    'before_reservation', 'reservation_response_lost', 'reserved_before_frame',
    'frame_before_readback', 'readback_mismatch', 'readback_unavailable',
    'validated_before_commit', 'commit_before_ack',
)


class U04EffectFaultMatrixTests(unittest.TestCase):
    def test_exact_late_worker_result_is_reconciled_without_replacement_execution(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        store = supervisor.store
        record = store.record_effect_result
        def lose_before_result(capability, receipt, **kwargs):
            store.crash()
            return record(capability, receipt, **kwargs)
        store.record_effect_result = lose_before_result
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        del store.record_effect_result
        capability = store.effect_capability('spawn-intent-slot-1-1')
        original = custodian._creation_receipts['spawn-slot-1-1']
        store.reset_volatile()
        reader = store.open_nonlive_entry(supervisor.authorization, 'exact-result-reader')
        result = store.record_effect_result(capability, original, actor=reader)
        self.assertEqual(result.receipt, original)
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        with self.assertRaises((StoreError, CustodyError)):
            custodian.create_once(supervisor._slot_tokens['slot-1-1'], original.launch_spec_digest,
                                  capability, capability.artifact_binding)
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_independent_port_registry_loss_preserves_unknown_and_one_time_counts(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        store = supervisor.store
        result = next(e for e in store.events if e.get('result_kind') == 'EFFECT_PORT_RECEIPT')
        effect_id = result['effect_id']
        capability = store.effect_capability(effect_id)
        custodian._effect_port_receipts.pop(effect_id)
        with self.assertRaises((StoreError, CustodyError)):
            from tools.decision_0009.acer_adapter.contracts import parse_effect_result_record
            from tools.decision_0009.acer_adapter.supervisor import _u04_canonical
            store._validated_port_observation(parse_effect_result_record(_u04_canonical(result)))
        with self.assertRaises((StoreError, CustodyError)):
            custodian.initiate_control(capability, capability.artifact_binding, lambda *args: None)
        self.assertEqual(custodian._control_counts[effect_id], 1)
        self.assertIsNone(store.witness.denial(supervisor._actor))

    def test_control_and_publication_results_use_exact_independent_port_receipt(self):
        import json
        from tools.decision_0009.acer_adapter.evidence import ImmutablePublication
        supervisor, _, custodian = make_supervisor()
        publication = ImmutablePublication(supervisor)
        publication.intent('dest', 'receipt-proof', b'exact source')
        expected = {'effect_id', 'acceptance_ref', 'target_id', 'original_generation',
                    'original_incarnation_id', 'original_session_id', 'original_fence',
                    'result_object', 'port_attestation'}
        ports = set()
        for event in supervisor.store.events:
            if event.get('record_type') != 'EFFECT_RESULT' or event.get('result_kind') != 'EFFECT_PORT_RECEIPT':
                continue
            ref = event['result']
            receipt = json.loads(supervisor.store.read_object(ref['object_id'], ref['sha256']))
            self.assertEqual(set(receipt), expected)
            self.assertEqual(receipt['acceptance_ref'], event['acceptance_ref'])
            original = supervisor.store._exact_ref(receipt['acceptance_ref'])
            producer = json.loads(original['envelope'].producer_bytes)
            for field, key in (('generation', 'original_generation'), ('incarnation_id', 'original_incarnation_id'),
                               ('session_id', 'original_session_id'), ('fence', 'original_fence')):
                self.assertEqual(receipt[key], producer[field])
            observation = receipt['result_object']
            self.assertEqual(len(supervisor.store.read_object(observation['object_id'], observation['sha256'])),
                             observation['length'])
            ports.add(receipt['target_id'])
        self.assertEqual(ports, {'offline-store', 'dest'})
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_substitution_inside_independent_creation_port_denies_before_counter(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, artifacts, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        create = custodian.create_once
        def substitute_after_upper_check(*args, **kwargs):
            artifacts.substitute('policy')
            return create(*args, **kwargs)
        custodian.create_once = substitute_after_upper_check
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_lost_intent_ack_cannot_be_redeemed_by_poisoning_volatile_views(self):
        from tools.decision_0009.acer_adapter.contracts import SpawnToken
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        store = supervisor.store
        commit = store._commit_u04
        def lost_intent(actor, boundary, event, **kwargs):
            if event.get('state') == 'SPAWN_INTENT_PERSISTED':
                kwargs['fault'] = 'commit_before_ack'
            return commit(actor, boundary, event, **kwargs)
        store._commit_u04 = lost_intent
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        del store._commit_u04
        capability = store.effect_capability('spawn-intent-slot-1-1')
        event = store._durable[capability.transition_revision - 1]['event']
        token = SpawnToken(event['spawn_token'], event['campaign_id'], event['boot_id'],
            event['slot_id'], event['attempt_id'], event['launch_spec_digest'],
            event['custodian_id'], capability.supervisor_generation)
        store._execution_revoked = store._publication_prohibited = store.containment_only = False
        store._supervisor_ready = True
        store._active_creation_grants.add(capability.effect_id)
        store._effect_status[capability.effect_id] = 'FIRST_DISPATCH_ACTIVE'
        with self.assertRaises((StoreError, CustodyError)):
            custodian.create_once(token, token.launch_spec_digest, capability, capability.artifact_binding)
        self.assertEqual(store.effect_acceptance_count(capability.effect_id), 0)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_revocation_after_creation_prevents_stale_result_commit_and_replacement(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        store = supervisor.store
        record = store.record_effect_result
        captured = []
        def create_before_loss(capability, receipt, **kwargs):
            captured.append(kwargs['actor'])
            store.crash()
            return record(capability, receipt, **kwargs)
        store.record_effect_result = create_before_loss
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        del store.record_effect_result
        self.assertEqual(captured, [supervisor._actor])
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        self.assertFalse(any(e.get('record_type') == 'EFFECT_RESULT' and
            e.get('effect_id') == 'spawn-intent-slot-1-1' for e in store.events))
        capability = store.effect_capability('spawn-intent-slot-1-1')
        token = supervisor._slot_tokens['slot-1-1']
        with self.assertRaises((StoreError, CustodyError)):
            custodian.create_once(token, token.launch_spec_digest, capability, capability.artifact_binding)
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_custody_loss_latches_only_with_independent_positive_invalidation(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.record_custodian_loss('temporarily-unreadable')
        self.assertIsNone(supervisor.store.witness.denial(supervisor._actor))
        live, _, independent = make_supervisor()
        independent.die()
        self.assertEqual(live.store.witness.denial(live._actor)[0], 'CUSTODY_LOSS_PROVEN')
        self.assertTrue(any(e.get('record_type') == 'CAMPAIGN_EXECUTION_DENIED' for e in live.store.events))

    def test_worker_intent_acceptance_and_result_commit_windows(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        for transaction in ('intent', 'acceptance', 'result'):
            for stage in U04_COMMIT_STAGES:
                with self.subTest(transaction=transaction, stage=stage):
                    supervisor, _, custodian = make_supervisor()
                    supervisor.make_slot_eligible('slot-1-1')
                    store = supervisor.store
                    commit = store._commit_u04
                    observed = []
                    def interrupt(actor, boundary, event, **kwargs):
                        selected = (
                            transaction == 'intent' and event.get('state') == 'SPAWN_INTENT_PERSISTED' or
                            transaction == 'acceptance' and event.get('record_type') == 'EFFECT_ACCEPTED' and
                                event.get('operation') == 'blocked-create' or
                            transaction == 'result' and event.get('record_type') == 'EFFECT_RESULT' and
                                event.get('result_kind') == 'CUSTODIAN_RECEIPT')
                        if selected:
                            observed.append((event.get('record_type', 'SPAWN_INTENT'), stage))
                            kwargs['fault'] = stage
                        return commit(actor, boundary, event, **kwargs)
                    store._commit_u04 = interrupt
                    with self.assertRaises((StoreError, CustodyError)):
                        supervisor.spawn_worker('slot-1-1', digest('launch'))
                    del store._commit_u04
                    self.assertEqual(len(observed), 1)
                    expected = 1 if transaction == 'result' else 0
                    self.assertEqual(custodian.underlying_create_count_for_all(), expected)
                    token = supervisor._slot_tokens.get('slot-1-1')
                    if token is not None:
                        with self.assertRaises((StoreError, CustodyError)):
                            capability = store.effect_capability('spawn-intent-slot-1-1')
                            custodian.create_once(token, token.launch_spec_digest,
                                                  capability, capability.artifact_binding)
                    self.assertEqual(custodian.underlying_create_count_for_all(), expected)
                    if stage == 'commit_before_ack' and transaction == 'result':
                        receipt = store.effect_result('spawn-intent-slot-1-1').receipt
                        self.assertEqual(receipt, custodian._creation_receipts[receipt.spawn_token])
                    if stage in ('frame_before_readback', 'validated_before_commit'):
                        frame = store._durable[-1]
                        exact = frame['bytes']
                        for interrupt in ('before_commit', 'lost_ack'):
                            with self.subTest(reconciliation=interrupt), self.assertRaises(StoreError):
                                store.reconcile_pending(store._authentication_service, supervisor.authorization,
                                                        fault=interrupt)
                        store.reconcile_pending(store._authentication_service, supervisor.authorization)
                        self.assertEqual(frame['bytes'], exact)
                        self.assertEqual(store.witness.query_transaction(frame['event_id'])[1].completion_mode,
                                         'RECOVERY_RECONCILE')
                        self.assertEqual(custodian.underlying_create_count_for_all(), expected)

    def test_acceptance_acknowledgement_then_reentrant_revocation_prevents_creation(self):
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        store = supervisor.store
        acceptance = store.accept_effect
        def accepted_then_lost(capability):
            result = acceptance(capability)
            store.crash()
            return result
        store.accept_effect = accepted_then_lost
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_original_receipt_remains_exact_after_containment_and_reap(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        original = supervisor.spawn_worker('slot-1-1', digest('launch'))
        token = supervisor._slot_tokens['slot-1-1']
        capability = supervisor.store.effect_capability('spawn-intent-slot-1-1')
        custodian.contain_spawn(token.token_id, 'containment', capability.artifact_binding)
        custodian.wait_reap(token.token_id)
        self.assertEqual(supervisor.store.effect_result(capability.effect_id).receipt, original)
        self.assertEqual(custodian.create_once(token, token.launch_spec_digest,
            capability, capability.artifact_binding), original)
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.supervisor, _, self.custodian = make_supervisor()
        self.supervisor.make_slot_eligible("slot-1-1")
        self.initial_receipt = self.supervisor.spawn_worker(
            "slot-1-1", digest("launch"))
        self.token = self.supervisor._slot_tokens["slot-1-1"]
        self.capability = self.supervisor.store.effect_capability(
            "spawn-intent-slot-1-1")
        self.binding = self.capability.artifact_binding

    def test_duplicate_and_concurrent_create_once_never_create_twice(self):
        receipts = []
        barrier = threading.Barrier(3)
        def request():
            barrier.wait()
            receipts.append(self.custodian.create_once(
                self.token, self.token.launch_spec_digest, self.capability,
                self.binding))
        threads = [threading.Thread(target=request) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(self.custodian.underlying_create_count(self.token.token_id), 1)
        self.assertEqual({receipt.status for receipt in receipts}, {"BLOCKED"})
        self.assertEqual(
            self.supervisor.store.effect_acceptance_count(self.capability.effect_id), 1)
        with self.assertRaises(CustodyError):
            self.custodian.create_once(self.token, digest("different"),
                                       self.capability, self.binding)

    def test_ambiguous_create_is_possibly_live_and_never_retried(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("ambiguous-launch"),
                                    fault="crash_after_create")
        token = supervisor._slot_tokens["slot-1-1"]
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        first = supervisor.lookup_historical_spawn_receipt("slot-1-1").receipt
        second = custodian.create_once(token, token.launch_spec_digest,
                                       capability, capability.artifact_binding)
        self.assertEqual((first.status, second.status), ("UNKNOWN", "UNKNOWN"))
        self.assertEqual(custodian.underlying_create_count(token.token_id), 1)
        self.assertEqual(supervisor.store.effect_acceptance_count(capability.effect_id), 1)
        self.assertTrue(custodian.inspect_spawn(token.token_id).possibly_live)

    def test_generation_and_intent_digest_substitution_cannot_replay_result(self):
        for capability in (
                dataclasses.replace(
                    self.capability,
                    supervisor_generation=self.capability.supervisor_generation + 1),
                dataclasses.replace(
                    self.capability, transition_event_digest=digest("substituted-intent"))):
            with self.subTest(capability=capability), self.assertRaises(CustodyError):
                self.custodian.create_once(
                    self.token, self.token.launch_spec_digest, capability,
                    capability.artifact_binding)
        self.assertEqual(self.custodian.underlying_create_count(self.token.token_id), 1)

    def test_child_can_exist_before_supervisor_identity_record(self):
        self.custodian.create_once(self.token, self.token.launch_spec_digest,
                                   self.capability, self.binding)
        inspection = self.custodian.inspect_spawn(self.token.token_id)
        self.assertEqual(inspection.status, "BLOCKED")
        self.assertIsNotNone(inspection.process_identity)

    def test_normal_reap_receipt_is_registry_bound(self):
        self.custodian.create_once(self.token, self.token.launch_spec_digest,
                                   self.capability, self.binding)
        self.custodian.contain_spawn(self.token.token_id, "contain-capability",
                                     artifact_binding())
        receipt = self.custodian.wait_reap(self.token.token_id)
        self.custodian.validate_reap_receipt(receipt)
        with self.assertRaises(CustodyError):
            self.custodian.validate_reap_receipt(
                receipt.__class__(**{**receipt.__dict__, "spawn_token": "other"}))

    def test_custodian_death_has_no_implicit_containment_or_reap(self):
        self.custodian.create_once(self.token, self.token.launch_spec_digest,
                                   self.capability, self.binding)
        self.custodian.die()
        with self.assertRaises(ContainmentUnavailable):
            self.custodian.contain_spawn(self.token.token_id, "contain-capability",
                                         artifact_binding())
        self.assertIsNone(self.custodian.get_reap_receipt(self.token.token_id))

    def test_survivor_is_separate_and_actual_actions_do_not_clear_taint(self):
        self.custodian.create_once(self.token, self.token.launch_spec_digest,
                                   self.capability, self.binding)
        survivor = OfflineSurvivor("survivor-1", "survivor-authority", self.binding)
        transfer = self.custodian.export_survivor_ownership(self.token.token_id, survivor)
        self.custodian.die()
        evidence = survivor.contain_transferred(transfer, "contain-capability")
        self.assertEqual(evidence.actor_identity, "survivor-1")
        self.assertNotEqual(evidence.actor_identity, self.custodian.identity)
        self.assertTrue(evidence.custody_uncertain)

    def test_original_survivor_transfer_ignores_session_cache_but_requires_independent_proof(self):
        self.custodian.create_once(self.token, self.token.launch_spec_digest,
                                   self.capability, self.binding)
        survivor = OfflineSurvivor('survivor-1', 'survivor-authority', self.binding)
        transfer = self.custodian.export_survivor_ownership(self.token.token_id, survivor)
        self.custodian.die()
        store = self.custodian._store
        store._sessions.clear()
        evidence = survivor.contain_transferred(transfer, 'contain-capability')
        self.assertTrue(evidence.custody_uncertain)
        self.assertEqual(evidence.spawn_token, self.token.token_id)
        self.assertEqual(self.custodian.underlying_create_count_for_all(), 1)

        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        supervisor.spawn_worker('slot-1-1', digest('launch'))
        capability = supervisor.store.effect_capability('spawn-intent-slot-1-1')
        survivor = OfflineSurvivor('survivor-1', 'survivor-authority', capability.artifact_binding)
        transfer = custodian.export_survivor_ownership('spawn-slot-1-1', survivor)
        custodian._transfers.clear()
        supervisor.store._sessions[transfer.session_id] = supervisor.session
        with self.assertRaises(ContainmentUnavailable):
            survivor.contain_transferred(transfer, 'contain-capability')
        self.assertEqual(survivor._acted, set())
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_capability_cannot_be_reused_for_a_different_token_or_spec(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        binding = capability.artifact_binding
        original = supervisor._slot_tokens["slot-1-1"]
        forged = dataclasses.replace(original, token_id="spawn-forged",
                                     launch_spec_digest=digest("forged-launch"))
        with self.assertRaises(CustodyError):
            custodian.create_once(forged, forged.launch_spec_digest, capability, binding)

    def test_actual_custodian_death_automatically_taints_store(self):
        supervisor, _, custodian = make_supervisor()
        custodian.die()
        self.assertIn("CUSTODY_UNCERTAIN", supervisor.safety_markers)
        self.assertTrue(any(reason.startswith("custody-uncertain:")
                            for reason in supervisor.store.taint))

    def test_forged_survivor_transfer_is_rejected(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        survivor = OfflineSurvivor("survivor-1", "survivor-authority",
                                   supervisor.verifier.verify(
                                       "CLEANUP_REQUESTED", supervisor.session.fence_epoch,
                                       supervisor.session.session_id))
        transfer = custodian.export_survivor_ownership(receipt.spawn_token, survivor)
        forged = dataclasses.replace(
            transfer,
            process_identity=dataclasses.replace(transfer.process_identity,
                                                 process_start_ticks=999999),
        )
        custodian.die()
        with self.assertRaises(ContainmentUnavailable):
            survivor.contain_transferred(forged, "contain-capability")
