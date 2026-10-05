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
                                     self.binding)
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
        d=self.custodian.establish_survivor_containment(self.token.token_id,self.supervisor._actor)
        factory=self.custodian._containment_factory
        __import__('acer_adapter_fakes').b_lifetimes(self.custodian).terminate(self.custodian)
        observed=factory.inspect(d['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(factory))
        self.assertEqual(observed['physical_initiations'],1)
        self.assertNotEqual(factory._actor_id(d),self.custodian.identity)
        self.assertEqual(observed['receipt']['custodian_id'],self.custodian.identity)
        self.assertIn('CUSTODY_UNCERTAIN',self.supervisor.safety_markers)
        self.assertEqual(self.supervisor.store.witness.denial(self.supervisor._actor)[0],'CUSTODY_LOSS_PROVEN')

    def test_original_survivor_transfer_ignores_session_cache_but_requires_independent_proof(self):
        d=self.custodian.establish_survivor_containment(self.token.token_id,self.supervisor._actor)
        factory=self.custodian._containment_factory
        self.custodian._store._sessions.clear()
        __import__('acer_adapter_fakes').b_lifetimes(self.custodian).terminate(self.custodian)
        observed=factory.inspect(d['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(factory))
        self.assertEqual(observed['physical_initiations'],1)
        self.assertEqual(observed['receipt']['spawn_token'],self.token.token_id)
        self.assertEqual(self.custodian.underlying_create_count_for_all(),1)

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


class CheckpointBSurvivorTests(unittest.TestCase):
    def test_original_establishment_then_independent_supervisor_terminal_contains_once(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        created = supervisor.spawn_worker('slot-1-1', digest('b-launch'))
        self.assertTrue(callable(getattr(custodian, 'establish_survivor_containment', None)),
                        'accepted B six-stage survivor establishment is missing')
        descriptor = custodian.establish_survivor_containment(created.spawn_token, supervisor._actor)
        self.assertEqual(descriptor['action'], 'CONTAIN_TOKEN_DOMAIN')
        self.assertIs(descriptor['may_wait'], False)
        self.assertIs(descriptor['authorizes_execution'], False)
        factory = custodian._containment_factory
        self.assertEqual(factory.inspect(descriptor['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(factory))['operation_state'], 'READY')
        # The harness supplies a genuine independently owned terminal transition;
        # a runtime supervisor has no terminal-observation/dispatch API.
        __import__('acer_adapter_fakes').b_lifetimes(custodian).terminate(supervisor._actor)
        observed = factory.inspect(descriptor['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(factory))
        self.assertEqual(observed['physical_initiations'], 1)
        self.assertEqual(observed['operation_state'], 'RESULT_AVAILABLE')
        self.assertEqual(observed['receipt']['status'], 'EXITED')
        __import__('acer_adapter_fakes').b_lifetimes(custodian).terminate(supervisor._actor)
        self.assertEqual(factory.inspect(descriptor['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(factory))['physical_initiations'], 1)


class CheckpointBTriggerMatrixTests(unittest.TestCase):
    def world(self, establish=True, fault=None):
        s,a,c=make_supervisor();s.make_slot_eligible('slot-1-1')
        r=s.spawn_worker('slot-1-1',digest('b-launch'))
        d=c.establish_survivor_containment(r.spawn_token,s._actor,fault=fault) if establish else None
        return s,a,c,d,c._containment_factory,__import__('acer_adapter_fakes').b_lifetimes(c)

    def snapshot(self,f,d): return f.inspect(d['delegation_id'],reader=__import__('acer_adapter_fakes').b_reader(f))
    def no_effect(self,f,d): self.assertEqual(self.snapshot(f,d)['physical_initiations'],0)

    def test_F01_supervisor_loss(self):
        s,a,c,d,f,l=self.world();l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_F02_ambiguous_supervisor(self):
        s,a,c,d,f,l=self.world();l.available=False
        self.no_effect(f,d);self.assertEqual(self.snapshot(f,d)['operation_state'],'READY')

    def test_F03_forged_loss(self):
        s,a,c,d,f,l=self.world();self.assertEqual(f.inspect_trigger(d['delegation_id'],b'{}\n',reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_UNAVAILABLE')
        self.no_effect(f,d);self.assertIsNone(s.store.witness.denial(s._actor))

    def test_F04_stale_supervisor(self):
        s,a,c,d,f,l=self.world();ref=self.failure(s);old=s._actor
        self.assert_cleanup_failure(s,c,d,f,ref)
        s.store.crash();s.store.open_nonlive_entry(s.authorization,'replacement')
        self.assert_cleanup_failure(s,c,d,f,ref)
        with self.assertRaisesRegex(RuntimeError,'captured opaque incarnation is no longer current'):
            f.request_original_cleanup(c,old,d['delegation_id'],ref)
        self.no_effect(f,d);l.terminate(old);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_F05_replacement_supervisor(self):
        s,a,c,d,f,l=self.world();ref=self.failure(s)
        self.assert_cleanup_failure(s,c,d,f,ref)
        s.store.crash();actor=s.store.open_nonlive_entry(s.authorization,'replacement')
        self.assert_cleanup_failure(s,c,d,f,ref)
        s.store.require_actor(actor,'HISTORY')
        with self.assertRaisesRegex(ContainmentUnavailable,'original live controller required'):
            f.request_original_cleanup(c,actor,d['delegation_id'],ref)
        self.no_effect(f,d);l.terminate(s._actor);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_F06_custodian_loss(self):
        s,a,c,d,f,l=self.world();l.terminate(c)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual(s.store.witness.denial(s._actor)[0],'CUSTODY_LOSS_PROVEN')
        self.assertIsNone(c.get_reap_receipt(d['spawn_token']['token_id']))

    def test_F07_ambiguous_custodian(self):
        s,a,c,d,f,l=self.world();l.available=False;self.no_effect(f,d)
        self.assertIsNone(s.store.witness.denial(s._actor))

    def test_F08_copied_and_delayed_evidence(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(c)
        item=next(iter(f._verifier.entries.values()))
        self.assertEqual(f.inspect_trigger(d['delegation_id'],bytes(item['trigger']),reader=__import__('acer_adapter_fakes').b_reader(f)),'VALIDATED_NOT_CLAIMED')
        self.no_effect(f,d);f._fault=None;l.terminate(c)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def failure(self,s):
        store=s.store;record={'state':'TAINTED','reason':'explicit-b-abort','raw_digest':digest('failure'),
            'raw_length':0,'authorization_digest':s.authorization.authorization_digest,
            'campaign_id':s.authorization.campaign_id,'authorizes_execution':False}
        return store._reference(store.record_original_diagnostic(s._actor,record))

    def assert_cleanup_failure(self,s,c,d,f,ref):
        frame=s.store._exact_ref(ref)
        _,commit=s.store.witness.query_transaction(frame['event_id'])
        self.assertEqual(frame['event']['state'],'TAINTED')
        self.assertEqual(frame['envelope'].boundary,'HISTORY')
        self.assertEqual(commit.completion_mode,'ORIGIN')
        import json
        self.assertEqual(json.loads(frame['envelope'].producer_bytes),f._entries[d['delegation_id']]['actor'].producer())
        self.assertTrue(c.alive)
        self.assertTrue(f._entries[d['delegation_id']]['exposed'])
        self.assertTrue(f._entries[d['delegation_id']]['domain'].target_valid())
        self.assertEqual(self.snapshot(f,d)['operation_state'],'READY')
        s.store.assert_healthy_authority()

    def test_F09_original_cleanup(self):
        s,a,c,d,f,l=self.world();ref=self.failure(s)
        self.assert_cleanup_failure(s,c,d,f,ref)
        f.request_original_cleanup(c,s._actor,d['delegation_id'],ref)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_F10_stale_cleanup(self):
        s,a,c,d,f,l=self.world();ref=self.failure(s);f._fault='before_claim'
        f.request_original_cleanup(c,s._actor,d['delegation_id'],ref);s.store.crash();f._fault=None
        with self.assertRaises((CustodyError,RuntimeError)):
            f.request_original_cleanup(c,s._actor,d['delegation_id'],ref)
        self.no_effect(f,d);l.terminate(s._actor);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_F11_survivor_death_before_claim(self):
        s,a,c,d,f,l=self.world();endpoint=f._entries[d['delegation_id']]['endpoint']
        l.terminate(endpoint);l.terminate(s._actor);self.no_effect(f,d)
        self.assertFalse(self.snapshot(f,d)['exposed'])

    def test_F12_atomic_consumption_has_no_ready_gap(self):
        s,a,c,d,f,l=self.world();f._fault='after_claim';l.terminate(s._actor)
        snap=self.snapshot(f,d);self.assertEqual(snap['operation_state'],'CLAIMED');self.assertIsNotNone(snap['consume'])
        f._fault=None;l.terminate(s._actor);self.no_effect(f,d)

    def test_F13_claimed_before_port_call(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
        self.assertTrue(self.snapshot(f,d)['domain_sealed']);f._fault=None;l.terminate(s._actor);self.no_effect(f,d)

    def test_F14_claimed_replay(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
        first=self.snapshot(f,d)['consume'];f._fault=None;l.terminate(c)
        self.no_effect(f,d);self.assertEqual(self.snapshot(f,d)['consume'],first)
        self.assertEqual(len(f._verifier.entries),2);self.assertEqual(len(f._verifier.uses),1)

    def test_F15_result_replay(self):
        s,a,c,d,f,l=self.world();l.terminate(s._actor);before=self.snapshot(f,d);l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d),before)

    def test_F16_wrong_worker(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        item=next(iter(f._verifier.entries.values()));import json
        value=json.loads(item['trigger']);value['spawn_token']['token_id']='wrong-worker'
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        self.assertEqual(f.inspect_trigger(d['delegation_id'],closed_canonical_bytes(value),reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_REJECTED');self.no_effect(f,d)

    def test_F17_wrong_survivor(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        item=next(iter(f._verifier.entries.values()));import json
        value=json.loads(item['trigger']);value['survivor_incarnation'][2]+=1
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        self.assertEqual(f.inspect_trigger(d['delegation_id'],closed_canonical_bytes(value),reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_REJECTED');self.no_effect(f,d)

    def test_F18_cross_campaign(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        item=next(iter(f._verifier.entries.values()));import json
        value=json.loads(item['trigger']);value['campaign_id']='wrong-campaign'
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        self.assertEqual(f.inspect_trigger(d['delegation_id'],closed_canonical_bytes(value),reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_REJECTED');self.no_effect(f,d)

    def test_F19_loss_under_quarantine(self):
        s,a,c,d,f,l=self.world();s.store.quarantined=True;s.store.witness.quarantined=True
        before=(s.store.revision,dict(s.store._objects),s.store.witness.high_generation)
        l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual((s.store.revision,dict(s.store._objects),s.store.witness.high_generation),before)

    def test_F20_unknown_under_quarantine(self):
        s,a,c,d,f,l=self.world();s.store.quarantined=True;l.available=False
        self.assertEqual(f.inspect_trigger(d['delegation_id'],b'{}\n',reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_UNAVAILABLE');self.no_effect(f,d)

    def test_F21_custody_loss_with_w_update_failure(self):
        s,a,c,d,f,l=self.world();s.store.witness.available=False;before=s.store.revision
        l.terminate(c);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual(s.store.revision,before);self.assertTrue(s.store.execution_revoked)

    def test_F22_original_then_survivor_join(self):
        s,a,c,d,f,l=self.world();c.contain_spawn(d['spawn_token']['token_id'],'original',f._entries[d['delegation_id']]['binding'])
        l.terminate(s._actor);snap=self.snapshot(f,d)
        self.assertEqual(snap['physical_initiations'],1);self.assertEqual(snap['teardowns'],1)

    def test_F23_containment_seals_original_release(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(c)
        self.assertTrue(self.snapshot(f,d)['domain_sealed'])
        self.assertTrue(callable(getattr(f,'_release_guard',None)),'shared target-port release exclusion missing')
        with self.assertRaises((CustodyError,RuntimeError)):
            f._release_guard(c,s._actor,d['spawn_token']['token_id'])

    def test_T1_F23_seal_is_only_release_denial(self):
        for sealed in (False,True):
            with self.subTest(containment_sealed=sealed):
                s,a,c,d,f,l=self.world();domain=f._entries[d['delegation_id']]['domain']
                original=c.initiate_control;reached=[]
                def control(capability,binding,dispatcher):
                    if binding.transition=='RELEASED_OR_POSSIBLY_RELEASED':
                        # A fully accepted original RELEASE reaches the native
                        # port. Only the seal changes; no terminal/loss trigger.
                        self.assertIs(s.store.validate_initiation(capability),s._actor)
                        f._release_guard(c,s._actor,d['spawn_token']['token_id'])
                        self.assertTrue(c.alive);self.assertTrue(domain.target_valid())
                        self.assertTrue(domain.worker.possibly_live);self.assertTrue(domain.worker.identity.alive)
                        self.assertIsNone(s.store.witness.denial(s._actor))
                        self.assertNotIn(s._actor,f._lost_supervisors)
                        self.assertNotIn(c,f._lost_sources)
                        self.assertEqual(domain.initiations,0)
                        domain.sealed=sealed;reached.append(True)
                    return original(capability,binding,dispatcher)
                c.initiate_control=control
                if sealed:
                    with self.assertRaisesRegex(ContainmentUnavailable,'irreversibly sealed'):
                        s.complete_worker_lifecycle('slot-1-1')
                else:s.complete_worker_lifecycle('slot-1-1')
                self.assertEqual(reached,[True])
                self.assertEqual(domain.releases,0 if sealed else 1)

    def test_T4_original_cleanup_quarantine_denies_before_initiation(self):
        s,a,c,d,f,l=self.world();ref=self.failure(s)
        self.assert_cleanup_failure(s,c,d,f,ref)
        self.assertIs(f._original_current(c,s._actor),s.store)
        s.store.quarantined=True
        before=(s.store.revision,dict(s.store._objects),dict(s.store.witness.pending),f._verifier.request_sequence)
        with self.assertRaisesRegex(RuntimeError,'quarantin'):
            f.request_original_cleanup(c,s._actor,d['delegation_id'],ref)
        self.assertEqual((s.store.revision,dict(s.store._objects),dict(s.store.witness.pending),f._verifier.request_sequence),before)
        self.no_effect(f,d)
        self.assertEqual(self.snapshot(f,d)['operation_state'],'READY')


class CheckpointBLowerPortTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect
    # Only new tests are collected for this class; shared fixture helpers above
    # remain implementation-independent oracles.
    def test_direct_port_cannot_resume_claimed_survivor_call(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
        domain=f._entries[d['delegation_id']]['domain']
        with self.assertRaises((CustodyError,RuntimeError)):
            domain._initiate(f._actor_id(d),d['operation_id'])
        self.no_effect(f,d)

    def test_required_ownership_invalidation_is_a_positive_independent_trigger(self):
        s,a,c,d,f,l=self.world()
        self.assertTrue(callable(getattr(l,'invalidate_ownership',None)),'required-binding observation source missing')
        l.invalidate_ownership(c,d['spawn_token']['token_id'])
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual(s.store.witness.denial(s._actor)[0],'CUSTODY_LOSS_PROVEN')

    def test_retained_c_loss_survives_discarded_source_caches(self):
        s,a,c,d,f,l=self.world()
        c._boot_custody.clear();c._creation_receipts.clear();c._creation_bindings.clear();c._registry.clear()
        s._slot_tokens.clear();s._slot_capabilities.clear()
        l.terminate(c)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual(s.store.witness.denial(s._actor)[0],'CUSTODY_LOSS_PROVEN')

    def test_copied_factory_cannot_register_or_dispatch(self):
        import copy
        s,a,c,d,f,l=self.world();copied=copy.copy(f)
        with self.assertRaises((CustodyError,RuntimeError)):
            copied._establish(c,d['spawn_token']['token_id'],s._actor)
        self.no_effect(f,d)


class CheckpointBEstablishmentAndReportTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect

    def test_survivor_report_healthy_rw_retains_original_owner_and_actual_actor(self):
        s,a,c,d,f,l=self.world();l.terminate(s._actor)
        actor=s.store.open_nonlive_entry(s.authorization,'b-report-reader')
        rw=s.store.recovery_writer_binding(actor);snap=f.inspect(d['delegation_id'],reader=rw)
        receipt=s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],
            supplement_kind='CONTAINMENT_EVIDENCE',evidence_bytes=snap['receipt_bytes'],
            source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id'])
        self.assertTrue(receipt.durable);self.assertEqual(snap['receipt']['custodian_id'],c.identity)
        self.assertNotEqual(f._actor_id(d),c.identity)
        before=s.store.revision
        with self.assertRaises((CustodyError,RuntimeError)):
            s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],
                supplement_kind='CONTAINMENT_EVIDENCE',evidence_bytes=snap['receipt_bytes'],
                source_id=c.identity,verifier_id=d['evidence_verifier_id'])
        self.assertEqual(s.store.revision,before)

    def test_survivor_death_before_exposure_never_opens_gate(self):
        s,a,c,d,f,l=self.world(establish=False)
        original=f._assert_artifact;calls=[0]
        def lose_at_final_guard(binding):
            original(binding);calls[0]+=1
            if calls[0]==3:
                entry=next(iter(f._entries.values()));l.terminate(entry['endpoint'])
        f._assert_artifact=lose_at_final_guard
        with self.assertRaises((CustodyError,RuntimeError)):
            c.establish_survivor_containment('spawn-slot-1-1',s._actor)
        entry=next(iter(f._entries.values()));self.assertFalse(entry['exposed'])

    def test_original_parent_reap_can_be_reported_after_parent_caches_are_lost(self):
        s,a,c,d,f,l=self.world();c.contain_spawn('spawn-slot-1-1','original',f._entries[d['delegation_id']]['binding'])
        reap=c.wait_reap('spawn-slot-1-1')
        from dataclasses import asdict
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        raw=closed_canonical_bytes(asdict(reap))
        c._registry.clear();l.terminate(c);s.store.crash()
        actor=s.store.open_nonlive_entry(s.authorization,'reap-reader');rw=s.store.recovery_writer_binding(actor)
        ref=f.inspect(d['delegation_id'],reader=rw)['transfer_ref']
        receipt=s.store.record_recovery_supplement(rw,parent_ref=ref,supplement_kind='REAP_EVIDENCE',
            evidence_bytes=raw,source_id=c.identity,verifier_id=c.identity)
        self.assertTrue(receipt.durable)

    def test_T2_survivor_origin_reap_refused_with_valid_parent_receipt(self):
        s,a,c,d,f,l=self.world()
        c.contain_spawn('spawn-slot-1-1','original',f._entries[d['delegation_id']]['binding'])
        reap=c.wait_reap('spawn-slot-1-1');c.validate_reap_receipt(reap)
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        raw=closed_canonical_bytes(dataclasses.asdict(reap))
        s.store.crash()
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'reap-origin-reader'))
        ref=f.inspect(d['delegation_id'],reader=rw)['transfer_ref']
        request=dict(parent_ref=ref,supplement_kind='REAP_EVIDENCE',evidence_bytes=raw,
                     verifier_id=c.identity)
        before=(s.store.revision,dict(s.store._objects),dict(s.store.witness.pending))
        with self.assertRaisesRegex(CustodyError,'survivor wait/reap unavailable'):
            s.store.record_recovery_supplement(rw,source_id=f._actor_id(d),**request)
        self.assertEqual((s.store.revision,dict(s.store._objects),dict(s.store.witness.pending)),before)
        # Identical bytes, verifier, parent, and RW: only actual source differs.
        self.assertTrue(s.store.record_recovery_supplement(rw,source_id=c.identity,**request).durable)

    def test_full_establishment_failure_stages_have_no_gate_before_exposure(self):
        from tools.decision_0009.acer_adapter.custody import OfflineContainmentFactory
        for stage in OfflineContainmentFactory.ESTABLISH_STAGES:
            with self.subTest(establishment_stage=stage):
                s,a,c,d,f,l=self.world(establish=False)
                with self.assertRaises((CustodyError,RuntimeError)):
                    c.establish_survivor_containment('spawn-slot-1-1',s._actor,fault=stage)
                entry=next(iter(f._entries.values()));d=entry['descriptor']
                expected=stage in ('exposed','acknowledged')
                self.assertEqual(entry['exposed'],expected)
                if d is not None:
                    l.terminate(s._actor)
                    self.assertEqual(self.snapshot(f,d)['physical_initiations'],1 if expected else 0)

    def test_lower_control_binding_mismatch_cannot_release_token_domain(self):
        s,a,c,d,f,l=self.world();original=c.initiate_control;observed=[]
        def boundary(capability,binding,dispatcher):
            if binding.transition=='WORKER_IDENTITY_ESTABLISHED':
                forged=dataclasses.replace(binding,transition='RELEASED_OR_POSSIBLY_RELEASED')
                with self.assertRaises((CustodyError,RuntimeError)):
                    original(capability,forged,dispatcher)
                observed.append(f._domains['spawn-slot-1-1'].releases)
            return original(capability,binding,dispatcher)
        c.initiate_control=boundary;s.complete_worker_lifecycle('slot-1-1')
        self.assertEqual(observed,[0]);self.assertEqual(f._domains['spawn-slot-1-1'].releases,1)

    def test_public_copies_have_no_inspection_or_trigger_delivery_permission(self):
        s,a,c,d,f,l=self.world()
        with self.assertRaises((CustodyError,RuntimeError)):
            f.inspect(d['delegation_id'])
        with self.assertRaises((CustodyError,RuntimeError)):
            f.inspect_trigger(d['delegation_id'],b'{}\n')
        self.no_effect(f,d)


class CheckpointBIntegrityTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect

    def test_fault_world_bootstrap_cannot_copy_reserved_survivor(self):
        from acer_adapter_fakes import independent_fault_world
        s,a,c=make_supervisor();other=independent_fault_world(s)
        self.assertIsNot(other.custodian._containment_factory.lock,c._containment_factory.lock)
        self.assertIsNot(other.custodian._containment_factory._verifier,c._containment_factory._verifier)
        s,a,c,d,f,l=self.world()
        with self.assertRaises(RuntimeError): independent_fault_world(s)

    def test_nested_source_loss_propagates_only_outside_c(self):
        s,a,c,d,f,l=self.world();seen=[]
        original=c._loss_callback
        def callback(reason):
            seen.append(f.lock.owned_by_current_thread());return original(reason)
        c._loss_callback=callback
        with f.lock:c.die()
        self.assertEqual(seen,[False])

    def test_corrupt_ready_never_replaces_consuming_trigger(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
        entry=f._entries[d['delegation_id']];consume=entry['operation']['consume']
        entry['operation']={'state':'READY','consume':None};f._fault=None;l.terminate(c)
        self.no_effect(f,d)
        self.assertEqual(f._verifier.uses[consume[0]],consume)
        self.assertEqual(self.snapshot(f,d)['operation_state'],'UNKNOWN')

    def test_lost_delegation_index_cannot_rereserve_actual_domain(self):
        s,a,c,d,f,l=self.world();f._tokens.clear()
        with self.assertRaises((CustodyError,RuntimeError)):
            c.establish_survivor_containment(d['spawn_token']['token_id'],s._actor)
        self.assertEqual(len(f._entries),1);self.no_effect(f,d)

    def test_initiation_observation_survives_lost_response_and_later_exit_query(self):
        s,a,c,d,f,l=self.world();f._fault='after_initiation';l.terminate(s._actor)
        before=self.snapshot(f,d)
        self.assertEqual(before['physical_initiations'],1)
        self.assertEqual(before['receipt']['status'],'IN_PROGRESS')
        old=before['receipt_bytes'];f._fault=None;l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'observer'))
        # Harness supplies the independently observed later port completion.
        f._entries[d['delegation_id']]['domain']._observe_exit()
        observed=f.observe_current_outcome(d['delegation_id'],reader=rw)
        self.assertEqual(observed['receipt']['status'],'EXITED')
        self.assertEqual(observed['physical_initiations'],1)
        self.assertEqual(f._verifier.observations[before['receipt']['receipt_id']]['bytes'],old)

    def test_unregistered_equal_channel_has_no_trigger_authority(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        entry=f._entries[d['delegation_id']];item=next(iter(f._verifier.entries.values()))
        class EqualChannel:
            def __eq__(self,other):return True
        self.assertIsNone(f._retain_trigger(entry,'SUPERVISOR_TERMINAL',item['facts'],EqualChannel()))
        self.no_effect(f,d)

    def test_revoke_during_final_artifact_guard_cannot_initiate(self):
        s,a,c,d,f,l=self.world();original=f._assert_artifact;calls=[0]
        def revoke(binding):
            original(binding);calls[0]+=1
            if calls[0]==2:l.terminate(f._entries[d['delegation_id']]['endpoint'])
        f._assert_artifact=revoke;l.terminate(s._actor)
        self.no_effect(f,d)

    def test_complete_independent_closure_is_required_at_final_gate(self):
        import copy
        for key in ('transfer_bytes','acceptance_bytes','creation_bytes','boot_custody','registration'):
            with self.subTest(closure_member=key):
                s,a,c,d,f,l=self.world();entry=f._entries[d['delegation_id']]
                entry['closure'][key]=b'forged'
                l.terminate(s._actor);self.no_effect(f,d)


class CheckpointBProtocolClosureTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect
    failure=CheckpointBTriggerMatrixTests.failure

    def test_T_AUTH_final_verifier_registered_channel_pair(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        e=f._entries[d['delegation_id']];tid=next(iter(f._verifier.entries));calls=[]
        original=f._validate_trigger
        def counted(*args):calls.append(args[2]);return original(*args)
        f._validate_trigger=counted;f._fault=None
        with self.assertRaises((CustodyError,RuntimeError)):f._deliver(e,tid,object(),e['endpoint'])
        self.no_effect(f,d);self.assertEqual(len(calls),1)
        f._deliver(e,tid,f._observer_channel,e['endpoint'])
        self.assertEqual(len(calls),4);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_T_REPLAY_complete_subject_and_evidence_digest_closure(self):
        import copy,json
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes,validate_survivor_trigger,ContractError
        fields=('store_identity','campaign_id','authorization_digest','target_identity_digest','descriptor_digest',
            'delegation_id','operation_id','source_custodian_id','source_custodian_incarnation',
            'original_generation','original_incarnation_id','original_session_id','original_fence',
            'producer_epoch','verifier_id','evidence_id','evidence_sequence','evidence_digest','trigger_sequence')
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        entry=f._entries[d['delegation_id']];item=next(iter(f._verifier.entries.values()))
        trigger=json.loads(item['trigger']);evidence=json.loads(item['evidence'])
        cases=[]
        for key in fields:
            changed=copy.deepcopy(trigger);value=changed[key];changed[key]=value+1 if type(value) is int else ('0'*64 if len(value)==64 else 'substituted')
            cases.append((key,changed,evidence))
        for key in ('token_id','campaign_id','boot_id','slot_id','attempt_id','launch_spec_digest','custodian_id','supervisor_generation'):
            changed=copy.deepcopy(trigger);value=changed['spawn_token'][key]
            changed['spawn_token'][key]=value+1 if type(value) is int else ('0'*64 if len(value)==64 else 'substituted')
            cases.append(('spawn_token.'+key,changed,evidence))
        for key in ('survivor_incarnation','producer_id','observer_id'):
            changed=copy.deepcopy(trigger);changed[key][-1]='substituted';cases.append((key,changed,evidence))
        changed=copy.deepcopy(evidence);changed['facts']['original_fence']+=1;cases.append(('same-evidence-id-changed-bytes',trigger,changed))
        for key,t,e in cases:
            with self.subTest(substitution=key),self.assertRaises(ContractError):
                validate_survivor_trigger(closed_canonical_bytes(t),closed_canonical_bytes(e),entry['descriptor_bytes'])
        self.no_effect(f,d);f._fault=None;l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_T_COPY_opaque_wrappers_and_scope_ceiling(self):
        import copy,pickle
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        entry=f._entries[d['delegation_id']];tid=next(iter(f._verifier.entries));endpoint=entry['endpoint']
        for candidate in (dataclasses.replace(endpoint),copy.copy(f),dict(d),d['capability_id']):
            with self.subTest(copy_type=type(candidate).__name__),self.assertRaises((CustodyError,RuntimeError,TypeError)):
                f._deliver(entry,tid,f._observer_channel,candidate)
        with self.assertRaises(TypeError):copy.copy(endpoint)
        with self.assertRaises(TypeError):copy.deepcopy(endpoint)
        with self.assertRaises(TypeError):pickle.dumps(endpoint)
        for action in (lambda:c.wait_reap(d['spawn_token']['token_id']),
            lambda:s.store.recovery_writer_binding(endpoint),lambda:s.store.record_recovery_entry(endpoint),
            lambda:s.store.require_actor(endpoint,'EXEC'),lambda:s.store.require_actor(endpoint,'ADMIT'),
            lambda:s.store.require_actor(endpoint,'RP'),lambda:c.establish_survivor_containment(d['spawn_token']['token_id'],endpoint)):
            with self.assertRaises((CustodyError,RuntimeError,TypeError)):action()
        self.no_effect(f,d);f._fault=None;l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_T_ATOMIC_all_operation_windows_and_response_loss(self):
        for stage,count,state in (('before_prepare',0,'READY'),('before_commit',0,'READY'),
            ('before_claim',0,'READY'),('prepare_ambiguous',0,'UNKNOWN'),('after_commit',0,'CLAIMED'),
            ('after_claim',0,'CLAIMED'),('before_initiation',0,'CLAIMED'),('after_initiation',1,'STARTED'),('result_before_response',1,'RESULT_AVAILABLE')):
            with self.subTest(operation_stage=stage):
                s,a,c,d,f,l=self.world();f._fault=stage;l.terminate(s._actor)
                snap=self.snapshot(f,d);self.assertEqual(snap['physical_initiations'],count);self.assertEqual(snap['operation_state'],state)
                self.assertFalse(snap['operation_state']=='READY' and snap['consume'] is not None)
                f._fault=None;l.terminate(s._actor)
                self.assertEqual(self.snapshot(f,d)['physical_initiations'],1 if state=='READY' else count)
                self.assertEqual(self.snapshot(f,d)['teardowns'],1 if state=='READY' else count)

    def test_T_RETENTION_loss_of_each_required_c_component_is_query_only(self):
        for lost in ('archive','delegation-proof','operation','handle','port-registry','endpoint','lifetime-service'):
            with self.subTest(lost=lost):
                s,a,c,d,f,l=self.world();e=f._entries[d['delegation_id']]
                if lost=='archive':f._verifier.available=False
                elif lost=='delegation-proof':f._verifier.delegations.clear()
                elif lost=='operation':e['operation']=None
                elif lost=='handle':e['domain'].handle_live=False
                elif lost=='port-registry':e['domain'].readable=False
                elif lost=='endpoint':l.terminate(e['endpoint'])
                else:l.available=False
                l.terminate(s._actor);self.no_effect(f,d)
                if lost in ('operation','port-registry'):self.assertEqual(self.snapshot(f,d)['operation_state'],'UNKNOWN')

    def test_T_CURRENT_full_target_identity_and_artifact_substitution(self):
        from dataclasses import replace
        for field in ('boot_id','host_pid','pid_namespace','namespace_pid','process_start_ticks','executable_path',
                'executable_device','executable_inode','executable_digest','cgroup_path','cgroup_device','cgroup_inode',
                'cgroup_members','custodian_id','spawn_token','gpu_uuid','host_id'):
            with self.subTest(target_field=field):
                s,a,c,d,f,l=self.world();domain=f._entries[d['delegation_id']]['domain'];value=getattr(domain.worker.identity,field)
                changed=(value+1 if type(value) is int else (value[0]+1,) if type(value) is tuple else
                    '0'*64 if len(value)==64 else '/substituted' if value.startswith('/') else 'substituted')
                domain.worker.identity=replace(domain.worker.identity,**{field:changed});l.terminate(s._actor);self.no_effect(f,d)
        s,a,c,d,f,l=self.world();f._artifact_verifier.root_binding_live=False;l.terminate(s._actor);self.no_effect(f,d)

    def test_T_CLEANUP_revocation_before_claim_or_final_port_prevents_cleanup(self):
        for call in (1,2):
            with self.subTest(revoke_at_verification=call):
                s,a,c,d,f,l=self.world();ref=self.failure(s);original=f._validate_trigger;calls=[0]
                def lose(*args):
                    value=original(*args);calls[0]+=1
                    if calls[0]==call:s.store.crash()
                    return value
                f._validate_trigger=lose
                with self.assertRaises((CustodyError,RuntimeError)):f.request_original_cleanup(c,s._actor,d['delegation_id'],ref)
                self.no_effect(f,d)
                f._validate_trigger=original;l.terminate(s._actor)
                self.assertEqual(self.snapshot(f,d)['physical_initiations'],1 if call==1 else 0)

    def test_T_EVIDENCE_report_forgery_cannot_mutate_d_or_latch(self):
        import json,copy
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        s,a,c,d,f,l=self.world();l.terminate(s._actor)
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'report-forgery'))
        snap=self.snapshot(f,d);receipt=json.loads(snap['receipt_bytes'])
        cases=[]
        for key,value in (('receipt_id','invented'),('custodian_id','substituted'),('spawn_token','other-token'),
            ('launch_spec_digest','0'*64),('status','BLOCKED'),('status','FAILED_NO_CHILD'),('status','REAPED'),('possibly_live',True)):
            changed=copy.deepcopy(receipt);changed[key]=value;cases.append((key,closed_canonical_bytes(changed)))
        changed=copy.deepcopy(receipt);changed['process_identity']['process_start_ticks']+=1;cases.append(('process',closed_canonical_bytes(changed)))
        cases.append(('trigger-as-receipt',next(iter(f._verifier.entries.values()))['trigger']))
        before=(s.store.revision,dict(s.store._objects),s.store.health,s.store.witness.denial(s.store._current_actor))
        for key,raw in cases:
            with self.subTest(receipt_attack=key),self.assertRaises((CustodyError,RuntimeError,KeyError)):
                s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],supplement_kind='CONTAINMENT_EVIDENCE',
                    evidence_bytes=raw,source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id'])
        self.assertEqual((s.store.revision,dict(s.store._objects),s.store.health,s.store.witness.denial(s.store._current_actor)),before)
        l.terminate(f._entries[d['delegation_id']]['endpoint'])
        self.assertTrue(s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],supplement_kind='CONTAINMENT_EVIDENCE',
            evidence_bytes=snap['receipt_bytes'],source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id']).durable)
        with self.assertRaises((CustodyError,RuntimeError)):c.wait_reap('not-a-child')

    def test_origin_delegation_all_witness_transaction_stages(self):
        for stage in U04_COMMIT_STAGES:
            with self.subTest(delegation_transaction_stage=stage):
                s,a,c,d,f,l=self.world(establish=False);original=s.store._commit_u04
                def fault(actor,boundary,event,**kwargs):
                    if event.get('record_type')=='SURVIVOR_TRANSFER':kwargs['fault']=stage
                    return original(actor,boundary,event,**kwargs)
                s.store._commit_u04=fault
                with self.assertRaises((CustodyError,RuntimeError)):c.establish_survivor_containment('spawn-slot-1-1',s._actor)
                e=next(iter(f._entries.values()));d=e['descriptor'];self.assertFalse(e['exposed'])
                if stage in ('frame_before_readback','validated_before_commit'):
                    raw=s.store._durable[-1]['bytes'];s.store.reconcile_pending(s.store._authentication_service,s.authorization)
                    self.assertEqual(s.store._durable[-1]['bytes'],raw)
                l.terminate(s._actor);self.no_effect(f,d)
                with self.assertRaises((CustodyError,RuntimeError)):c.establish_survivor_containment('spawn-slot-1-1',s._actor)

    def test_exposure_lifetime_races_all_three_domains(self):
        for subject in ('supervisor','source','survivor'):
            for side in ('before','after'):
                with self.subTest(lifetime=subject,exposure_side=side):
                    s,a,c,d,f,l=self.world(establish=False)
                    if side=='before':
                        original=f._assert_artifact;calls=[0]
                        def lose(binding):
                            original(binding);calls[0]+=1
                            if calls[0]==3:
                                e=next(iter(f._entries.values()));target=s._actor if subject=='supervisor' else c if subject=='source' else e['endpoint']
                                l.terminate(target)
                        f._assert_artifact=lose
                        with self.assertRaises((CustodyError,RuntimeError)):c.establish_survivor_containment('spawn-slot-1-1',s._actor)
                        e=next(iter(f._entries.values()));self.assertFalse(e['exposed']);self.assertEqual(e['domain'].initiations,0)
                    else:
                        d=c.establish_survivor_containment('spawn-slot-1-1',s._actor);e=f._entries[d['delegation_id']]
                        l.terminate(s._actor if subject=='supervisor' else c if subject=='source' else e['endpoint'])
                        if subject=='survivor':l.terminate(s._actor)
                        self.assertEqual(e['domain'].initiations,0 if subject=='survivor' else 1)


class CheckpointBReportClosureTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect

    def test_original_source_receipt_and_join_report_actual_source(self):
        from dataclasses import asdict
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        for join in (False,True):
            with self.subTest(join=join):
                s,a,c,d,f,l=self.world();e=f._entries[d['delegation_id']]
                c.contain_spawn('spawn-slot-1-1','original',e['binding'])
                raw=closed_canonical_bytes(asdict(e['domain'].worker.receipt))
                if join:l.terminate(s._actor)
                else:s.store.crash()
                rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'source-report'))
                receipt=s.store.record_recovery_supplement(rw,parent_ref=d['original_ownership_ref'],
                    supplement_kind='CONTAINMENT_EVIDENCE',evidence_bytes=raw,source_id=c.identity,verifier_id=c.identity)
                self.assertTrue(receipt.durable)
                if join:
                    snap=f.inspect(d['delegation_id'],reader=rw)
                    self.assertEqual(snap['receipt_bytes'],raw)
                    self.assertEqual(snap['physical_initiations'],1)
                with self.assertRaises((CustodyError,RuntimeError)):
                    s.store.record_recovery_supplement(rw,parent_ref=d['original_ownership_ref'],
                        supplement_kind='CONTAINMENT_EVIDENCE',evidence_bytes=raw,
                        source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id'])

    def test_closed_failure_envelope_retains_original_verified_diagnostic(self):
        s,a,c,d,f,l=self.world();record={'state':'TAINTED','reason':'SOURCE_UNAVAILABLE',
            'raw_digest':digest('failure'),'raw_length':0,'authorization_digest':s.authorization.authorization_digest,
            'campaign_id':s.authorization.campaign_id,'authorizes_execution':False}
        ref=s.store._reference(s.store.record_original_diagnostic(s._actor,record))
        self.assertTrue(callable(getattr(c,'observe_failure_envelope',None)),'closed failure-envelope source missing')
        raw=c.observe_failure_envelope(ref,'SOURCE_UNAVAILABLE')
        s.store.crash();rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'failure-report'))
        receipt=s.store.record_recovery_supplement(rw,parent_ref=ref,supplement_kind='FAILURE_ENVELOPE',
            evidence_bytes=raw,source_id=c.identity,verifier_id=f._verifier.identity)
        self.assertTrue(receipt.durable)
        import json
        from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
        value=json.loads(raw)
        for key,replacement in (('failure_code','invented'),('source_refs',[d['original_ownership_ref']]),('raw_object_refs',[None]),('extra',True)):
            with self.subTest(failure_envelope_field=key):
                changed=dict(value);changed[key]=replacement;before=(s.store.revision,dict(s.store._objects))
                with self.assertRaises((CustodyError,RuntimeError)):
                    s.store.record_recovery_supplement(rw,parent_ref=ref,supplement_kind='FAILURE_ENVELOPE',
                        evidence_bytes=closed_canonical_bytes(changed),source_id=c.identity,verifier_id=f._verifier.identity)
                self.assertEqual((s.store.revision,dict(s.store._objects)),before)

    def test_archived_dispatch_report_requires_exact_consumption_proof(self):
        s,a,c,d,f,l=self.world();l.terminate(s._actor);snap=self.snapshot(f,d)
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'consumption-report'))
        f._verifier.uses.clear();before=(s.store.revision,dict(s.store._objects))
        with self.assertRaises((CustodyError,RuntimeError)):
            s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],supplement_kind='CONTAINMENT_EVIDENCE',
                evidence_bytes=snap['receipt_bytes'],source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id'])
        self.assertEqual((s.store.revision,dict(s.store._objects)),before)

    def test_trigger_validation_only_supports_truthful_unavailability_obligation(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'unavailability-report'))
        ref=f._entries[d['delegation_id']]['transfer_ref']
        target={'kind':'CUSTODIAN','identity':c.identity,'destination_id':None,'object_key':None,
            'subject_ref':ref,'subject_state':'KNOWN','evidence_ref':None,'evidence_state':'UNAVAILABLE'}
        before=s.store.revision
        with self.assertRaises((CustodyError,RuntimeError)):
            s.store.record_recovery_obligation(rw,obligation_id='forged-loss',kind='CONTAINMENT_UNAVAILABLE',
                reason_code='CUSTODIAN_UNAVAILABLE',subject_refs=[d['original_ownership_ref'],ref],target_ref=target)
        self.assertEqual(s.store.revision,before)
        l.terminate(c)
        receipt=s.store.record_recovery_obligation(rw,obligation_id='proven-unavailability',kind='CONTAINMENT_UNAVAILABLE',
            reason_code='CUSTODIAN_UNAVAILABLE',subject_refs=[d['original_ownership_ref'],ref],target_ref=target)
        self.assertTrue(receipt.durable);self.no_effect(f,d)

    def test_T_W_positive_loss_survives_failed_update_restoration_and_reset(self):
        s,a,c,d,f,l=self.world();s.store.witness.available=False;l.terminate(c)
        self.assertTrue(s.store.execution_revoked);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        s.store.witness.available=True;s.store.reset_volatile()
        actor=s.store.open_nonlive_entry(s.authorization,'restored-reader')
        # A retains its established first-positive predicate precedence. With
        # the initial W update unavailable, nonlive entry first proves boot loss.
        denial=s.store.witness.denial(actor)
        self.assertEqual(denial[0],'UNFINISHED_BOOT_LOSS')
        proof=f._verifier.delegations[d['delegation_id']]
        from tools.decision_0009.acer_adapter.contracts import parse_closed_canonical
        self.assertTrue(f._confirms_required_loss(c,parse_closed_canonical(proof['boot_custody'])[0]))
        for n in range(2):
            s.store.crash();s.store.reset_volatile();actor=s.store.open_nonlive_entry(s.authorization,'repeat-reader')
            self.assertEqual(s.store.witness.denial(actor),denial)
            self.assertTrue(s.store.execution_revoked)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)


class CheckpointBConcurrencyTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot

    def thread(self,action,errors,started=None):
        def run():
            if started is not None:started.set()
            try:action()
            except Exception as exc:errors.append(exc)
        t=threading.Thread(target=run,daemon=True);t.start();return t

    def finish(self,threads):
        for t in threads:t.join(5)
        self.assertFalse(any(t.is_alive() for t in threads),'bounded interleaving deadlocked')

    def test_F22_both_source_survivor_orders_share_one_actual_port(self):
        for winner in ('source','survivor'):
            with self.subTest(port_winner=winner):
                s,a,c,d,f,l=self.world();e=f._entries[d['delegation_id']];domain=e['domain']
                entered=threading.Event();proceed=threading.Event();attempted=threading.Event();errors=[]
                original=domain._initiate
                def boundary(*args,**kwargs):
                    entered.set();self.assertTrue(proceed.wait(5));return original(*args,**kwargs)
                domain._initiate=boundary
                source=lambda:c.contain_spawn('spawn-slot-1-1','original',e['binding'])
                survivor=lambda:l.terminate(s._actor)
                first=self.thread(source if winner=='source' else survivor,errors)
                self.assertTrue(entered.wait(5))
                second=self.thread(survivor if winner=='source' else source,errors,attempted)
                self.assertTrue(attempted.wait(5));self.assertEqual(domain.initiations,0)
                proceed.set();self.finish((first,second));self.assertEqual(errors,[])
                snap=self.snapshot(f,d);self.assertEqual((snap['physical_initiations'],snap['teardowns']),(1,1))
                self.assertTrue(snap['domain_sealed'])
                self.assertEqual(domain.claim[0],c.identity if winner=='source' else f._actor_id(d))
                self.assertEqual(snap['receipt']['custodian_id'],c.identity)
                if winner=='source':self.assertEqual(snap['receipt']['receipt_id'],'contained-spawn-slot-1-1')

    def test_F23_both_release_containment_orders_and_callbacks_outside_c(self):
        for winner in ('release','containment'):
            with self.subTest(port_winner=winner):
                s,a,c,d,f,l=self.world();domain=f._entries[d['delegation_id']]['domain'];errors=[]
                release_stage=threading.Event();allow_release=threading.Event();initiated=threading.Event();seen=[]
                original=c.initiate_control;native=domain._initiate
                def contain_boundary(*args,**kwargs):
                    result=native(*args,**kwargs);initiated.set();return result
                domain._initiate=contain_boundary
                def control(capability,binding,dispatcher):
                    if binding.transition!='RELEASED_OR_POSSIBLY_RELEASED':return original(capability,binding,dispatcher)
                    if winner=='containment':
                        release_stage.set();self.assertTrue(allow_release.wait(5))
                    def observed_dispatch(cap,art):
                        seen.append(f.lock.owned_by_current_thread())
                        release_stage.set();self.assertTrue(allow_release.wait(5))
                        return dispatcher(cap,art)
                    return original(capability,binding,observed_dispatch)
                c.initiate_control=control
                release=self.thread(lambda:s.complete_worker_lifecycle('slot-1-1'),errors)
                self.assertTrue(release_stage.wait(5))
                loss=self.thread(lambda:l.terminate(s._actor),errors)
                self.assertTrue(initiated.wait(5));allow_release.set();self.finish((release,loss))
                self.assertEqual((domain.initiations,domain.teardowns),(1,1))
                self.assertEqual(domain.releases,1 if winner=='release' else 0)
                self.assertTrue(domain.sealed)
                self.assertEqual(seen,[False] if winner=='release' else [])
                self.assertTrue(all(isinstance(error,(CustodyError,RuntimeError)) for error in errors))

    def test_duplicate_preclaim_deliveries_race_one_immutable_consume(self):
        s,a,c,d,f,l=self.world();f._fault='before_claim';l.terminate(s._actor)
        e=f._entries[d['delegation_id']];tid=next(iter(f._verifier.entries));f._fault=None
        start=threading.Barrier(3);errors=[]
        def deliver():start.wait(5);f._deliver(e,tid,f._observer_channel,e['endpoint'])
        threads=[self.thread(deliver,errors) for _ in range(2)]
        start.wait(5);self.finish(threads);self.assertEqual(errors,[])
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)
        self.assertEqual(len(f._verifier.uses),1)

    def test_source_claim_without_initiation_cannot_be_replaced_by_survivor(self):
        s,a,c,d,f,l=self.world();domain=f._entries[d['delegation_id']]['domain']
        domain.claim=(c.identity,'original-containment-spawn-slot-1-1');domain.sealed=True
        l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d)['physical_initiations'],0)
        self.assertEqual(self.snapshot(f,d)['operation_state'],'CLAIMED')
        l.terminate(s._actor);self.assertEqual(domain.initiations,0)


class CheckpointBFinalBoundaryTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect
    failure=CheckpointBTriggerMatrixTests.failure

    def test_T10_unknown_and_observation_only_exit_never_claim_initiation(self):
        from dataclasses import replace
        for outcome in ('UNKNOWN','EXITED'):
            with self.subTest(independent_observation=outcome):
                s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
                e=f._entries[d['delegation_id']]
                if outcome=='EXITED':
                    # Independently modeled external exit; this is not port
                    # initiation and is never labeled as containment causation.
                    e['domain'].worker.identity=replace(e['domain'].worker.identity,alive=False)
                    e['domain'].worker.possibly_live=False
                rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'outcome-reader'))
                snap=f.observe_current_outcome(d['delegation_id'],reader=rw)
                self.assertEqual(snap['receipt']['status'],outcome);self.assertEqual(snap['physical_initiations'],0)
                observation=f._verifier.observations[snap['receipt']['receipt_id']]
                self.assertFalse(observation['initiated']);self.assertTrue(observation['observation_only'])
                self.assertTrue(s.store.record_recovery_supplement(rw,parent_ref=snap['transfer_ref'],
                    supplement_kind='CONTAINMENT_EVIDENCE',evidence_bytes=snap['receipt_bytes'],source_id=f._actor_id(d),
                    verifier_id=d['evidence_verifier_id']).durable)

    def test_s_dead_has_archived_report_but_cannot_create_new_observation(self):
        s,a,c,d,f,l=self.world();f._fault='after_initiation';l.terminate(s._actor)
        l.terminate(f._entries[d['delegation_id']]['endpoint'])
        rw=s.store.recovery_writer_binding(s.store.open_nonlive_entry(s.authorization,'dead-observer'))
        prior=self.snapshot(f,d);before=len(f._verifier.observations)
        with self.assertRaises((CustodyError,RuntimeError)):f.observe_current_outcome(d['delegation_id'],reader=rw)
        self.assertEqual(len(f._verifier.observations),before)
        self.assertTrue(s.store.record_recovery_supplement(rw,parent_ref=prior['transfer_ref'],supplement_kind='CONTAINMENT_EVIDENCE',
            evidence_bytes=prior['receipt_bytes'],source_id=f._actor_id(d),verifier_id=d['evidence_verifier_id']).durable)

    def test_T_POSITIVE_missing_and_ambiguous_signals_have_no_loss_authority(self):
        for ambiguous in ('heartbeat','timeout','pid-lookup-miss','channel-close','stale-message','unreadable-source'):
            with self.subTest(ambiguous_observation=ambiguous):
                s,a,c,d,f,l=self.world();entry=f._entries[d['delegation_id']]
                if ambiguous=='unreadable-source':l.available=False
                # No independently bound terminal event exists for these caller
                # observations. Authentic-looking bytes still lack membership.
                from tools.decision_0009.acer_adapter.contracts import closed_canonical_bytes
                raw=closed_canonical_bytes({'observation':ambiguous,'original_session':s._actor.session_id})
                self.assertEqual(f.inspect_trigger(d['delegation_id'],raw,reader=__import__('acer_adapter_fakes').b_reader(f)),'TRIGGER_UNAVAILABLE')
                self.no_effect(f,d);self.assertEqual(f._verifier.entries,{})
                self.assertIsNone(s.store.witness.denial(s._actor))
                l.available=True;l.terminate(s._actor);self.assertEqual(self.snapshot(f,d)['physical_initiations'],1)

    def test_T_CLEANUP_exact_origin_ref_and_subject_are_mandatory(self):
        import copy
        for changed in ('digest','revision','event-id','ownership-not-failure','wrong-delegation','uncommitted','reconciled'):
            with self.subTest(cleanup_proof=changed):
                s,a,c,d,f,l=self.world();ref=self.failure(s)
                if changed=='digest':ref['payload_digest']='0'*64
                elif changed=='revision':ref['revision']+=1
                elif changed=='event-id':ref['event_id']='forged'
                elif changed=='ownership-not-failure':ref=d['original_ownership_ref']
                elif changed=='wrong-delegation':d=dict(d,delegation_id='other-delegation')
                elif changed in ('uncommitted','reconciled'):
                    # A real original diagnostic is interrupted in its witnessed
                    # commit window; reconciliation never supplies ORIGIN ACK.
                    record={'state':'TAINTED','reason':'SOURCE_UNAVAILABLE','raw_digest':digest('raw'),
                        'raw_length':0,'authorization_digest':s.authorization.authorization_digest,
                        'campaign_id':s.authorization.campaign_id,'authorizes_execution':False}
                    with self.assertRaises(RuntimeError):s.store._commit_u04(s._actor,'HISTORY',record,fault='validated_before_commit')
                    tail=s.store._durable[-1];ref=s.store._reference(tail['receipt'])
                    if changed=='reconciled':s.store.reconcile_pending(s.store._authentication_service,s.authorization)
                with self.assertRaises((CustodyError,RuntimeError)):f.request_original_cleanup(c,s._actor,d['delegation_id'],ref)
                self.assertEqual(sum(x.initiations for x in f._domains.values()),0)

    def test_establishment_stage_losses_cannot_complete_after_restart(self):
        from tools.decision_0009.acer_adapter.custody import OfflineContainmentFactory
        for stage in OfflineContainmentFactory.ESTABLISH_STAGES[:5]:
            for subject in ('supervisor','source','survivor'):
                with self.subTest(stage=stage,lost_domain=subject):
                    s,a,c,d,f,l=self.world(establish=False)
                    with self.assertRaises((CustodyError,RuntimeError)):
                        c.establish_survivor_containment('spawn-slot-1-1',s._actor,fault=stage)
                    e=next(iter(f._entries.values()));l.terminate(s._actor if subject=='supervisor' else c if subject=='source' else e['endpoint'])
                    self.assertFalse(e['exposed']);self.assertEqual(e['domain'].initiations,0)
                    s.store.crash();s.store.reset_volatile();new=s.store.open_nonlive_entry(s.authorization,'partial-recovery')
                    with self.assertRaises((CustodyError,RuntimeError)):c.establish_survivor_containment('spawn-slot-1-1',new)
                    self.assertFalse(e['exposed']);self.assertEqual(e['domain'].initiations,0)


class CheckpointBNativeCurrentnessTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect

    def test_all_survivor_continuity_guards_detect_same_stack_revocation(self):
        for stage in (1,2,3,4):
            for loss in ('gate','handle','artifact'):
                with self.subTest(continuity_guard=stage,loss=loss):
                    s,a,c,d,f,l=self.world();original=f._assert_artifact;calls=[0]
                    def invalidate(binding):
                        original(binding);calls[0]+=1
                        if calls[0]==stage:
                            if loss=='gate':l.terminate(f._entries[d['delegation_id']]['endpoint'])
                            elif loss=='handle':f._entries[d['delegation_id']]['domain'].handle_live=False
                            else:f._artifact_verifier.root_binding_live=False
                    f._assert_artifact=invalidate;l.terminate(s._actor);self.no_effect(f,d)

    def test_original_containment_native_port_detects_source_loss_during_validation(self):
        for stage in (1,2):
            with self.subTest(original_continuity_guard=stage):
                s,a,c,d,f,l=self.world();original=f._assert_original_containment;calls=[0]
                def lose(domain,binding):
                    original(domain,binding);calls[0]+=1
                    if calls[0]==stage:c.die()
                f._assert_original_containment=lose
                with self.assertRaises((CustodyError,RuntimeError)):
                    c.contain_spawn('spawn-slot-1-1','original',f._entries[d['delegation_id']]['binding'])
                self.no_effect(f,d)


class CheckpointBMultipleDomainTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot

    def test_one_lifetime_loss_notifies_every_independently_bound_domain(self):
        from acer_adapter_fakes import core_attempt_bytes,residual_observations
        for subject in ('supervisor','source'):
            with self.subTest(terminal_subject=subject):
                s,a,c,d,f,l=self.world();s.complete_worker_lifecycle('slot-1-1')
                s.persist_local_attempt_evidence('slot-1-1',core_attempt_bytes(s.authorization.slots[0]),residual_observations())
                s.make_slot_eligible('slot-1-2');child=s.spawn_worker('slot-1-2',digest('second-launch'))
                second=c.establish_survivor_containment(child.spawn_token,s._actor)
                l.terminate(s._actor if subject=='supervisor' else c)
                first=self.snapshot(f,d);other=self.snapshot(f,second)
                self.assertEqual(first['operation_state'],'RESULT_AVAILABLE')
                # Original uninterrupted cleanup already initiated this domain;
                # the later survivor joins that same retained source action.
                self.assertEqual(first['physical_initiations'],1)
                self.assertEqual(first['receipt']['receipt_id'],'contained-spawn-slot-1-1')
                self.assertEqual(other['operation_state'],'RESULT_AVAILABLE')
                self.assertEqual(other['physical_initiations'],1)
                self.assertEqual(len(f._verifier.uses),2)

    def test_original_source_cannot_contain_after_positive_unobserved_endpoint_loss(self):
        from acer_adapter_fakes import b_lifetimes
        s,a,c=make_supervisor();s.make_slot_eligible('slot-1-1');created=s.spawn_worker('slot-1-1',digest('launch'))
        f=c._containment_factory;b_lifetimes(c).terminate(c)
        with self.assertRaises((CustodyError,RuntimeError)):
            c.contain_spawn(created.spawn_token,'original',c.original_creation_binding(created.spawn_token))
        self.assertFalse(c.alive)


class CheckpointBResponseTruthfulnessTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot
    no_effect=CheckpointBTriggerMatrixTests.no_effect

    def test_lost_result_response_retains_exact_receipt_without_retry(self):
        s,a,c,d,f,l=self.world();f._fault='result_before_response';l.terminate(s._actor)
        e=f._entries[d['delegation_id']];before=self.snapshot(f,d)
        self.assertEqual(e['last_delivery_status'],'OUTCOME_UNKNOWN')
        self.assertEqual(before['operation_state'],'RESULT_AVAILABLE')
        self.assertEqual(before['physical_initiations'],1)
        f._fault=None;l.terminate(s._actor)
        self.assertEqual(self.snapshot(f,d),before)
        self.assertEqual(e['last_delivery_status'],'EXISTING_RESULT')

    def test_original_join_cannot_report_claimed_gap_as_containment(self):
        s,a,c,d,f,l=self.world();f._fault='before_initiation';l.terminate(s._actor)
        e=f._entries[d['delegation_id']]
        with self.assertRaises((CustodyError,RuntimeError)):
            c.contain_spawn(d['spawn_token']['token_id'],'original',e['binding'])
        self.no_effect(f,d);self.assertEqual(e['operation']['state'],'CLAIMED')
        self.assertEqual(f._verifier.observations,{})


class CheckpointBTargetPortRetentionTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world
    snapshot=CheckpointBTriggerMatrixTests.snapshot

    def test_lost_target_index_cannot_rebuild_and_repeat_original_teardown(self):
        s,a,c,d,f,l=self.world();old=f._entries[d['delegation_id']]['domain']
        c.contain_spawn('spawn-slot-1-1','original',f._entries[d['delegation_id']]['binding'])
        self.assertEqual(old.teardowns,1);f._domains.clear()
        with self.assertRaises((CustodyError,RuntimeError)):
            c.contain_spawn('spawn-slot-1-1','original',f._entries[d['delegation_id']]['binding'])
        self.assertEqual(old.teardowns,1);self.assertEqual(f._domains,{})

    def test_all_factory_indexes_lost_cannot_establish_replacement_gate(self):
        s,a,c,d,f,l=self.world();old=f._entries[d['delegation_id']]['domain']
        f._entries.clear();f._tokens.clear();f._domains.clear();f._endpoints.clear();f._verifier.delegations.clear()
        with self.assertRaises((CustodyError,RuntimeError)):
            c.establish_survivor_containment('spawn-slot-1-1',s._actor)
        self.assertEqual(old.initiations,0);self.assertEqual(f._domains,{})

    def test_lost_target_index_denies_actual_current_original_release(self):
        s,a,c,d,f,l=self.world();old=f._entries[d['delegation_id']]['domain'];original=c.initiate_control;observed=[]
        def lost(capability,binding,dispatcher):
            if binding.transition=='RELEASED_OR_POSSIBLY_RELEASED':
                f._domains.clear();observed.append(True)
            return original(capability,binding,dispatcher)
        c.initiate_control=lost
        with self.assertRaises((CustodyError,RuntimeError)):s.complete_worker_lifecycle('slot-1-1')
        self.assertEqual(observed,[True]);self.assertEqual(old.releases,0)
        self.assertEqual(old.initiations,0);self.assertEqual(f._domains,{})


class CheckpointBSlotReleaseTests(unittest.TestCase):
    world=CheckpointBTriggerMatrixTests.world

    def test_original_slot_only_release_intent_cannot_reopen_contained_domain(self):
        s,a,c,d,f,l=self.world();e=f._entries[d['delegation_id']]
        c.contain_spawn('spawn-slot-1-1','original',e['binding'])
        controls=dict(c._control_counts)
        with self.assertRaises((CustodyError,RuntimeError)):
            s._transition('attempt','RELEASE_ELIGIBLE','slot-only-after-containment',{'slot_id':'slot-1-1'})
        self.assertEqual(c._control_counts,controls)
        self.assertEqual(e['domain'].releases,0)
        self.assertEqual(e['domain'].initiations,1)
