import threading
import unittest

from tools.decision_0009.acer_adapter.supervisor import (
    AuthorizationDenied, CASMismatch, DuplicateEvent, LostAcknowledgement, OfflineDurableStore,
    OfflineWitness, Quarantined, StaleRead, StoreError, TransactionPending,
)


class CheckpointBRecoveryTests(unittest.TestCase):
    def test_terminal_historical_result_reconciliation_does_not_invent_boot_loss(self):
        from acer_adapter_fakes import make_supervisor
        from test_acer_adapter_supervisor import SupervisorTests
        world = make_supervisor()
        completed = SupervisorTests(
            'test_campaign_candidate_publication_precedes_campaign_completion')
        completed.make_supervisor = lambda: world
        completed.test_campaign_candidate_publication_precedes_campaign_completion()
        supervisor, _, custodian = world
        store = supervisor.store
        store.crash()
        actor = store.open_nonlive_entry(supervisor.authorization, 'terminal-result-observer')
        self.assertEqual(actor.mode, 'TERMINAL')
        self.assertIsNone(store.witness.denial(actor))
        closure_before = store.validated_campaign_closure()
        boot_four_before = store.validated_boot_closure(4)
        self.assertIsNotNone(closure_before)
        self.assertIsNotNone(boot_four_before)
        self.assertEqual(supervisor.current_boot_ordinal, 4)
        self.assertEqual(supervisor.boot_state, 'BOOT_COMPLETE')
        results = [f['event'] for f in store._committed_frames()
                   if f['event'].get('record_type') == 'EFFECT_RESULT'
                   and f['event'].get('result_kind') == 'EFFECT_PORT_RECEIPT']
        self.assertTrue(results)
        capability = store.effect_capability(results[0]['effect_id'])
        controls_before = dict(custodian._control_counts)
        creates_before = custodian.underlying_create_count_for_all()
        original_commit = store._commit_u04

        def interrupt_result(actor, boundary, event, **kwargs):
            if boundary == 'RESULT':
                kwargs['fault'] = 'validated_before_commit'
            return original_commit(actor, boundary, event, **kwargs)

        store._commit_u04 = interrupt_result
        try:
            with self.assertRaises(TransactionPending):
                store.record_control_effect_result(actor, capability)
        finally:
            store._commit_u04 = original_commit
        self.assertEqual(store.health, 'RECONCILABLE')
        pending = store._durable[-1]
        exact_bytes = pending['bytes']
        self.assertEqual(pending['event']['result'], results[0]['result'])
        self.assertEqual(pending['envelope'].boundary, 'RESULT')
        self.assertEqual(store.witness.query_transaction(pending['event_id'])[0], 'PENDING')
        self.assertEqual(store._validate_reconciliation_frame(pending['envelope'])[0], 'PENDING')
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthenticationError
        before_invalid = (store.health, store._current_actor, store.revision,
                          store.witness.high_generation, store.witness.current_fence,
                          dict(store.witness.pending), dict(store.witness._denials))
        for service, approval, rejection in (
                (object(), supervisor.authorization, AuthorizationDenied),
                (store._authentication_service,
                 replace(supervisor.authorization, authorization_id='unenrolled-input'),
                 OfflineChairAuthenticationError)):
            with self.subTest(invalid_service=service is not store._authentication_service):
                with self.assertRaises(rejection):
                    store.reconcile_pending(service, approval)
                self.assertEqual((store.health, store._current_actor, store.revision,
                                  store.witness.high_generation, store.witness.current_fence,
                                  dict(store.witness.pending), dict(store.witness._denials)),
                                 before_invalid)
        store.crash()
        receipt = store.reconcile_pending(store._authentication_service, supervisor.authorization)
        self.assertTrue(receipt.durable)
        self.assertEqual(store.witness.query_transaction(pending['event_id'])[0], 'COMMITTED')
        self.assertEqual(store._durable[-1]['bytes'], exact_bytes)
        self.assertEqual(store.witness.query_transaction(pending['event_id'])[1].completion_mode,
                         'RECOVERY_RECONCILE')
        self.assertEqual(custodian._control_counts, controls_before)
        self.assertEqual(custodian.underlying_create_count_for_all(), creates_before)
        self.assertEqual(store.health, 'HEALTHY')
        self.assertEqual(store.validated_campaign_closure(), closure_before)
        self.assertEqual(store.validated_boot_closure(4), boot_four_before)
        self.assertEqual(store._derived_nonlive_mode(supervisor.authorization), 'TERMINAL')
        denial = store.witness.denial(actor)
        self.assertIsNone(None if denial is None else denial[0],
                          'terminal historical RESULT is not an active unfinished boot')


    def test_terminal_pending_exec_reconciliation_does_not_invent_boot_loss(self):
        from acer_adapter_fakes import make_supervisor
        from test_acer_adapter_supervisor import SupervisorTests
        from tools.decision_0009.acer_adapter.contracts import (
            MeasurementWindowTransition, WINDOW_OPERATION,
        )
        from tools.decision_0009.acer_adapter.supervisor import _DEDICATED_AUTHORITY
        world = make_supervisor()
        completed = SupervisorTests(
            'test_campaign_candidate_publication_precedes_campaign_completion')
        completed.make_supervisor = lambda: world
        completed.test_campaign_candidate_publication_precedes_campaign_completion()
        supervisor, _, custodian = world
        store, actor = supervisor.store, supervisor._actor
        closure_before = store.validated_campaign_closure()
        self.assertIsNotNone(closure_before)
        self.assertIsNone(store.witness.denial(actor))
        controls_before = dict(custodian._control_counts)
        creates_before = custodian.underlying_create_count_for_all()
        operation_id = store._next_window_operation_id(_DEDICATED_AUTHORITY, actor=actor)
        transition = MeasurementWindowTransition(
            store.identity, WINDOW_OPERATION, operation_id, 'measurement-' + operation_id,
            supervisor.current_window, supervisor.window_epoch,
            'OUTSIDE_MEASURED_WINDOWS', supervisor.window_epoch + 1,
            actor.authorization_digest, actor.campaign_id, actor.generation,
            actor.session_id, actor.fence)
        store._register_window_operation(_DEDICATED_AUTHORITY, transition, actor=actor)
        with self.assertRaises(TransactionPending):
            store._append_window_result(_DEDICATED_AUTHORITY, transition,
                                       fault='validated_before_commit', actor=actor)
        pending = store._durable[-1]
        self.assertEqual(pending['envelope'].boundary, 'EXEC')
        self.assertEqual(store.health, 'RECONCILABLE')
        exact_bytes = pending['bytes']
        store.crash()
        receipt = store.reconcile_pending(store._authentication_service, supervisor.authorization)
        self.assertTrue(receipt.durable)
        self.assertEqual(pending['bytes'], exact_bytes)
        self.assertEqual(store.witness.query_transaction(pending['event_id'])[1].completion_mode,
                         'RECOVERY_RECONCILE')
        self.assertEqual(store.health, 'HEALTHY')
        self.assertEqual(store.validated_campaign_closure(), closure_before)
        self.assertEqual(store._derived_nonlive_mode(supervisor.authorization), 'TERMINAL')
        self.assertEqual(custodian._control_counts, controls_before)
        self.assertEqual(custodian.underlying_create_count_for_all(), creates_before)
        self.assertIsNone(store.witness.denial(actor))

    def test_unfinished_boot_pending_exec_and_result_reconciliation_still_deny(self):
        from acer_adapter_fakes import make_supervisor
        for boundary in ('EXEC', 'RESULT'):
            with self.subTest(boundary=boundary):
                supervisor, _, custodian = make_supervisor()
                store, actor = supervisor.store, supervisor._actor
                self.assertIsNone(store.validated_campaign_closure())
                self.assertIsNone(store.witness.denial(actor))
                controls_before = dict(custodian._control_counts)
                creates_before = custodian.underlying_create_count_for_all()
                commit = store._commit_u04

                def interrupt(captured, selected, event, **kwargs):
                    if selected == boundary:
                        kwargs['fault'] = 'validated_before_commit'
                    return commit(captured, selected, event, **kwargs)

                store._commit_u04 = interrupt
                try:
                    with self.assertRaises(TransactionPending):
                        if boundary == 'EXEC':
                            supervisor.make_slot_eligible('slot-1-1')
                        else:
                            result = next(e for e in store.events
                                          if e.get('result_kind') == 'EFFECT_PORT_RECEIPT')
                            store.record_control_effect_result(
                                actor, store.effect_capability(result['effect_id']))
                finally:
                    store._commit_u04 = commit
                pending = store._durable[-1]
                self.assertEqual(pending['envelope'].boundary, boundary)
                exact_bytes = pending['bytes']
                store.crash()
                store.reconcile_pending(store._authentication_service, supervisor.authorization)
                self.assertEqual(store.witness.denial(actor)[0], 'UNFINISHED_BOOT_LOSS')
                self.assertEqual(pending['bytes'], exact_bytes)
                self.assertEqual(store.witness.query_transaction(pending['event_id'])[1].completion_mode,
                                 'RECOVERY_RECONCILE')
                self.assertEqual(store.health, 'HEALTHY')
                self.assertEqual(custodian._control_counts, controls_before)
                self.assertEqual(custodian.underlying_create_count_for_all(), creates_before)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.witness = OfflineWitness("witness-1")
        self.store = OfflineDurableStore("store-1", self.witness)
        self.fence = self.store.acquire_fence("owner-1")

    def test_append_is_monotonic_and_duplicate_ids_are_content_addressed(self):
        first = self.store.append(0, self.fence, "event-1", {"value": "first"})
        duplicate = self.store.append(0, self.fence, "event-1", {"value": "first"})
        self.assertEqual(first, duplicate)
        self.assertEqual(first.revision, 1)
        with self.assertRaises(DuplicateEvent):
            self.store.append(1, self.fence, "event-1", {"value": "changed"})
        with self.assertRaises(CASMismatch):
            self.store.append(0, self.fence, "event-2", {"value": "second"})

    def test_generic_append_paths_reject_every_reserved_control_result(self):
        reserved = (
            {"state": "ATTEMPT_COMPLETE", "state_domain": "attempt"},
            {"record_type": "PUBLICATION", "state": "PUBLICATION_VERIFIED"},
            {"state": "BOOT_COMPLETE", "state_domain": "boot"},
            {"state": "CAMPAIGN_COMPLETE", "state_domain": "campaign"},
            {"record_type": "MEASUREMENT_WINDOW",
             "window": "OUTSIDE_MEASURED_WINDOWS", "window_epoch": 1},
            {"record_type": "EFFECT_RESULT", "effect_id": "effect-1",
             "result": "accepted"},
            {"authorizes_execution": True, "effect_id": "effect-2",
             "operation": "append-transition"},
        )
        for index, event in enumerate(reserved):
            for path in ("ordinary", "nonauthorizing"):
                with self.subTest(index=index, path=path), self.assertRaises(StoreError):
                    if path == "ordinary":
                        self.store.append(self.store.revision, self.fence,
                                          "injected-%d" % index, event)
                    else:
                        self.store.append_nonauthorizing(
                            self.fence, "injected-nonauthorizing-%d" % index, event)
        self.assertEqual(self.store.revision, 0)
        receipt = self.store.append_nonauthorizing(
            self.fence, "forensic-1",
            {"record_type": "FORENSIC_NOTE", "detail": "retained"},
        )
        self.assertEqual(receipt.revision, 1)

    def test_concurrent_writers_linearize_to_one_revision(self):
        outcomes = []
        barrier = threading.Barrier(3)
        def writer(number):
            barrier.wait()
            try:
                outcomes.append(self.store.append(0, self.fence, "event-%d" % number,
                                                   {"writer": number}).revision)
            except CASMismatch:
                outcomes.append("cas")
        threads = [threading.Thread(target=writer, args=(n,)) for n in (1, 2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertCountEqual(outcomes, [1, "cas"])

    def test_lost_ack_is_durable_and_never_reapplied(self):
        with self.assertRaises(LostAcknowledgement) as lost:
            self.store.append(0, self.fence, "event-1", {"value": "durable"},
                              fault="lost_ack")
        self.assertEqual(lost.exception.receipt.revision, 1)
        receipt = self.store.append(0, self.fence, "event-1", {"value": "durable"})
        self.assertEqual(receipt.revision, 1)
        self.assertEqual(self.store.revision, 1)

    def test_torn_write_witness_divergence_and_rollback_quarantine(self):
        for fault in ("torn", "witness_ahead", "journal_ahead"):
            witness = OfflineWitness("w-" + fault)
            store = OfflineDurableStore("s-" + fault, witness)
            fence = store.acquire_fence("owner")
            expected = TransactionPending if fault == 'journal_ahead' else Quarantined
            with self.subTest(fault=fault), self.assertRaises(expected):
                store.append(0, fence, "event", {"fault": fault}, fault=fault)
            self.assertEqual(store.quarantined, fault != 'journal_ahead')
            self.assertTrue(store.containment_only)
        self.store.append(0, self.fence, "event", {"ok": 1})
        self.store.simulate_rollback(0)
        with self.assertRaises(Quarantined):
            self.store.read_verified(0)

    def test_stale_read_and_nonreusable_fencing_epochs_cannot_authorize(self):
        self.store.append(0, self.fence, "event", {"ok": 1})
        with self.assertRaises(StaleRead):
            self.store.read_verified(2)
        second = self.store.acquire_fence("owner-2", fail=True)
        third = self.store.acquire_fence("owner-3")
        self.assertEqual((self.fence, second, third), (1, 2, 3))
        with self.assertRaises(CASMismatch):
            self.store.append(1, self.fence, "stale", {"ok": 2})

    def test_taint_and_consumption_are_sticky_across_crash_and_snapshot_rollback(self):
        self.store.consume("slot", "slot-1")
        self.store.add_taint("identity-mismatch")
        snapshot = self.store.snapshot()
        self.store.crash()
        self.assertTrue(self.store.is_consumed("slot", "slot-1"))
        self.assertIn("identity-mismatch", self.store.taint)
        with self.assertRaises(Quarantined):
            self.store.restore_snapshot({**snapshot, "revision": 0})

    def test_committed_events_and_readbacks_are_deeply_immutable(self):
        source = {"record_type": "FORENSIC_NOTE", "nested": {"values": [1, 2]}}
        self.store.append(0, self.fence, "event-deep", source)
        source["nested"]["values"].append(3)
        first = self.store.events
        first[0]["nested"]["values"].append(4)
        self.assertEqual(self.store.events[0]["nested"]["values"], [1, 2])


class U04PendingFrameCharacterizationTests(unittest.TestCase):
    def test_u04_complete_pending_frame_is_reconcilable(self):
        witness = OfflineWitness("pending-witness")
        store = OfflineDurableStore("pending-store", witness)
        fence = store.acquire_fence("owner")
        with self.assertRaises(StoreError):
            store.append(0, fence, "pending-event", {"value": "exact"},
                         fault="journal_ahead")
        self.assertEqual(store.events, [{"value": "exact"}])
        self.assertEqual(len(witness.pending), 1)
        self.assertFalse(store.quarantined,
                         "complete frame with exact reservation is reconcilable skew")


class U04ReconciliationRepairTests(unittest.TestCase):
    def witness_state(self, witness):
        return {name: dict(value) if isinstance(value, dict) else value
                for name, value in vars(witness).items()
                if name not in ('_lock', '_store', '_custodian')}

    def authority_state(self, store):
        names = ('_health', 'quarantined', 'containment_only', '_current_actor',
                 '_current_reconciler', '_entry_mode', '_execution_revoked',
                 '_publication_prohibited', '_supervisor_ready', '_pending_reset',
                 '_supervisor_generation', '_sessions', '_acceptance_acks')
        return {name: dict(value) if isinstance(value, dict) else value
                for name in names for value in (getattr(store, name),)}

    def pending_entry(self):
        from acer_adapter_fakes import make_supervisor
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        store.crash()
        commit = store._commit_u04
        def interrupted(actor, boundary, event, **kwargs):
            return commit(actor, boundary, event, fault='validated_before_commit', **kwargs)
        store._commit_u04 = interrupted
        with self.assertRaises(TransactionPending):
            store.open_nonlive_entry(supervisor.authorization, 'pending-entry-reader')
        del store._commit_u04
        store.crash()
        self.assertEqual(store._durable[-1]['envelope'].boundary, 'ENTRY')
        return supervisor, store, store.witness

    def test_f1_direct_reconciler_after_live_readback_quarantine_is_read_only(self):
        from acer_adapter_fakes import make_supervisor
        supervisor, _, _ = make_supervisor()
        store, witness = supervisor.store, supervisor.store.witness
        commit = store._commit_u04
        def mismatch(actor, boundary, event, **kwargs):
            kwargs['fault'] = 'readback_mismatch'
            return commit(actor, boundary, event, **kwargs)
        store._commit_u04 = mismatch
        with self.assertRaises(Quarantined):
            supervisor.set_measurement_window('DWELL')
        del store._commit_u04
        store.crash()
        self.assertTrue(store.quarantined)
        for operation in ('generation', 'fence', 'reconciler', 'reconciler'):
            with self.subTest(operation=operation):
                before = self.witness_state(witness), self.authority_state(store)
                with self.assertRaises((AuthorizationDenied, Quarantined)):
                    if operation == 'generation':
                        witness.allocate_generation(store.identity)
                    elif operation == 'fence':
                        witness.acquire_fence('quarantined-reader')
                    else:
                        witness.issue_reconciler(store._durable[-1]['envelope'])
                self.assertEqual((self.witness_state(witness), self.authority_state(store)), before)

    def test_f1_entry_reconciliation_rejects_divergent_prefix_without_witness_mutation(self):
        for port in ('store', 'witness'):
            for corruption in ('bytes', 'witness'):
                with self.subTest(port=port, corruption=corruption):
                    supervisor, store, witness = self.pending_entry()
                    if corruption == 'bytes':
                        store._durable[1]['bytes'] += b'corrupt earlier committed frame'
                    else:
                        from dataclasses import replace
                        old = store._durable[1]['envelope']
                        commit = witness._commits[old.transaction_id]
                        witness._commits[old.transaction_id] = replace(commit,
                            reservation=replace(commit.reservation, frame_digest='f' * 64))
                    inspection = store.verified_prefix()
                    self.assertEqual(inspection['stop_reason'], 'QUARANTINED')
                    self.assertEqual(len(inspection['frames']), 1)
                    before = self.witness_state(witness)
                    for _ in range(2):
                        with self.assertRaises((AuthorizationDenied, Quarantined)):
                            if port == 'store':
                                store.reconcile_pending(store._authentication_service, supervisor.authorization)
                            else:
                                witness.issue_reconciler(store._durable[-1]['envelope'])
                        self.assertEqual(self.witness_state(witness), before)
                        self.assertTrue(store.quarantined)
                        self.assertEqual(store.health, 'QUARANTINED')
                        self.assertEqual(len(store.verified_prefix()['frames']), 1)

    def test_f1_direct_reconciler_exact_tail_positive_control(self):
        supervisor, store, witness = self.pending_entry()
        envelope = store._durable[-1]['envelope']
        raw = store._durable[-1]['bytes']
        generation, fence = witness.high_generation, witness.high_fence
        binding = witness.issue_reconciler(envelope)
        self.assertEqual(binding.generation, generation + 1)
        self.assertEqual(binding.fence, fence + 1)
        receipt = store.reconcile_pending(store._authentication_service, supervisor.authorization)
        self.assertEqual(witness.query_transaction(receipt.event_id)[1].completion_mode, 'RECOVERY_RECONCILE')
        self.assertEqual(store._durable[-1]['bytes'], raw)
        self.assertFalse(store.quarantined)
        self.assertEqual(store.health, 'HEALTHY')
        self.assertIsNone(store._current_actor)
        self.assertTrue(store.execution_revoked)

    def test_f1_reconciliation_commit_rechecks_prefix_after_binding_issuance(self):
        supervisor, store, witness = self.pending_entry()
        envelope = store._durable[-1]['envelope']
        readback = store._independent_frame_readback
        def corrupt_prefix(revision):
            raw = readback(revision)
            store._durable[1]['bytes'] += b'prefix changed after reconciler issuance'
            return raw
        store._independent_frame_readback = corrupt_prefix
        revision = witness.high_revision
        with self.assertRaises(Quarantined):
            store.reconcile_pending(store._authentication_service, supervisor.authorization)
        self.assertEqual(witness.high_revision, revision)
        self.assertEqual(witness.query_transaction(envelope.transaction_id)[0], 'PENDING')
        self.assertTrue(store.quarantined)

    def alternate_approval_supervisor(self):
        from dataclasses import replace
        from acer_adapter_fakes import (MutableArtifacts, activation, offline_chair_service,
                                       offline_activation_service, session, u04_authorization)
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthorizationVerifier
        from tools.decision_0009.acer_adapter.contracts import authorization_digest
        from tools.decision_0009.acer_adapter.custody import OfflineCustodian
        from tools.decision_0009.acer_adapter.supervisor import ArtifactVerificationPrimitive, PersistentSupervisor
        artifacts = MutableArtifacts()
        original = u04_authorization(artifacts)
        alternate = replace(original, authorization_id='alternate-enrolled-approval')
        alternate = replace(alternate, authorization_digest=authorization_digest(alternate))
        root = offline_chair_service(original).root
        service = OfflineChairAuthorizationVerifier(replace(root,
            approvals=root.approvals + offline_chair_service(alternate).root.approvals))
        store = OfflineDurableStore('store-1', OfflineWitness('witness-1'),
            chair_verifier=service, activation_verifier=offline_activation_service(original))
        supervisor = PersistentSupervisor(store, ArtifactVerificationPrimitive(
            'offline-root', original, artifacts.read), OfflineCustodian('custodian-1'), original, session())
        supervisor.admit_campaign(activation())
        supervisor.establish_boot_custody('custody-proof', True, True)
        supervisor.complete_boot_custody()
        return supervisor, alternate

    def test_f2_alternate_enrolled_approval_leaves_live_and_waiting_authority_unchanged(self):
        from acer_adapter_fakes import complete_boot
        for mode in ('LIVE', 'WAITING'):
            with self.subTest(mode=mode):
                supervisor, alternate = self.alternate_approval_supervisor()
                store, witness = supervisor.store, supervisor.store.witness
                if mode == 'WAITING':
                    complete_boot(supervisor)
                    supervisor.begin_boot_handoff(2)
                    supervisor.commit_planned_shutdown()
                    store.open_nonlive_entry(supervisor.authorization, 'waiting-reader')
                self.assertEqual(store._current_actor.mode, mode)
                self.assertEqual(store.health, 'HEALTHY')
                before = self.authority_state(store), self.witness_state(witness)
                with self.assertRaises(AuthorizationDenied):
                    store.reconcile_pending(store._authentication_service, alternate)
                self.assertEqual((self.authority_state(store), self.witness_state(witness)), before)
                store.read_verified(0)
                self.assertEqual((self.authority_state(store), self.witness_state(witness)), before)

    def test_f2_changed_authorization_bytes_or_digest_has_zero_mutation(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthenticationError
        supervisor, _ = self.alternate_approval_supervisor()
        store, witness = supervisor.store, supervisor.store.witness
        for supplied in (replace(supervisor.authorization, authorization_id='unenrolled-bytes'),
                         replace(supervisor.authorization, authorization_digest='f' * 64)):
            with self.subTest(authorization_id=supplied.authorization_id):
                before = self.authority_state(store), self.witness_state(witness)
                with self.assertRaises((AuthorizationDenied, OfflineChairAuthenticationError)):
                    store.reconcile_pending(store._authentication_service, supplied)
                self.assertEqual((self.authority_state(store), self.witness_state(witness)), before)

    def test_f2_actual_frame_or_reservation_corruption_still_quarantines(self):
        from dataclasses import replace
        for corruption in ('frame', 'reservation', 'envelope-binding'):
            with self.subTest(corruption=corruption):
                supervisor, store, witness = self.pending_entry()
                envelope = store._durable[-1]['envelope']
                if corruption == 'frame':
                    store._durable[-1]['bytes'] += b'corrupt actual tail'
                elif corruption == 'envelope-binding':
                    store._durable[-1]['envelope'] = replace(envelope, authorization_digest='f' * 64)
                else:
                    witness.pending[envelope.revision] = replace(
                        witness.pending[envelope.revision], frame_digest='f' * 64)
                before = self.witness_state(witness)
                with self.assertRaises(Quarantined):
                    store.reconcile_pending(store._authentication_service, supervisor.authorization)
                self.assertTrue(store.quarantined)
                self.assertEqual(store.health, 'QUARANTINED')
                self.assertEqual(self.witness_state(witness), before)


class U04PersistenceKernelTests(unittest.TestCase):
    def test_quarantine_and_v2_binding_close_direct_witness_mutation_ports(self):
        for operation in ('generation', 'fence', 'legacy-reservation', 'legacy-commit'):
            with self.subTest(operation=operation):
                store, witness, actor, _, _ = self.foundation()
                if operation in ('generation', 'fence'):
                    store._durable[0]['bytes'] += b'corrupt retained frame'
                    with self.assertRaises(Quarantined):
                        store.read_verified(0)
                before = (witness.high_generation, witness.high_fence,
                          witness.current_fence, witness.high_revision,
                          witness.high_chain_digest, dict(witness.pending))
                with self.assertRaises((AuthorizationDenied, Quarantined)):
                    if operation == 'generation':
                        witness.allocate_generation(store.identity)
                    elif operation == 'fence':
                        witness.acquire_fence('caller-without-healthy-store')
                    elif operation == 'legacy-reservation':
                        witness.reserve(witness.high_revision + 1, 'f' * 64)
                    else:
                        witness.commit(witness.high_revision + 1, 'f' * 64)
                self.assertEqual((witness.high_generation, witness.high_fence,
                                  witness.current_fence, witness.high_revision,
                                  witness.high_chain_digest, witness.pending), before)

    def test_configured_read_only_inspector_cannot_allocate_or_become_an_actor(self):
        from acer_adapter_fakes import make_supervisor
        supervisor, _, custodian = make_supervisor()
        store, witness = supervisor.store, supervisor.store.witness
        before = (store.revision, witness.high_generation, witness.high_fence, store._current_actor)
        reader = store.read_only_inspector(store._authentication_service, supervisor.authorization, 'offline-local-reader')
        snapshot = reader.snapshot()
        self.assertEqual(snapshot['reader_identity'], 'offline-local-reader')
        self.assertFalse(snapshot['authorizes_execution'])
        self.assertTrue(snapshot['frames'])
        with self.assertRaises(AuthorizationDenied):
            store.read_only_inspector(store._authentication_service, supervisor.authorization, 'unconfigured-reader')
        with self.assertRaises(AuthorizationDenied):
            store.read_only_inspector(object(), supervisor.authorization, 'offline-local-reader')
        with self.assertRaises(AuthorizationDenied):
            witness.authenticate(reader, store.identity, 'EXEC')
        store._durable[-1]['bytes'] += b'corrupt suffix'
        snapshot = reader.snapshot()
        self.assertEqual(snapshot['stop_reason'], 'QUARANTINED')
        self.assertTrue(snapshot['frames'])
        self.assertEqual(snapshot['untrusted_raw_bytes'][-1], store._durable[-1]['bytes'])
        self.assertEqual((store.revision, witness.high_generation, witness.high_fence, store._current_actor), before)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_transaction_identity_cannot_overwrite_an_original_witness_commit(self):
        store, witness, actor, authorization, _ = self.foundation()
        original = store._durable[0]
        commit = store._commit_u04
        def collide(current, boundary, event, **kwargs):
            kwargs['event_id'] = original['event_id']
            return commit(current, boundary, event, **kwargs)
        store._commit_u04 = collide
        with self.assertRaises(AuthorizationDenied):
            store.admit_authorization(actor, authorization)
        self.assertEqual((store.revision, witness.high_revision), (1, 1))
        self.assertEqual(witness.pending, {})
        self.assertEqual(witness.query_transaction(original['event_id'])[1].reservation.frame_digest,
                         original['envelope'].frame_digest)

    def test_witness_cannot_commit_caller_bytes_when_actual_durable_frame_is_absent(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.supervisor import _U04_BOUNDARIES
        store, witness, actor, _, _ = self.foundation()
        envelope = replace(store._durable[0]['envelope'], transaction_id='unretained-frame', revision=2,
                           predecessor_revision=1, predecessor_hash=store.chain_digest)
        reservation = witness.reserve_frame(actor, envelope, _U04_BOUNDARIES['ENTRY'])
        with self.assertRaises(AuthorizationDenied):
            witness.commit_frame(actor, envelope, reservation, _U04_BOUNDARIES['ENTRY'],
                                 envelope.canonical_bytes())
        self.assertEqual(witness.high_revision, 1)
        self.assertEqual(witness.query_transaction(envelope.transaction_id)[0], 'PENDING')

    def test_loss_during_reconciliation_revokes_opaque_binding_before_exact_retry(self):
        from acer_adapter_fakes import u04_authorization, offline_chair_service
        store, witness, _, authorization, service = self.foundation()
        # A second exact non-authorizing transaction is interrupted before W
        # commit. Its original producer and reservation stay immutable.
        actor = store._current_actor
        with self.assertRaises(StoreError):
            store.admit_authorization(actor, authorization, fault='validated_before_commit')
        with self.assertRaises(StoreError):
            store.reconcile_pending(service, authorization, fault='before_commit')
        envelope = store._durable[-1]['envelope']
        binding = witness._reconcilers[envelope.transaction_id]
        store.crash()
        with self.assertRaises(AuthorizationDenied):
            witness.reconcile_frame(binding, envelope, envelope.canonical_bytes())
        store.reconcile_pending(service, authorization)
        committed = witness.query_transaction(envelope.transaction_id)[1]
        self.assertEqual(committed.completion_mode, 'RECOVERY_RECONCILE')
        import json
        self.assertGreater(json.loads(committed.completer_bytes)['generation'], binding.generation)
        self.assertIsNone(store._current_actor)

    def test_explicit_committed_failure_latch_survives_failed_mirror_and_reset(self):
        from acer_adapter_fakes import make_supervisor
        supervisor, _, custodian = make_supervisor()
        store, witness, actor = supervisor.store, supervisor.store.witness, supervisor.store._current_actor
        commit = store._commit_u04
        def fail_mirror(current, boundary, event, **kwargs):
            if boundary == 'DENY':
                raise StoreError('denial mirror unavailable after W latch')
            return commit(current, boundary, event, **kwargs)
        store._commit_u04 = fail_mirror
        with self.assertRaises(StoreError):
            supervisor._write_failure_record('explicit-original-failure', b'bounded original evidence')
        del store._commit_u04
        denial = witness.denial(actor)
        self.assertEqual(denial[0], 'EXPLICIT_ABORT_OR_FAILURE')
        self.assertTrue(any(e.get('state') == 'TAINTED' for e in store.events))
        self.assertFalse(any(e.get('record_type') == 'CAMPAIGN_EXECUTION_DENIED' for e in store.events))
        store.reset_volatile()
        current = store.open_nonlive_entry(supervisor.authorization, 'failure-history-reader')
        self.assertEqual(witness.denial(current), denial)
        with self.assertRaises(AuthorizationDenied):
            store.require_actor(current, 'EXEC')
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_interrupted_original_authorization_is_denied_from_complete_loss_evidence(self):
        store, witness, actor, authorization, _ = self.foundation()
        store.admit_authorization(actor, authorization)
        store.crash()
        store.reset_volatile()
        reader = store.open_nonlive_entry(authorization, 'interrupted-init-reader')
        self.assertEqual(reader.mode, 'RECOVERY')
        self.assertEqual(witness.denial(reader)[0], 'INTERRUPTED_ADMISSION')
        with self.assertRaises(AuthorizationDenied):
            store.complete_fresh_admission(reader, authorization, None)

    def test_observed_complete_journal_rollback_latches_but_missing_tail_does_not(self):
        store, witness, actor, _, _ = self.foundation()
        store.simulate_rollback(0)
        self.assertEqual(witness.denial(actor),
                         ('DURABLE_HISTORY_CONTRADICTION', (actor.incarnation_id + '-1',)))
        store.reset_volatile()
        self.assertEqual(witness.denial(actor)[0], 'DURABLE_HISTORY_CONTRADICTION')
        store, witness, actor, _, _ = self.foundation()
        # A missing available tail is divergence, but its cause/outcome is
        # unknown. It does not prove that the rollback operation occurred.
        store._durable = []
        with self.assertRaises(StoreError):
            store.read_verified(0)
        self.assertIsNone(witness.denial(actor))

    def test_unavailable_loss_never_revives_witness_token_when_evidence_returns(self):
        from acer_adapter_fakes import make_supervisor
        supervisor, _, custodian = make_supervisor()
        store, witness, old = supervisor.store, supervisor.store.witness, supervisor.store._current_actor
        witness.available = False
        with self.assertRaises(StoreError):
            store.crash()
        self.assertIsNone(store._current_actor)
        self.assertIsNone(witness.denial(old))
        witness.available = True
        with self.assertRaises(AuthorizationDenied):
            witness.authenticate(old, store.identity, 'EXEC')
        store.reset_volatile()
        self.assertEqual(witness._acknowledged, {})
        self.assertNotIn(store.identity, witness._actors)
        current = store.open_nonlive_entry(supervisor.authorization, 'reader-after-unavailable-loss')
        self.assertEqual(current.mode, 'RECOVERY')
        self.assertEqual(witness.denial(current)[0], 'UNFINISHED_BOOT_LOSS')
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_entry_rejects_forged_class_generation_reference_and_duplicate_binding(self):
        from copy import deepcopy
        store, witness, actor, _, _ = self.foundation()
        original = store.events[0]
        for field, value in (('authority_class', 'EVIDENCE_RECOVERY'),
                             ('witness_generation_receipt', 'generation-999'),
                             ('entry_refs', [{'event_id': 'invented', 'revision': 1,
                                              'payload_digest': 'f' * 64}]),
                             ('mode', 'WAITING')):
            event = deepcopy(original)
            event['record_id'] = actor.incarnation_id + '-2'
            event[field] = value
            with self.subTest(field=field), self.assertRaises(AuthorizationDenied):
                store._commit_u04(actor, 'ENTRY', event)
        event = dict(original, record_id=actor.incarnation_id + '-2')
        with self.assertRaises(AuthorizationDenied):
            store._commit_u04(actor, 'ENTRY', event)
        self.assertEqual((store.revision, witness.high_revision), (1, 1))

    def test_all_fourteen_u04_records_reject_every_foreign_writer_boundary(self):
        from acer_adapter_fakes import make_supervisor
        from tools.decision_0009.acer_adapter.contracts import ContractError
        supervisor, _, custodian = make_supervisor()
        store, actor = supervisor.store, supervisor.store._current_actor
        registry = {
            'SUPERVISOR_INCARNATION': 'ENTRY', 'PLANNED_SHUTDOWN_COMMITTED': 'SHUTDOWN',
            'ACTIVATION_RESERVED': 'ADMIT', 'ACTIVATION_ADMITTED': 'ADMIT',
            'EFFECT_ACCEPTED': 'EXEC', 'EFFECT_RESULT': 'RESULT', 'CAMPAIGN_EXECUTION_DENIED': 'DENY',
            'RECOVERY_ENTRY': 'RW', 'RECOVERY_OBLIGATION': 'RW', 'RECOVERY_SUPPLEMENT': 'RW',
            'RECOVERY_PUBLICATION_INTENT': 'RP', 'RECOVERY_PUBLICATION_ACCEPTED': 'RP',
            'RECOVERY_PUBLICATION_RESULT': 'RP', 'RECOVERY_PUBLICATION_VERIFIED': 'RP',
        }
        before = (store.revision, store.witness.high_revision)
        for record, writer in registry.items():
            for boundary in ('ENTRY', 'INIT', 'EXEC', 'RESULT', 'SHUTDOWN', 'ADMIT', 'DENY', 'HISTORY', 'RW', 'RP'):
                if boundary == writer and writer not in ('RW', 'RP'):
                    continue
                event = store._u04_common(actor, record, 'EVIDENCE', False)
                with self.subTest(record=record, boundary=boundary), self.assertRaises((ContractError, StoreError)):
                    store._commit_u04(actor, boundary, event)
                self.assertEqual((store.revision, store.witness.high_revision), before)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_runtime_cannot_replace_pinned_bootstrap_authority_references(self):
        from acer_adapter_fakes import make_supervisor
        from tools.decision_0009.acer_adapter.custody import OfflineCustodian
        store, witness, _, _, service = self.foundation()
        for field, substitute in (('_authentication_service', None),
                                  ('_activation_authentication_service', object()),
                                  ('witness', OfflineWitness('replacement-witness')),
                                  ('identity', 'substituted-store')):
            with self.subTest(field=field), self.assertRaises(AuthorizationDenied):
                setattr(store, field, substitute)
        self.assertIs(store._authentication_service, service)
        self.assertIs(store.witness, witness)
        self.assertEqual(store.identity, 'store-1')
        supervisor, _, custodian = make_supervisor()
        for field in ('_custodian', '_artifact_verifier'):
            with self.subTest(field=field), self.assertRaises(AuthorizationDenied):
                setattr(supervisor.store, field, object())
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.bind_custodian(OfflineCustodian('substituted-custodian'))
        self.assertIs(supervisor.store._custodian, custodian)

    def test_legacy_session_and_acceptance_ports_cannot_mint_live_authority(self):
        from acer_adapter_fakes import session, consumed_create_capability
        store = OfflineDurableStore('legacy-store', OfflineWitness('legacy-witness'))
        with self.assertRaises(AuthorizationDenied):
            store.register_session(session())
        with self.assertRaises(AuthorizationDenied):
            store.accept_effect(consumed_create_capability())
        with self.assertRaises(AuthorizationDenied):
            store.put_object('legacy-new-object', b'unwitnessed new bytes')
        self.assertEqual(store._accepted_effects, set())
        self.assertEqual(store._objects, {})
        self.assertEqual(store.revision, 0)

    def test_all_eight_transaction_types_reject_corrupt_witness_or_journal_without_effects(self):
        from acer_adapter_fakes import make_supervisor, complete_boot, activation, independent_fault_world
        from tools.decision_0009.acer_adapter.contracts import CustodyError
        seed, _, _ = make_supervisor()
        complete_boot(seed)
        predecessor = seed.predecessor_closure_digest
        seed.begin_boot_handoff(2)
        seed.commit_planned_shutdown()
        seed.activate_next_boot(activation(2, 'boot-2', predecessor))
        selectors = {
            'incarnation': ('record_type', 'SUPERVISOR_INCARNATION'),
            'authorization': ('state', 'AUTHORIZATION_ADMITTED'),
            'intent': ('state', 'SPAWN_INTENT_PERSISTED'),
            'acceptance': ('record_type', 'EFFECT_ACCEPTED'),
            'result': ('record_type', 'EFFECT_RESULT'),
            'shutdown': ('record_type', 'PLANNED_SHUTDOWN_COMMITTED'),
            'reservation': ('record_type', 'ACTIVATION_RESERVED'),
            'admission': ('record_type', 'ACTIVATION_ADMITTED'),
        }
        for transaction, (field, value) in selectors.items():
            for corruption in ('witness-ahead', 'conflict', 'unreserved', 'rollback'):
                with self.subTest(transaction=transaction, corruption=corruption):
                    world = independent_fault_world(seed)
                    store, witness = world.store, world.store.witness
                    frame = next(f for f in store._durable if f['event'].get(field) == value)
                    before = world.custodian.underlying_create_count_for_all()
                    if corruption == 'witness-ahead':
                        witness.high_revision += 1
                    elif corruption == 'conflict':
                        frame['bytes'] += b'conflicting retained bytes'
                    elif corruption == 'unreserved':
                        witness._commits.pop(frame['event_id'])
                    else:
                        store._durable = store._durable[:frame['receipt'].revision - 1]
                    with self.assertRaises(Quarantined):
                        store.read_verified(0)
                    high = (witness.high_generation, witness.high_fence)
                    store.reset_volatile()
                    self.assertIsNone(store._current_actor)
                    self.assertEqual(witness._acknowledged, {})
                    with self.assertRaises((StoreError, CustodyError)):
                        world.make_slot_eligible('slot-2-1')
                    self.assertEqual(world.custodian.underlying_create_count_for_all(), before)
                    self.assertEqual((witness.high_generation, witness.high_fence), high)

    def test_positive_retained_digest_conflict_latches_but_unreadable_evidence_does_not(self):
        import json
        from tools.decision_0009.acer_adapter.supervisor import _u04_canonical, _U04_BOUNDARIES
        store, witness, actor, _, _ = self.foundation()
        frame = store._durable[0]
        retained = json.loads(frame['bytes'])
        retained['payload']['mode'] = 'WAITING'
        frame['bytes'] = _u04_canonical(retained)
        with self.assertRaises(StoreError):
            store.read_verified(0)
        self.assertEqual(witness.denial(actor)[0], 'DURABLE_HISTORY_CONTRADICTION')
        self.assertEqual(witness.denial(actor)[1], (frame['event_id'],))
        store, witness, actor, _, _ = self.foundation()
        def unavailable(revision):
            raise OSError('independent evidence unavailable')
        store._independent_frame_readback = unavailable
        with self.assertRaises(AuthorizationDenied):
            witness.deny_durable_digest_conflict(store, _boundary=_U04_BOUNDARIES['DENY'])
        self.assertIsNone(witness.denial(actor))
        del store._independent_frame_readback

    def foundation(self):
        from acer_adapter_fakes import offline_chair_service, u04_authorization
        payload = u04_authorization()
        service = offline_chair_service(payload)
        witness = OfflineWitness("witness-1")
        store = OfflineDurableStore("store-1", witness, chair_verifier=service)
        self.assertTrue(hasattr(store, "begin_fresh_entry"), "authenticated ENTRY required")
        actor = store.begin_fresh_entry(service, payload, "supervisor-1")
        return store, witness, actor, payload, service

    def test_authenticated_incarnation_is_durable_but_not_execution(self):
        store, witness, actor, _, _ = self.foundation()
        self.assertEqual(actor.mode, "FRESH")
        self.assertFalse(actor.execution_live)
        self.assertEqual(actor.generation, witness.high_generation)
        records = store.events
        self.assertEqual(records[-1]["record_type"], "SUPERVISOR_INCARNATION")
        self.assertEqual(records[-1]["incarnation_id"], actor.incarnation_id)
        self.assertEqual(witness.high_revision, store.revision)
        self.assertNotEqual(store._durable[-1]["receipt"].event_digest,
                            store._durable[-1]["receipt"].chain_digest)

    def test_copied_identity_and_current_numeric_fence_cannot_reserve(self):
        from dataclasses import replace
        store, witness, actor, _, _ = self.foundation()
        copied = replace(actor)
        with self.assertRaises(AuthorizationDenied):
            witness.authenticate(copied, store.identity, "ENTRY")
        store.crash()
        with self.assertRaises(AuthorizationDenied):
            witness.authenticate(actor, store.identity, "ENTRY")

    def test_generation_burns_even_when_allocation_response_is_lost(self):
        store, witness, _, _, _ = self.foundation()
        high = witness.high_generation
        with self.assertRaises(StoreError):
            witness.allocate_generation(store.identity, fault="lost_ack")
        self.assertEqual(witness.allocate_generation(store.identity), high + 2)

    def test_envelope_readback_detects_payload_and_fact_mutation(self):
        store, _, _, _, _ = self.foundation()
        frame = store._durable[-1]
        frame["event"]["incarnation_id"] = "substituted"
        with self.assertRaises(Quarantined):
            store.read_verified(0)

    def test_kernel_fault_stages_for_incarnation_binding(self):
        from acer_adapter_fakes import offline_chair_service, u04_authorization
        payload = u04_authorization()
        service = offline_chair_service(payload)
        stages = ("before_reservation", "reservation_response_lost", "reserved_before_frame",
                  "frame_before_readback", "readback_mismatch", "readback_unavailable",
                  "validated_before_commit", "commit_before_ack")
        for stage in stages:
            with self.subTest(transaction="SUPERVISOR_INCARNATION", stage=stage):
                witness = OfflineWitness("witness-1")
                store = OfflineDurableStore("store-1", witness, chair_verifier=service)
                self.assertTrue(hasattr(store, "begin_fresh_entry"))
                with self.assertRaises(StoreError):
                    store.begin_fresh_entry(service, payload, "supervisor-1", fault=stage)
                self.assertTrue(store.execution_revoked)
                if stage == "commit_before_ack":
                    self.assertEqual(witness.high_revision, 1)
                elif stage in ("frame_before_readback", "validated_before_commit"):
                    self.assertEqual(store.health, "RECONCILABLE")
                    exact = store._durable[-1]['bytes']
                    for interrupt in ('before_commit', 'lost_ack'):
                        with self.subTest(reconciliation=interrupt), self.assertRaises(StoreError):
                            store.reconcile_pending(service, payload, fault=interrupt)
                    store.reconcile_pending(service, payload)
                    self.assertEqual(store._durable[-1]['bytes'], exact)
                    self.assertEqual(witness.query_transaction(store._durable[-1]['event_id'])[1].completion_mode,
                                     'RECOVERY_RECONCILE')
                else:
                    self.assertEqual(witness.high_revision, 0)

    def test_exact_reconciliation_preserves_origin_and_never_replays_effects(self):
        from acer_adapter_fakes import offline_chair_service, u04_authorization
        payload = u04_authorization()
        service = offline_chair_service(payload)
        witness = OfflineWitness("witness-1")
        store = OfflineDurableStore("store-1", witness, chair_verifier=service)
        self.assertTrue(hasattr(store, "begin_fresh_entry"))
        with self.assertRaises(StoreError):
            store.begin_fresh_entry(service, payload, "supervisor-1",
                                    fault="validated_before_commit")
        frame = store._durable[-1]
        original = frame["envelope"].producer_bytes
        self.assertTrue(hasattr(store, "reconcile_pending"), "exact reconciliation required")
        before = frame["bytes"]
        receipt = store.reconcile_pending(service, payload)
        status, commit = witness.query_transaction(receipt.event_id)
        self.assertEqual(status, "COMMITTED")
        self.assertEqual(commit.completion_mode, "RECOVERY_RECONCILE")
        self.assertEqual(commit.reservation.initiator_bytes, original)
        self.assertEqual(frame["bytes"], before)
        self.assertEqual(store.reconcile_pending(service, payload), receipt)
        self.assertTrue(store.execution_revoked)

    def test_missing_unreserved_conflicting_or_rollback_history_quarantines(self):
        for corruption in ("missing", "unreserved", "conflict", "rollback"):
            with self.subTest(corruption=corruption):
                store, witness, _, _, _ = self.foundation()
                if corruption in ("missing", "rollback"):
                    store._durable.clear()  # fault model only; never a recovery repair
                elif corruption == "unreserved":
                    witness._commits.clear()
                else:
                    store._durable[-1]["bytes"] += b"conflict"
                with self.assertRaises(Quarantined):
                    store.read_verified(0)
                self.assertTrue(store.containment_only)

    def test_quarantine_preserves_independently_verified_prefix_without_authority(self):
        from acer_adapter_fakes import make_supervisor, inject_untrusted_record
        supervisor, _, custodian = make_supervisor()
        store = supervisor.store
        exact = tuple(f['bytes'] for f in store._durable)
        generation, fence = store.witness.high_generation, store.witness.high_fence
        inject_untrusted_record(store, fence, 'unreserved-forensic-tail', {'state': 'BOOT_COMPLETE'})
        with self.assertRaises(Quarantined):
            store.read_verified(0)
        inspection = store.verified_prefix()
        self.assertEqual(tuple(f['bytes'] for f in inspection['frames']), exact)
        self.assertEqual(inspection['stop_reason'], 'QUARANTINED')
        self.assertFalse(inspection['authorizes_execution'])
        inspection['frames'][0]['event']['mode'] = 'LIVE'
        self.assertEqual(store._durable[0]['event']['mode'], 'FRESH')
        store.witness.available = False
        self.assertEqual(store.verified_prefix()['stop_reason'], 'UNKNOWN')
        self.assertEqual(store.verified_prefix()['frames'], ())
        self.assertEqual((store.witness.high_generation, store.witness.high_fence), (generation, fence))
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_init_admitted_binding_is_exact_witnessed_and_not_a_live_token(self):
        store, witness, actor, payload, service = self.foundation()
        self.assertTrue(hasattr(store, "admit_authorization"), "witnessed INIT required")
        receipt = store.admit_authorization(actor, payload)
        self.assertEqual(witness.query_transaction(receipt.event_id)[0], "COMMITTED")
        store.validate_admitted_authorization(payload)
        self.assertFalse(actor.execution_live)
        self.assertTrue(store.execution_revoked)
        with self.assertRaises(AuthorizationDenied):
            store.admit_authorization(actor, payload)

    def test_another_valid_approval_cannot_replace_original_admission(self):
        from dataclasses import replace
        from acer_adapter_fakes import u04_authorization, offline_chair_service
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthorizationVerifier
        from tools.decision_0009.acer_adapter.contracts import authorization_digest
        payload = u04_authorization()
        changed = replace(payload, nonce="another-nonce", authorization_id="another-authorization")
        changed = replace(changed, authorization_digest=authorization_digest(changed))
        one = offline_chair_service(payload)
        two = offline_chair_service(changed)
        service = OfflineChairAuthorizationVerifier(replace(one.root,
            approvals=one.root.approvals + two.root.approvals))
        witness = OfflineWitness("witness-1")
        store = OfflineDurableStore("store-1", witness, chair_verifier=service)
        actor = store.begin_fresh_entry(service, payload, "supervisor-1")
        self.assertTrue(hasattr(store, "admit_authorization"))
        store.admit_authorization(actor, payload)
        service.verify(changed, store_identity="store-1", campaign_id="campaign-1")
        with self.assertRaises(AuthorizationDenied):
            store.validate_admitted_authorization(changed)

    def test_exhaustive_reset_discards_every_authority_cache(self):
        from tools.decision_0009.acer_adapter import supervisor as module
        store, witness, actor, payload, _ = self.foundation()
        self.assertTrue(hasattr(module, "STORE_FIELD_DOMAINS"), "exhaustive reset map required")
        self.assertEqual(set(vars(store)), set(module.STORE_FIELD_DOMAINS))
        self.assertEqual(set(vars(store)), set(module.STORE_FIELD_CLASSIFICATION))
        self.assertEqual({value['authority_class'] for value in module.STORE_FIELD_CLASSIFICATION.values()}, {
            'durable authority', 'derived historical view', 'volatile cache', 'immutable provenance',
            'current volatile capability', 'non-authorizing diagnostic state'})
        store._sessions["poison"] = actor
        store._accepted_effects.add("poison")
        store._publication_grants["poison"] = actor
        store._slot_grants["poison"] = actor
        store.reset_volatile()
        self.assertEqual(store._sessions, {})
        self.assertEqual(store._accepted_effects, set())
        self.assertEqual(store._publication_grants, {})
        self.assertEqual(store._slot_grants, {})
        self.assertIsNone(store._current_actor)
        self.assertFalse(store._supervisor_ready)
        self.assertEqual(store._supervisor_generation, witness.high_generation)
        self.assertTrue(store.execution_revoked)
        self.assertTrue(store.publication_prohibited)
        with self.assertRaises(AuthorizationDenied):
            witness.authenticate(actor, store.identity, "ENTRY")

    def test_new_foundation_cannot_fall_back_to_legacy_runtime_or_append(self):
        from acer_adapter_fakes import MutableArtifacts, session
        from tools.decision_0009.acer_adapter.custody import OfflineCustodian
        from tools.decision_0009.acer_adapter.supervisor import (
            ArtifactVerificationPrimitive, PersistentSupervisor,
        )
        store, witness, actor, payload, _ = self.foundation()
        revision = store.revision
        generation = witness.high_generation
        with self.assertRaises(AuthorizationDenied):
            store.append(store.revision, actor.fence, "legacy-route", {"value": "bypass"})
        verifier = ArtifactVerificationPrimitive("offline-root", payload, MutableArtifacts().read)
        reader = PersistentSupervisor(store, verifier, OfflineCustodian('custodian-1'),
                                      payload, session(actor.fence))
        self.assertFalse(reader.session.execution_live)
        with self.assertRaises(AuthorizationDenied):
            reader.admit_campaign(__import__('acer_adapter_fakes').activation())
        self.assertEqual(store.revision, revision)
        self.assertEqual(witness.high_generation, generation)

    def test_init_fault_matrix_never_exposes_live_authority(self):
        for stage in ("before_reservation", "reservation_response_lost", "reserved_before_frame",
                      "frame_before_readback", "readback_mismatch", "readback_unavailable",
                      "validated_before_commit", "commit_before_ack"):
            with self.subTest(transaction="AUTHORIZATION_ADMITTED", stage=stage):
                store, witness, actor, payload, _ = self.foundation()
                before = witness.high_revision
                with self.assertRaises(StoreError):
                    store.admit_authorization(actor, payload, fault=stage)
                self.assertFalse(actor.execution_live)
                self.assertTrue(store.execution_revoked)
                self.assertEqual(witness.high_revision,
                                 before + (1 if stage == "commit_before_ack" else 0))
                if stage in ('frame_before_readback', 'validated_before_commit'):
                    exact = store._durable[-1]['bytes']
                    for interrupt in ('before_commit', 'lost_ack'):
                        with self.subTest(reconciliation=interrupt), self.assertRaises(StoreError):
                            store.reconcile_pending(store._authentication_service, payload, fault=interrupt)
                    store.reconcile_pending(store._authentication_service, payload)
                    self.assertEqual(store._durable[-1]['bytes'], exact)
                    self.assertTrue(store.execution_revoked)

    def test_reconciliation_interruption_and_lost_response_remain_exact_history(self):
        from acer_adapter_fakes import offline_chair_service, u04_authorization
        for stage in ("before_commit", "lost_ack"):
            with self.subTest(stage=stage):
                payload = u04_authorization()
                service = offline_chair_service(payload)
                witness = OfflineWitness("witness-1")
                store = OfflineDurableStore("store-1", witness, chair_verifier=service)
                with self.assertRaises(StoreError):
                    store.begin_fresh_entry(service, payload, "supervisor-1",
                                            fault="validated_before_commit")
                exact = store._durable[-1]["bytes"]
                with self.assertRaises(StoreError):
                    store.reconcile_pending(service, payload, fault=stage)
                store.reconcile_pending(service, payload)
                record = witness.query_transaction(store._durable[-1]["event_id"])[1]
                self.assertEqual(record.completion_mode, "RECOVERY_RECONCILE")
                self.assertEqual(store._durable[-1]["bytes"], exact)
                self.assertEqual(len(store._durable), 1)
                self.assertTrue(store.execution_revoked)

    def test_caller_actor_label_cannot_register_a_live_witness_actor(self):
        from dataclasses import replace
        store, witness, actor, _, _ = self.foundation()
        store.crash()
        forged = replace(actor, mode="LIVE", token=object())
        with self.assertRaises(AuthorizationDenied):
            witness.register_actor(forged)

    def test_failed_fresh_entry_never_becomes_a_fresh_store_again(self):
        from acer_adapter_fakes import offline_chair_service, u04_authorization
        payload = u04_authorization()
        service = offline_chair_service(payload)
        store = OfflineDurableStore("store-1", OfflineWitness("witness-1"),
                                    chair_verifier=service)
        with self.assertRaises(StoreError):
            store.begin_fresh_entry(service, payload, "supervisor-1",
                                    fault="before_reservation")
        with self.assertRaises(AuthorizationDenied):
            store.begin_fresh_entry(service, payload, "supervisor-1")

    def test_same_thread_revocation_after_commit_prevents_acknowledgement(self):
        store, witness, actor, payload, _ = self.foundation()
        read = store._independent_frame_readback
        observed = []

        def readback(revision):
            raw = read(revision)
            if revision == 2 and witness.high_revision == 2 and not observed:
                observed.append("revoked")
                store.crash()
            return raw

        store._independent_frame_readback = readback
        with self.assertRaises(StoreError):
            store.admit_authorization(actor, payload)
        self.assertEqual(observed, ["revoked"])
        self.assertEqual(witness.high_revision, 2)
        self.assertIsNone(store._current_actor)
