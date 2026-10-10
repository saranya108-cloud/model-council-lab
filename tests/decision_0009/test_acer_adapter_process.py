"""Checkpoint D: real local proof boundaries, never a live workload runner."""

import importlib.util
import socket
import struct
import unittest


class ProcessTransportTests(unittest.TestCase):
    def module(self):
        name = 'tools.decision_0009.acer_adapter.local_ipc'
        self.assertIsNotNone(importlib.util.find_spec(name),
                             'D requires a closed socket-pair transport')
        return __import__(name, fromlist=['Channel'])

    def test_canonical_framing_rejects_duplicate_keys(self):
        ipc = self.module()
        with self.assertRaises(ipc.ProtocolError):
            ipc.decode(b'{"a":1,"a":2}\n')

    def test_canonical_framing_rejects_noncanonical_and_nonclosed_values(self):
        ipc = self.module()
        for raw in (b'{ "a":1}\n', b'{"a":1.0}\n', b'{"a":NaN}\n', b'[]\n'):
            with self.subTest(raw=raw), self.assertRaises(ipc.ProtocolError):
                ipc.decode(raw)
        with self.assertRaises(ipc.ProtocolError):
            ipc.canonical({'authorization': ('malformed', 'carrier')})

    def test_length_is_bounded_before_body_read(self):
        ipc = self.module()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            b.sendall(struct.pack('!I', ipc.MAX_MESSAGE + 1))
            with self.assertRaises(ipc.ProtocolError):
                ipc.read_message(a)
        finally:
            a.close()
            b.close()

    def test_fixed_role_rejects_application_fault_request(self):
        ipc = self.module()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel = ipc.Channel(a, 'CONTROLLER', 'JPS')
            with self.assertRaises(ipc.ProtocolError):
                channel.request('FAULT_PREFIX', {'length': 1})
        finally:
            a.close()
            b.close()

    def test_original_channel_replay_and_wrong_response_correlation_are_rejected(self):
        ipc = self.module()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            h, w = ipc.Channel(a, 'H', 'W'), ipc.Channel(b, 'W', 'H')
            h.begin('FENCE', {'channel': 0})
            original = w.receive()
            w.answer({'fenced': True})
            h.receive()
            ipc.write_message(a, original)
            with self.assertRaises(ipc.ProtocolError):
                w.receive()
            h.begin('PING', {})
            msg = w.receive()
            ipc.write_message(b, dict(version=1, sender='W', receiver='H', kind='RESPONSE',
                id=msg['id'] + 1, operation='REPLY', body=dict(ok=True, result={}, error=None)))
            with self.assertRaises(ipc.ProtocolError):
                h.receive()
        finally:
            a.close()
            b.close()

    def test_accepted_failure_distinctions_survive_closed_encoding(self):
        ipc = self.module()
        from tools.decision_0009.acer_adapter.supervisor import (TransactionPending, Quarantined,
            AuthorizationDenied, CASMismatch, StaleRead, DispatchUncertain)
        from tools.decision_0009.acer_adapter.custody import ContainmentUnavailable
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthenticationError
        cases = (TransactionPending('original-tx', 'reservation-response', 'UNKNOWN'),
                 Quarantined('quarantine'), AuthorizationDenied('denial'),
                 ContainmentUnavailable('original service unavailable'), CASMismatch('cas'),
                 StaleRead('read'), DispatchUncertain('uncertain'), OfflineChairAuthenticationError('enrollment'))
        for exc in cases:
            with self.subTest(kind=type(exc).__name__), self.assertRaises(type(exc)) as caught:
                ipc.raise_failure(ipc.decode(ipc.canonical(ipc.failure_record(exc))))
            if isinstance(exc, TransactionPending):
                self.assertEqual((caught.exception.transaction_id, caught.exception.stage, caught.exception.status),
                                 ('original-tx', 'reservation-response', 'UNKNOWN'))


class ProcessProofTests(unittest.TestCase):
    def recovered(self, world):
        world.command('initialize')
        world.command('reserve_original')
        world.terminate_controller()
        return world.recover()

    def test_copied_carriers_cannot_substitute_for_accepted_authority(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied
        from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthenticationError
        with ProofWorld('accepted-copy-rejection') as world:
            self.recovered(world)
            before = world.observe()
            for action in ('substitute_enrollment', 'copied_actor', 'copied_binding', 'copied_frame',
                           'lower_object', 'lower_barrier', 'lower_allocation', 'lower_fence'):
                expected = OfflineChairAuthenticationError if action == 'substitute_enrollment' else AuthorizationDenied
                with self.subTest(action=action), self.assertRaises(expected):
                    world.command(action)
            after = world.observe()
            self.assertEqual(before['jps'], after['jps'])
            self.assertEqual(before['w'], after['w'])
            self.assertEqual(before['c'], after['c'])
            world.command('continue')
            with self.assertRaises(AuthorizationDenied):
                world.command('copied_grant')

    def test_accepted_pending_frame_reconciles_only_original_w(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-pending-reconciliation') as world:
            self.recovered(world)
            loss = world.crash_at('readback_before_commit')
            before = world.observe()
            self.assertEqual(before['w']['health'], 'RECONCILABLE')
            world.recover_and_crash('after_reconcile_before_reentry')
            after = world.observe()
            self.assertEqual(before['jps'], after['jps'])
            self.assertEqual(before['c'], after['c'])
            commit = after['w']['commits'][loss['transaction']]
            self.assertEqual(commit['completion_mode'], 'RECOVERY_RECONCILE')
            self.assertEqual(commit['reservation']['initiator_hex'], before['w']['pending'][0]['initiator_hex'])
            world.recover()
            resolved = world.observe()
            self.assertEqual(resolved['w']['commits'][loss['transaction']], commit)
            world.command('continue')

    def test_actual_c_initiation_survives_controller_loss_without_duplicate(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read
        with ProofWorld('accepted-c-initiation-loss') as world:
            self.recovered(world)
            world.crash_at_c('initiated_before_result')
            cut = _process_data_read(world.c_cut_observation['registries'])
            self.assertIn('IN_FLIGHT', {o['status'] for o in cut['operations'].values()})
            world.recover()
            before = world.observe()
            world.command('query')
            after = world.observe()
            b = _process_data_read(before['c']['registries'])
            a = _process_data_read(after['c']['registries'])
            self.assertEqual(b['counts'], a['counts'])
            self.assertTrue(all(count == 1 for count in a['counts'].values()))

    def test_accepted_controller_loss_cut_points(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read, Quarantined
        stages = ('before_reservation', 'after_reservation_before_frame', 'partial_frame',
            'bytes_written_before_barrier', 'barrier_complete_before_readback',
            'commit_before_ack', 'acceptance_before_claim',
            'result_frame_before_commit', 'result_commit_before_ack')
        incomplete = {'after_reservation_before_frame', 'partial_frame', 'bytes_written_before_barrier'}
        for stage in stages:
            with self.subTest(stage=stage), ProofWorld('accepted-cut-' + stage, fault_case=True) as world:
                self.recovered(world)
                loss = world.crash_at(stage)
                self.assertEqual(loss['returncode'], -9)
                before = world.observe()
                if stage in ('partial_frame', 'bytes_written_before_barrier'):
                    self.assertFalse(before['jps']['barrier'])
                if stage == 'partial_frame':
                    self.assertEqual(len(bytes.fromhex(before['jps']['tail_hex'])), 7)
                if stage == 'barrier_complete_before_readback':
                    self.assertTrue(before['jps']['barrier'])
                    self.assertEqual(before['jps']['records'][-1]['payload']['record_type'],
                                     'RECOVERY_PUBLICATION_ACCEPTED')
                if stage in incomplete:
                    if stage == 'bytes_written_before_barrier':
                        self.assertEqual(world.recover()['mode'], 'INSPECTION')
                        self.assertIsNone(world.command('inspect_runtime')['actor'])
                        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied
                        with self.assertRaises(AuthorizationDenied):
                            world.command('continue')
                    else:
                        with self.assertRaises(Quarantined):
                            world.recover()
                    after = world.observe()
                    self.assertEqual(before['jps'], after['jps'])
                    self.assertEqual(before['c'], after['c'])
                else:
                    world.recover()
                    if stage.startswith('result_'):
                        world.command('query')
                    else:
                        world.command('continue')
                    after = world.observe()
                    registry = _process_data_read(after['c']['registries'])
                    self.assertTrue(all(n == 1 for n in registry['counts'].values()))
                    self.assertLessEqual(len(registry['claims']), 1)
                    if loss['transaction'] in before['w']['commits']:
                        self.assertEqual(before['w']['commits'][loss['transaction']],
                                         after['w']['commits'][loss['transaction']])

    def test_original_w_acknowledgement_loss_preserves_facts(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read, Quarantined
        for operation in ('RESERVE_FRAME', 'COMMIT_FRAME', 'ACK_FRAME'):
            with self.subTest(operation=operation), ProofWorld('accepted-w-ack-' + operation) as world:
                self.recovered(world)
                world.response_loss('W', operation)
                before = world.observe()
                if operation == 'RESERVE_FRAME':
                    self.assertEqual(len(before['w']['pending']), 1)
                    with self.assertRaises(Quarantined):
                        world.recover()
                else:
                    self.assertEqual(before['w']['pending'], [])
                    world.recover()
                    world.command('continue')
                    registry = _process_data_read(world.observe()['c']['registries'])
                    self.assertEqual(len(registry['claims']), 1)
                    self.assertTrue(all(n == 1 for n in registry['counts'].values()))

    def test_c_claim_and_authentic_result_acknowledgement_loss(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read
        for stage in ('claimed_before_initiation', 'authentic_result_before_reply'):
            with self.subTest(stage=stage), ProofWorld('accepted-c-cut-' + stage) as world:
                self.recovered(world)
                world.crash_at_c(stage)
                world.recover()
                before = _process_data_read(world.observe()['c']['registries'])
                world.command('query')
                after = _process_data_read(world.observe()['c']['registries'])
                self.assertEqual(before['counts'], after['counts'])
                self.assertEqual(len(after['claims']), 1)
                self.assertTrue(all(n == 1 for n in after['counts'].values()))
        with ProofWorld('accepted-c-response-loss') as world:
            self.recovered(world)
            world.response_loss('C', 'RP_INITIATE')
            world.recover()
            before = world.observe()
            world.command('query')
            self.assertEqual(before['c']['registries'], world.observe()['c']['registries'])

    def test_missing_registry_or_observation_is_unknown(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied, _process_data_read
        for facts in (['registry'], ['mirror'], ['result_observation']):
            with self.subTest(facts=facts), ProofWorld('accepted-missing-' + facts[0]) as world:
                self.recovered(world)
                world.command('continue')
                world.forget(facts)
                before = _process_data_read(world.observe()['c']['registries'])
                world.command('query')
                after = world.observe()
                events = [r['payload'] for r in after['jps']['records'] if
                          r['payload'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT']
                self.assertEqual(events[-1]['outcome'], 'UNKNOWN')
                self.assertEqual(events[-1]['reason_code'], 'READBACK_UNAVAILABLE' if
                    facts == ['result_observation'] else 'DESTINATION_REGISTRY_UNAVAILABLE')
                with self.assertRaises(AuthorizationDenied):
                    world.command('continue')
                retained = _process_data_read(world.observe()['c']['registries'])
                self.assertEqual(before['claims'], retained['claims'])
                self.assertEqual(before['counts'], retained['counts'])

    def test_fenced_delayed_original_channel_requests_cannot_mutate(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import Quarantined
        for role, operation in (('C', 'RP_INITIATE'), ('JPS', 'WRITE_FRAME'), ('JPS', 'BARRIER')):
            with self.subTest(role=role, operation=operation), ProofWorld('accepted-delay-' + operation) as world:
                self.recovered(world)
                world.delay_then_crash(role, operation)
                if role == 'C':
                    world.recover()
                else:
                    if operation == 'BARRIER':
                        self.assertEqual(world.recover()['mode'], 'INSPECTION')
                        self.assertIsNone(world.command('inspect_runtime')['actor'])
                    else:
                        with self.assertRaises(Quarantined):
                            world.recover()
                before = world.observe()
                released = world.release(role)
                self.assertTrue(released['denied'])
                after = world.observe()
                self.assertEqual(before['jps'], after['jps'])
                self.assertEqual(before['c'], after['c'])

    def test_original_service_loss_denies_recovery_without_replacement(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.process_services import OwnershipError
        for role in ('W', 'C', 'JPS'):
            with self.subTest(role=role), ProofWorld('accepted-service-loss-' + role) as world:
                world.command('initialize')
                world.command('reserve_original')
                world.terminate_controller()
                self.assertTrue(world.kill_service(role)['reaped'])
                with self.assertRaises(OwnershipError):
                    world.recover()
                with self.assertRaises(OwnershipError):
                    world.owner.launch(role, [], [])

    def test_quarantine_denies_public_and_lower_operations(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import Quarantined
        with ProofWorld('accepted-quarantine') as world:
            self.recovered(world)
            world.quarantine()
            before = world.observe()
            for action in ('continue', 'copied_frame', 'lower_object', 'lower_barrier'):
                with self.subTest(action=action), self.assertRaises(Quarantined):
                    world.command(action)
            self.assertEqual(before['jps'], world.observe()['jps'])
            self.assertEqual(before['c'], world.observe()['c'])

    def test_retained_owned_process_capability_rejects_impostors(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-process-impostors') as world:
            result = world.reject_impostors()
            self.assertEqual(result, {'rejected': 3, 'signal_syscalls': 0})
        self.assertTrue(world.quiescent)

    def test_quarantine_denies_exact_pending_reconciliation(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import Quarantined
        with ProofWorld('accepted-quarantine-reconciliation') as world:
            self.recovered(world)
            loss = world.crash_at('readback_before_commit')
            self.assertEqual(world.observe()['w']['health'], 'RECONCILABLE')
            world.quarantine()
            before = world.observe()
            with self.assertRaises(Quarantined):
                world.recover()
            after = world.observe()
            self.assertEqual(before['jps'], after['jps'])
            self.assertEqual(before['c'], after['c'])
            self.assertEqual(before['w']['pending'], after['w']['pending'])
            self.assertNotIn(loss['transaction'], after['w']['commits'])

    def test_loss_before_reconciliation_preserves_exact_pending_checkpoint(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-before-reconciliation-loss') as world:
            self.recovered(world)
            loss = world.crash_at('readback_before_commit')
            before = world.observe()
            world.recover_and_crash('before_reconcile')
            after = world.observe()
            self.assertEqual(before['jps'], after['jps'])
            self.assertEqual(before['c'], after['c'])
            self.assertEqual(before['w']['pending'], after['w']['pending'])
            world.recover()
            self.assertEqual(world.observe()['w']['commits'][loss['transaction']]['completion_mode'],
                             'RECOVERY_RECONCILE')
            world.command('continue')

    def test_accepted_c_retained_pending_claimed_inflight_and_complete(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.evidence import PublicationAcknowledgementLost
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read, AuthorizationDenied
        for fault, status in (('before_claim', 'NOT_STARTED'), ('after_claim', 'CLAIMED'),
                              ('after_initiation', 'IN_FLIGHT'), ('after_readback', 'COMPLETE')):
            with self.subTest(fault=fault), ProofWorld('accepted-retained-' + status) as world:
                self.recovered(world)
                world.destination_ack_loss(fault)
                with self.assertRaises(PublicationAcknowledgementLost):
                    world.command('continue')
                retained = _process_data_read(world.observe()['c']['registries'])
                self.assertIn(status, {v['status'] for v in retained['operations'].values()})
                world.terminate_controller()
                world.recover()
                world.command('query')
                after = world.observe()
                current = _process_data_read(after['c']['registries'])
                self.assertEqual(retained['counts'], current['counts'])
                self.assertEqual(retained['claims'], current['claims'])
                if status in ('CLAIMED', 'IN_FLIGHT'):
                    results = [f['payload'] for f in after['jps']['records'] if
                        f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT']
                    self.assertEqual(results[-1]['outcome'], 'UNKNOWN')
                    with self.assertRaises(AuthorizationDenied):
                        world.command('continue')

    def test_accepted_supplement_registry_loss_does_not_recreate_freshness(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.evidence import PublicationAcknowledgementLost
        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied, _process_data_read
        cases = (('supplement_keep_subject', 'after_claim'),
                 ('supplement_keep_operation', 'after_initiation'),
                 ('supplement_keep_both', ''), ('supplement_acceptance_only', 'before_claim'))
        for fact, fault in cases:
            with self.subTest(fact=fact, fault=fault), ProofWorld('accepted-supplement-' + fact) as world:
                self.recovered(world)
                for action in ('continue', 'durable', 'verify', 'make_supplement'):
                    world.command(action)
                if fault:
                    world.destination_ack_loss(fault)
                    with self.assertRaises(PublicationAcknowledgementLost):
                        world.command('perform_supplement')
                else:
                    world.command('perform_supplement')
                before = world.observe()
                acceptances = [f['payload'] for f in before['jps']['records'] if
                    f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' and
                    f['payload'].get('object_key') != world.subject['object_key']]
                self.assertEqual(len(acceptances), 1)
                world.forget([fact])
                world.terminate_controller()
                world.recover()
                retained = _process_data_read(world.observe()['c']['registries'])
                world.command('query_supplement')
                after = world.observe()
                result = [f['payload'] for f in after['jps']['records'] if
                          f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT'][-1]
                self.assertEqual((result['outcome'], result['reason_code']),
                                 ('UNKNOWN', 'DESTINATION_REGISTRY_UNAVAILABLE'))
                with self.assertRaises(AuthorizationDenied):
                    world.command('perform_supplement')
                final = _process_data_read(world.observe()['c']['registries'])
                self.assertEqual(retained['counts'], final['counts'])
                self.assertEqual(retained['claims'], final['claims'])
                self.assertNotIn(acceptances[0]['object_key'], final['objects'])
                self.assertEqual(final['objects']['evidence/proof']['bytes'], world._source)
                accepted_after = [f['payload'] for f in world.observe()['jps']['records'] if
                    f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_ACCEPTED' and
                    f['payload'].get('object_key') != world.subject['object_key']]
                self.assertEqual(acceptances, accepted_after)

    def test_stable_conflict_and_denial_ack_loss_remain_irreversible(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied
        with ProofWorld('accepted-stable-conflict-denial') as world:
            world.command('initialize')
            world.command('reserve_original')
            with self.assertRaises(AuthorizationDenied):
                world.command('write_original_partial')
            world.terminate_controller()
            world.recover()
            first = world.observe()['w']['denials']
            self.assertTrue(first)
            world.response_loss('W', 'DENY_CAMPAIGN', action='query')
            observed = world.observe()
            results = [f['payload'] for f in observed['jps']['records'] if
                       f['payload'].get('record_type') == 'RECOVERY_PUBLICATION_RESULT']
            self.assertEqual(results[-1]['outcome'], 'PARTIAL')
            self.assertEqual(first, observed['w']['denials'])
            world.recover()
            with self.assertRaises(AuthorizationDenied):
                world.command('continue')
            self.assertEqual(first, world.observe()['w']['denials'])

    def test_fault_journal_rollback_and_chain_conflict_are_not_repaired(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied, Quarantined
        for fault in ('F08', 'F09'):
            with self.subTest(fault=fault), ProofWorld('accepted-history-' + fault, fault_case=True) as world:
                world.command('initialize')
                world.command('reserve_original')
                world.terminate_controller()
                mutation = world.corrupt(fault)
                before = world.observe()
                try:
                    result = world.recover()
                except Quarantined:
                    pass
                else:
                    self.assertEqual(result['mode'], 'INSPECTION')
                    self.assertIsNone(world.command('inspect_runtime')['actor'])
                    with self.assertRaises(AuthorizationDenied):
                        world.command('continue')
                after = world.observe()
                self.assertEqual(before['jps'], after['jps'])
                self.assertEqual(before['c'], after['c'])
                self.assertTrue(mutation['preimage_sha256'])
                self.assertTrue(mutation['postimage_sha256'])

    def test_endpoint_and_root_substitution_are_distinct_from_enrollment(self):
        import copy
        import os
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.journal_persistence import JournalPersistence, PersistenceError
        from tools.decision_0009.acer_adapter.local_ipc import ProtocolError
        with ProofWorld('accepted-endpoint-root-substitution', fault_case=True) as world:
            self.recovered(world)
            before = world.observe()
            with self.assertRaises(TypeError):
                copy.copy(world._channels['C'])
            with self.assertRaises(ProtocolError):
                world._channels['C'].request('SETUP', {'configuration': dict(world._controller_configuration)})
            wrong = list(before['jps']['root_identity'])
            wrong[1] += 1
            with self.assertRaises(PersistenceError):
                JournalPersistence(world.journal, wrong, fault_case=True)
            alias = world.journal.parent / (world.case_id + '-root-alias')
            os.symlink(world.journal.name, alias)
            with self.assertRaises(OSError):
                JournalPersistence(alias, before['jps']['root_identity'], fault_case=True)
            ancestor = world.journal.parent / (world.case_id + '-ancestor-alias')
            os.symlink('.', ancestor)
            with self.assertRaises(OSError) as caught:
                JournalPersistence(ancestor / world.journal.name, before['jps']['root_identity'], fault_case=True)
            import errno
            self.assertIn(caught.exception.errno, (errno.ELOOP, errno.ENOTDIR))
            world.faults.append(dict(fault='F10', rejected=['copied-channel', 'service-reenrollment',
                                                          'root-identity', 'root-symlink', 'ancestor-symlink'],
                                     artifacts=[str(alias), str(ancestor)]))
            after = world.observe()
            self.assertEqual(before, after)

    def test_fence_ack_loss_keeps_original_revocation_frontier(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-fence-ack-loss') as world:
            world.command('initialize')
            world.command('reserve_original')
            world.terminate_controller()
            world.suppress_fence_ack()
            world.recover()
            self.assertTrue(world.observe()['w']['frontiers'])
            world.command('continue')

    def test_only_original_harness_thread_can_wait_or_signal(self):
        import signal
        import threading
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.process_services import OwnershipError
        with ProofWorld('accepted-sole-wait-owner') as world:
            rejected = []
            before = world.owner.signal_syscalls
            def attempt():
                for operation in (lambda: world.owner.poll(world.controller),
                                  lambda: world.owner.signal(world.controller, signal.SIGKILL)):
                    try:
                        operation()
                    except OwnershipError:
                        rejected.append(True)
            thread = threading.Thread(target=attempt, daemon=False)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(rejected), 2)
            self.assertEqual(world.owner.signal_syscalls, before)
            world.faults.append(dict(fault='F11', sole_waiter_rejections=2, signal_syscalls=0))

    def test_owned_cleanup_uses_term_after_closed_shutdown_is_pending(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-bounded-cleanup') as world:
            self.recovered(world)
            world.control.begin('RUN', {'action': 'continue', 'cut': 'before_reservation'})
            stage = world.control.receive()
            self.assertEqual(stage['operation'], 'STAGE')
            world.close()
            self.assertTrue(world.quiescent)
            self.assertLessEqual(world.owner.quiescence()['peak_operating_processes_including_h'], 5)
            self.assertTrue(any(e['event'] == 'SIGNAL' and e['signal'] == 15 for e in world.owner.observations))
            self.assertTrue(any(e['event'] == 'EXIT_REAP' and e['returncode'] == -15 for e in world.owner.observations))

    def test_reconciliation_ack_loss_resolves_only_the_same_checkpoint(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        with ProofWorld('accepted-reconcile-ack-loss') as world:
            self.recovered(world)
            loss = world.crash_at('readback_before_commit')
            before = world.observe()
            world._replacement()
            world.response_loss('W', 'RECONCILE', action='recover')
            world.faults.append(dict(fault='F12', transaction=loss['transaction'], cut='reconciliation-ack-loss'))
            after = world.observe()
            self.assertEqual(before['jps'], after['jps'])
            self.assertEqual(before['c'], after['c'])
            completed = after['w']['commits'][loss['transaction']]
            self.assertEqual(completed['completion_mode'], 'RECOVERY_RECONCILE')
            world.recover()
            self.assertEqual(completed, world.observe()['w']['commits'][loss['transaction']])
            world.command('continue')

    def test_accepted_original_history_death_reconstruction_continuation(self):
        from decision_0009.acer_adapter_process_support import ProofWorld
        from tools.decision_0009.acer_adapter.supervisor import _process_data_read
        with ProofWorld('accepted-positive-chain') as world:
            admitted = world.command('initialize')
            self.assertEqual(admitted['controller_type'], 'PersistentSupervisor')
            self.assertEqual(admitted['mode'], 'LIVE')
            world.command('reserve_original')
            before = world.observe()
            original = [r for r in before['jps']['records'] if
                r['payload'].get('record_type') == 'PUBLICATION' and
                r['payload'].get('operation') == 'intent' and
                r['authority_facts'].get('publication_grant', {}).get('phase') == 'INTENT']
            self.assertEqual(len(original), 1)
            self.assertTrue(before['c']['original_source_owned'])
            retained = _process_data_read(before['c']['registries'])
            source = retained['subjects']['evidence/proof']
            self.assertEqual(source['original_intent_ref']['event_id'], original[0]['transaction_id'])
            self.assertIsNotNone(source['original_create_ref'])
            self.assertEqual(retained['objects']['evidence/proof']['bytes'], b'')
            lost = world.terminate_controller()
            self.assertTrue(lost['reaped'])
            self.assertEqual(lost['returncode'], -9)
            recovered = world.recover()
            self.assertEqual(recovered['controller_type'], 'PersistentSupervisor')
            runtime = world.command('inspect_runtime')
            self.assertEqual(runtime['actor']['mode'], 'RECOVERY')
            self.assertEqual(runtime['registered_sessions'], [])
            self.assertEqual(runtime['publication_grants'], [])
            self.assertEqual(runtime['rp_grants'], [])
            # Accepted reconstruction retains a historical window view. Its
            # old operation capabilities and executing session do not return.
            self.assertEqual(runtime['window_operation_ids'], [])
            for action in ('continue', 'durable', 'verify'):
                world.command(action)
            after = world.observe()
            final = _process_data_read(after['c']['registries'])
            self.assertEqual(final['objects']['evidence/proof']['bytes'], world._source)
            self.assertTrue(final['objects']['evidence/proof']['namespace_durable'])
            self.assertEqual(len(final['claims']), 3)
            self.assertTrue(all(count == 1 for count in final['counts'].values()))
            self.assertEqual(after['continuity'], before['continuity'])
            self.assertEqual(after['jps']['records'][:len(before['jps']['records'])], before['jps']['records'])
            self.assertEqual(after['jps']['records'][-1]['payload']['record_type'], 'RECOVERY_PUBLICATION_VERIFIED')
        self.assertTrue(world.quiescent)
