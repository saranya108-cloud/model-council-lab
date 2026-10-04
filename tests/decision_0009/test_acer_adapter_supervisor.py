from dataclasses import replace
import json
import threading
import unittest

from tools.decision_0009.acer_adapter.contracts import ContractError, CustodyError, REMOVED_STATES
from tools.decision_0009.acer_adapter.supervisor import (
    AuthorizationDenied, DispatchUncertain, PersistentSupervisor, Quarantined,
    _canonical, _sha, authorize_and_dispatch,
)
from tools.decision_0009.startup_characterization import policy as core_policy
from acer_adapter_fakes import (
    RecordingDispatch, activation, complete_boot, core_attempt_bytes, digest,
    local_attempt_evidence, make_supervisor, record_all_local_attempts,
    residual_observations, session, u04_authorization, offline_chair_service, offline_activation_service, inject_untrusted_record,
)


class U04BaselineCharacterizationTests(unittest.TestCase):
    """Revision 6 oracles exercised through the original public seams.

    Keep these triggers when migrating fixtures: a constructor, crash callback,
    or historical label must never manufacture authority.
    """

    def test_u04_unplanned_restart_cannot_create_worker(self):
        original, _, custodian = make_supervisor()
        original.store.crash()
        restarted = _restart(original)
        self.assertEqual(original.store.witness.denial(restarted._actor)[0], 'UNFINISHED_BOOT_LOSS')
        with self.assertRaises(AuthorizationDenied):
            restarted.make_slot_eligible("slot-1-1")
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_u04_history_never_registers_live_sessions(self):
        original, _, _ = make_supervisor()
        original.store.crash()
        restarted = _restart(original)
        self.assertFalse(any(item.execution_live
                             for item in restarted.store._sessions.values()))

    def test_u04_effect_acceptance_requires_committed_frame(self):
        original, _, custodian = make_supervisor()
        original.make_slot_eligible("slot-1-1")
        observed = []
        accept = original.store.accept_effect

        def inspect_acceptance(capability):
            result = accept(capability)
            if capability.operation == "blocked-create":
                observed.append(any(
                    event.get("record_type") == "EFFECT_ACCEPTED" and
                    event.get("effect_id") == capability.effect_id
                    for event in original.store.events))
            return result

        original.store.accept_effect = inspect_acceptance
        original.spawn_worker("slot-1-1", digest("launch"))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        self.assertEqual(observed, [True])

    def test_u04_handoff_loss_cannot_activate_next_boot(self):
        original, _, custodian = make_supervisor()
        complete_boot(original)
        predecessor = original.predecessor_closure_digest
        original.begin_boot_handoff(2)
        original.store.crash()
        restarted = _restart(original)
        with self.assertRaises(AuthorizationDenied):
            restarted.activate_next_boot(activation(2, "boot-2", predecessor))
        self.assertEqual(original.store.witness.denial(restarted._actor)[0], 'UNPLANNED_HANDOFF_LOSS')
        self.assertEqual(custodian.underlying_create_count_for_all(), 3)

    def test_u04_restart_cannot_issue_normal_publication_grants(self):
        from tools.decision_0009.acer_adapter.evidence import ImmutablePublication
        original, _, _ = make_supervisor()
        original.store.crash()
        restarted = _restart(original)
        publisher = ImmutablePublication(restarted)
        with self.assertRaises(AuthorizationDenied):
            publisher.intent("offline-destination", "evidence", b"exact evidence\n")

    def test_u04_restart_cannot_restore_window_authority(self):
        original, _, _ = make_supervisor()
        original.set_measurement_window("DWELL")
        original.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        original.store.crash()
        restarted = _restart(original)
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(AuthorizationDenied):
            restarted.set_measurement_window("DWELL")

    def test_u04_same_thread_crash_revokes_interrupted_stack(self):
        original, _, custodian = make_supervisor()
        original.make_slot_eligible("slot-1-1")
        with self.assertRaises(AuthorizationDenied):
            original.spawn_worker("slot-1-1", digest("launch"),
                                  interlock=original.store.crash)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_u04_uninterrupted_worker_and_publication_positive_control(self):
        from tools.decision_0009.acer_adapter.evidence import ImmutablePublication
        original, _, custodian = make_supervisor()
        original.make_slot_eligible("slot-1-1")
        self.assertEqual(original.spawn_worker("slot-1-1", digest("launch")).status,
                         "BLOCKED")
        publisher = ImmutablePublication(original)
        payload = b"exact evidence\n"
        intent = publisher.intent("offline-destination", "evidence", payload)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, payload)
        self.assertIsNotNone(publisher.verify(intent))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)


class U04ShutdownAdmissionFaultMatrixTests(unittest.TestCase):
    def test_admission_input_negatives_leave_original_waiting_unconsumed(self):
        from dataclasses import replace
        from acer_adapter_fakes import independent_fault_world
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        seed, _, _ = make_supervisor()
        complete_boot(seed)
        predecessor = seed.predecessor_closure_digest
        seed.begin_boot_handoff(2)
        seed.commit_planned_shutdown()
        genuine = activation(2, 'boot-2', predecessor)
        changes = {
            'ordinal': {'boot_ordinal': 3}, 'reused-boot': {'observed_boot_id': 'boot-1'},
            'chair': {'chair_identity': 'untrusted-chair'}, 'authorization': {'authorization_digest': 'f' * 64},
            'predecessor': {'predecessor_closure_digest': 'e' * 64},
            'activation-replay': {'activation_id': 'activation-1'},
            'unenrolled-activation': {'activation_id': 'unenrolled-activation'},
            'unenrolled-boot': {'observed_boot_id': 'unenrolled-boot'},
        }
        for condition, mutation in changes.items():
            with self.subTest(condition=condition):
                world = independent_fault_world(seed)
                store, witness = world.store, world.store.witness
                before = (store.revision, witness.high_generation, witness.high_fence)
                with self.assertRaises((StoreError, ContractError)):
                    store.admit_next_boot(world.authorization, replace(genuine, **mutation), 'new-controller')
                self.assertEqual((store.revision, witness.high_generation, witness.high_fence), before)
                self.assertFalse(store.is_consumed('boot_activation', genuine.activation_id))
                self.assertIsNone(witness.denial(world._actor))
                self.assertEqual(store.waiting_shutdown(world.authorization)['event']['next_ordinal'], 2)
                self.assertEqual(world.custodian.underlying_create_count_for_all(), 3)
        for unavailable in ('witness', 'custodian'):
            with self.subTest(unavailable=unavailable):
                world = independent_fault_world(seed)
                target = world.store.witness if unavailable == 'witness' else world.custodian
                attribute = 'available' if unavailable == 'witness' else 'alive'
                setattr(target, attribute, False)
                with self.assertRaises((StoreError, ContractError)):
                    world.store.admit_next_boot(world.authorization, genuine, 'new-controller')
                self.assertIsNone(world.store.witness.denial(world._actor))
                setattr(target, attribute, True)
                self.assertEqual(world.store.waiting_shutdown(world.authorization)['event']['next_ordinal'], 2)
        positive = independent_fault_world(seed)
        actor, session = positive.store.admit_next_boot(positive.authorization, genuine, 'new-controller')
        self.assertEqual(actor.mode, 'LIVE')
        self.assertIs(positive.store.actor_for_session(session), actor)
        self.assertTrue(positive.store.is_consumed('boot_activation', genuine.activation_id))
        self.assertEqual(positive.custodian._revoked_through, session.fence_epoch - 1)
        self.assertEqual(positive.custodian.underlying_create_count_for_all(), 3)

    def test_failure_after_activation_reservation_denies_before_any_repair_or_restart(self):
        from dataclasses import replace
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        supervisor, _, custodian = make_supervisor()
        complete_boot(supervisor)
        predecessor = supervisor.predecessor_closure_digest
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        store = supervisor.store
        revoke = custodian.revoke_all_lower_fences
        def incomplete_lower_ack(actor):
            return replace(revoke(actor), revoked_fences=())
        custodian.revoke_all_lower_fences = incomplete_lower_ack
        with self.assertRaises((StoreError, CustodyError)):
            supervisor.activate_next_boot(activation(2, 'boot-2', predecessor))
        self.assertTrue(any(e.get('record_type') == 'ACTIVATION_RESERVED' for e in store.events))
        self.assertFalse(any(e.get('record_type') == 'ACTIVATION_ADMITTED' for e in store.events))
        self.assertIsNone(store._current_actor)
        self.assertEqual(next(iter(store.witness._denials.values()))[0], 'INTERRUPTED_ADMISSION')
        self.assertEqual(custodian.underlying_create_count_for_all(), 3)
        with self.assertRaises((StoreError, CustodyError)):
            store.waiting_shutdown(supervisor.authorization)

    def test_shutdown_and_activation_commit_windows(self):
        from acer_adapter_fakes import independent_fault_world
        from test_acer_adapter_custody import U04_COMMIT_STAGES
        from tools.decision_0009.acer_adapter.supervisor import StoreError
        seed, _, _ = make_supervisor()
        complete_boot(seed)
        predecessor = seed.predecessor_closure_digest
        seed.begin_boot_handoff(2)
        shutdown_seed = independent_fault_world(seed)
        shutdown_seed.commit_planned_shutdown()
        for transaction in ('shutdown', 'reservation', 'admission'):
            for stage in U04_COMMIT_STAGES:
                with self.subTest(transaction=transaction, stage=stage):
                    supervisor = independent_fault_world(seed if transaction == 'shutdown' else shutdown_seed)
                    store = supervisor.store
                    original_actor = store._current_actor
                    before_count = supervisor.custodian.underlying_create_count_for_all()
                    with self.assertRaises((StoreError, CustodyError)):
                        if transaction == 'shutdown':
                            supervisor.commit_planned_shutdown(fault=stage)
                        else:
                            store.admit_next_boot(supervisor.authorization,
                                activation(2, 'boot-2', predecessor), 'supervisor-2', **{
                                    ('reservation_fault' if transaction == 'reservation' else 'admission_fault'): stage})
                    self.assertEqual(supervisor.custodian.underlying_create_count_for_all(), before_count)
                    self.assertFalse(store._supervisor_ready and store._current_actor is not None and
                                     store._current_actor.mode == 'LIVE')
                    if transaction == 'shutdown' and stage == 'commit_before_ack':
                        self.assertIsNone(store._current_actor)
                        self.assertEqual(store.waiting_shutdown(supervisor.authorization)['event']['next_ordinal'], 2)
                        # Exact successful logical exit remains evidence when
                        # the original response or a subsequent read is lost.
                        original_read = store.read_verified
                        def unreadable(*args, **kwargs):
                            raise StoreError('temporarily unreadable original shutdown')
                        store.read_verified = unreadable
                        with self.assertRaises(StoreError):
                            store.waiting_shutdown(supervisor.authorization)
                        self.assertIsNone(store.witness.denial(original_actor))
                        del store.read_verified
                        self.assertEqual(store.waiting_shutdown(supervisor.authorization)['event']['next_ordinal'], 2)
                    elif transaction == 'reservation' and stage == 'before_reservation':
                        # No activation reservation exists at this deterministic
                        # pre-reservation seam. The old shutdown stays evidence;
                        # the pending actor still exposes no execution authority.
                        self.assertEqual(store.waiting_shutdown(supervisor.authorization)['event']['next_ordinal'], 2)
                    else:
                        with self.assertRaises((StoreError, CustodyError)):
                            store.waiting_shutdown(supervisor.authorization)
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
                        self.assertEqual(next(iter(store.witness._denials.values()))[0],
                            'SHUTDOWN_PENDING_AT_LOSS' if transaction == 'shutdown' else 'INTERRUPTED_ADMISSION')
                        with self.assertRaises((StoreError, CustodyError)):
                            store.waiting_shutdown(supervisor.authorization)
                    if transaction == 'shutdown' and stage == 'commit_before_ack':
                        store.reset_volatile()
                        self.assertEqual(store.waiting_shutdown(supervisor.authorization)['event']['next_ordinal'], 2)
                    with self.assertRaises((StoreError, CustodyError)):
                        store.require_actor(original_actor)


class U04OperationalKernelTests(unittest.TestCase):
    def test_inner_verification_root_cannot_substitute_admitted_artifact_policy(self):
        import hashlib
        supervisor, artifacts, custodian = make_supervisor()
        store, verifier = supervisor.store, supervisor.verifier
        original_authorization = supervisor.authorization
        artifacts.substitute('policy')
        substitute = replace(original_authorization,
            policy_digest=hashlib.sha256(artifacts.values['policy']).hexdigest())
        # Simulate corruption inside the pinned service independently of the
        # public reference guard. The lower store must still bind the original
        # admitted complete authorization, not the service's changed label.
        verifier.__dict__['authorization'] = substitute
        before = (store.revision, dict(custodian._control_counts))
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible('slot-1-1')
        self.assertEqual(custodian._control_counts, before[1])
        self.assertFalse(any(e.get('state') == 'SLOT_SPAWN_ELIGIBLE' for e in store.events))
        self.assertTrue(all(f['envelope'].boundary in ('HISTORY', 'DENY') and
                            f['event']['authorizes_execution'] is False
                            for f in store._durable[before[0]:]))
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

        positive, _, original_custodian = make_supervisor()
        for field, value in (('authorization', substitute), ('identity', 'changed-verifier'),
                             ('artifact_reader', lambda: {})):
            with self.subTest(field=field), self.assertRaises(AuthorizationDenied):
                setattr(positive.verifier, field, value)
        positive.make_slot_eligible('slot-1-1')
        positive.spawn_worker('slot-1-1', digest('launch'))
        self.assertEqual(original_custodian.underlying_create_count_for_all(), 1)

    def test_independent_lifecycle_record_rejects_caller_process_identity(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        supervisor.spawn_worker('slot-1-1', digest('launch'))
        commit = supervisor.store._commit_u04
        def substitute(actor, boundary, event, **kwargs):
            if event.get('operation') == 'worker-lifecycle' and event.get('state') == 'WORKER_IDENTITY_ESTABLISHED':
                event = dict(event, host_pid=999999)
            return commit(actor, boundary, event, **kwargs)
        supervisor.store._commit_u04 = substitute
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_worker_lifecycle('slot-1-1')
        self.assertFalse(any(e.get('state') == 'WORKER_IDENTITY_ESTABLISHED'
                             for e in supervisor.store.events))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_independent_worker_record_rejects_forged_custodian_receipt(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        commit = supervisor.store._commit_u04
        def substitute(actor, boundary, event, **kwargs):
            if event.get('operation') == 'record-worker-creation':
                event = dict(event, custodian_receipt='invented-receipt')
            return commit(actor, boundary, event, **kwargs)
        supervisor.store._commit_u04 = substitute
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker('slot-1-1', digest('launch'))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        self.assertFalse(any(e.get('state') == 'WORKER_CREATION_IN_PROGRESS'
                             for e in supervisor.store.events))

    def test_uninterrupted_creation_ignores_poisoned_legacy_views(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        store = supervisor.store
        create = custodian.create_once
        def poisoned_views(token, launch_spec_digest, capability, binding, **kwargs):
            identity = capability.effect_id
            store._sessions.clear()
            store._slot_grants[token.slot_id] = 'forged'
            store._effect_capabilities[identity] = 'forged'
            store._effect_status[identity] = 'KNOWN_RESULT'
            store._effect_results[identity] = 'forged'
            store._active_creation_grants.clear()
            store._accepted_effects.add(identity)
            store._acceptance_acks[identity] = 'forged'
            return create(token, launch_spec_digest, capability, binding, **kwargs)
        custodian.create_once = poisoned_views
        receipt = supervisor.spawn_worker('slot-1-1', digest('launch'))
        self.assertEqual(receipt.status, 'BLOCKED')
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        self.assertEqual(store.effect_acceptance_count('spawn-intent-slot-1-1'), 1)
        self.assertEqual(store.effect_result('spawn-intent-slot-1-1').receipt, receipt)

    def test_option_b_shutdown_is_required_before_separate_admission(self):
        supervisor, _, custodian = make_supervisor()
        complete_boot(supervisor)
        predecessor = supervisor.predecessor_closure_digest
        supervisor.begin_boot_handoff(2)
        with self.assertRaises(AuthorizationDenied):
            supervisor.activate_next_boot(activation(2, 'boot-2', predecessor))
        self.assertTrue(hasattr(supervisor, 'commit_planned_shutdown'))
        supervisor.commit_planned_shutdown()
        old = supervisor._actor
        supervisor.activate_next_boot(activation(2, 'boot-2', predecessor))
        self.assertEqual(supervisor.current_boot_ordinal, 2)
        self.assertTrue(supervisor.session.execution_live)
        self.assertIsNot(supervisor._actor, old)
        self.assertEqual(custodian.underlying_create_count_for_all(), 3)

    def test_fresh_v2_admission_is_witnessed_and_constructor_is_nonexecuting(self):
        from acer_adapter_fakes import MutableArtifacts, offline_chair_service, offline_activation_service, u04_authorization
        from tools.decision_0009.acer_adapter.custody import OfflineCustodian
        from tools.decision_0009.acer_adapter.supervisor import (
            ArtifactVerificationPrimitive, OfflineDurableStore, OfflineWitness)
        artifacts = MutableArtifacts()
        auth = u04_authorization(artifacts)
        store = OfflineDurableStore('store-1', OfflineWitness('witness-1'),
                                    chair_verifier=offline_chair_service(auth),
                                    activation_verifier=offline_activation_service(auth))
        supervisor = PersistentSupervisor(store, ArtifactVerificationPrimitive(
            'offline-root', auth, artifacts.read), OfflineCustodian('custodian-1'),
            auth, session())
        self.assertFalse(supervisor.session.execution_live)
        supervisor.admit_campaign(replace(activation(), authorization_digest=auth.authorization_digest))
        self.assertTrue(supervisor.session.execution_live)
        self.assertEqual(store._current_actor.mode, 'LIVE')
        self.assertTrue(all('envelope' in frame for frame in store._durable))
        self.assertEqual(store.witness.high_revision, store.revision)

    def test_poisoned_legacy_acceptance_and_session_views_cannot_create(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        supervisor.spawn_worker('slot-1-1', digest('launch'), fault=None)
        supervisor.store.crash()
        supervisor.store._supervisor_ready = True
        supervisor.store._execution_revoked = False
        supervisor.store.containment_only = False
        supervisor.store._sessions[supervisor.session.session_id] = supervisor.session
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.effect_intent(supervisor.store.effect_capability('spawn-intent-slot-1-1'))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)



class SupervisorTests(unittest.TestCase):
    def make_supervisor(self):
        return make_supervisor()

    def test_spawn_intent_is_witnessed_before_create_and_in_progress_follows(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        states = [event["state"] for event in supervisor.store.events if "state" in event]
        self.assertLess(states.index("SPAWN_INTENT_PERSISTED"),
                        custodian.first_create_observed_store_revision)
        self.assertEqual(states[-1], "WORKER_CREATION_IN_PROGRESS")
        self.assertEqual(receipt.status, "BLOCKED")

    def test_crash_after_intent_and_ambiguous_dispatch_never_retry_create(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    fault="crash_after_intent")
        recovered = supervisor.recover_spawn("slot-1-1")
        self.assertEqual(recovered.status, "UNKNOWN")
        self.assertTrue(recovered.possibly_live)
        self.assertEqual(custodian.underlying_create_count(recovered.spawn_token), 0)
        token = supervisor._slot_tokens["slot-1-1"]
        saved = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        with self.assertRaises(CustodyError):
            custodian.create_once(token, token.launch_spec_digest, saved,
                                  saved.artifact_binding)
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertIn("CONTAINMENT_ONLY_RECOVERY", supervisor.safety_markers)
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-1-1", digest("launch"))

        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    fault="crash_after_create")
        recovered = supervisor.recover_spawn("slot-1-1")
        self.assertTrue(recovered.possibly_live)
        self.assertEqual(custodian.underlying_create_count(recovered.spawn_token), 1)
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-1-1", digest("launch"))

    def test_known_result_replay_and_old_generation_historical_lookup_are_read_only(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        first = supervisor.spawn_worker("slot-1-1", digest("launch"))
        token = supervisor._slot_tokens["slot-1-1"]
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        replay = custodian.create_once(token, token.launch_spec_digest, capability,
                                       capability.artifact_binding)
        self.assertIs(replay, first)
        self.assertEqual(custodian.underlying_create_count(token.token_id), 1)
        self.assertEqual(supervisor.store.effect_acceptance_count(capability.effect_id), 1)
        before_revision = supervisor.store.revision
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        # Construction records a non-executing ENTRY and may mirror proven loss.
        before_revision = supervisor.store.revision
        with self.assertRaises(CustodyError):
            custodian.create_once(token, token.launch_spec_digest, capability,
                                  capability.artifact_binding)
        historical = restarted.lookup_historical_spawn_receipt("slot-1-1")
        self.assertEqual(historical.receipt, first)
        self.assertEqual(historical.supervisor_generation,
                         capability.supervisor_generation)
        self.assertEqual(custodian.underlying_create_count(token.token_id), 1)
        self.assertEqual(supervisor.store.revision, before_revision)

    def test_acceptance_without_result_persistence_is_unresolved_and_never_retried(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    fault="crash_after_acceptance")
        token = supervisor._slot_tokens["slot-1-1"]
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        with self.assertRaises(CustodyError):
            custodian.create_once(token, token.launch_spec_digest, capability,
                                  capability.artifact_binding)
        self.assertEqual(custodian.underlying_create_count(token.token_id), 0)
        self.assertTrue(supervisor.recover_spawn("slot-1-1").possibly_live)

    def test_boot_custody_adds_no_baseline_and_core_baseline_remains_sixty_seconds(self):
        supervisor, _, _ = self.make_supervisor()
        custody = next(event for event in supervisor.store.events
                       if event.get("state") == "BOOT_CUSTODY_COMPLETE")
        self.assertEqual(custody["extra_pre_spawn_baseline_ns"], 0)
        self.assertEqual(core_policy.BASELINE_NS, 60 * core_policy.SECOND_NS)

    def test_boot_completion_requires_finalized_candidate_and_verified_publication(self):
        supervisor, _, _ = self.make_supervisor()
        from tools.decision_0009.acer_adapter.evidence import (
            EvidenceError, ImmutablePublication, build_closure_candidate,
        )
        unfinalized = build_closure_candidate("boot", {"boot_id": "boot-1", "objects": ["a"]})
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "candidate", unfinalized.bytes)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, unfinalized.bytes)
        receipt = publisher.verify(intent)
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(unfinalized, receipt)
        record_all_local_attempts(supervisor)
        candidate = supervisor.finalize_boot_closure_candidate(
            {"boot_id": "boot-1", "objects": ["different"]})
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(candidate, receipt)

    def test_boots_two_through_four_require_fresh_exact_activations(self):
        supervisor, _, _ = self.make_supervisor()
        used = set()
        prior_fence = supervisor.session.fence_epoch
        for next_boot in (2, 3, 4):
            closure = complete_boot(supervisor)
            supervisor.begin_boot_handoff(next_boot)
            supervisor.commit_planned_shutdown()
            activation_record = activation(
                next_boot, "boot-%d" % next_boot, closure,
                activation_id="fresh-activation-%d" % next_boot)
            self.assertNotIn(activation_record.activation_id, used)
            supervisor.activate_next_boot(activation_record)
            self.assertGreater(supervisor.session.fence_epoch, prior_fence)
            prior_fence = supervisor.session.fence_epoch
            used.add(activation_record.activation_id)
            supervisor.establish_boot_custody(
                "custody-proof-%d" % next_boot, True, True)
            supervisor.complete_boot_custody()
        self.assertEqual(supervisor.current_boot_ordinal, 4)

    def test_campaign_candidate_publication_precedes_campaign_completion(self):
        import json
        from tools.decision_0009.acer_adapter.evidence import (
            ImmutablePublication, canonical_core_bytes,
        )
        supervisor, _, _ = self.make_supervisor()
        boot_digests = []
        for boot in (1, 2, 3, 4):
            boot_digests.append(complete_boot(supervisor))
            if boot < 4:
                supervisor.begin_boot_handoff(boot + 1)
                supervisor.commit_planned_shutdown()
                supervisor.activate_next_boot(activation(
                    boot + 1, "boot-%d" % (boot + 1), boot_digests[-1],
                    activation_id="campaign-activation-%d" % (boot + 1)))
                supervisor.establish_boot_custody("custody-%d" % (boot + 1), True, True)
                supervisor.complete_boot_custody()
        candidate = supervisor.finalize_campaign_closure_candidate(
            {"campaign_id": "campaign-1", "objects": boot_digests})
        self.assertNotIn(b"CAMPAIGN_COMPLETE", candidate.bytes)
        publisher = ImmutablePublication(supervisor)
        receipts = []
        values = [candidate.bytes]
        values.extend(canonical_core_bytes(value)
                      for value in json.loads(candidate.bytes)["payload"]["objects"])
        for index, value in enumerate(values):
            intent = publisher.intent("dest", "campaign-object-%d" % index, value)
            publisher.exclusive_create(intent)
            publisher.write_durable(intent, value)
            receipts.append(publisher.verify(intent))
        supervisor.complete_campaign(candidate, tuple(receipts))
        self.assertEqual(supervisor.campaign_state, "CAMPAIGN_COMPLETE")

    def test_substitution_between_verification_and_dispatch_denies_effect(self):
        supervisor, artifacts, _ = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    interlock=lambda: artifacts.substitute("adapter"))
        self.assertEqual(supervisor.custodian.underlying_create_count_for_all(), 0)
        self.assertTrue(supervisor.store.taint)

    def test_changed_bytes_before_first_worker_of_later_boot_denies_create(self):
        supervisor, artifacts, _ = self.make_supervisor()
        closure = complete_boot(supervisor)
        prior_creates = supervisor.custodian.underlying_create_count_for_all()
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        supervisor.activate_next_boot(activation(2, "boot-2", closure))
        supervisor.establish_boot_custody("custody-proof-2", True, True)
        supervisor.complete_boot_custody()
        supervisor.make_slot_eligible("slot-2-1")
        artifacts.substitute("core")
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-2-1", digest("launch-2"))
        self.assertEqual(supervisor.custodian.underlying_create_count_for_all(), prior_creates)

    def test_authorization_replay_wrong_activation_and_stale_fence_fail(self):
        supervisor, _, _ = self.make_supervisor()
        with self.assertRaises(ContractError):
            supervisor.admit_campaign(activation())
        closure = complete_boot(supervisor)
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        with self.assertRaises(AuthorizationDenied):
            supervisor.activate_next_boot(activation(3, "boot-2", closure))
        supervisor.store.acquire_fence("new-owner")
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-1")

    def test_every_local_successor_prerequisite_is_individually_required_but_publication_is_not(self):
        for key in ("core_bytes", "raw_evidence", "reap", "residual",
                    "immutable_storage", "readback", "valid_completion",
                    "witnessed", "durable", "no_unresolved_worker"):
            supervisor, _, _ = self.make_supervisor()
            with self.subTest(missing=key), self.assertRaises(AuthorizationDenied):
                supervisor.record_local_attempt_evidence(
                    "slot-1-1", local_attempt_evidence(missing=key))
        supervisor, _, _ = self.make_supervisor()
        record_all_local_attempts(supervisor)
        supervisor.session = replace(supervisor.session, execution_live=False)
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-2")
        supervisor, _, _ = self.make_supervisor()
        record_all_local_attempts(supervisor)
        supervisor.record_failure("late-contradiction", b"observed contradiction")
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-2")
        supervisor, _, _ = self.make_supervisor()
        record_all_local_attempts(supervisor)
        self.assertEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

    def test_custodian_death_at_lifecycle_points_is_sticky_uncertainty(self):
        for point in ("before_identity", "after_release", "before_wait", "after_exit"):
            supervisor, _, _ = self.make_supervisor()
            supervisor.record_custodian_loss(point)
            self.assertIn("CUSTODY_UNCERTAIN", supervisor.safety_markers)
            self.assertIn("TAINTED", supervisor.safety_markers)
            with self.assertRaises(AuthorizationDenied):
                supervisor.make_slot_eligible("slot-1-2")
            self.assertFalse(supervisor.synthetic_reap)
            self.assertFalse(supervisor.synthetic_residual_clearance)

    def test_non_authorizing_failure_write_survives_verifier_failure(self):
        supervisor, artifacts, _ = self.make_supervisor()
        artifacts.substitute("policy")
        supervisor.record_failure("verification-failed", b"bounded raw failure")
        self.assertIn("verification-failed", supervisor.store.taint)
        self.assertFalse(supervisor.store.last_event_authorizes_execution)

    def test_fence_change_after_cas_prevents_effect_acceptance(self):
        supervisor, _, _ = self.make_supervisor()
        dispatch = RecordingDispatch()
        specification = {"effect_id": "race-effect", "target": "offline-store",
                         "operation": "append-transition", "event_id": "race-event",
                         "event": {}}
        with self.assertRaises(AuthorizationDenied):
            authorize_and_dispatch(
                supervisor.store, supervisor.verifier, supervisor.store.revision,
                supervisor.session.fence_epoch, supervisor.session,
                "SLOT_SPAWN_ELIGIBLE", specification, dispatch,
                interlock=lambda: supervisor.store.acquire_fence("racer"),
            )
        self.assertEqual(dispatch.calls, [])

    def test_direct_dispatch_under_taint_and_unregistered_session_fail(self):
        for mutation in ("taint", "session"):
            supervisor, _, _ = self.make_supervisor()
            candidate_session = supervisor.session
            if mutation == "taint":
                supervisor.record_failure("direct-dispatch-prohibited", b"explicit failure")
            else:
                candidate_session = session(supervisor.session.fence_epoch)
                candidate_session = replace(candidate_session, session_id="unregistered-session")
            dispatch = RecordingDispatch()
            specification = {"effect_id": "direct-" + mutation,
                             "target": "offline-store", "operation": "append-transition",
                             "event_id": "direct-event-" + mutation, "event": {}}
            with self.subTest(mutation=mutation), self.assertRaises(AuthorizationDenied):
                authorize_and_dispatch(
                    supervisor.store, supervisor.verifier, supervisor.store.revision,
                    candidate_session.fence_epoch, candidate_session,
                    "SLOT_SPAWN_ELIGIBLE", specification, dispatch)
            self.assertEqual(dispatch.calls, [])

    def test_removed_states_never_cross_effect_boundary(self):
        for removed in REMOVED_STATES:
            supervisor, _, _ = self.make_supervisor()
            specification = {"effect_id": "removed-" + removed.lower(),
                             "target": "offline-store", "operation": "append-transition",
                             "event_id": "removed-event-" + removed.lower(), "event": {}}
            with self.subTest(removed=removed), self.assertRaises(ContractError):
                authorize_and_dispatch(
                    supervisor.store, supervisor.verifier, supervisor.store.revision,
                    supervisor.session.fence_epoch, supervisor.session,
                    removed, specification, RecordingDispatch())
            self.assertNotIn(removed, [event.get("state") for event in supervisor.store.events])

    def test_effect_boundary_rejects_valid_state_with_wrong_predecessor(self):
        supervisor, _, _ = self.make_supervisor()
        specification = {"effect_id": "skipped-transition", "target": "offline-store",
                         "operation": "append-transition", "event_id": "skipped-event",
                         "event": {}}
        with self.assertRaises(AuthorizationDenied):
            authorize_and_dispatch(
                supervisor.store, supervisor.verifier, supervisor.store.revision,
                supervisor.session.fence_epoch, supervisor.session,
                "ATTEMPT_COMPLETE", specification, RecordingDispatch())

    def test_successor_rejects_caller_claim_while_worker_is_live_and_unreaped(self):
        supervisor, _, _ = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        with self.assertRaises(AuthorizationDenied):
            supervisor.record_local_attempt_evidence("slot-1-1", local_attempt_evidence())
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-2")

    def test_restart_reconstructs_unresolved_spawn_as_possibly_live(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"), fault="crash_after_intent")
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertEqual(restarted.attempt_state, "SPAWN_INTENT_PERSISTED")
        self.assertTrue(restarted.recover_spawn("slot-1-1").possibly_live)

    def test_restart_reconstructs_completion_consumption_and_custody_taint(self):
        supervisor, _, custodian = self.make_supervisor()
        closure = complete_boot(supervisor)
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertEqual(restarted.boot_state, "BOOT_COMPLETE")
        self.assertEqual(restarted._completed_boots, {1})
        self.assertEqual(restarted.predecessor_closure_digest, closure)
        self.assertTrue(restarted.store.is_consumed("slot", "slot-1-1"))
        self.assertIn("boot", restarted._finalized_candidates)
        custodian.die()
        after_loss = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertIn("CUSTODY_UNCERTAIN", after_loss.safety_markers)
        self.assertIn("TAINTED", after_loss.safety_markers)

    def test_closure_rejects_candidate_substitution_and_missing_manifest_receipts(self):
        from tools.decision_0009.acer_adapter.evidence import ImmutablePublication
        supervisor, _, _ = self.make_supervisor()
        record_all_local_attempts(supervisor)
        candidate = supervisor.finalize_boot_closure_candidate(
            {"boot_id": "boot-1", "objects": ["attempts", "custody"]})
        substitute = candidate.__class__(
            "boot", digest("substitute"), b'{"candidate":"substitute"}\n',
            candidate.object_digests)
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "substitute", substitute.bytes)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, substitute.bytes)
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(substitute, publisher.verify(intent))
        intent = publisher.intent("dest", "candidate", candidate.bytes)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, candidate.bytes)
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(candidate, publisher.verify(intent))

    def test_repeated_boot_id_is_rejected(self):
        supervisor, _, _ = self.make_supervisor()
        closure = complete_boot(supervisor)
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        with self.assertRaises(AuthorizationDenied):
            supervisor.activate_next_boot(activation(2, "boot-1", closure,
                                                      activation_id="fresh-id"))

    def test_artifact_labels_cannot_authorize_wrong_content(self):
        supervisor, artifacts, _ = self.make_supervisor()
        artifacts.values["core"]["files"]["core/policy.py"] = b"wrong core bytes\n"
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-1")
        supervisor, artifacts, _ = self.make_supervisor()
        artifacts.values["core"]["commit"] = "724700217f8d7183757768fb2a856872b64a3cf3"
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-1")

    def test_restart_retains_unresolved_release_intent(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        for state in ("WORKER_IDENTITY_ESTABLISHED",
                      "WORKER_IDENTITY_DURABLY_RECORDED",
                      "RELEASE_ELIGIBLE", "RELEASE_INTENT"):
            supervisor._transition("attempt", state,
                                   "partial-%s" % state.lower(),
                                   {"slot_id": "slot-1-1"})
            supervisor.attempt_state = state
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertEqual(restarted.attempt_state, "RELEASE_INTENT")
        self.assertTrue(restarted.store.is_consumed("slot", "slot-1-1"))
        with self.assertRaises(AuthorizationDenied):
            restarted.make_slot_eligible("slot-1-2")

    def test_malformed_input_revokes_before_witness_failure_reporting(self):
        from tools.decision_0009.acer_adapter.evidence import EvidencePipeline
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        pipeline = EvidencePipeline()
        reference = pipeline.capture("transport", b"\xff", 1, 1)
        supervisor.store.witness.available = False
        with self.assertRaises(Exception):
            supervisor.run_contained(lambda: pipeline.decode(reference), b"\xff")
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertIn("TAINTED", supervisor.safety_markers)
        self.assertIn("malformed-input", supervisor.store.taint)
        self.assertEqual(custodian.inspect_spawn(receipt.spawn_token).status, "EXITED")
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-2")

    def test_pending_publication_does_not_gate_same_boot_successor(self):
        from tools.decision_0009.acer_adapter.evidence import ImmutablePublication
        supervisor, _, _ = self.make_supervisor()
        publisher = ImmutablePublication(supervisor)
        publisher.intent("dest", "pending", b"pending")
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        supervisor.complete_worker_lifecycle("slot-1-1")
        slot = supervisor.authorization.slots[0]
        supervisor.persist_local_attempt_evidence(
            "slot-1-1", core_attempt_bytes(slot), residual_observations())
        supervisor.make_slot_eligible("slot-1-2")
        self.assertEqual(supervisor.attempt_state, "SLOT_SPAWN_ELIGIBLE")

    def test_campaign_id_substitution_cannot_redeem_spawn_capability(self):
        supervisor, _, custodian = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    fault="crash_after_intent")
        token = supervisor._slot_tokens["slot-1-1"]
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        forged = replace(token, campaign_id="campaign-substitute")
        with self.assertRaises(CustodyError):
            custodian.create_once(forged, forged.launch_spec_digest, capability,
                                  capability.artifact_binding)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_witness_outage_or_quarantine_blocks_create_before_effect(self):
        for failure in ("outage", "quarantine"):
            supervisor, _, custodian = self.make_supervisor()
            supervisor.make_slot_eligible("slot-1-1")
            with self.assertRaises(DispatchUncertain):
                supervisor.spawn_worker("slot-1-1", digest("launch"),
                                        fault="crash_after_intent")
            token = supervisor._slot_tokens["slot-1-1"]
            capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
            if failure == "outage":
                supervisor.store.witness.available = False
            else:
                supervisor.store.witness.quarantined = True
            with self.subTest(failure=failure), self.assertRaises(CustodyError):
                custodian.create_once(token, token.launch_spec_digest, capability,
                                      capability.artifact_binding)
            self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_boot_activation_operation_cannot_bypass_transition_preconditions(self):
        supervisor, _, _ = self.make_supervisor()
        specification = {
            "effect_id": "forged-activation-operation", "target": "offline-store",
            "operation": "consume-boot-activation", "event_id": "forged-activation-event",
            "event": {"record_type": "BOOT_ACTIVATION", "activation_id": "forged",
                      "activated_boot_ordinal": 2, "observed_boot_id": "boot-2",
                      "predecessor_closure_digest": digest("not-complete")},
        }
        with self.assertRaises(AuthorizationDenied):
            authorize_and_dispatch(
                supervisor.store, supervisor.verifier, supervisor.store.revision,
                supervisor.session.fence_epoch, supervisor.session,
                "ATTEMPT_COMPLETE", specification, RecordingDispatch())

    def test_invalid_core_attempt_or_failed_residual_cannot_complete(self):
        supervisor, _, _ = self.make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        supervisor.complete_worker_lifecycle("slot-1-1")
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence(
                "slot-1-1", b'{"attempt_id":"attempt-1-1"}',
                residual_observations())
        self.assertNotEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

    def test_reconstruction_rejects_forged_completion_claims_and_empty_residual_manifest(self):
        supervisor, _, custodian = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        reap = supervisor.complete_worker_lifecycle(slot.slot_id)
        unrelated_digest = supervisor.store.put_object("unrelated-json", b"{}", actor=supervisor._actor)
        forged = {
            "state": "ATTEMPT_COMPLETE", "state_domain": "attempt",
            "slot_id": slot.slot_id, "attempt_id": "attempt-unrelated",
            "spawn_token": "spawn-" + slot.slot_id,
            "raw_object_id": "unrelated-json", "raw_digest": unrelated_digest,
            "raw_readback_digest": unrelated_digest,
            "normalized_object_id": "unrelated-json",
            "normalized_digest": unrelated_digest,
            "normalized_readback_digest": unrelated_digest,
            "core_object_id": "unrelated-json", "core_digest": unrelated_digest,
            "core_readback_digest": unrelated_digest,
            "reap_receipt_id": reap.receipt_id,
            "reap_receipt_digest": digest("claimed-reap"),
            "residual_object_ids": [], "residual_sample_digests": [],
            "residual_sample_count": 3, "residual_clear": True,
            "core_validated": True, "disposition": "valid",
            "completion_digest": digest("forged-completion"),
            "boot_ordinal": 1, "campaign_id": "campaign-1",
        }
        _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
                              "historical-forged-completion", forged)
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertNotIn(slot.slot_id, restarted._completed_attempts)
        self.assertTrue(restarted.store.execution_revoked)
        with self.assertRaises(AuthorizationDenied):
            restarted.make_slot_eligible("slot-1-2")

    def test_completion_validator_binds_identity_and_every_retained_object(self):
        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        supervisor.persist_local_attempt_evidence(
            slot.slot_id, core_attempt_bytes(slot), residual_observations())
        record = supervisor._completed_attempts[slot.slot_id]
        object_ids = [record["raw_object_id"], record["normalized_object_id"],
                      record["core_object_id"], *record["residual_object_ids"]]
        for object_id in object_ids:
            original = supervisor.store._objects[object_id]
            for mutation in ("remove", "substitute"):
                if mutation == "remove":
                    supervisor.store._objects.pop(object_id)
                else:
                    supervisor.store._objects[object_id] = b"substituted"
                with self.subTest(object_id=object_id, mutation=mutation):
                    self.assertFalse(supervisor._authoritative_attempt_complete(
                        slot.slot_id, record))
                supervisor.store._objects[object_id] = original
        self.assertTrue(supervisor._authoritative_attempt_complete(slot.slot_id, record))
        self.assertFalse(supervisor._authoritative_attempt_complete("slot-1-2", record))
        for field, value in (("attempt_id", "attempt-unrelated"),
                             ("campaign_id", "campaign-foreign"),
                             ("boot_id", "boot-foreign")):
            forged = dict(record)
            forged[field] = value
            manifest = {key: forged[key] for key in forged
                        if key != "completion_digest"}
            forged["completion_digest"] = _sha(_canonical(manifest))
            with self.subTest(field=field), self.assertRaises(AuthorizationDenied):
                supervisor._validate_attempt_completion_record(
                    slot.slot_id, forged, require_completion_event=False)

        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence(
                slot.slot_id, core_attempt_bytes(slot),
                residual_observations(allocated_bytes=1))
        self.assertNotEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence(
                slot.slot_id, core_attempt_bytes(slot),
                residual_observations(attempt_id="attempt-unrelated"))
        self.assertNotEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence(
                slot.slot_id, core_attempt_bytes(slot),
                residual_observations(observed_times=(1, 2, 3)))
        self.assertNotEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

    def test_large_valid_core_attempt_crosses_authoritative_ingestion(self):
        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        raw = core_attempt_bytes(slot)
        self.assertGreater(len(raw), 1_048_576)
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        completion = supervisor.persist_local_attempt_evidence(
            slot.slot_id, raw, residual_observations())
        self.assertEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")
        self.assertEqual(supervisor._completed_attempts[slot.slot_id]["completion_digest"],
                         completion)

    def test_accepted_core_exact_eight_mib_boundary_and_one_byte_over_fail_closed(self):
        limit = 8_388_608
        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        base = core_attempt_bytes(slot).rstrip()
        exact = base + (b" " * (limit - len(base) - 1)) + b"\n"
        self.assertEqual(len(exact), limit)
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch-exact-limit"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        supervisor.persist_local_attempt_evidence(
            slot.slot_id, exact, residual_observations())
        self.assertEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

        supervisor, _, _ = self.make_supervisor()
        slot = supervisor.authorization.slots[0]
        supervisor.make_slot_eligible(slot.slot_id)
        supervisor.spawn_worker(slot.slot_id, digest("launch-over-limit"))
        supervisor.complete_worker_lifecycle(slot.slot_id)
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence(
                slot.slot_id, exact + b" ", residual_observations())
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertNotEqual(supervisor.attempt_state, "ATTEMPT_COMPLETE")

    def test_boot_two_unresolved_spawn_restart_is_containment_only(self):
        supervisor, _, custodian = self.make_supervisor()
        closure = complete_boot(supervisor)
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        supervisor.activate_next_boot(activation(2, "boot-2", closure))
        supervisor.establish_boot_custody("custody-proof-2", True, True)
        supervisor.complete_boot_custody()
        supervisor.make_slot_eligible("slot-2-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-2-1", digest("launch-2"),
                                    fault="crash_after_intent")
        restarted = PersistentSupervisor(
            supervisor.store, supervisor.verifier, custodian,
            supervisor.authorization, supervisor.session)
        self.assertEqual(restarted.current_boot_ordinal, 2)
        self.assertEqual(restarted.current_boot_id, "boot-2")
        self.assertEqual(restarted.attempt_state, "SPAWN_INTENT_PERSISTED")
        self.assertTrue(restarted.recover_spawn("slot-2-1").possibly_live)
        self.assertIn("CONTAINMENT_ONLY_RECOVERY", restarted.safety_markers)
        with self.assertRaises(AuthorizationDenied):
            restarted.spawn_worker("slot-2-1", digest("launch-2"))

    def test_boot_two_unresolved_creation_does_not_restore_authority_during_receipt_lookup(self):
        supervisor, _, custodian = self.make_supervisor()
        closure = complete_boot(supervisor)
        boot_one_receipt = supervisor.lookup_historical_spawn_receipt("slot-1-1")
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        supervisor.activate_next_boot(activation(2, "boot-2", closure))
        supervisor.establish_boot_custody("custody-proof-2", True, True)
        supervisor.complete_boot_custody()
        supervisor.make_slot_eligible("slot-2-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-2-1", digest("launch-2"),
                                    fault="crash_after_intent")
        before = supervisor.store.revision
        inspected = supervisor.lookup_historical_spawn_receipt("slot-1-1")
        self.assertEqual(inspected, boot_one_receipt)
        self.assertEqual(supervisor.store.revision, before)
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertEqual(custodian.underlying_create_count("spawn-slot-2-1"), 0)


# ---------------------------------------------------------------------------
# Decision 0009 independent-review regressions (Blockers 1-3).
#
# These tests reproduce the review's commit-blocking paths.  They were added
# before the correction and fail on the inherited implementation.
# ---------------------------------------------------------------------------

from tools.decision_0009.acer_adapter.contracts import STATE_DOMAINS, SpawnToken
from tools.decision_0009.acer_adapter.supervisor import StoreError

# The only transitions that remain available through the general
# ``append-transition`` surface.  Everything else is reserved for a dedicated,
# evidence-validating operation.
EXPECTED_GENERIC_TRANSITIONS = frozenset((
    "WORKER_IDENTITY_ESTABLISHED", "WORKER_IDENTITY_DURABLY_RECORDED",
    "RELEASE_ELIGIBLE", "RELEASE_INTENT", "RELEASED_OR_POSSIBLY_RELEASED",
))

LEGAL_PREDECESSOR = {
    "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED": "CAMPAIGN_ADMITTED",
    "CAMPAIGN_COMPLETE": "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
    "CAMPAIGN_CLOSED_FAILED": "CAMPAIGN_ADMITTED",
    "BOOT_CUSTODY_COMPLETE": "BOOT_CUSTODY_ESTABLISHED",
    "BOOT_CLOSURE_CANDIDATE_FINALIZED": "BOOT_CUSTODY_COMPLETE",
    "BOOT_COMPLETE": "BOOT_CLOSURE_CANDIDATE_FINALIZED",
    "BOOT_HANDOFF_PENDING": "BOOT_COMPLETE",
    "SPAWN_INTENT_PERSISTED": "SLOT_SPAWN_ELIGIBLE",
    "WORKER_CREATION_IN_PROGRESS": "SPAWN_INTENT_PERSISTED",
    "WORKER_IDENTITY_ESTABLISHED": "WORKER_CREATION_IN_PROGRESS",
    "WORKER_IDENTITY_DURABLY_RECORDED": "WORKER_IDENTITY_ESTABLISHED",
    "RELEASE_ELIGIBLE": "WORKER_IDENTITY_DURABLY_RECORDED",
    "RELEASE_INTENT": "RELEASE_ELIGIBLE",
    "RELEASED_OR_POSSIBLY_RELEASED": "RELEASE_INTENT",
    "CUDA_CALL_GATE_PASSED": "RELEASED_OR_POSSIBLY_RELEASED",
    "CLEANUP_REQUESTED": "CUDA_CALL_GATE_PASSED",
    "EXIT_OBSERVED": "CLEANUP_REQUESTED",
    "REAPING_PROVEN": "EXIT_OBSERVED",
    "RESIDUAL_CLEARANCE_PROVEN": "REAPING_PROVEN",
    "ATTEMPT_COMPLETE": "RESIDUAL_CLEARANCE_PROVEN",
    "NORMALIZATION_BOUND": "RAW_CAPTURED",
    "IMMUTABLE_BYTES_STORED": "NORMALIZATION_BOUND",
    "READBACK_VERIFIED": "IMMUTABLE_BYTES_STORED",
    "ATTEMPT_EVIDENCE_FINALIZED": "READBACK_VERIFIED",
}


def _domain(state):
    return next(domain for domain, states in STATE_DOMAINS.items() if state in states)


def _append_unprovenanced(store, fence_epoch, event_id, event):
    """Low-level fixture seam: retain a deliberately unprovenanced,
    nonauthorizing record through the store's control plumbing.  Such a
    record never carries window or publication operation provenance."""
    record = dict(event)
    record["authorizes_execution"] = False
    return inject_untrusted_record(store, fence_epoch, event_id, record)


def _generic(supervisor, state, suffix, event=None, dispatcher=None, sess=None):
    sess = sess or supervisor.session
    return authorize_and_dispatch(
        supervisor.store, supervisor.verifier, supervisor.store.revision,
        sess.fence_epoch, sess, state,
        {"effect_id": suffix, "target": "offline-store",
         "operation": "append-transition", "event_id": "event-" + suffix,
         "event": dict(event or {})},
        dispatcher or RecordingDispatch())


def _plant(supervisor, state, suffix, extra=None, operation="append-transition",
           boot_ordinal=None):
    """Write a historical record shaped like dispatcher output, bypassing the
    authorization boundary (the review's store-level forgery model)."""
    sess = supervisor.session
    event = dict(extra or {})
    event.update({
        "state": state, "effect_id": suffix, "state_domain": _domain(state),
        "session_id": sess.session_id, "session_owner": sess.owner_identity,
        "session_live": True, "fence_epoch": sess.fence_epoch,
        "boot_ordinal": boot_ordinal or sess.boot_ordinal,
        "session_boot_ordinal": sess.boot_ordinal,
        "supervisor_generation": supervisor.store._supervisor_generation,
        "authorization_digest": supervisor.authorization.authorization_digest,
        "campaign_id": supervisor.authorization.campaign_id,
        "target": "offline-store", "operation": operation,
        "verification_id": "verification-forged", "authorizes_execution": True,
        "dispatch_resolved": False,
        "consumption": {"kind": "effect", "identity": suffix},
    })
    return inject_untrusted_record(supervisor.store, sess.fence_epoch, 'event-' + suffix, event)


def _restart(supervisor):
    return PersistentSupervisor(
        supervisor.store, supervisor.verifier, supervisor.custodian,
        supervisor.authorization, supervisor.session)


def _direct_create(supervisor, slot_id, *, boot_id=None, generation=None, suffix=None):
    """Invoke the general dispatcher's blocked-create path directly."""
    slot = next(item for item in supervisor.authorization.slots if item.slot_id == slot_id)
    generation = generation or supervisor.store._supervisor_generation
    token = SpawnToken("spawn-" + slot_id, supervisor.authorization.campaign_id,
                       boot_id or supervisor.current_boot_id, slot_id, slot.attempt_id,
                       digest("launch-" + slot_id), supervisor.custodian.identity,
                       generation)
    event = {"spawn_token": token.token_id,
             "launch_spec_digest": token.launch_spec_digest,
             "slot_id": slot_id, "attempt_id": slot.attempt_id,
             "boot_id": token.boot_id, "campaign_id": token.campaign_id,
             "custodian_id": token.custodian_id,
             "supervisor_generation": generation}
    suffix = suffix or "forged-create-" + slot_id

    def dispatch(capability, binding):
        return supervisor.custodian.create_once(
            token, token.launch_spec_digest, capability, binding)

    return authorize_and_dispatch(
        supervisor.store, supervisor.verifier, supervisor.store.revision,
        supervisor.session.fence_epoch, supervisor.session,
        "SPAWN_INTENT_PERSISTED",
        {"effect_id": suffix, "target": supervisor.custodian.identity,
         "operation": "blocked-create", "event_id": "event-" + suffix,
         "event": event}, dispatch)


def _candidate_fields(kind="boot"):
    from tools.decision_0009.acer_adapter.evidence import build_closure_candidate
    payload = ({"boot_id": "boot-1", "objects": ["forged"]} if kind == "boot"
               else {"campaign_id": "campaign-1", "objects": ["forged"]})
    candidate = build_closure_candidate(kind, payload)
    return candidate, {"candidate_digest": candidate.digest,
                       "candidate_kind": candidate.kind,
                       "candidate_bytes": candidate.bytes.hex(),
                       "object_digests": list(candidate.object_digests)}


class ReviewBlockerRegressionTests(unittest.TestCase):
    # ---- Blocker 1: generic transition surface and reserved completion ----

    def test_generic_dispatcher_cannot_forge_boot_closure_candidate_or_completion(self):
        supervisor, _, custodian = make_supervisor()
        candidate, fields = _candidate_fields("boot")
        rejected = []
        for state, suffix, event in (
                ("BOOT_CLOSURE_CANDIDATE_FINALIZED", "forged-boot-candidate", fields),
                ("BOOT_COMPLETE", "forged-boot-complete",
                 {"candidate_digest": candidate.digest})):
            try:
                _generic(supervisor, state, suffix, event)
            except AuthorizationDenied:
                rejected.append(state)
        self.assertEqual(rejected, ["BOOT_CLOSURE_CANDIDATE_FINALIZED", "BOOT_COMPLETE"])
        states = [event.get("state") for event in supervisor.store.events]
        self.assertNotIn("BOOT_CLOSURE_CANDIDATE_FINALIZED", states)
        self.assertNotIn("BOOT_COMPLETE", states)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_forged_boot_closure_history_is_not_reconstructed_and_boot_two_cannot_activate(self):
        for operation in ("append-transition", "complete-boot"):
            supervisor, _, _ = make_supervisor()
            candidate, fields = _candidate_fields("boot")
            _plant(supervisor, "BOOT_CLOSURE_CANDIDATE_FINALIZED",
                   "forged-boot-candidate", fields,
                   operation=("append-transition" if operation == "append-transition"
                              else "finalize-boot-closure-candidate"))
            receipt = _plant(supervisor, "BOOT_COMPLETE", "forged-boot-complete",
                             {"candidate_digest": candidate.digest,
                              "candidate_kind": "boot",
                              "publication_manifest": [candidate.digest]},
                             operation=operation)
            restarted = _restart(supervisor)
            with self.subTest(operation=operation):
                self.assertNotEqual(restarted.boot_state, "BOOT_COMPLETE")
                self.assertNotIn(1, restarted._completed_boots)
                self.assertIsNone(restarted.predecessor_closure_digest)
                self.assertTrue(restarted.store.execution_revoked)
                self.assertTrue(restarted.store.publication_prohibited)
                with self.assertRaises(AuthorizationDenied):
                    restarted.begin_boot_handoff(2)
                    restarted.commit_planned_shutdown()
                with self.assertRaises(Quarantined):
                    restarted.activate_next_boot(activation(
                        2, "boot-2", receipt.event_digest,
                        activation_id="forged-activation-2"))
                self.assertEqual(restarted.store.health, "QUARANTINED")
                self.assertFalse(restarted.session.execution_live)
                self.assertNotIn("forged-activation-2", restarted.activation_ids)

    def test_generic_dispatcher_cannot_forge_campaign_closure_or_completion(self):
        supervisor, _, _ = make_supervisor()
        candidate, fields = _candidate_fields("campaign")
        rejected = []
        for state, suffix, event in (
                ("CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED", "forged-campaign-candidate", fields),
                ("CAMPAIGN_COMPLETE", "forged-campaign-complete",
                 {"candidate_digest": candidate.digest})):
            try:
                _generic(supervisor, state, suffix, event)
            except AuthorizationDenied:
                rejected.append(state)
        self.assertEqual(rejected, ["CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
                                    "CAMPAIGN_COMPLETE"])
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.campaign_state, "CAMPAIGN_COMPLETE")

    def test_forged_campaign_completion_history_is_not_reconstructed(self):
        for operation in ("append-transition", "complete-campaign"):
            supervisor, _, _ = make_supervisor()
            candidate, fields = _candidate_fields("campaign")
            _plant(supervisor, "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
                   "forged-campaign-candidate", fields,
                   operation=("append-transition" if operation == "append-transition"
                              else "finalize-campaign-closure-candidate"))
            _plant(supervisor, "CAMPAIGN_COMPLETE", "forged-campaign-complete",
                   {"candidate_digest": candidate.digest, "candidate_kind": "campaign",
                    "publication_manifest": [candidate.digest]},
                   operation=operation)
            restarted = _restart(supervisor)
            with self.subTest(operation=operation):
                self.assertNotEqual(restarted.campaign_state, "CAMPAIGN_COMPLETE")
                self.assertNotIn("campaign", restarted._finalized_candidates)
                self.assertTrue(restarted.store.execution_revoked)
                self.assertTrue(restarted.store.publication_prohibited)

    def test_generic_dispatcher_rejects_every_reserved_transition_from_legal_predecessor(self):
        accepted = []
        for domain, states in sorted(STATE_DOMAINS.items()):
            if domain == "safety":
                continue
            for state in sorted(states):
                if state in EXPECTED_GENERIC_TRANSITIONS:
                    continue
                supervisor, _, custodian = make_supervisor()
                predecessor = LEGAL_PREDECESSOR.get(state)
                if predecessor is not None:
                    _plant(supervisor, predecessor, "legal-predecessor-" + state.lower())
                before = supervisor.store.revision
                try:
                    _generic(supervisor, state, "generic-" + state.lower(),
                             {"slot_id": "slot-1-1"})
                except (AuthorizationDenied, ContractError):
                    pass
                else:
                    accepted.append(state)
                with self.subTest(state=state):
                    self.assertEqual(supervisor.store.revision, before)
                    self.assertEqual(custodian.underlying_create_count_for_all(), 0)
        self.assertEqual(accepted, [])

    def test_generic_allowlist_admits_only_closed_custody_observation_payloads(self):
        supervisor, _, _ = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        token = supervisor._slot_tokens["slot-1-1"]
        _generic(supervisor, "WORKER_IDENTITY_ESTABLISHED", "observed-identity",
                 {"slot_id": "slot-1-1", "spawn_token": token.token_id,
                  "host_pid": 10001, "start_ticks": 50001})
        stored = next(event for event in supervisor.store.events
                      if event.get('effect_id') == 'observed-identity' and
                      event.get('state') == 'WORKER_IDENTITY_ESTABLISHED')
        self.assertEqual(stored["state"], "WORKER_IDENTITY_ESTABLISHED")
        self.assertEqual(stored["operation"], "append-transition")
        self.assertNotIn("record_type", stored)
        restarted = _restart(supervisor)
        self.assertIn("CUSTODY_UNCERTAIN", restarted.safety_markers)
        self.assertTrue(restarted.store.execution_revoked)

    # ---- Blocker 2: payload smuggling of reserved control metadata ----

    def test_general_transition_cannot_smuggle_reserved_control_metadata(self):
        smuggled = {
            "measurement-window": {"record_type": "MEASUREMENT_WINDOW",
                                   "window": "OUTSIDE_MEASURED_WINDOWS",
                                   "window_epoch": 9},
            "boot-activation": {"record_type": "BOOT_ACTIVATION",
                                "activation_id": "smuggled-activation",
                                "activated_boot_ordinal": 2,
                                "observed_boot_id": "boot-2",
                                "predecessor_closure_digest": digest("none")},
            "effect-result": {"record_type": "EFFECT_RESULT", "result": "accepted",
                              "receipt_id": "create-spawn-slot-1-1"},
            "completion": {"completion_digest": digest("forged-completion"),
                           "candidate_digest": digest("forged-candidate"),
                           "publication_manifest": [digest("forged")]},
            "selector": {"operation": "complete-boot"},
            "authority-flag": {"authorizes_execution": False, "dispatch_resolved": True},
            "unknown": {"unexpected_field": "value"},
        }
        for label, extra in smuggled.items():
            supervisor, _, _ = make_supervisor()
            supervisor.make_slot_eligible("slot-1-1")
            supervisor.spawn_worker("slot-1-1", digest("launch"))
            before = supervisor.store.revision
            event = {"slot_id": "slot-1-1"}
            event.update(extra)
            with self.subTest(label=label):
                with self.assertRaises(AuthorizationDenied):
                    _generic(supervisor, "WORKER_IDENTITY_ESTABLISHED",
                             "smuggle-" + label, event)
                self.assertEqual(supervisor.store.revision, before)

    def test_smuggled_measurement_window_history_cannot_reopen_publication(self):
        from tools.decision_0009.acer_adapter.evidence import (
            EvidenceError, ImmutablePublication,
        )
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "window-smuggle", b"value")
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        supervisor.set_measurement_window("DWELL")
        smuggle = {"slot_id": "slot-1-1", "record_type": "MEASUREMENT_WINDOW",
                   "window": "OUTSIDE_MEASURED_WINDOWS",
                   "window_epoch": supervisor.window_epoch + 1}
        try:
            _generic(supervisor, "WORKER_IDENTITY_ESTABLISHED", "window-smuggle", smuggle)
        except AuthorizationDenied:
            _plant(supervisor, "WORKER_IDENTITY_ESTABLISHED", "window-smuggle", smuggle)
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.current_window, "OUTSIDE_MEASURED_WINDOWS")
        with self.assertRaises(EvidenceError):
            ImmutablePublication(restarted).exclusive_create(intent)

    def test_smuggled_boot_activation_history_is_not_consumed_on_restart(self):
        supervisor, _, _ = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        smuggle = {"slot_id": "slot-1-1", "record_type": "BOOT_ACTIVATION",
                   "activation_id": "smuggled-activation",
                   "activated_boot_ordinal": 2, "observed_boot_id": "boot-2",
                   "predecessor_closure_digest": digest("never-completed")}
        try:
            _generic(supervisor, "WORKER_IDENTITY_ESTABLISHED", "activation-smuggle",
                     smuggle)
        except AuthorizationDenied:
            _plant(supervisor, "WORKER_IDENTITY_ESTABLISHED", "activation-smuggle",
                   smuggle)
        restarted = _restart(supervisor)
        self.assertEqual(restarted.store.health, "QUARANTINED")
        self.assertFalse(restarted.session.execution_live)
        self.assertNotIn("smuggled-activation", restarted.activation_ids)
        self.assertTrue(restarted.store.execution_revoked)
        with self.assertRaises(AuthorizationDenied):
            restarted.make_slot_eligible("slot-2-1")

    def test_nonauthorizing_and_restart_paths_cannot_carry_reserved_metadata(self):
        supervisor, _, _ = make_supervisor()
        for index, event in enumerate((
                {"record_type": "BOOT_ACTIVATION", "activation_id": "x",
                 "activated_boot_ordinal": 2, "observed_boot_id": "boot-2"},
                {"record_type": "MEASUREMENT_WINDOW", "window": "DWELL",
                 "window_epoch": 2},
                {"record_type": "EFFECT_RESULT", "effect_id": "x"},
                {"record_type": "PUBLICATION", "state": "PUBLICATION_VERIFIED"},
                {"state": "BOOT_COMPLETE"}, {"state": "ATTEMPT_COMPLETE"})):
            with self.subTest(index=index), self.assertRaises(StoreError):
                supervisor.store.append_nonauthorizing(
                    supervisor.session.fence_epoch, "nonauth-reserved-%d" % index, event)
        # A legacy diagnostic writer cannot mutate the single U-04 journal.
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.append_nonauthorizing(
            supervisor.session.fence_epoch, "nonauth-lookalike",
            {"record_type": "FORENSIC_NOTE", "window": "OUTSIDE_MEASURED_WINDOWS",
             "window_epoch": 99, "activation_id": "lookalike",
             "observed_boot_id": "boot-2", "activated_boot_ordinal": 2,
             "completion_digest": digest("lookalike"), "operation": "complete-boot"})
        restarted = _restart(supervisor)
        self.assertEqual(restarted.current_boot_ordinal, 1)
        self.assertEqual(restarted.window_epoch, supervisor.window_epoch)
        self.assertNotIn("lookalike", restarted.activation_ids)
        self.assertEqual(restarted._completed_boots, set())

    # ---- Blocker 3: creation must pass the store-backed successor gate ----

    def test_generic_eligibility_and_direct_blocked_create_cannot_create_successor(self):
        supervisor, _, custodian = make_supervisor()
        try:
            _generic(supervisor, "SLOT_SPAWN_ELIGIBLE", "generic-eligible-slot-1-2",
                     {"slot_id": "slot-1-2"})
        except AuthorizationDenied:
            pass
        with self.assertRaises((AuthorizationDenied, CustodyError)):
            _direct_create(supervisor, "slot-1-2")
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)
        self.assertEqual(custodian.inspect_spawn("spawn-slot-1-2").status, "FAILED_NO_CHILD")
        self.assertFalse(supervisor.store.is_consumed("slot", "slot-1-2"))
        self.assertNotIn("slot-1-1", supervisor._completed_attempts)
        self.assertFalse(any(event.get("state") == "SPAWN_INTENT_PERSISTED" and
                             event.get("slot_id") == "slot-1-2"
                             for event in supervisor.store.events))

    def test_direct_blocked_create_rejects_wrong_slot_boot_generation_and_fake_eligibility(self):
        cases = ("wrong-slot", "wrong-boot", "stale-generation",
                 "unconsumed-generic-eligibility", "fake-reconstructed-eligibility")
        for case in cases:
            supervisor, _, custodian = make_supervisor()
            target_slot, boot_id = "slot-1-1", None
            if case == "wrong-slot":
                supervisor.make_slot_eligible("slot-1-1")
                target_slot = "slot-1-2"
            elif case == "wrong-boot":
                supervisor.make_slot_eligible("slot-1-1")
                boot_id = "boot-2"
            elif case == "stale-generation":
                supervisor.make_slot_eligible("slot-1-1")
                supervisor = _restart(supervisor)
            elif case == "unconsumed-generic-eligibility":
                try:
                    _generic(supervisor, "SLOT_SPAWN_ELIGIBLE", "generic-eligible",
                             {"slot_id": "slot-1-1"})
                except AuthorizationDenied:
                    pass
            else:
                _plant(supervisor, "SLOT_SPAWN_ELIGIBLE", "slot-slot-1-1-eligible",
                       {"slot_id": "slot-1-1", "attempt_id": "attempt-1-1",
                        "boot_id": "boot-1", "spawn_token": "spawn-slot-1-1",
                        "custodian_id": custodian.identity,
                        "predecessor_slot_id": None,
                        "predecessor_completion_digest": None},
                       operation="make-slot-eligible")
                # Poisoning an old consumption view cannot provenance the planted frame.
                supervisor.store._consumed.add(("slot", "slot-1-1"))
                supervisor = _restart(supervisor)
                boot_id = "boot-1"  # immutable original identity, never inspector authority
            with self.subTest(case=case):
                with self.assertRaises((StoreError, CustodyError)):
                    _direct_create(supervisor, target_slot, boot_id=boot_id)
                self.assertEqual(custodian.underlying_create_count_for_all(), 0)
                if case == "wrong-boot":
                    # The legitimate eligibility is untouched by the rejected forgery.
                    supervisor.spawn_worker(target_slot, digest("launch"))
                    self.assertEqual(custodian.underlying_create_count_for_all(), 1)
                    continue
                with self.assertRaises(StoreError):
                    supervisor.spawn_worker(target_slot, digest("launch"))
                self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_legitimate_eligibility_then_spawn_still_creates_exactly_once(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        self.assertEqual(receipt.status, "BLOCKED")
        self.assertEqual(custodian.underlying_create_count("spawn-slot-1-1"), 1)
        with self.assertRaises((AuthorizationDenied, CustodyError)):
            _direct_create(supervisor, "slot-1-1", suffix="second-create-slot-1-1")
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-1-1", digest("launch"))
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_capability_registration_cannot_mint_provenance_for_planted_history(self):
        from tools.decision_0009.acer_adapter.contracts import EffectCapability
        supervisor, _, _ = make_supervisor()
        candidate, fields = _candidate_fields("boot")
        _plant(supervisor, "BOOT_CLOSURE_CANDIDATE_FINALIZED", "planted-candidate",
               fields, operation="finalize-boot-closure-candidate")
        receipt = _plant(supervisor, "BOOT_COMPLETE", "planted-complete",
                         {"candidate_digest": candidate.digest}, operation="complete-boot")
        binding = supervisor.verifier.verify("BOOT_COMPLETE", supervisor.session.fence_epoch,
                                             supervisor.session.session_id)
        forged = EffectCapability(
            "capability-planted-complete", receipt.event_id, receipt.revision,
            receipt.event_digest, binding, supervisor.authorization.authorization_digest,
            supervisor.session.fence_epoch, supervisor.session.session_id,
            "offline-store", "complete-boot", "planted-complete",
            supervisor.store._supervisor_generation, True)
        with self.assertRaises(AuthorizationDenied):
            supervisor.store.register_effect_capability(forged)
        restarted = _restart(supervisor)
        self.assertNotIn(1, restarted._completed_boots)
        self.assertTrue(restarted.store.publication_prohibited)

    # ---- incidental hardening at the same boundaries ----

    def test_fence_change_after_cas_still_denies_allowed_general_transition(self):
        supervisor, _, _ = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        dispatch = RecordingDispatch()
        with self.assertRaises(AuthorizationDenied):
            authorize_and_dispatch(
                supervisor.store, supervisor.verifier, supervisor.store.revision,
                supervisor.session.fence_epoch, supervisor.session,
                "WORKER_IDENTITY_ESTABLISHED",
                {"effect_id": "race-general", "target": "offline-store",
                 "operation": "append-transition", "event_id": "race-general-event",
                 "event": {"slot_id": "slot-1-1"}},
                dispatch, interlock=lambda: supervisor.store.acquire_fence("racer"))
        self.assertEqual(dispatch.calls, [])
        self.assertTrue(supervisor.store.execution_revoked)

    def test_malformed_reserved_history_fails_closed_instead_of_raising(self):
        supervisor, _, _ = make_supervisor()
        _plant(supervisor, "BOOT_HANDOFF_PENDING", "malformed-activation",
               {"record_type": "BOOT_ACTIVATION"}, operation="consume-boot-activation")
        restarted = _restart(supervisor)
        self.assertTrue(restarted.store.execution_revoked)
        self.assertTrue(restarted.store.publication_prohibited)
        self.assertEqual(restarted.store.health, "QUARANTINED")
        self.assertFalse(restarted.session.execution_live)

    def test_reused_boot_id_is_rejected_before_a_new_fence_is_taken(self):
        supervisor, _, _ = make_supervisor()
        closure = complete_boot(supervisor)
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        high_fence = supervisor.store.witness.high_fence
        with self.assertRaises(AuthorizationDenied):
            supervisor.activate_next_boot(activation(2, "boot-1", closure,
                                                      activation_id="reused-boot-id"))
        self.assertEqual(supervisor.store.witness.high_fence, high_fence)

    def test_local_spawn_state_is_not_recorded_before_durable_intent(self):
        supervisor, artifacts, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        artifacts.substitute("core")
        with self.assertRaises(AuthorizationDenied):
            supervisor.spawn_worker("slot-1-1", digest("launch"))
        self.assertIsNone(supervisor.store.event_receipt("event-spawn-intent-slot-1-1"))
        self.assertNotIn("slot-1-1", supervisor._slot_tokens)
        self.assertFalse(supervisor._slot_capabilities["slot-1-1"].consumed)
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)


# ---------------------------------------------------------------------------
# Decision 0009 independent Sol 6 review regressions (Findings 1-3).
#
# The reproduction tests below were added before the correction and fail on
# the inherited 124-test implementation.  Each binds a retained record to the
# dedicated operation, identity, and lifecycle point that produced it.
# ---------------------------------------------------------------------------

import copy
import json as _json
from unittest import mock

from tools.decision_0009.acer_adapter import supervisor as supervisor_module
from tools.decision_0009.acer_adapter.custody import OfflineCustodian
from tools.decision_0009.acer_adapter.evidence import (
    EvidenceError, ImmutablePublication, PublicationIntent, build_closure_candidate,
    canonical_core_bytes,
)
from tools.decision_0009.acer_adapter.supervisor import (
    ArtifactVerificationPrimitive, OfflineDurableStore, OfflineWitness,
    _DEDICATED_AUTHORITY,
)
from acer_adapter_fakes import MutableArtifacts, authorization


def _dedicated(supervisor, operation, state, suffix, event, sess=None):
    """Call the specialized operation boundary directly.  The module-private
    dedicated authority is importable, so it is not treated as evidence."""
    sess = sess or supervisor.session
    return authorize_and_dispatch(
        supervisor.store, supervisor.verifier, supervisor.store.revision,
        sess.fence_epoch, sess, state,
        {"effect_id": suffix, "target": "offline-store", "operation": operation,
         "event_id": "event-" + suffix, "event": dict(event)},
        RecordingDispatch(), _authority=_DEDICATED_AUTHORITY)


def _publish(supervisor, destination, key_prefix, values):
    publisher = ImmutablePublication(supervisor)
    receipts = []
    for index, value in enumerate(values):
        intent = publisher.intent(destination, "%s-%d" % (key_prefix, index), value)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, value)
        receipts.append(publisher.verify(intent))
    return tuple(receipts)


def _closure_values(candidate):
    return [candidate.bytes] + [
        canonical_core_bytes(value)
        for value in _json.loads(candidate.bytes)["payload"]["objects"]]


def _supervisor_without_boot_custody():
    artifacts = MutableArtifacts()
    auth = u04_authorization(artifacts)
    store = OfflineDurableStore("store-1", OfflineWitness("witness-1"),
        chair_verifier=offline_chair_service(auth), activation_verifier=offline_activation_service(auth))
    fence = 1
    verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
    custodian = OfflineCustodian("custodian-1")
    supervisor = PersistentSupervisor(store, verifier, custodian, auth, session(fence))
    supervisor.admit_campaign(activation())
    return supervisor, custodian


def _states(supervisor, state):
    return [event for event in supervisor.store.events if event.get("state") == state]


def _dedicated_eligibility(supervisor, slot_id):
    slot = next(item for item in supervisor.authorization.slots if item.slot_id == slot_id)
    return _dedicated(supervisor, "make-slot-eligible", "SLOT_SPAWN_ELIGIBLE",
                      "dedicated-eligible-" + slot_id,
                      {"slot_id": slot_id, "attempt_id": slot.attempt_id,
                       "boot_id": supervisor.store.boot_identity(slot.boot_ordinal),
                       "spawn_token": "spawn-" + slot_id,
                       "custodian_id": supervisor.custodian.identity,
                       "predecessor_slot_id": None,
                       "predecessor_completion_digest": None})


def _dedicated_create(supervisor, slot_id):
    """Blocked-create through the dedicated boundary with dedicated authority."""
    slot = next(item for item in supervisor.authorization.slots if item.slot_id == slot_id)
    generation = supervisor.store._supervisor_generation
    token = SpawnToken("spawn-" + slot_id, supervisor.authorization.campaign_id,
                       supervisor.store.boot_identity(slot.boot_ordinal), slot_id,
                       slot.attempt_id, digest("launch-" + slot_id),
                       supervisor.custodian.identity, generation)
    event = {"spawn_token": token.token_id, "launch_spec_digest": token.launch_spec_digest,
             "slot_id": slot_id, "attempt_id": slot.attempt_id, "boot_id": token.boot_id,
             "campaign_id": token.campaign_id, "custodian_id": token.custodian_id,
             "supervisor_generation": generation}

    def dispatch(capability, binding):
        return supervisor.custodian.create_once(
            token, token.launch_spec_digest, capability, binding)

    return authorize_and_dispatch(
        supervisor.store, supervisor.verifier, supervisor.store.revision,
        supervisor.session.fence_epoch, supervisor.session, "SPAWN_INTENT_PERSISTED",
        {"effect_id": "dedicated-create-" + slot_id,
         "target": supervisor.custodian.identity, "operation": "blocked-create",
         "event_id": "event-dedicated-create-" + slot_id, "event": event},
        dispatch, _authority=_DEDICATED_AUTHORITY)


class SolSixBootClosureOrderingTests(unittest.TestCase):
    """Finding 1: publication before candidate finalization cannot close a boot."""

    PAYLOAD = {"boot_id": "boot-1", "objects": ["attempts", "custody"]}

    def test_prepublished_exact_future_candidate_cannot_complete_boot(self):
        supervisor, _, _ = make_supervisor()
        future = build_closure_candidate("boot", dict(self.PAYLOAD))
        early = _publish(supervisor, "offline-destination", "prepublished",
                         _closure_values(future))
        record_all_local_attempts(supervisor)
        candidate = supervisor.finalize_boot_closure_candidate(dict(self.PAYLOAD))
        self.assertEqual(candidate, future)
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(candidate, early)
        self.assertEqual(_states(supervisor, "BOOT_COMPLETE"), [])
        self.assertIsNone(supervisor.store.validated_boot_closure(1))
        from acer_adapter_fakes import independent_fault_world
        live_seed = independent_fault_world(supervisor)
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.boot_state, "BOOT_COMPLETE")
        self.assertNotIn(1, restarted._completed_boots)
        self.assertIsNone(restarted.store.validated_boot_closure(1))
        with self.assertRaises(EvidenceError):
            _publish(restarted, "offline-destination", "denied-after-restart", _closure_values(candidate))
        # The rejection is clean: publishing the finalized candidate afterwards
        # closes the boot on the separate uninterrupted original incarnation.
        restarted = live_seed
        late = _publish(restarted, "offline-destination", "post-finalization",
                        _closure_values(candidate))
        closure = restarted.complete_boot(candidate, late)
        again = _restart(restarted)
        self.assertEqual(again.boot_state, "BOOT_COMPLETE")
        self.assertEqual(again.store.validated_boot_closure(1), closure)
        self.assertEqual(again.reconstruction_violations, [])

    def test_reconstruction_rejects_completion_bound_to_prefinalization_publication(self):
        supervisor, _, _ = make_supervisor()
        future = build_closure_candidate("boot", dict(self.PAYLOAD))
        early = _publish(supervisor, "offline-destination", "prepublished",
                         _closure_values(future))
        record_all_local_attempts(supervisor)
        candidate = supervisor.finalize_boot_closure_candidate(dict(self.PAYLOAD))
        payload = supervisor._closure_payload(
            candidate, early, "BOOT_CLOSURE_CANDIDATE_FINALIZED", 1)
        payload["boot_id"] = supervisor.current_boot_id
        # Bypass the live boundary check so that reconstruction is tested alone.
        with mock.patch.object(supervisor_module, "_closure_publication_proof",
                               lambda *args, **kwargs: None, create=True):
            _dedicated(supervisor, "complete-boot", "BOOT_COMPLETE",
                       "boot-1-complete-prepublished", payload)
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.boot_state, "BOOT_COMPLETE")
        self.assertNotIn(1, restarted._completed_boots)
        self.assertIsNone(restarted.store.validated_boot_closure(1))
        self.assertIn("invalid-boot-closure:1", restarted.reconstruction_violations)
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(AuthorizationDenied):
            restarted.begin_boot_handoff(2)
            restarted.commit_planned_shutdown()

    def test_identical_object_publications_from_an_earlier_boot_cannot_close_later_boot(self):
        supervisor, _, _ = make_supervisor()
        record_all_local_attempts(supervisor)
        first = supervisor.finalize_boot_closure_candidate(dict(self.PAYLOAD))
        first_receipts = _publish(supervisor, "offline-destination", "boot-1-object",
                                  _closure_values(first))
        closure = supervisor.complete_boot(first, first_receipts)
        supervisor.begin_boot_handoff(2)
        supervisor.commit_planned_shutdown()
        supervisor.activate_next_boot(activation(2, "boot-2", closure,
                                                 activation_id="activation-2"))
        supervisor.establish_boot_custody("custody-proof-2", True, True)
        supervisor.complete_boot_custody()
        record_all_local_attempts(supervisor)
        second = supervisor.finalize_boot_closure_candidate(
            {"boot_id": "boot-2", "objects": ["attempts", "custody"]})
        self.assertEqual(second.object_digests, first.object_digests)
        fresh = _publish(supervisor, "offline-destination", "boot-2-candidate",
                         [second.bytes])
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_boot(second, fresh + first_receipts[1:])
        self.assertEqual([event["boot_ordinal"] for event in
                          _states(supervisor, "BOOT_COMPLETE")], [1])
        restarted = _restart(supervisor)
        self.assertNotIn(2, restarted._completed_boots)
        self.assertIsNone(restarted.store.validated_boot_closure(2))
        self.assertEqual(restarted.store.validated_boot_closure(1), closure)

    def test_valid_order_attempts_candidate_publication_completion_reconstructs(self):
        supervisor, _, _ = make_supervisor()
        closure = complete_boot(supervisor)
        events = supervisor.store.events
        attempts = [index for index, event in enumerate(events)
                    if event.get("state") == "ATTEMPT_COMPLETE"]
        candidate_at = next(index for index, event in enumerate(events)
                            if event.get("state") == "BOOT_CLOSURE_CANDIDATE_FINALIZED")
        publications = [index for index, event in enumerate(events)
                        if event.get("record_type") == "PUBLICATION"]
        completion_at = next(index for index, event in enumerate(events)
                             if event.get("state") == "BOOT_COMPLETE")
        self.assertEqual(len(attempts), 3)
        self.assertLess(max(attempts), candidate_at)
        self.assertLess(candidate_at, min(publications))
        self.assertLess(max(publications), completion_at)
        supervisor.store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.boot_state, "BOOT_COMPLETE")
        self.assertEqual(restarted.store.validated_boot_closure(1), closure)
        self.assertEqual(restarted.reconstruction_violations, [])


FORGED_ATTESTATION = {
    "attestation_id": "boot-custody-forged", "custodian_id": "custodian-1",
    "watchdog_id": "custodian-1/watchdog", "observer_id": "isolated-observer",
    "store_identity": "store-1", "authorization_digest": digest("authorization"),
    "campaign_id": "campaign-1", "boot_id": "boot-1", "boot_ordinal": 1,
    "supervisor_generation": 1, "session_id": "session-1", "fence_epoch": 1,
    "custody_proof_digest": digest("forged-proof"), "observer_isolated": True,
    "watchdog_ready": True,
}


class SolSixBootCustodyEvidenceTests(unittest.TestCase):
    """Finding 2: the custody-state boundary validates custody evidence itself."""

    def _forge_custody(self, supervisor):
        """Try the review's payloads, then correctly shaped forged evidence."""
        accepted = []
        attempts = (
            ("establish-boot-custody", "BOOT_CUSTODY_ESTABLISHED",
             ({}, {"boot_id": "boot-1", "custody_attestation": dict(FORGED_ATTESTATION)})),
            ("complete-boot-custody", "BOOT_CUSTODY_COMPLETE",
             ({"extra_pre_spawn_baseline_ns": 0},
              {"extra_pre_spawn_baseline_ns": 0,
               "custody_established_event_digest": "0" * 64,
               "custody_attestation_digest": "0" * 64})),
        )
        for operation, state, payloads in attempts:
            for index, payload in enumerate(payloads):
                try:
                    _dedicated(supervisor, operation, state,
                               "forged-%s-%d" % (operation, index), payload)
                except AuthorizationDenied:
                    continue
                accepted.append(state)
                break
        return accepted

    def _assert_first_slot_denied(self, supervisor, custodian):
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(AuthorizationDenied):
            _dedicated_eligibility(supervisor, "slot-1-1")
        with self.assertRaises((AuthorizationDenied, CustodyError)):
            _dedicated_create(supervisor, "slot-1-1")
        self.assertEqual(custodian.underlying_create_count_for_all(), 0)

    def test_specialized_custody_boundary_without_custody_proof_is_rejected(self):
        supervisor, custodian = _supervisor_without_boot_custody()
        self.assertEqual(self._forge_custody(supervisor), [])
        self.assertEqual(_states(supervisor, "BOOT_CUSTODY_ESTABLISHED"), [])
        self.assertEqual(_states(supervisor, "BOOT_CUSTODY_COMPLETE"), [])
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.boot_state, "BOOT_CUSTODY_COMPLETE")
        self._assert_first_slot_denied(restarted, custodian)

    def test_reconstruction_revalidates_custody_evidence_behind_provenanced_records(self):
        supervisor, custodian = _supervisor_without_boot_custody()
        # Bypass the live boundary check so that reconstruction is tested alone.
        with mock.patch.object(supervisor_module, "_boot_custody_evidence",
                               lambda *args, **kwargs: None, create=True):
            self.assertEqual(self._forge_custody(supervisor),
                             ["BOOT_CUSTODY_ESTABLISHED", "BOOT_CUSTODY_COMPLETE"])
        # The first-slot gate itself requires validated custody, not the label.
        with self.assertRaises(AuthorizationDenied):
            _dedicated_eligibility(supervisor, "slot-1-1")
        restarted = _restart(supervisor)
        self.assertNotEqual(restarted.boot_state, "BOOT_CUSTODY_COMPLETE")
        self.assertTrue(any(violation.startswith("invalid-boot-custody")
                            for violation in restarted.reconstruction_violations))
        self.assertTrue(restarted.store.execution_revoked)
        self._assert_first_slot_denied(restarted, custodian)

    def test_legitimate_custody_reconstructs_and_permits_exactly_one_first_worker(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible('slot-1-1')
        self.assertEqual(supervisor.spawn_worker('slot-1-1', digest('launch')).status, 'BLOCKED')
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)
        supervisor.store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.boot_state, "BOOT_CUSTODY_COMPLETE")
        self.assertEqual(restarted.reconstruction_violations, [])
        with self.assertRaises(AuthorizationDenied):
            restarted.make_slot_eligible('slot-1-1')
        self.assertEqual(custodian.underlying_create_count_for_all(), 1)

    def test_custody_evidence_substitution_is_rejected(self):
        supervisor, custodian = _supervisor_without_boot_custody()
        sess = supervisor.session
        base = dict(store_identity="store-1",
                    authorization_digest=supervisor.authorization.authorization_digest,
                    campaign_id="campaign-1", boot_id="boot-1", boot_ordinal=1,
                    supervisor_generation=supervisor.store._supervisor_generation,
                    session_id=sess.session_id, fence_epoch=sess.fence_epoch,
                    observer_id="isolated-observer", custody_proof="custody-proof",
                    observer_isolated=True, watchdog_ready=True)

        def establish(record, target=None, suffix="substituted"):
            _dedicated(target or supervisor, "establish-boot-custody",
                       "BOOT_CUSTODY_ESTABLISHED", suffix,
                       {"boot_id": "boot-1", "custody_attestation": record})

        for name, changes in {
                "another-boot": dict(boot_id="boot-2", boot_ordinal=2),
                "another-boot-id": dict(boot_id="boot-9"),
                "another-campaign": dict(campaign_id="campaign-2"),
                "another-authorization": dict(authorization_digest=digest("other")),
                "stale-session": dict(session_id="session-stale"),
                "stale-fence": dict(fence_epoch=sess.fence_epoch + 7),
                "another-store": dict(store_identity="store-2"),
                "observer-is-supervisor": dict(observer_id=sess.owner_identity)}.items():
            with self.subTest(name):
                try:
                    attestation = custodian.attest_boot_custody(**dict(base, **changes))
                except CustodyError:
                    continue
                with self.assertRaises(AuthorizationDenied):
                    establish(attestation.record(), suffix="substituted-" + name)
        genuine = custodian.attest_boot_custody(**base)
        for field, value in (("observer_id", "another-observer"),
                             ("watchdog_id", "another-watchdog"),
                             ("custodian_id", "custodian-2"),
                             ("observer_isolated", False), ("watchdog_ready", False),
                             ("custody_proof_digest", digest("another-proof"))):
            with self.subTest(field), self.assertRaises(AuthorizationDenied):
                establish(dict(genuine.record(), **{field: value}),
                          suffix="tampered-" + field)
        for observer in (custodian.identity, custodian.watchdog_identity):
            with self.subTest(observer=observer), self.assertRaises(CustodyError):
                custodian.attest_boot_custody(**dict(base, observer_id=observer))
        with self.assertRaises(CustodyError):
            OfflineCustodian("custodian-2").attest_boot_custody(**base)
        # A new supervisor generation cannot adopt the earlier generation's evidence.
        restarted = _restart(supervisor)
        with self.assertRaises(AuthorizationDenied):
            establish(genuine.record(), target=restarted, suffix="stale-generation")
        with self.assertRaises(AuthorizationDenied):
            restarted.establish_boot_custody("custody-proof", True, True)
        # Exact substitution negatives and success remain on uninterrupted membership.
        live, custodian = _supervisor_without_boot_custody()
        live.establish_boot_custody("custody-proof", True, True)
        established = live.store.provenanced_frames("BOOT_CUSTODY_ESTABLISHED")[0]
        other = custodian.attest_boot_custody(**dict(
            base, supervisor_generation=live.store._supervisor_generation,
            observer_id="second-observer"))
        for name, payload in {
                "other-attestation": {
                    "custody_established_event_digest":
                        established["receipt"].event_digest,
                    "custody_attestation_digest": supervisor_module._sha(
                        supervisor_module._canonical(other.record()))},
                "other-established-event": {
                    "custody_established_event_digest": "1" * 64,
                    "custody_attestation_digest": supervisor_module._sha(
                        supervisor_module._canonical(
                            established["event"]["custody_attestation"]))}}.items():
            with self.subTest(name), self.assertRaises(AuthorizationDenied):
                _dedicated(live, "complete-boot-custody", "BOOT_CUSTODY_COMPLETE",
                           "complete-" + name, dict(payload, extra_pre_spawn_baseline_ns=0))
        self.assertEqual(_states(live, "BOOT_CUSTODY_COMPLETE"), [])
        live.complete_boot_custody()
        self.assertEqual(live.boot_state, "BOOT_CUSTODY_COMPLETE")
        self.assertEqual(_restart(live).reconstruction_violations, [])


def _publication_records(supervisor, key=None):
    return [copy.deepcopy(frame['event']) for entries in
            supervisor_module._publication_frame_groups(supervisor.store).values()
            for _, frame in entries if key is None or frame['event'].get('object_key') == key]


def _forge_publication_history(supervisor, donor, records, operation_ids=None):
    """Retain publication-shaped records and their objects directly in the store,
    bypassing every publication operation grant (the review's forgery model)."""
    for object_id, value in donor.store._objects.items():
        if object_id.startswith("publication-"):
            supervisor.store._objects[object_id] = bytes(value)
    for index, record in enumerate(records):
        record = dict(record)
        if operation_ids is not None:
            record["operation_id"] = operation_ids[index]
        _append_unprovenanced(
            supervisor.store, supervisor.session.fence_epoch,
            "forged-publication-%d-%d" % (supervisor.store.revision, index), record)


class SolSixPublicationProvenanceTests(unittest.TestCase):
    """Finding 3: reconstruction requires the operation grant behind each record."""

    def _assert_not_reconstructed(self, supervisor, key):
        restarted = _restart(supervisor)
        self.assertTrue(restarted.reconstruction_violations)
        self.assertTrue(restarted.store.publication_prohibited)
        try:
            recovered = ImmutablePublication(restarted)
        except (EvidenceError, AuthorizationDenied):
            recovered = None
        if recovered is not None:
            self.assertNotEqual(recovered._states.get(("dest", key)), "VERIFIED")
        forged = next(event for event in _publication_records(supervisor, key)
                      if event["state"] == "PUBLICATION_VERIFIED")
        from tools.decision_0009.acer_adapter.contracts import PublicationReceipt
        receipt = PublicationReceipt(
            "publication-receipt-" + forged["object_digest"][:16], "dest", key,
            forged["object_digest"], forged["length"], "PUBLICATION_VERIFIED",
            forged["readback_digest"])
        with self.assertRaises(AuthorizationDenied):
            restarted._verify_publication_receipts(None, receipt)
        return restarted

    def test_complete_chain_without_operation_grants_is_not_reconstructed_verified(self):
        donor, _, _ = make_supervisor()
        _publish(donor, "dest", "grantless", [b"value"])
        supervisor, _, _ = make_supervisor()
        _forge_publication_history(supervisor, donor, _publication_records(donor))
        self.assertEqual(supervisor.store._publication_grants, {})
        self.assertEqual([event["state"] for event in _publication_records(supervisor)],
                         ["PUBLICATION_INTENT", "EXCLUSIVE_CREATE", "PUBLICATION_WRITTEN",
                          "DURABLE_BYTES", "PUBLICATION_VERIFIED"])
        self._assert_not_reconstructed(supervisor, "grantless-0")

    def test_grants_consumed_by_another_publication_cannot_provenance_a_chain(self):
        donor, _, _ = make_supervisor()
        _publish(donor, "dest", "other", [b"value"])
        _publish(donor, "dest", "reused", [b"value"])
        supervisor, _, _ = make_supervisor()
        _publish(supervisor, "dest", "other", [b"value"])
        other_ids = [event["operation_id"] for event in
                     _publication_records(supervisor, "other-0")]
        _forge_publication_history(supervisor, donor,
                                   _publication_records(donor, "reused-0"), other_ids)
        self._assert_not_reconstructed(supervisor, "reused-0")

    def test_issued_but_unconsumed_or_earlier_window_grant_cannot_provenance_verify(self):
        for rollover in (False, True):
            with self.subTest(rollover=rollover):
                donor, _, _ = make_supervisor()
                publisher = ImmutablePublication(donor)
                intent = publisher.intent("dest", "unconsumed-0", b"value")
                publisher.exclusive_create(intent)
                publisher.write_durable(intent, b"value")
                if rollover:
                    donor.set_measurement_window("DWELL")
                    donor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
                publisher.verify(intent)
                supervisor, _, _ = make_supervisor()
                publisher = ImmutablePublication(supervisor)
                intent = publisher.intent("dest", "unconsumed-0", b"value")
                publisher.exclusive_create(intent)
                publisher.write_durable(intent, b"value")
                grant = supervisor.issue_publication_grant(
                    supervisor.publication_binding(), "verify", intent)
                if rollover:
                    supervisor.set_measurement_window("DWELL")
                    supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
                verified = _publication_records(donor, "unconsumed-0")[-1]
                # Copy under a locally issued ID still cannot supply W provenance.
                _forge_publication_history(supervisor, donor, [verified], [grant.grant_id])
                self._assert_not_reconstructed(supervisor, "unconsumed-0")

    def test_grant_issued_before_candidate_finalization_cannot_publish_after_it(self):
        supervisor, _, _ = make_supervisor()
        record_all_local_attempts(supervisor)
        value = b"late-object"
        intent = PublicationIntent("publish-late", "dest", "late", supervisor_module._sha(value),
                                   len(value), value)
        binding = supervisor.publication_binding()
        grant = supervisor.issue_publication_grant(binding, "intent", intent)
        supervisor.finalize_boot_closure_candidate(
            {"boot_id": "boot-1", "objects": ["attempts", "custody"]})
        with self.assertRaises(AuthorizationDenied):
            supervisor.perform_publication(binding, grant, intent, payload=value)
        self.assertEqual(_publication_records(supervisor, "late"), [])

    def test_granted_publication_restarts_exactly_verified(self):
        supervisor, _, _ = make_supervisor()
        receipt = _publish(supervisor, "dest", "granted", [b"value"])[0]
        records = _publication_records(supervisor, "granted-0")
        self.assertEqual(len({record["operation_id"] for record in records}), 5)
        supervisor.store.crash()
        recovered_supervisor = supervisor
        for _ in range(2):
            recovered_supervisor = _restart(recovered_supervisor)
            self.assertEqual(recovered_supervisor.reconstruction_violations, [])
            self.assertTrue(recovered_supervisor.store.publication_prohibited)
            recovered = ImmutablePublication(recovered_supervisor)
            intent = recovered._intents[("dest", "granted-0")]
            self.assertEqual(recovered._states[("dest", "granted-0")], "VERIFIED")
            self.assertEqual(recovered.reconcile(intent), receipt)
            self.assertEqual(
                recovered_supervisor._verify_publication_receipts(None, receipt),
                (receipt,))

    # ---- consolidation extension: grant identity includes destination/key ----

    def test_grants_for_another_destination_or_key_cannot_provenance_a_chain(self):
        value = b"value"
        shared = {"intent_id": "publish-shared-key", "object_digest": _sha(value),
                  "length": len(value), "bytes": value}
        source = PublicationIntent(destination="dest", object_key="shared-source", **shared)
        target = PublicationIntent(destination="dest", object_key="shared-target", **shared)
        donor, _, _ = make_supervisor()
        _publish_all(donor, target)
        supervisor, _, _ = make_supervisor()
        _publish_all(supervisor, source)
        source_ids = [event["operation_id"] for event in
                      _publication_records(supervisor, "shared-source")]
        _forge_publication_history(supervisor, donor,
                                   _publication_records(donor, "shared-target"), source_ids)
        self._assert_not_reconstructed(supervisor, "shared-target")


# ---------------------------------------------------------------------------
# Decision 0009 bounded consolidation: canonical publication identity and
# measurement-window provenance.
#
# The negative-case field inventories below are written literally.  They are
# deliberately not derived from production projection helpers or dataclass
# field enumeration, so a field dropped from a production contract still has a
# failing substitution here.
# ---------------------------------------------------------------------------

import dataclasses

from tools.decision_0009.acer_adapter.contracts import (
    MeasurementWindowTransition, OperationResultBinding, PublicationIdentity,
    PublicationOperationGrant, PublicationReceipt,
)
from tools.decision_0009.acer_adapter.supervisor import LostAcknowledgement

PUBLICATION_IDENTITY_FIELDS = (
    "intent_id", "destination", "object_key", "object_digest", "length",
)
PUBLICATION_BINDING_FIELDS = (
    "store_identity", "grant_id", "operation", "expected_prior_state", "window_epoch",
    "authorization_digest", "campaign_id", "boot_id", "boot_ordinal",
    "closure_candidate_event_digest", "supervisor_generation", "session_id",
    "fence_epoch",
)
WINDOW_BINDING_FIELDS = (
    "store_identity", "operation_id", "operation", "event_id", "previous_window",
    "previous_window_epoch", "window", "window_epoch", "authorization_digest",
    "campaign_id", "supervisor_generation", "session_id", "fence_epoch",
)
RESULT_BINDING_FIELDS = ("event_id", "revision", "event_digest")
PUBLICATION_OPERATION_SEQUENCE = ("intent", "create", "write", "durable", "verify")
PUBLICATION_STATE_FOR = {
    "intent": "PUBLICATION_INTENT", "create": "EXCLUSIVE_CREATE",
    "write": "PUBLICATION_WRITTEN", "durable": "DURABLE_BYTES",
    "verify": "PUBLICATION_VERIFIED",
}
# Publication record field names as retained history spells them.
PUBLICATION_RECORD_BINDING_FIELDS = (
    "intent_id", "destination", "object_key", "object_digest", "length",
    "operation_id", "operation", "prior_state", "window_epoch",
    "authorization_digest", "campaign_id", "boot_id", "boot_ordinal",
    "closure_candidate_event_digest", "supervisor_generation", "session_id",
    "fence_epoch",
)
WINDOW_RECORD_BINDING_FIELDS = (
    "operation_id", "operation", "previous_window", "previous_window_epoch", "window",
    "window_epoch", "authorization_digest", "campaign_id", "supervisor_generation",
    "session_id", "fence_epoch",
)
SHARED_VALUE = b"value"


def _direct_intent(value=SHARED_VALUE, *, intent_id="publish-shared", destination="dest-a",
                   object_key="key-a"):
    return PublicationIntent(intent_id, destination, object_key, _sha(value), len(value),
                             value)


def _identity_substitutions(intent):
    """One substituted intent per identity field.  Destination and key
    substitutions keep the intent ID, source bytes, and digest identical."""
    other = b"VALUE"  # same length as the shared value, different digest
    substituted = {
        "intent_id": PublicationIntent("publish-other", intent.destination,
                                       intent.object_key, intent.object_digest,
                                       intent.length, intent.bytes),
        "destination": PublicationIntent(intent.intent_id, "dest-other",
                                         intent.object_key, intent.object_digest,
                                         intent.length, intent.bytes),
        "object_key": PublicationIntent(intent.intent_id, intent.destination,
                                        "key-other", intent.object_digest,
                                        intent.length, intent.bytes),
        "object_digest": PublicationIntent(intent.intent_id, intent.destination,
                                           intent.object_key, _sha(other), len(other),
                                           other),
        # A length change cannot keep bytes, digest, and length consistent; the
        # canonical identity rejects the source/length mismatch.
        "length": PublicationIntent(intent.intent_id, intent.destination,
                                    intent.object_key, intent.object_digest,
                                    intent.length + 1, intent.bytes),
    }
    assert tuple(substituted) == PUBLICATION_IDENTITY_FIELDS
    return substituted


def _operation_payload(operation, intent):
    return intent.bytes if operation in ("intent", "write") else None


def _perform(supervisor, operation, intent):
    binding = supervisor.publication_binding()
    grant = supervisor.issue_publication_grant(binding, operation, intent)
    return grant, supervisor.perform_publication(
        binding, grant, intent, payload=_operation_payload(operation, intent))


def _advance_publication(supervisor, intent, before_operation):
    grants = []
    for operation in PUBLICATION_OPERATION_SEQUENCE[
            :PUBLICATION_OPERATION_SEQUENCE.index(before_operation)]:
        grants.append(_perform(supervisor, operation, intent)[0])
    return grants


def _publish_all(supervisor, intent):
    grants = _advance_publication(supervisor, intent, "verify")
    grant, receipt = _perform(supervisor, "verify", intent)
    return grants + [grant], receipt


def _publication_effects(store):
    """Everything a rejected-before-consumption operation must leave unchanged."""
    return (store.revision, frozenset(store._consumed_publication_grants),
            dict(store._publication_grant_records), dict(store._objects),
            store.publication_prohibited, store.execution_revoked)


def _forced(instance, **changes):
    """Individually changed contract value.  When the closed contract itself
    rejects the change, bypass construction so the consuming path is still
    exercised; the caller records that the contract rejected it."""
    try:
        return dataclasses.replace(instance, **changes), False
    except ContractError:
        forged = object.__new__(type(instance))
        for field in dataclasses.fields(instance):
            object.__setattr__(forged, field.name, getattr(instance, field.name))
        for name, value in changes.items():
            object.__setattr__(forged, name, value)
        return forged, True


def _rewrite_retained_record(store, event_id, mutate, results, key, new_event_id=None):
    """Store-level forgery of one retained record.  The bound result is
    re-pointed at the rewritten bytes, so only the canonical field comparison
    can reject it.  Returns a restore function."""
    index = store.frame_index(event_id)
    frame = store._durable[index]
    original = (frame["event_id"], frame["event"], frame["bytes"], frame["receipt"])
    old_result = results.get(key)
    event = copy.deepcopy(frame["event"])
    mutate(event)
    encoded = _canonical(event)
    frame_event_id = new_event_id or frame["event_id"]
    receipt = replace(frame["receipt"], event_digest=_sha(encoded), event_id=frame_event_id)
    frame.update({"event_id": frame_event_id, "event": event, "bytes": encoded,
                  "receipt": receipt})
    results[key] = OperationResultBinding(frame_event_id, receipt.revision,
                                          receipt.event_digest)

    def restore():
        frame.update(dict(zip(("event_id", "event", "bytes", "receipt"), original)))
        if old_result is None:
            results.pop(key, None)
        else:
            results[key] = old_result
    return restore


def _frame_by_state(store, state, object_key=None):
    return next(frame for frame in reversed(store._durable)
                if frame["event"].get("state") == state and
                frame["event"].get("record_type") == "PUBLICATION" and
                (object_key is None or frame["event"].get("object_key") == object_key))


def _window_frames(store):
    return [frame for frame in store._durable
            if frame["event"].get("record_type") == "MEASUREMENT_WINDOW"]


def _unadmitted_supervisor():
    artifacts = MutableArtifacts()
    auth = u04_authorization(artifacts)
    store = OfflineDurableStore("store-1", OfflineWitness("witness-1"),
        chair_verifier=offline_chair_service(auth), activation_verifier=offline_activation_service(auth))
    fence = 1
    verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
    return PersistentSupervisor(store, verifier, OfflineCustodian("custodian-1"), auth,
                                session(fence))


class ConsolidatedPublicationIdentityTests(unittest.TestCase):
    """Creation, consumption, and reconstruction share one publication identity
    and one operation binding."""

    def test_original_defect_destination_key_substitution_is_rejected_before_consumption(self):
        # Reproduction 1 (runnable on the inherited implementation, where it
        # consumed the grant for A and reconstructed B as VERIFIED).
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        a = _direct_intent(destination="dest-a", object_key="key-a")
        b = _direct_intent(destination="dest-b", object_key="key-b")
        self.assertEqual((a.intent_id, a.object_digest, a.length, a.bytes),
                         (b.intent_id, b.object_digest, b.length, b.bytes))
        binding = supervisor.publication_binding()
        grant_a = supervisor.issue_publication_grant(binding, "intent", a)
        before = _publication_effects(store)
        with self.assertRaises(AuthorizationDenied):
            supervisor.perform_publication(binding, grant_a, b, payload=SHARED_VALUE)
        self.assertEqual(_publication_effects(store), before)
        self.assertFalse(store.publication_grant_consumed(grant_a.grant_id))
        grants_b, receipt_b = _publish_all(supervisor, b)
        self.assertNotIn(grant_a.grant_id, {grant.grant_id for grant in grants_b})
        for grant in grants_b:
            self.assertEqual(store._publication_grants[grant.grant_id].identity,
                             PublicationIdentity("publish-shared", "dest-b", "key-b",
                                                 _sha(SHARED_VALUE), len(SHARED_VALUE)))
        # The unconsumed grant for A still performs exactly A.
        supervisor.perform_publication(binding, grant_a, a, payload=SHARED_VALUE)
        store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.reconstruction_violations, [])
        recovered = ImmutablePublication(restarted)
        self.assertEqual(recovered._states[("dest-b", "key-b")], "VERIFIED")
        self.assertNotIn(("dest-a", "key-a"), recovered._states)
        self.assertEqual(restarted._verify_publication_receipts(None, receipt_b),
                         (receipt_b,))
        intent_records = [event for event in restarted.store.events
                          if event.get("state") == "PUBLICATION_INTENT"]
        self.assertEqual({(event["destination"], event["operation_id"])
                          for event in intent_records},
                         {("dest-b", grants_b[0].grant_id), ("dest-a", grant_a.grant_id)})

    def test_each_identity_substitution_is_rejected_before_consumption_for_every_operation(self):
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            supervisor, _, _ = make_supervisor()
            store = supervisor.store
            intent = _direct_intent(object_key="key-" + operation)
            _advance_publication(supervisor, intent, operation)
            binding = supervisor.publication_binding()
            grant = supervisor.issue_publication_grant(binding, operation, intent)
            for field, substituted in _identity_substitutions(intent).items():
                with self.subTest(operation=operation, field=field):
                    before = _publication_effects(store)
                    with self.assertRaises(AuthorizationDenied):
                        supervisor.perform_publication(
                            binding, grant, substituted,
                            payload=_operation_payload(operation, substituted))
                    self.assertEqual(_publication_effects(store), before)
            # Valid control: the exact identity succeeds with the same grant.
            supervisor.perform_publication(binding, grant, intent,
                                           payload=_operation_payload(operation, intent))
            self.assertTrue(store.publication_grant_consumed(grant.grant_id))
            self.assertIn(grant.grant_id, store._publication_grant_records)
            self.assertEqual(_frame_by_state(store, PUBLICATION_STATE_FOR[operation],
                                             intent.object_key)["event"]["operation_id"],
                             grant.grant_id)

    def test_each_operation_binding_field_substitution_is_rejected_before_consumption(self):
        contract_rejected = set()
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            supervisor, _, _ = make_supervisor()
            store = supervisor.store
            intent = _direct_intent(object_key="bind-" + operation)
            _advance_publication(supervisor, intent, operation)
            binding = supervisor.publication_binding()
            grant = supervisor.issue_publication_grant(binding, operation, intent)
            request = grant.binding
            other_operation = next(name for name in PUBLICATION_OPERATION_SEQUENCE
                                   if name != operation)
            other_prior = ("DURABLE_BYTES" if request.expected_prior_state != "DURABLE_BYTES"
                           else "PUBLICATION_INTENT")
            binding_substitutes = {
                "store_identity": "store-foreign",
                "grant_id": "publication-grant-999",
                "operation": other_operation,
                "expected_prior_state": other_prior,
                "window_epoch": request.window_epoch + 1,
                "authorization_digest": digest("foreign-authorization"),
                "campaign_id": "campaign-foreign",
                "boot_id": "boot-foreign",
                "boot_ordinal": request.boot_ordinal + 1,
                "closure_candidate_event_digest": digest("foreign-candidate"),
                "supervisor_generation": request.supervisor_generation + 1,
                "session_id": "session-foreign",
                "fence_epoch": request.fence_epoch + 1,
            }
            identity_substitutes = {
                "intent_id": "publish-other",
                "destination": "dest-other",
                "object_key": "key-other",
                "object_digest": digest("other-object"),
                "length": request.identity.length + 1,
            }
            self.assertEqual(tuple(binding_substitutes), PUBLICATION_BINDING_FIELDS)
            self.assertEqual(tuple(identity_substitutes), PUBLICATION_IDENTITY_FIELDS)
            cases = []
            for field, value in binding_substitutes.items():
                forged, rejected = _forced(request, **{field: value})
                cases.append((field, forged, rejected))
            for field, value in identity_substitutes.items():
                identity = dataclasses.replace(request.identity, **{field: value})
                cases.append(("identity." + field, dataclasses.replace(request, identity=identity),
                              False))
            for field, forged_binding, rejected in cases:
                if rejected:
                    contract_rejected.add(field)
                forged = PublicationOperationGrant(forged_binding,
                                                   forged_binding.attestation_digest())
                with self.subTest(operation=operation, field=field, layer="presented"):
                    before = _publication_effects(store)
                    with self.assertRaises(AuthorizationDenied):
                        supervisor.perform_publication(
                            binding, forged, intent,
                            payload=_operation_payload(operation, intent))
                    self.assertEqual(_publication_effects(store), before)
                if field == "grant_id":
                    # A grant under another ID can enter the store-owned registry
                    # only through issuance, which enforces the store sequence.
                    with self.assertRaises(StoreError):
                        store._register_publication_grant(_DEDICATED_AUTHORITY, forged)
                    continue
                with self.subTest(operation=operation, field=field, layer="registered"):
                    store._publication_grants[grant.grant_id] = forged
                    try:
                        before = _publication_effects(store)
                        with self.assertRaises(AuthorizationDenied):
                            supervisor.perform_publication(
                                binding, forged, intent,
                                payload=_operation_payload(operation, intent))
                        self.assertEqual(_publication_effects(store), before)
                    finally:
                        store._publication_grants[grant.grant_id] = grant
            with self.subTest(operation=operation, field="attestation"):
                altered = PublicationOperationGrant(request, digest("altered-attestation"))
                store._publication_grants[grant.grant_id] = altered
                try:
                    for presented in (altered,):
                        before = _publication_effects(store)
                        with self.assertRaises(AuthorizationDenied):
                            supervisor.perform_publication(
                                binding, presented, intent,
                                payload=_operation_payload(operation, intent))
                        self.assertEqual(_publication_effects(store), before)
                finally:
                    store._publication_grants[grant.grant_id] = grant
            # Poisoned V registration cannot revoke or substitute the original
            # witnessed grant. The same exact grant remains the positive control.
            store._publication_grants[grant.grant_id] = altered
            supervisor.perform_publication(binding, grant, intent,
                                           payload=_operation_payload(operation, intent))
            self.assertIn(grant.grant_id, store._publication_grant_records)
        # Individually changing the operation or its prior state is rejected by
        # the closed contract itself as well as by consumption.
        self.assertEqual(contract_rejected, {"operation", "expected_prior_state"})

    def _assert_not_authoritative(self, supervisor, key, receipt):
        frames = [frame for frame in supervisor.store._durable
                  if frame["event"].get("object_key") == key]
        with self.assertRaises(AuthorizationDenied):
            supervisor._verify_publication_receipts(None, receipt)
        self._assert_no_verified_view(supervisor, key)
        restarted = _restart(supervisor)
        self.assertTrue(restarted.reconstruction_violations)
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(AuthorizationDenied):
            restarted._verify_publication_receipts(None, receipt)
        self._assert_no_verified_view(restarted, key)
        self.assertTrue(frames)  # retained, never deleted

    def _assert_no_verified_view(self, supervisor, key):
        """Snapshot and publisher views either fail closed or show no
        verification for ``key``."""
        try:
            records = supervisor.publication_snapshot(supervisor.publication_binding())
        except (AuthorizationDenied, StoreError):
            records = []
        self.assertNotIn("PUBLICATION_VERIFIED",
                         [record["state"] for record in records
                          if record.get("object_key") == key])
        try:
            publisher = ImmutablePublication(supervisor)
        except (EvidenceError, AuthorizationDenied, StoreError):
            return
        self.assertNotEqual(publisher._states.get(("dest-a", key)), "VERIFIED")
        self.assertFalse([receipt for (destination, object_key), receipt
                          in publisher._receipts.items() if object_key == key])

    def test_historical_record_result_and_proof_substitutions_are_not_provenanced(self):
        record_substitutes = {
            "intent_id": "publish-other",
            "destination": "dest-other",
            "object_key": "key-other",
            "object_digest": digest("other-object"),
            "length": len(SHARED_VALUE) + 1,
            "operation_id": "publication-grant-1",
            "operation": "durable",
            "prior_state": "PUBLICATION_WRITTEN",
            "window_epoch": 2,
            "authorization_digest": digest("foreign-authorization"),
            "campaign_id": "campaign-foreign",
            "boot_id": "boot-foreign",
            "boot_ordinal": 2,
            "closure_candidate_event_digest": digest("foreign-candidate"),
            "supervisor_generation": 99,
            "session_id": "session-foreign",
            "fence_epoch": 99,
        }
        self.assertEqual(tuple(record_substitutes), PUBLICATION_RECORD_BINDING_FIELDS)
        extra = {
            "record_type": ("record_type", "MEASUREMENT_WINDOW"),
            "authorizes_execution": ("authorizes_execution", True),
            "missing-operation-id": ("operation_id", None),
        }

        def verified_history():
            supervisor, _, _ = make_supervisor()
            intent = _direct_intent(object_key="history")
            grants, receipt = _publish_all(supervisor, intent)
            frame = _frame_by_state(supervisor.store, "PUBLICATION_VERIFIED", "history")
            self.assertTrue(supervisor.store.publication_record_provenanced(frame))
            return supervisor, grants[-1], receipt, frame

        for field, value in list(record_substitutes.items()) + list(extra.values()):
            with self.subTest(layer="record", field=field, value=value):
                supervisor, grant, receipt, frame = verified_history()
                records = supervisor.store._publication_grant_records

                def mutate(event, field=field, value=value):
                    if value is None:
                        event.pop(field)
                    else:
                        event[field] = value
                _rewrite_retained_record(supervisor.store, frame["event_id"], mutate,
                                         records, grant.grant_id)
                self.assertFalse(supervisor.store.publication_record_provenanced(
                    supervisor.store._durable[supervisor.store.frame_index(
                        frame["event_id"])]))
                self._assert_not_authoritative(supervisor, "history", receipt)
        for field in RESULT_BINDING_FIELDS:
            with self.subTest(layer="result", field=field):
                supervisor, grant, receipt, frame = verified_history()
                bound = supervisor.store._publication_grant_records[grant.grant_id]
                substitute = {"event_id": "publication-other-event",
                              "revision": bound.revision - 1,
                              "event_digest": digest("other-result")}[field]
                supervisor.store._publication_grant_records[grant.grant_id] = (
                    dataclasses.replace(bound, **{field: substitute}))
                # A retained V result index has no authority over the exact D/W result.
                self.assertTrue(supervisor.store.publication_record_provenanced(frame))
                self.assertEqual(ImmutablePublication(supervisor).reconcile(
                    _direct_intent(object_key="history")), receipt)
        store_cases = {
            "store_identity": lambda store, grant: store._publication_grants.__setitem__(
                grant.grant_id, PublicationOperationGrant(
                    dataclasses.replace(grant.binding, store_identity="store-foreign"),
                    dataclasses.replace(grant.binding,
                                        store_identity="store-foreign").attestation_digest())),
            "altered-attestation": lambda store, grant: store._publication_grants.__setitem__(
                grant.grant_id, PublicationOperationGrant(grant.binding,
                                                          digest("altered-attestation"))),
            "missing-result": lambda store, grant: store._publication_grant_records.pop(
                grant.grant_id),
            "missing-grant": lambda store, grant: store._publication_grants.pop(
                grant.grant_id),
            "unconsumed-grant": lambda store, grant: store._consumed_publication_grants.discard(
                grant.grant_id),
        }
        for label, tamper in store_cases.items():
            with self.subTest(layer="store", field=label):
                supervisor, grant, receipt, frame = verified_history()
                tamper(supervisor.store, grant)
                self.assertTrue(supervisor.store.publication_record_provenanced(frame))
                self.assertEqual(ImmutablePublication(supervisor).reconcile(
                    _direct_intent(object_key="history")), receipt)


class ConsolidatedWindowProvenanceTests(unittest.TestCase):
    """One validated window history serves transitions, reconstruction,
    issuance, consumption, and publication-chain validation."""

    def _assert_publication_denied(self, supervisor, key="denied"):
        with self.assertRaises(AuthorizationDenied):
            supervisor.issue_publication_grant(supervisor.publication_binding(), "intent",
                                               _direct_intent(object_key=key))

    def test_original_defect_unprovenanced_outside_after_dwell_cannot_reopen_publication(self):
        # Reproduction 2 (runnable on the inherited implementation, where the
        # retained record reconstructed as the current outside window).
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "window-defect", b"value")
        supervisor.set_measurement_window("DWELL")
        epoch = supervisor.window_epoch
        old_shape = {"record_type": "MEASUREMENT_WINDOW",
                     "window": "OUTSIDE_MEASURED_WINDOWS", "window_epoch": epoch + 1,
                     "authorization_digest": supervisor.authorization.authorization_digest,
                     "campaign_id": supervisor.authorization.campaign_id,
                     "supervisor_generation": supervisor.store._supervisor_generation,
                     "session_id": supervisor.session.session_id,
                     "fence_epoch": supervisor.session.fence_epoch}
        _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
                              "forged-window", old_shape)
        supervisor.store.crash()
        restarted = _restart(supervisor)
        self.assertIsNone(restarted.current_window)
        self.assertEqual(restarted.store.health, "QUARANTINED")
        self.assertEqual(restarted.window_epoch, 0)
        self.assertIn("unprovenanced-reserved-record:MEASUREMENT_WINDOW",
                      restarted.reconstruction_violations)
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(EvidenceError):
            ImmutablePublication(restarted).exclusive_create(intent)
        self._assert_publication_denied(restarted)
        self.assertEqual(sum(1 for event in restarted.store.events
                             if event.get("window_epoch") == epoch + 1), 1)

    def test_outside_dwell_outside_with_restart_permits_publication_only_at_final_epoch(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "final-epoch", b"value")
        early = supervisor.issue_publication_grant(supervisor.publication_binding(), "create",
                                                   intent)
        supervisor.set_measurement_window("DWELL")
        self._assert_publication_denied(supervisor)
        with self.assertRaises(EvidenceError):
            publisher.exclusive_create(intent)
        supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        operations = [frame["event"] for frame in _window_frames(store)]
        self.assertEqual([(event["previous_window"], event["previous_window_epoch"],
                           event["window"], event["window_epoch"]) for event in operations],
                         [(None, 0, "OUTSIDE_MEASURED_WINDOWS", 1),
                          ("OUTSIDE_MEASURED_WINDOWS", 1, "DWELL", 2),
                          ("DWELL", 2, "OUTSIDE_MEASURED_WINDOWS", 3)])
        self.assertEqual({event["operation"] for event in operations},
                         {"set-measurement-window"})
        self.assertEqual(len({event["operation_id"] for event in operations}), 3)
        store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.reconstruction_violations, [])
        self.assertEqual((restarted.current_window, restarted.window_epoch),
                         ("OUTSIDE_MEASURED_WINDOWS", 3))
        with self.assertRaises(AuthorizationDenied):
            restarted.perform_publication(restarted.publication_binding(), early, intent)
        recovered = ImmutablePublication(restarted)
        with self.assertRaises(EvidenceError):
            recovered.exclusive_create(intent)
        # Retain the final-epoch positive on uninterrupted current membership.
        live, _, _ = make_supervisor()
        publisher = ImmutablePublication(live)
        intent = publisher.intent("dest", "final-epoch", b"value")
        live.set_measurement_window("DWELL")
        live.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        publisher.exclusive_create(intent)
        created = _frame_by_state(live.store, "EXCLUSIVE_CREATE", "final-epoch")["event"]
        self.assertEqual(created["window_epoch"], 3)

    def _dwell_then_outside(self):
        supervisor, _, _ = make_supervisor()
        supervisor.set_measurement_window("DWELL")
        supervisor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        return supervisor, _window_frames(supervisor.store)[-1]

    def _assert_window_not_authorizing(self, supervisor, frame_event_id):
        store = supervisor.store
        frame = store._durable[store.frame_index(frame_event_id)]
        self.assertFalse(store.window_record_provenanced(frame))
        self._assert_publication_denied(supervisor)
        restarted = _restart(supervisor)
        self.assertTrue(restarted.reconstruction_violations)
        self.assertIsNone(restarted.current_window)
        self.assertTrue(restarted.store.publication_prohibited)
        self._assert_publication_denied(restarted)
        self.assertIn(frame_event_id, [item["event_id"] for item in store._durable])

    def test_each_window_binding_field_substitution_is_rejected(self):
        contract_rejected = set()
        for field in WINDOW_BINDING_FIELDS:
            with self.subTest(layer="registered-operation", field=field):
                supervisor, frame = self._dwell_then_outside()
                store = supervisor.store
                operation_id = frame["event"]["operation_id"]
                transition = store._window_operations[operation_id]
                substitute = {
                    "store_identity": "store-foreign",
                    "operation_id": "window-operation-99",
                    "operation": "set-other-window",
                    "event_id": "measurement-window-operation-99",
                    "previous_window": "MEASURED_PREPARATION",
                    "previous_window_epoch": transition.previous_window_epoch + 1,
                    "window": "RESIDUAL_CLEARANCE",
                    "window_epoch": transition.window_epoch + 1,
                    "authorization_digest": digest("foreign-authorization"),
                    "campaign_id": "campaign-foreign",
                    "supervisor_generation": transition.supervisor_generation + 1,
                    "session_id": "session-foreign",
                    "fence_epoch": transition.fence_epoch + 1,
                }[field]
                forged, rejected = _forced(transition, **{field: substitute})
                if rejected:
                    contract_rejected.add(field)
                store._window_operations[operation_id] = forged
                self.assertTrue(store.window_record_provenanced(frame))
                self.assertEqual(supervisor.current_window, "OUTSIDE_MEASURED_WINDOWS")
                self.assertTrue(supervisor.issue_publication_grant(
                    supervisor.publication_binding(), "intent", _direct_intent(object_key="cache-proof")))
        self.assertEqual(contract_rejected,
                         {"operation", "previous_window_epoch", "window_epoch"})
        record_substitutes = {
            "operation_id": "window-operation-1",
            "operation": "set-other-window",
            "previous_window": "MEASURED_PREPARATION",
            "previous_window_epoch": 1,
            "window": "RESIDUAL_CLEARANCE",
            "window_epoch": 4,
            "authorization_digest": digest("foreign-authorization"),
            "campaign_id": "campaign-foreign",
            "supervisor_generation": 99,
            "session_id": "session-foreign",
            "fence_epoch": 99,
        }
        self.assertEqual(tuple(record_substitutes), WINDOW_RECORD_BINDING_FIELDS)
        extra = [("record_type", "FORENSIC_NOTE"), ("authorizes_execution", True),
                 ("operation_id", None)]
        for field, value in list(record_substitutes.items()) + extra + [("event_id", None)]:
            with self.subTest(layer="record", field=field, value=value):
                supervisor, frame = self._dwell_then_outside()
                store = supervisor.store
                operation_id = frame["event"]["operation_id"]
                new_event_id = "measurement-substituted" if field == "event_id" else None

                def mutate(event, field=field, value=value):
                    if field == "event_id":
                        return
                    if value is None:
                        event.pop(field)
                    else:
                        event[field] = value
                _rewrite_retained_record(store, frame["event_id"], mutate,
                                         store._window_results, operation_id,
                                         new_event_id=new_event_id)
                self._assert_window_not_authorizing(supervisor,
                                                    new_event_id or frame["event_id"])
        for field in RESULT_BINDING_FIELDS:
            with self.subTest(layer="result", field=field):
                supervisor, frame = self._dwell_then_outside()
                store = supervisor.store
                operation_id = frame["event"]["operation_id"]
                bound = store._window_results[operation_id]
                store._window_results[operation_id] = dataclasses.replace(bound, **{
                    field: {"event_id": "measurement-other",
                            "revision": bound.revision - 1,
                            "event_digest": digest("other-window-result")}[field]})
                self.assertTrue(store.window_record_provenanced(frame))
                self.assertEqual(supervisor.current_window, "OUTSIDE_MEASURED_WINDOWS")
        for label in ("missing-result", "missing-operation"):
            with self.subTest(layer="proof", field=label):
                supervisor, frame = self._dwell_then_outside()
                store = supervisor.store
                operation_id = frame["event"]["operation_id"]
                (store._window_results if label == "missing-result"
                 else store._window_operations).pop(operation_id)
                self.assertTrue(store.window_record_provenanced(frame))
                self.assertEqual(supervisor.current_window, "OUTSIDE_MEASURED_WINDOWS")

    def test_window_partial_operation_stages_deny_publication_without_fallback(self):
        for stage in ("registered-before-append", "append-acknowledgement-lost",
                      "appended-before-result-binding"):
            with self.subTest(stage=stage):
                supervisor, _, _ = make_supervisor()
                store = supervisor.store
                self.assertEqual((supervisor.current_window, supervisor.window_epoch),
                                 ("OUTSIDE_MEASURED_WINDOWS", 1))
                original_append = store._append_window_result
                if stage == "registered-before-append":
                    def interrupted(authority, transition, fault=None, **kwargs):
                        return original_append(authority, transition, fault="before_reservation", **kwargs)
                    store._append_window_result = interrupted
                elif stage == "append-acknowledgement-lost":
                    store._append_window_result = (
                        lambda authority, transition, fault=None, **kwargs:
                        original_append(authority, transition, fault="commit_before_ack", **kwargs))
                else:
                    def unbound(authority, operation_id, receipt, **kwargs):
                        raise StoreError("interrupted before result binding")
                    store._bind_window_result = unbound
                with self.assertRaises(StoreError):
                    supervisor.set_measurement_window("DWELL")
                store.__dict__.pop("_append_window_result", None)
                store.__dict__.pop("_bind_window_result", None)
                pending = [operation_id for operation_id in store._window_operations
                           if operation_id not in store._window_results]
                self.assertEqual(len(pending), 1)
                # No fallback to the earlier outside window.
                self.assertIsNone(supervisor.current_window)
                self.assertTrue(store.publication_prohibited)
                self._assert_publication_denied(supervisor)
                dwell = [frame for frame in _window_frames(store)
                         if frame["event"]["window"] == "DWELL"]
                self.assertEqual(len(dwell), 0 if stage == "registered-before-append" else 1)
                store.crash()
                restarted = _restart(supervisor)
                # V registration is not a pending transaction. Only complete
                # witnessed D history survives; no history restores a live port.
                self.assertEqual(restarted.current_window,
                    "OUTSIDE_MEASURED_WINDOWS" if stage == "registered-before-append" else "DWELL")
                self.assertEqual(restarted.window_epoch, 1 if stage == "registered-before-append" else 2)
                self.assertFalse(restarted.session.execution_live)
                self.assertTrue(restarted.store.publication_prohibited)
                self._assert_publication_denied(restarted)
                with self.assertRaises(AuthorizationDenied):
                    restarted.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")

    def test_bound_window_result_interrupted_before_exposure_recovers_exact_history(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        original_bind = store._bind_window_result

        def bind_then_interrupt(authority, operation_id, receipt, **kwargs):
            original_bind(authority, operation_id, receipt, **kwargs)
            raise RuntimeError("interrupted after result binding")
        store._bind_window_result = bind_then_interrupt
        with self.assertRaises(RuntimeError):
            supervisor.set_measurement_window("DWELL")
        store.__dict__.pop("_bind_window_result")
        self.assertIsNone(supervisor.current_window)
        self.assertTrue(store.publication_prohibited)
        window_records = len(_window_frames(store))
        store.crash()
        restarted = _restart(supervisor)
        self.assertEqual((restarted.current_window, restarted.window_epoch), ("DWELL", 2))
        self.assertFalse([reason for reason in restarted.reconstruction_violations
                          if "window" in reason])
        self.assertEqual(len(_window_frames(store)), window_records)
        # Historical reconciliation does not clear the sticky prohibition.
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(AuthorizationDenied):
            restarted.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")

    def test_smuggled_measurement_window_through_control_seam_cannot_reopen_publication(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "seam-smuggle", b"value")
        supervisor.set_measurement_window("DWELL")
        current = next(frame["event"] for frame in reversed(_window_frames(supervisor.store)))
        lookalike = dict(current)
        lookalike.update({"operation_id": "window-operation-%d" % (
                              supervisor.store._window_operation_sequence + 1),
                          "previous_window": "DWELL",
                          "previous_window_epoch": current["window_epoch"],
                          "window": "OUTSIDE_MEASURED_WINDOWS",
                          "window_epoch": current["window_epoch"] + 1})
        with self.assertRaises(AuthorizationDenied):
            supervisor.store._append_control(
                supervisor.store.revision, supervisor.session.fence_epoch,
                "measurement-" + lookalike["operation_id"], lookalike)
        _append_unprovenanced(supervisor.store, supervisor.session.fence_epoch,
            "measurement-" + lookalike["operation_id"], lookalike)
        restarted = _restart(supervisor)
        self.assertIsNone(restarted.current_window)
        self.assertIn("unprovenanced-reserved-record:MEASUREMENT_WINDOW",
                      restarted.reconstruction_violations)
        with self.assertRaises(EvidenceError):
            ImmutablePublication(restarted).exclusive_create(intent)


class ConsolidatedInitializationTests(unittest.TestCase):
    def test_fresh_admission_establishes_provenanced_initial_outside_epoch(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        frames = _window_frames(store)
        self.assertEqual(len(frames), 1)
        initial = frames[0]["event"]
        self.assertEqual(initial["record_type"], "MEASUREMENT_WINDOW")
        self.assertIs(initial["authorizes_execution"], False)
        self.assertEqual(initial["operation"], "set-measurement-window")
        self.assertEqual((initial["previous_window"], initial["previous_window_epoch"],
                          initial["window"], initial["window_epoch"]),
                         (None, 0, "OUTSIDE_MEASURED_WINDOWS", 1))
        self.assertEqual(store._initial_window_operations, {initial["operation_id"]})
        admitted = next(index for index, event in enumerate(store.events)
                        if event.get("state") == "CAMPAIGN_ADMITTED")
        self.assertLess(admitted, store.frame_index(frames[0]["event_id"]))
        self.assertIsNone(store._initialization_token)
        recovered = supervisor
        for index in range(3):
            store.crash()
            recovered = _restart(recovered)
            self.assertEqual(recovered.reconstruction_violations, [])
            self.assertEqual((recovered.current_window, recovered.window_epoch),
                             ("OUTSIDE_MEASURED_WINDOWS", 1))
            with self.assertRaises(AuthorizationDenied):
                recovered.issue_publication_grant(
                    recovered.publication_binding(), "intent",
                    _direct_intent(object_key="fresh-%d" % index))
        self.assertEqual(len(_window_frames(store)), 1)

    def test_empty_unadmitted_store_is_uninitialized_and_non_authorizing(self):
        supervisor = _unadmitted_supervisor()
        store = supervisor.store
        exact = tuple(f['bytes'] for f in store._durable)
        for current in (supervisor, _restart(supervisor), _restart(_restart(supervisor))):
            self.assertEqual((current.current_window, current.window_epoch), (None, 0))
            self.assertFalse(current.session.execution_live)
            with self.assertRaises(AuthorizationDenied):
                current.issue_publication_grant(current.publication_binding(), "intent",
                                                _direct_intent(object_key="unadmitted"))
            with self.assertRaises(AuthorizationDenied):
                current.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        self.assertEqual(tuple(f['bytes'] for f in store._durable), exact)
        self.assertEqual(store._window_operations, {})
        # Burned ENTRY cannot be restarted into fresh admission.
        admitted = _restart(supervisor)
        with self.assertRaises(AuthorizationDenied):
            admitted.admit_campaign(activation())
        live = _unadmitted_supervisor()
        live.admit_campaign(activation())
        self.assertEqual((live.current_window, live.window_epoch),
                         ("OUTSIDE_MEASURED_WINDOWS", 1))

    def test_initialization_eligibility_is_established_before_admission_writes_only(self):
        supervisor = _unadmitted_supervisor()
        store = supervisor.store
        with self.assertRaises(AuthorizationDenied):
            store.append_nonauthorizing(supervisor.session.fence_epoch, "prior-note",
                                        {"record_type": "FORENSIC_NOTE"})
        inject_untrusted_record(store, supervisor.session.fence_epoch, "prior-note",
                                {"record_type": "FORENSIC_NOTE"})
        revision = store.revision
        with self.assertRaises(StoreError):
            supervisor.admit_campaign(activation())
        self.assertEqual(store.revision, revision)
        self.assertIsNone(supervisor.campaign_state)
        fresh = _unadmitted_supervisor()
        initial = MeasurementWindowTransition(
            fresh.store.identity, "set-measurement-window", "window-operation-1",
            "measurement-window-operation-1", None, 0, "OUTSIDE_MEASURED_WINDOWS", 1,
            fresh.authorization.authorization_digest, fresh.authorization.campaign_id,
            fresh.store._supervisor_generation, fresh.session.session_id,
            fresh.session.fence_epoch)
        for token in (None, object()):
            with self.subTest(token=token), self.assertRaises(StoreError):
                fresh.store._register_window_operation(_DEDICATED_AUTHORITY, initial,
                                                       initialization=token)
        with self.assertRaises(AuthorizationDenied):
            fresh.store._begin_window_initialization(object())
        self.assertEqual(fresh.store._window_operations, {})

    def test_interrupted_admission_is_never_completed_by_reconstruction(self):
        for stage in ("before-initial-registration", "initial-registered-before-append",
                      "initial-appended-before-result-binding"):
            with self.subTest(stage=stage):
                supervisor = _unadmitted_supervisor()
                store = supervisor.store
                commit = store._commit_u04
                fault = {'before-initial-registration': 'before_reservation',
                         'initial-registered-before-append': 'frame_before_readback',
                         'initial-appended-before-result-binding': 'commit_before_ack'}[stage]
                def interrupted(actor, boundary, event, **kwargs):
                    if boundary == 'INIT' and event.get('record_type') == 'MEASUREMENT_WINDOW':
                        kwargs['fault'] = fault
                    return commit(actor, boundary, event, **kwargs)
                store._commit_u04 = interrupted
                with self.assertRaises((RuntimeError, StoreError)):
                    supervisor.admit_campaign(activation())
                del store._commit_u04
                self.assertIsNone(store._initialization_token)
                self.assertEqual(store._window_results, {})
                with self.assertRaises(AuthorizationDenied):
                    supervisor.issue_publication_grant(
                        supervisor.publication_binding(), "intent",
                        _direct_intent(object_key="interrupted"))
                store.crash()
                restarted = _restart(supervisor)
                self.assertFalse(restarted.session.execution_live)
                self.assertEqual(len(_window_frames(store)), 0 if fault == 'before_reservation' else 1)
                self.assertEqual(restarted.custodian.underlying_create_count_for_all(), 0)
                self.assertTrue(restarted.store.publication_prohibited)
                with self.assertRaises(AuthorizationDenied):
                    restarted.issue_publication_grant(
                        restarted.publication_binding(), "intent",
                        _direct_intent(object_key="interrupted"))
                with self.assertRaises((ContractError, AuthorizationDenied)):
                    restarted.admit_campaign(activation())
                self.assertFalse(restarted.session.execution_live)

    def test_old_history_missing_window_provenance_is_retained_and_never_upgraded(self):
        supervisor = _unadmitted_supervisor()

        commit = supervisor.store._commit_u04
        def crash(actor, boundary, event, **kwargs):
            if boundary == 'INIT' and event.get('record_type') == 'MEASUREMENT_WINDOW':
                kwargs['fault'] = 'before_reservation'
            return commit(actor, boundary, event, **kwargs)
        supervisor.store._commit_u04 = crash
        with self.assertRaises(StoreError):
            supervisor.admit_campaign(activation())
        del supervisor.store._commit_u04
        store = supervisor.store
        old_shape = {"record_type": "MEASUREMENT_WINDOW",
                     "window": "OUTSIDE_MEASURED_WINDOWS", "window_epoch": 1,
                     "authorization_digest": supervisor.authorization.authorization_digest,
                     "campaign_id": supervisor.authorization.campaign_id,
                     "supervisor_generation": store._supervisor_generation,
                     "session_id": supervisor.session.session_id,
                     "fence_epoch": supervisor.session.fence_epoch}
        _append_unprovenanced(store, supervisor.session.fence_epoch, "window-1", old_shape)
        recovered = supervisor
        for _ in range(2):
            store.crash()
            recovered = _restart(recovered)
            self.assertIn("unprovenanced-reserved-record:MEASUREMENT_WINDOW",
                          recovered.reconstruction_violations)
            self.assertEqual(store.health, 'QUARANTINED')
            self.assertEqual((recovered.current_window, recovered.window_epoch), (None, 0))
            with self.assertRaises(AuthorizationDenied):
                recovered.issue_publication_grant(
                    recovered.publication_binding(), "intent",
                    _direct_intent(object_key="old-history"))
        self.assertEqual([frame["event"] for frame in _window_frames(store)],
                         [dict(old_shape, authorizes_execution=False)])
        self.assertEqual(store._window_operations, {})
        self.assertEqual(store._window_results, {})


PARTIAL_PUBLICATION_STAGES = (
    "after-consumption", "after-object-operation", "append-acknowledgement-lost",
    "appended-before-result-binding",
)


def _interrupt_publication(store, stage):
    if stage == "after-consumption":
        original = store._consume_publication_grant

        def consume(authority, grant, **kwargs):
            original(authority, grant, **kwargs)
            raise StoreError("interrupted after consumption")
        store._consume_publication_grant = consume
    elif stage == "after-object-operation":
        def append(authority, grant, event_id, event, **kwargs):
            raise StoreError("interrupted after the object operation, before append")
        store._append_publication_result = append
    elif stage == "append-acknowledgement-lost":
        original = store._append_publication_result

        def append(authority, grant, event_id, event, **kwargs):
            raise LostAcknowledgement(original(authority, grant, event_id, event, **kwargs))
        store._append_publication_result = append
    else:
        def bind(authority, grant_id, receipt, **kwargs):
            raise StoreError("interrupted before result binding")
        store._bind_publication_grant = bind


def _restore_publication(store):
    for name in ("_consume_publication_grant", "_append_publication_result",
                 "_bind_publication_grant"):
        store.__dict__.pop(name, None)


class ConsolidatedPartialPublicationTests(unittest.TestCase):
    def test_interrupted_publication_retains_consumption_and_never_fabricates_a_result(self):
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            for stage in PARTIAL_PUBLICATION_STAGES:
                with self.subTest(operation=operation, stage=stage):
                    supervisor, _, _ = make_supervisor()
                    store = supervisor.store
                    key = "partial-%s-%s" % (operation, stage)
                    intent = _direct_intent(object_key=key)
                    _advance_publication(supervisor, intent, operation)
                    binding = supervisor.publication_binding()
                    grant = supervisor.issue_publication_grant(binding, operation, intent)
                    _interrupt_publication(store, stage)
                    try:
                        with self.assertRaises(StoreError):
                            supervisor.perform_publication(
                                binding, grant, intent,
                                payload=_operation_payload(operation, intent))
                    finally:
                        _restore_publication(store)
                    appended = [frame for frame in store._durable
                                if frame["event"].get("operation_id") == grant.grant_id and
                                json.loads(frame['envelope'].authority_fact_bytes).get('publication_grant', {}).get('phase') == 'RESULT']
                    self.assertEqual(len(appended), 1 if stage in (
                        "append-acknowledgement-lost",
                        "appended-before-result-binding") else 0)
                    for frame in appended:
                        self.assertEqual(store.publication_record_provenanced(frame),
                                         stage == 'appended-before-result-binding')
                    self.assertEqual(store.publication_grant_consumed(grant.grant_id),
                                     stage != 'after-consumption')
                    self.assertEqual(supervisor.custodian._publication_counts.get(grant.grant_id, 0),
                                     0 if stage == 'after-consumption' else 1)
                    self.assertNotIn(grant.grant_id, store._publication_grant_records)
                    self.assertTrue(store.publication_prohibited)
                    self.assertTrue(store.execution_revoked)
                    with self.assertRaises(AuthorizationDenied):
                        supervisor.perform_publication(
                            binding, grant, intent,
                            payload=_operation_payload(operation, intent))
                    with self.assertRaises(AuthorizationDenied):
                        supervisor.issue_publication_grant(binding, operation, intent)
                    store.crash()
                    restarted = _restart(supervisor)
                    self.assertFalse(restarted.session.execution_live)
                    self.assertEqual(store.publication_grant_consumed(grant.grant_id),
                                     stage != 'after-consumption')
                    self.assertNotIn(grant.grant_id, store._publication_grant_records)
                    self.assertTrue(restarted.store.publication_prohibited)
                    self.assertEqual(bool([frame for frame in store._durable
                                      if frame["event"].get("object_key") == key and
                                      frame["event"].get("state") ==
                                      PUBLICATION_STATE_FOR[operation] and
                                      store.publication_record_provenanced(frame)]),
                                     stage == 'appended-before-result-binding')
                    with self.assertRaises(AuthorizationDenied):
                        restarted.issue_publication_grant(
                            restarted.publication_binding(), operation, intent)
                    receipt = PublicationReceipt(
                        "publication-receipt-" + intent.object_digest[:16],
                        intent.destination, intent.object_key, intent.object_digest,
                        intent.length, "PUBLICATION_VERIFIED", intent.object_digest)
                    if stage == 'appended-before-result-binding' and operation == 'verify':
                        self.assertEqual(restarted._verify_publication_receipts(None, receipt), (receipt,))
                    else:
                        with self.assertRaises(AuthorizationDenied):
                            restarted._verify_publication_receipts(None, receipt)
                    self.assertEqual(supervisor.custodian._publication_counts.get(grant.grant_id, 0),
                                     0 if stage == 'after-consumption' else 1)


class ConsolidatedCompletedHistoryTests(unittest.TestCase):
    def test_bound_publication_result_interrupted_before_response_recovers_read_only(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        intent = _direct_intent(object_key="bound-then-interrupted")
        _advance_publication(supervisor, intent, "verify")
        binding = supervisor.publication_binding()
        grant = supervisor.issue_publication_grant(binding, "verify", intent)
        original_bind = store._bind_publication_grant

        def bind_then_interrupt(authority, grant_id, receipt, **kwargs):
            original_bind(authority, grant_id, receipt, **kwargs)
            raise RuntimeError("interrupted before caller acknowledgement")
        store._bind_publication_grant = bind_then_interrupt
        try:
            with self.assertRaises(RuntimeError):
                supervisor.perform_publication(binding, grant, intent)
        finally:
            _restore_publication(store)
        self.assertIn(grant.grant_id, store._publication_grant_records)
        self.assertTrue(store.publication_prohibited)
        store.crash()
        restarted = _restart(supervisor)
        self.assertFalse([reason for reason in restarted.reconstruction_violations
                          if "publication" in reason])
        recovered = ImmutablePublication(restarted)
        receipt = recovered.reconcile(intent)
        # The interruption is after both independently observed typed result
        # and publication frame. Reconciliation is exact and read-only.
        self.assertEqual(receipt.state, "PUBLICATION_VERIFIED")
        self.assertEqual(restarted._verify_publication_receipts(None, receipt), (receipt,))
        self.assertEqual(len([event for event in _publication_records(restarted)
                              if event.get("state") == "PUBLICATION_VERIFIED"]), 1)
        # Read-only reconciliation never clears the prohibition.
        self.assertTrue(restarted.store.publication_prohibited)
        with self.assertRaises(EvidenceError):
            recovered.intent("dest", "after-failure", b"value")

    def test_verified_history_survives_new_supervisors_but_old_grants_cannot_mutate(self):
        supervisor, _, _ = make_supervisor()
        intent = _direct_intent(object_key="historical")
        grants, receipt = _publish_all(supervisor, intent)
        first = _frame_by_state(supervisor.store, "PUBLICATION_INTENT", "historical")
        restarted = _restart(supervisor)
        newest = _restart(restarted)
        self.assertGreater(newest._supervisor_generation,
                           first["event"]["supervisor_generation"])
        for current in (restarted, newest):
            self.assertEqual(current.reconstruction_violations, [])
            self.assertTrue(current.store.publication_record_provenanced(first))
        self.assertEqual(newest._verify_publication_receipts(None, receipt), (receipt,))
        self.assertEqual(ImmutablePublication(newest).reconcile(intent), receipt)
        binding = newest.publication_binding()
        for grant in grants:
            with self.subTest(grant=grant.grant_id), self.assertRaises(AuthorizationDenied):
                newest.perform_publication(binding, grant, intent,
                                           payload=_operation_payload(grant.operation, intent))
        other = _direct_intent(object_key="after-restart")
        for stale in (supervisor, restarted):
            with self.assertRaises(AuthorizationDenied):
                stale.issue_publication_grant(stale.publication_binding(), "intent", other)
        with self.assertRaises(AuthorizationDenied):
            newest.issue_publication_grant(binding, 'intent', other)
        live, _, _ = make_supervisor()
        binding = live.publication_binding()
        fresh = live.issue_publication_grant(binding, 'intent', other)
        with self.assertRaises(AuthorizationDenied):
            supervisor.perform_publication(supervisor.publication_binding(), fresh, other,
                                           payload=other.bytes)
        self.assertFalse(live.store.publication_grant_consumed(fresh.grant_id))
        live.perform_publication(binding, fresh, other, payload=other.bytes)
        self.assertFalse(live.store.publication_prohibited)


class ConsolidatedDownstreamClosureTests(unittest.TestCase):
    """Snapshots, receipts, and boot/campaign closure consume the same
    validated publication chain and window history."""

    def _publication_tampers(self, store, frame, grant_id, window_frame):
        records = store._publication_grant_records

        def record(field, value):
            return lambda: _rewrite_retained_record(
                store, frame["event_id"], lambda event: event.update({field: value}),
                records, grant_id)

        def window_result():
            operation_id = window_frame["event"]["operation_id"]
            # Conflict in witnessed history, not deletion of a derived V index.
            return _rewrite_retained_record(store, window_frame['event_id'],
                lambda event: event.update(window='DWELL'), store._window_results, operation_id)
        return {
            "destination": record("destination", "dest-other"),
            "object_key": record("object_key", "key-other"),
            "intent_id": record("intent_id", "publish-other"),
            "window-provenance": window_result,
        }

    def test_invalid_identity_or_window_provenance_prevents_boot_closure(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        record_all_local_attempts(supervisor)
        candidate = supervisor.finalize_boot_closure_candidate(
            {"boot_id": supervisor.current_boot_id, "objects": ["attempts", "custody"]})
        publisher = ImmutablePublication(supervisor)
        receipts = []
        for index, value in enumerate(_closure_values(candidate)):
            intent = publisher.intent("offline-destination", "boot-1-object-%d" % index,
                                      value)
            publisher.exclusive_create(intent)
            publisher.write_durable(intent, value)
            receipts.append(publisher.verify(intent))
        receipts = tuple(receipts)
        frame = _frame_by_state(store, "PUBLICATION_VERIFIED", "boot-1-object-0")
        grant_id = frame["event"]["operation_id"]
        candidate_frame = supervisor._candidate_frame("BOOT_CLOSURE_CANDIDATE_FINALIZED", 1)
        from acer_adapter_fakes import independent_fault_world
        seed = supervisor
        for label in ('destination', 'object_key', 'intent_id', 'window-provenance'):
            with self.subTest(label=label):
                supervisor = independent_fault_world(seed)
                store = supervisor.store
                current_frame = _frame_by_state(store, "PUBLICATION_VERIFIED", "boot-1-object-0")
                candidate_frame = supervisor._candidate_frame("BOOT_CLOSURE_CANDIDATE_FINALIZED", 1)
                tamper = self._publication_tampers(store, current_frame, grant_id, _window_frames(store)[0])[label]
                restore = tamper()
                try:
                    with self.assertRaises(AuthorizationDenied):
                        supervisor._verify_publication_receipts(candidate, receipts,
                                                                candidate_frame)
                    with self.assertRaises((AuthorizationDenied, StoreError)):
                        supervisor.publication_snapshot(supervisor.publication_binding())
                    with self.assertRaises(StoreError):
                        supervisor.complete_boot(candidate, receipts)
                    self.assertEqual(supervisor.boot_state, "BOOT_CLOSURE_CANDIDATE_FINALIZED")
                    self.assertFalse(_states(supervisor, "BOOT_COMPLETE"))
                finally:
                    restore()
        # Valid control: candidate -> publication -> completion reconstructs.
        supervisor, store = seed, seed.store
        closure = supervisor.complete_boot(candidate, receipts)
        store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.reconstruction_violations, [])
        self.assertEqual(restarted.boot_state, "BOOT_COMPLETE")
        self.assertEqual(restarted.store.validated_boot_closure(1), closure)
        # Invalid provenance in retained history prevents closure reconstruction.
        frame = _frame_by_state(store, "PUBLICATION_VERIFIED", "boot-1-object-0")
        tampers = self._publication_tampers(store, frame, grant_id, _window_frames(store)[0])
        tampers["destination"]()
        rejected = _restart(restarted)
        self.assertEqual(store.health, 'QUARANTINED')
        self.assertNotEqual(rejected.boot_state, "BOOT_COMPLETE")
        with self.assertRaises(StoreError):
            rejected.store.validated_boot_closure(1)

    def test_invalid_publication_identity_prevents_campaign_closure(self):
        supervisor, _, _ = make_supervisor()
        store = supervisor.store
        boot_digests = []
        for boot in (1, 2, 3, 4):
            boot_digests.append(complete_boot(supervisor))
            if boot < 4:
                supervisor.begin_boot_handoff(boot + 1)
                supervisor.commit_planned_shutdown()
                supervisor.activate_next_boot(activation(
                    boot + 1, "boot-%d" % (boot + 1), boot_digests[-1],
                    activation_id="consolidated-activation-%d" % (boot + 1)))
                supervisor.establish_boot_custody("custody-%d" % (boot + 1), True, True)
                supervisor.complete_boot_custody()
        candidate = supervisor.finalize_campaign_closure_candidate(
            {"campaign_id": "campaign-1", "objects": boot_digests})
        publisher = ImmutablePublication(supervisor)
        receipts = []
        for index, value in enumerate(_closure_values(candidate)):
            intent = publisher.intent("dest", "consolidated-campaign-%d" % index, value)
            publisher.exclusive_create(intent)
            publisher.write_durable(intent, value)
            receipts.append(publisher.verify(intent))
        receipts = tuple(receipts)
        frame = _frame_by_state(store, "PUBLICATION_VERIFIED", "consolidated-campaign-0")
        grant_id = frame["event"]["operation_id"]
        from acer_adapter_fakes import independent_fault_world
        seed = supervisor
        for label in ('destination', 'object_key', 'intent_id', 'window-provenance'):
            with self.subTest(label=label):
                supervisor = independent_fault_world(seed)
                store = supervisor.store
                current_frame = _frame_by_state(store, "PUBLICATION_VERIFIED", "consolidated-campaign-0")
                tamper = self._publication_tampers(store, current_frame, grant_id, _window_frames(store)[0])[label]
                restore = tamper()
                try:
                    with self.assertRaises(StoreError):
                        supervisor.complete_campaign(candidate, receipts)
                    self.assertEqual(supervisor.campaign_state,
                                     "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED")
                finally:
                    restore()
        supervisor, store = seed, seed.store
        supervisor.complete_campaign(candidate, receipts)
        self.assertEqual(supervisor.campaign_state, "CAMPAIGN_COMPLETE")
        store.crash()
        restarted = _restart(supervisor)
        self.assertEqual(restarted.reconstruction_violations, [])
        self.assertEqual(restarted.campaign_state, "CAMPAIGN_COMPLETE")
        self._publication_tampers(store, frame, grant_id,
                                  _window_frames(store)[0])["object_key"]()
        rejected = _restart(restarted)
        self.assertEqual(store.health, 'QUARANTINED')
        self.assertNotEqual(rejected.campaign_state, "CAMPAIGN_COMPLETE")
        with self.assertRaises(StoreError):
            rejected.store.validated_campaign_closure()


class _ReleaseRecordingLock:
    """Wraps the store's authorization lock and records, at every outermost
    release, whether a started-but-unbound operation was already prohibited."""

    def __init__(self, store):
        self._lock = store.authorization_lock
        self._store = store
        self._baseline_revision = store.revision
        self._depth = 0
        self.releases = []

    def __enter__(self):
        self._lock.acquire()
        self._depth += 1
        return self

    def __exit__(self, *exc_info):
        self._depth -= 1
        if self._depth == 0:
            store = self._store
            unbound = (
                [grant_id for grant_id in store._consumed_publication_grants
                 if grant_id not in store._publication_grant_records] +
                [operation_id for operation_id in store._window_operations
                 if operation_id not in store._window_results])
            journaled_start = any(f['event'].get('record_type') in ('PUBLICATION', 'EFFECT_ACCEPTED')
                                  for f in store._durable[self._baseline_revision:])
            self.releases.append((bool(unbound) or journaled_start, store.publication_prohibited,
                                  store.execution_revoked))
        self._lock.release()
        return False


class ConsolidatedOrderingTests(unittest.TestCase):
    def test_started_operation_failure_is_prohibited_before_the_authorization_lock_is_released(self):
        cases = {
            "publication-before-result-binding": ("publication", "_bind_publication_grant"),
            "publication-after-object-operation": ("publication",
                                                   "_append_publication_result"),
            "window-before-result-binding": ("window", "_bind_window_result"),
            "window-before-append": ("window", "_append_window_result"),
        }
        for label, (family, method) in cases.items():
            with self.subTest(case=label):
                supervisor, _, _ = make_supervisor()
                store = supervisor.store
                intent = _direct_intent(object_key="ordering-" + label)
                _advance_publication(supervisor, intent, "create")
                binding = supervisor.publication_binding()
                grant = supervisor.issue_publication_grant(binding, "create", intent)
                recorder = _ReleaseRecordingLock(store)
                store.authorization_lock = recorder

                def interrupted(*args, **kwargs):
                    raise StoreError("interrupted")
                setattr(store, method, interrupted)
                try:
                    with self.assertRaises(StoreError):
                        if family == "publication":
                            supervisor.perform_publication(binding, grant, intent)
                        else:
                            supervisor.set_measurement_window("DWELL")
                finally:
                    store.__dict__.pop(method, None)
                    store.authorization_lock = recorder._lock
                started = [release for release in recorder.releases if release[0]]
                self.assertTrue(started)
                self.assertTrue(all(prohibited and revoked
                                    for _, prohibited, revoked in started), started)


class _TakeoverScheduleLock:
    """Observe a real failed nonblocking acquisition, then wait boundedly.

    No scheduling conclusion depends on a sleep or on a thread merely starting.
    The snapshot is taken after contention is demonstrated, before acquisition.
    """

    def __init__(self, store, watched_name):
        self.lock = store.authorization_lock
        self.store = store
        self.watched_name = watched_name
        self.contended = threading.Event()
        self.snapshot = None

    def acquire(self):
        if not self.lock.acquire(blocking=False):
            if threading.current_thread().name == self.watched_name:
                self.snapshot = (self.store._supervisor_generation,
                                 dict(self.store._sessions),
                                 self.store.bound_custodian()._loss_callback)
                self.contended.set()
            if not self.lock.acquire(timeout=5):
                raise AssertionError("authorization lock wait exceeded bound")
        return True

    def release(self):
        self.lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc_info):
        self.release()
        return False


class SupervisorTakeoverTests(unittest.TestCase):
    def _start(self, name, operation):
        outcome = {}

        def run():
            try:
                outcome["result"] = operation()
            except BaseException as exc:
                outcome["error"] = exc

        thread = threading.Thread(target=run, name=name, daemon=True)
        thread.start()
        return thread, outcome

    def _join(self, *threads):
        for thread in threads:
            thread.join(timeout=5)
        self.assertFalse([thread.name for thread in threads if thread.is_alive()],
                         "offline test threads did not finish")

    def _operation_first(self, family, operation="intent", *, entry="constructor",
                         stage="start"):
        old, _, custodian = make_supervisor()
        store = old.store
        intent = _direct_intent(object_key="takeover-" + operation)
        if family == "window":
            old.set_measurement_window("DWELL")
            method = "_register_window_operation"
            invoke = lambda: old.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
        else:
            _advance_publication(old, intent, operation)
            binding = old.publication_binding()
            grant = old.issue_publication_grant(binding, operation, intent)
            method = "_consume_publication_grant"
            invoke = lambda: old.perform_publication(
                binding, grant, intent, payload=_operation_payload(operation, intent))
        if stage == "bound":
            method = ("_bind_window_result" if family == "window"
                      else "_bind_publication_grant")
        before = (store._supervisor_generation, dict(store._sessions),
                  custodian._loss_callback)
        paused, release = threading.Event(), threading.Event()
        original = getattr(store, method)

        def pause(*args, **kwargs):
            if stage == "bound":
                result = original(*args, **kwargs)
            paused.set()
            if not release.wait(timeout=5):
                raise AssertionError("operation release exceeded bound")
            if stage != 'bound':
                result = original(*args, **kwargs)
            # The instrumentation is not a store field at the reset boundary.
            store.__dict__.pop(method, None)
            return result

        lock = _TakeoverScheduleLock(store, "successor")
        store.authorization_lock = lock
        successor_session = replace(old.session, session_id="successor-session")
        threads = []
        try:
            with mock.patch.object(type(store), method,
                    lambda current, *args, **kwargs: pause(*args, **kwargs)):
                worker, outcome = self._start("old-operation", invoke)
                threads.append(worker)
                self.assertTrue(paused.wait(timeout=5), "operation did not reach seam")
                take_over = (store.claim_supervisor if entry == "claim" else
                             lambda: PersistentSupervisor(
                                 store, old.verifier, custodian,
                                 old.authorization, successor_session))
                successor, takeover = self._start("successor", take_over)
                threads.append(successor)
                if entry == 'claim':
                    self._join(successor)
                    self.assertIsInstance(takeover.get('error'), AuthorizationDenied)
                    observed = before
                else:
                    self.assertTrue(lock.contended.wait(timeout=5),
                                    "successor did not contend on authorization lock")
                    observed = lock.snapshot
                release.set()
                self._join(*threads)
        finally:
            release.set()
            self._join(*threads)
            store.authorization_lock = lock.lock
            store.__dict__.pop(method, None)
        self.assertNotIn("error", outcome)
        if entry == "claim":
            self.assertEqual(store._supervisor_generation, before[0])
            self.assertFalse(store.execution_revoked)
            current = old
        else:
            self.assertNotIn("error", takeover)
            self.assertEqual(store._supervisor_generation, before[0] + 1)
            current = takeover["result"]
            self.assertFalse(current.session.execution_live)
        self.assertEqual(current.reconstruction_violations, [])
        self.assertEqual(current.current_window, "OUTSIDE_MEASURED_WINDOWS")
        if family == "publication":
            self.assertTrue(any(f['event'].get('operation_id') == grant.grant_id and
                store.publication_record_provenanced(f) for f in store._durable))
            for remaining in PUBLICATION_OPERATION_SEQUENCE[
                    PUBLICATION_OPERATION_SEQUENCE.index(operation) + 1:]:
                if entry == 'claim':
                    _perform(current, remaining, intent)
                else:
                    with self.assertRaises(AuthorizationDenied):
                        _perform(current, remaining, intent)
        else:
            if entry == 'claim':
                _publish_all(current, intent)
            else:
                with self.assertRaises(AuthorizationDenied):
                    _publish_all(current, intent)
        newest = _restart(current)
        self.assertEqual(newest.reconstruction_violations, [])
        if entry == 'claim' or (family == 'publication' and operation == 'verify'):
            self.assertEqual(ImmutablePublication(newest).reconcile(intent).state,
                             "PUBLICATION_VERIFIED")
        elif family == 'publication':
            self.assertEqual(ImmutablePublication(newest).reconcile(intent),
                {'intent': 'INTENT', 'create': 'RESERVED', 'write': 'WRITTEN', 'durable': 'DURABLE'}[operation])
        self.assertEqual(observed, before,
                         "takeover changed generation/session/custody during protected operation")

    def test_window_operation_finishes_before_takeover_can_advance_generation(self):
        self._operation_first("window")

    def test_publication_operation_finishes_before_takeover_can_advance_generation(self):
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            with self.subTest(operation=operation):
                self._operation_first("publication", operation)

    def test_bare_claim_waits_for_window_and_publication_operations(self):
        self._operation_first("window", entry="claim")
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            with self.subTest(operation=operation):
                self._operation_first("publication", operation, entry="claim")

    def test_takeover_waits_through_result_binding_and_window_exposure(self):
        self._operation_first("window", stage="bound")
        for operation in PUBLICATION_OPERATION_SEQUENCE:
            with self.subTest(operation=operation):
                self._operation_first("publication", operation, stage="bound")

    def test_takeover_first_denies_stale_window_and_publication_without_effects(self):
        for family in ("window", *PUBLICATION_OPERATION_SEQUENCE):
            with self.subTest(operation=family):
                old, _, _ = make_supervisor()
                store = old.store
                intent = _direct_intent()
                if family != "window":
                    _advance_publication(old, intent, family)
                    binding = old.publication_binding()
                    grant = old.issue_publication_grant(binding, family, intent)
                entered, release = threading.Event(), threading.Event()
                reconstruct = PersistentSupervisor._reconstruct

                def paused_reconstruct(current):
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("reconstruction release exceeded bound")
                    reconstruct(current)

                lock = _TakeoverScheduleLock(store, "stale-operation")
                store.authorization_lock = lock
                threads = []
                try:
                    with mock.patch.object(PersistentSupervisor, "_reconstruct",
                                           paused_reconstruct):
                        successor, takeover = self._start("successor", lambda: _restart(old))
                        threads.append(successor)
                        self.assertTrue(entered.wait(timeout=5))
                        before = (dict(store._objects), dict(old.custodian._publication_counts),
                                  tuple(f['bytes'] for f in _window_frames(store)),
                                  tuple(f['bytes'] for entries in supervisor_module._publication_frame_groups(store).values()
                                        for _, f in entries))
                        if family == "window":
                            invoke = lambda: old.set_measurement_window("DWELL")
                        else:
                            invoke = lambda: old.perform_publication(
                                binding, grant, intent,
                                payload=_operation_payload(family, intent))
                        worker, outcome = self._start("stale-operation", invoke)
                        threads.append(worker)
                        self.assertTrue(lock.contended.wait(timeout=5))
                        release.set()
                        self._join(*threads)
                finally:
                    release.set()
                    self._join(*threads)
                    store.authorization_lock = lock.lock
                self.assertNotIn("error", takeover)
                self.assertIsInstance(outcome.get("error"), AuthorizationDenied)
                self.assertEqual((dict(store._objects), dict(old.custodian._publication_counts),
                                  tuple(f['bytes'] for f in _window_frames(store)),
                                  tuple(f['bytes'] for entries in supervisor_module._publication_frame_groups(store).values()
                                        for _, f in entries)), before)

    def test_competing_successors_serialize_reconstruction_and_custody_binding(self):
        old, _, custodian = make_supervisor()
        store = old.store
        entered, release = threading.Event(), threading.Event()
        reconstruct = PersistentSupervisor._reconstruct
        generations = []

        def paused_reconstruct(current):
            generations.append(current._supervisor_generation)
            if threading.current_thread().name == "first-successor":
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("first successor release exceeded bound")
            reconstruct(current)

        lock = _TakeoverScheduleLock(store, "second-successor")
        store.authorization_lock = lock
        threads = []
        try:
            with mock.patch.object(PersistentSupervisor, "_reconstruct", paused_reconstruct):
                first, first_outcome = self._start("first-successor", lambda: _restart(old))
                threads.append(first)
                self.assertTrue(entered.wait(timeout=5))
                first_generation = store._supervisor_generation
                first_callback = custodian._loss_callback
                second, second_outcome = self._start("second-successor", lambda: _restart(old))
                threads.append(second)
                self.assertTrue(lock.contended.wait(timeout=5))
                observed = lock.snapshot
                release.set()
                self._join(*threads)
        finally:
            release.set()
            self._join(*threads)
            store.authorization_lock = lock.lock
        self.assertNotIn("error", first_outcome)
        self.assertNotIn("error", second_outcome)
        self.assertEqual(observed[0], first_generation)
        self.assertEqual(observed[2], first_callback)
        # Reconstruction runs before a fresh non-executing ENTRY is allocated.
        self.assertEqual(generations, [1, 2])
        self.assertEqual(custodian._loss_callback.__self__, second_outcome["result"])
        with self.assertRaises(AuthorizationDenied):
            first_outcome["result"].set_measurement_window("DWELL")
        with self.assertRaises(AuthorizationDenied):
            second_outcome["result"].set_measurement_window("DWELL")

    def test_reconstruction_cannot_expose_authority_or_reenter_takeover(self):
        old, _, _ = make_supervisor()
        store = old.store
        reconstruct = PersistentSupervisor._reconstruct
        denials = []

        def direct_transition(current):
            # A legal first-slot transition through the lower authorization
            # boundary, bypassing the supervisor's early session check.
            return authorize_and_dispatch(
                store, current.verifier, store.revision, current.session.fence_epoch,
                current.session, "SLOT_SPAWN_ELIGIBLE",
                {"effect_id": "readiness-slot", "target": store.identity,
                 "operation": "make-slot-eligible", "event_id": "readiness-slot-event",
                 "event": {"slot_id": "slot-1-1", "attempt_id": "attempt-1-1",
                           "boot_id": "boot-1", "spawn_token": "spawn-slot-1-1",
                           "custodian_id": current.custodian.identity,
                           "predecessor_slot_id": None,
                           "predecessor_completion_digest": None}},
                lambda capability, binding: None,
                _authority=supervisor_module._DEDICATED_AUTHORITY)

        def inspect(current):
            reconstruct(current)
            # Even after replay, readiness must wait until the takeover finishes.
            actions = (
                current._ensure_session,
                lambda: current.set_measurement_window("DWELL"),
                lambda: current.issue_publication_grant(
                    current.publication_binding(), "intent", _direct_intent()),
                store.claim_supervisor,
                lambda: _restart(current),
                lambda: direct_transition(current),
            )
            # Nested construction must fail before entering reconstruction again.
            if len(denials):
                raise AssertionError("recursive reconstruction was entered")
            denials.append([])
            for action in actions:
                try:
                    action()
                except AuthorizationDenied:
                    denials[0].append(True)
                except BaseException:
                    denials[0].append(False)
                else:
                    denials[0].append(False)

        with mock.patch.object(PersistentSupervisor, "_reconstruct", inspect):
            current = _restart(old)
        self.assertEqual(denials, [[True] * 6])
        self.assertEqual(store._supervisor_generation, 2)
        self.assertTrue(store.execution_revoked)
        current.publication_snapshot(current.publication_binding())  # historical read only
        with self.assertRaises(AuthorizationDenied):
            direct_transition(current)
        with self.assertRaises(AuthorizationDenied):
            current.set_measurement_window("DWELL")

    def test_reentrant_takeover_is_denied_before_shared_state_changes(self):
        for entry in ("constructor", "claim"):
            for seam in ("window", "publication", "interlock", "verifier"):
                with self.subTest(entry=entry, seam=seam):
                    old, _, custodian = make_supervisor()
                    store = old.store
                    before = (store._supervisor_generation, dict(store._sessions),
                              custodian._loss_callback)
                    denials = []

                    def attempt_takeover():
                        try:
                            if entry == "claim":
                                store.claim_supervisor()
                            else:
                                PersistentSupervisor(
                                    store, old.verifier, custodian, old.authorization,
                                    replace(old.session, session_id="reentrant-session"))
                        except AuthorizationDenied:
                            denials.append(True)
                        else:
                            denials.append(False)

                    intent = _direct_intent()
                    binding = old.publication_binding()
                    grant = old.issue_publication_grant(binding, "intent", intent)
                    if seam == "interlock":
                        old.perform_publication(binding, grant, intent, intent.bytes,
                                                interlock=attempt_takeover)
                    else:
                        target, method = ((old.verifier, "verify") if seam == "verifier"
                                          else (store, "_register_window_operation")
                                          if seam == "window" else
                                          (store, "_consume_publication_grant"))
                        original = getattr(target, method)

                        def callback(*args, **kwargs):
                            attempt_takeover()
                            return original(*args, **kwargs)

                        with mock.patch.object(target, method, callback):
                            if seam == "window":
                                old.set_measurement_window("DWELL")
                            elif seam == "verifier":
                                old.make_slot_eligible("slot-1-1")
                            else:
                                old.perform_publication(binding, grant, intent, intent.bytes)
                    self.assertEqual(denials, [True])
                    self.assertEqual((store._supervisor_generation, store._sessions,
                                      custodian._loss_callback), before)
                    self.assertFalse(store.publication_prohibited)

    def test_takeover_failure_is_sticky_for_session_custody_and_reconstruction(self):
        for stage in ("session", "custody", "reconstruction"):
            for error_type in (RuntimeError, KeyboardInterrupt):
                with self.subTest(stage=stage, error=error_type.__name__):
                    old, _, custodian = make_supervisor()
                    store = old.store
                    target, method = {
                        "session": (store, "reset_volatile"),
                        "custody": (custodian, "bind_authority"),
                        "reconstruction": (PersistentSupervisor, "_reconstruct"),
                    }[stage]
                    with mock.patch.object(target, method, side_effect=error_type("interrupted")):
                        with self.assertRaises(error_type):
                            _restart(old)
                    self.assertTrue(store.execution_revoked)
                    self.assertTrue(store.publication_prohibited)
                    self.assertTrue(store.containment_only)
                    with self.assertRaises(AuthorizationDenied):
                        old.set_measurement_window("DWELL")
                    newest = _restart(old)
                    with self.assertRaises(AuthorizationDenied):
                        newest.issue_publication_grant(
                            newest.publication_binding(), "intent", _direct_intent())

    def test_bare_generation_claim_never_makes_authority_ready(self):
        old, _, _ = make_supervisor()
        store = old.store
        before = store.witness.high_generation
        with self.assertRaises(AuthorizationDenied):
            store.claim_supervisor()
        self.assertEqual(store.witness.high_generation, before)
        old.set_measurement_window("DWELL")  # rejected legacy call did not revoke genuine authority
        current = _restart(old)
        self.assertEqual(current.reconstruction_violations, [])
        with self.assertRaises(AuthorizationDenied):
            current.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")

    def test_interrupted_operation_installs_prohibition_before_waiting_takeover(self):
        for family in ("window", "publication"):
            for bound in (False, True):
                with self.subTest(family=family, bound=bound):
                    old, _, _ = make_supervisor()
                    store = old.store
                    intent = _direct_intent()
                    binding = old.publication_binding()
                    grant = old.issue_publication_grant(binding, "intent", intent)
                    method = ("_bind_window_result" if family == "window" else
                              "_bind_publication_grant")
                    original = getattr(store, method)
                    reconstruct = PersistentSupervisor._reconstruct
                    paused, release = threading.Event(), threading.Event()
                    latches_at_takeover = []

                    def interrupt(*args, **kwargs):
                        if bound:
                            original(*args, **kwargs)
                        paused.set()
                        if not release.wait(timeout=5):
                            raise AssertionError("failure release exceeded bound")
                        store.__dict__.pop(method, None)
                        raise KeyboardInterrupt("interrupted before operation return")

                    def inspect_latches(current):
                        # Check the sticky flags before replay can derive them.
                        latches_at_takeover.append((store._execution_revoked,
                                                   store._publication_prohibited))
                        return reconstruct(current)

                    lock = _TakeoverScheduleLock(store, "successor")
                    store.authorization_lock = lock
                    threads = []
                    try:
                        with mock.patch.object(type(store), method,
                                lambda current, *args, **kwargs: interrupt(*args, **kwargs)), mock.patch.object(
                                PersistentSupervisor, "_reconstruct", inspect_latches):
                            invoke = (lambda: old.set_measurement_window("DWELL")) if (
                                family == "window") else lambda: old.perform_publication(
                                    binding, grant, intent, intent.bytes)
                            worker, outcome = self._start("old-operation", invoke)
                            threads.append(worker)
                            self.assertTrue(paused.wait(timeout=5))
                            successor, takeover = self._start("successor", lambda: _restart(old))
                            threads.append(successor)
                            self.assertTrue(lock.contended.wait(timeout=5))
                            observed_generation = lock.snapshot[0]
                            release.set()
                            self._join(*threads)
                    finally:
                        release.set()
                        self._join(*threads)
                        store.authorization_lock = lock.lock
                        store.__dict__.pop(method, None)
                    self.assertEqual(observed_generation, old._supervisor_generation)
                    self.assertIsInstance(outcome.get("error"), KeyboardInterrupt)
                    self.assertNotIn("error", takeover)
                    self.assertEqual(latches_at_takeover, [(True, True)])
                    current = takeover["result"]
                    self.assertFalse(current.session.execution_live)
                    # Result binding is V bookkeeping after a committed kernel
                    # result. Both seams retain exact read-only D/W evidence.
                    self.assertEqual(store.witness.pending, {})
                    if family == "publication":
                        self.assertTrue(store.publication_grant_consumed(grant.grant_id))
                        self.assertTrue(any(f['event'].get('operation_id') == grant.grant_id and
                            store.publication_record_provenanced(f) for f in store._durable))
                    for survivor in (current, _restart(current)):
                        with self.assertRaises(AuthorizationDenied):
                            survivor.set_measurement_window("OUTSIDE_MEASURED_WINDOWS")
                        with self.assertRaises(AuthorizationDenied):
                            survivor.issue_publication_grant(
                                survivor.publication_binding(), "intent", _direct_intent())
