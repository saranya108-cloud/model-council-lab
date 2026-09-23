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
        survivor = OfflineSurvivor("survivor-1", "survivor-authority", artifact_binding())
        transfer = self.custodian.export_survivor_ownership(self.token.token_id, survivor)
        self.custodian.die()
        evidence = survivor.contain_transferred(transfer, "contain-capability")
        self.assertEqual(evidence.actor_identity, "survivor-1")
        self.assertNotEqual(evidence.actor_identity, self.custodian.identity)
        self.assertTrue(evidence.custody_uncertain)

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
