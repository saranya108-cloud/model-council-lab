import threading
import unittest

from tools.decision_0009.acer_adapter.supervisor import (
    CASMismatch, DuplicateEvent, LostAcknowledgement, OfflineDurableStore,
    OfflineWitness, Quarantined, StaleRead, StoreError,
)


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
            with self.subTest(fault=fault), self.assertRaises(Quarantined):
                store.append(0, fence, "event", {"fault": fault}, fault=fault)
            self.assertTrue(store.quarantined)
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
