from dataclasses import replace
import unittest

from tools.decision_0009.acer_adapter.contracts import ContractError
from tools.decision_0009.acer_adapter.evidence import (
    EvidenceError, ImmutablePublication, canonical_core_bytes,
)
from tools.decision_0009.acer_adapter.supervisor import AuthorizationDenied, DispatchUncertain
from acer_adapter_fakes import (
    artifact_binding, consumed_create_capability, digest, make_supervisor, spawn_token,
)


class ContainmentTests(unittest.TestCase):
    def test_watchdog_contains_blocked_worker_after_supervisor_loss(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        with self.assertRaises(DispatchUncertain):
            supervisor.spawn_worker("slot-1-1", digest("launch"),
                                    fault="crash_after_create")
        token = supervisor._slot_tokens["slot-1-1"]
        capability = supervisor.store.effect_capability("spawn-intent-slot-1-1")
        binding = capability.artifact_binding
        custodian.create_once(token, token.launch_spec_digest, capability, binding)
        evidence = custodian.watchdog_supervisor_lost(token.token_id, binding)
        self.assertEqual(evidence.action, "CONTAIN")
        self.assertEqual(custodian.inspect_spawn(token.token_id).status, "EXITED")
        self.assertIsNone(custodian.get_reap_receipt(token.token_id))
        receipt = custodian.wait_reap(token.token_id)
        self.assertEqual(receipt.spawn_token, token.token_id)

    def test_containment_does_not_create_successor_or_synthetic_clearance(self):
        supervisor, _, _ = make_supervisor()
        supervisor.record_custodian_loss("after-release")
        supervisor.record_failure("containment-only", b"worker may be live")
        with self.assertRaises(AuthorizationDenied):
            supervisor.make_slot_eligible("slot-1-2")
        self.assertFalse(supervisor.synthetic_reap)
        self.assertFalse(supervisor.synthetic_residual_clearance)

    def test_direct_ingestion_failure_installs_containment(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        with self.assertRaises(AuthorizationDenied):
            supervisor.persist_local_attempt_evidence("slot-1-1", b"not-json")
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertIn("TAINTED", supervisor.safety_markers)
        self.assertEqual(custodian.inspect_spawn(receipt.spawn_token).status, "EXITED")

    def test_direct_failure_recording_with_witness_outage_stays_prohibited(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        supervisor.store.witness.available = False
        with self.assertRaises(Exception):
            supervisor.record_failure("witness-outage", b"raw failure")
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertIn("TAINTED", supervisor.safety_markers)
        self.assertIn("witness-outage", supervisor.store.taint)
        self.assertEqual(custodian.inspect_spawn(receipt.spawn_token).status, "EXITED")

    def test_serializer_and_verifier_failure_cannot_block_authorized_cleanup(self):
        supervisor, artifacts, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
        artifacts.substitute("policy")
        with self.assertRaises(Exception):
            supervisor.run_contained(
                lambda: canonical_core_bytes({"bad": float("nan")}), b"bad")
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertEqual(custodian.inspect_spawn(receipt.spawn_token).status, "EXITED")

    def test_direct_lifecycle_verifier_failure_latches_before_publication_reporting(self):
        for publication_state in ("RESERVED", "WRITTEN", "DURABLE"):
            supervisor, artifacts, custodian = make_supervisor()
            publisher = ImmutablePublication(supervisor)
            intent = publisher.intent("dest", "failure-" + publication_state.lower(), b"value")
            publisher.exclusive_create(intent)
            if publication_state in ("WRITTEN", "DURABLE"):
                publisher.write(intent, b"value")
            if publication_state == "DURABLE":
                publisher.make_durable(intent)
            supervisor.make_slot_eligible("slot-1-1")
            receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
            artifacts.substitute("policy")
            with self.subTest(state=publication_state), self.assertRaises(AuthorizationDenied):
                supervisor.complete_worker_lifecycle("slot-1-1")
            self.assertTrue(supervisor.store.execution_revoked)
            self.assertTrue(supervisor.store.publication_prohibited)
            self.assertIn("authoritative-verification-failure", supervisor.store.taint)
            self.assertEqual(custodian.inspect_spawn(receipt.spawn_token).status, "EXITED")
            with self.assertRaises(EvidenceError):
                ({"RESERVED": lambda: publisher.write(intent, b"value"),
                  "WRITTEN": lambda: publisher.make_durable(intent),
                  "DURABLE": lambda: publisher.verify(intent)}[publication_state])()

    def test_failure_latch_precedes_malformed_or_oversized_diagnostics(self):
        for reason, raw in ((["malformed"], b"raw"),
                            ("oversized", b"x" * (1_048_576 + 1))):
            supervisor, _, _ = make_supervisor()
            with self.subTest(reason=reason), self.assertRaises(ContractError):
                supervisor.record_failure(reason, raw)
            self.assertTrue(supervisor.store.execution_revoked)
            self.assertTrue(supervisor.store.publication_prohibited)
            self.assertIn("reported-failure", supervisor.store.taint)

    def test_nested_containment_preserves_original_failure_when_cleanup_and_reporting_fail(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        original_contain = custodian.contain_spawn
        custodian.contain_spawn = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("cleanup failed"))
        supervisor.store.witness.available = False
        def fail():
            raise RuntimeError("original verifier failure")
        try:
            with self.assertRaisesRegex(RuntimeError, "original verifier failure"):
                supervisor.run_contained(lambda: supervisor.run_contained(fail))
        finally:
            custodian.contain_spawn = original_contain
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertIn("malformed-input", supervisor.store.taint)

    def test_one_cleanup_failure_does_not_prevent_other_cleanup_attempts(self):
        supervisor, _, custodian = make_supervisor()
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        first = supervisor._slot_tokens["slot-1-1"]
        second = replace(first, token_id="spawn-slot-1-2", slot_id="slot-1-2",
                         attempt_id="attempt-1-2")
        supervisor._slot_tokens = {"slot-1-1": first, "slot-1-2": second}
        inspected = []
        original_inspect = custodian.inspect_spawn
        original_contain = custodian.contain_spawn
        def inspect(token_id):
            inspected.append(token_id)
            return original_inspect(token_id)
        def contain(token_id, *args):
            if token_id == first.token_id:
                raise RuntimeError("first cleanup failed")
            return original_contain(token_id, *args)
        custodian.inspect_spawn = inspect
        custodian.contain_spawn = contain
        try:
            with self.assertRaisesRegex(RuntimeError, "original failure"):
                supervisor.run_contained(
                    lambda: (_ for _ in ()).throw(RuntimeError("original failure")))
        finally:
            custodian.inspect_spawn = original_inspect
            custodian.contain_spawn = original_contain
        self.assertEqual(inspected, [first.token_id, second.token_id])

    def test_publication_witness_failure_installs_sticky_prohibition(self):
        supervisor, _, _ = make_supervisor()
        publisher = ImmutablePublication(supervisor)
        intent = publisher.intent("dest", "witness-failure", b"value")
        publisher.exclusive_create(intent)
        with self.assertRaises(EvidenceError):
            publisher.write(
                intent, b"value",
                interlock=lambda: setattr(supervisor.store.witness, "available", False),
            )
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertTrue(supervisor.store.publication_prohibited)
        self.assertIn("publication-authority-failure", supervisor.store.taint)


# ---------------------------------------------------------------------------
# Decision 0009 independent-review regressions (Blocker 4).
#
# The failure is induced at the *later* direct lifecycle verification point,
# after CLEANUP_REQUESTED has already been durably recorded.  These tests were
# added before the correction and fail on the inherited implementation.
# ---------------------------------------------------------------------------

from tools.decision_0009.acer_adapter.supervisor import PersistentSupervisor

_PROMOTE = {
    "RESERVED": lambda publisher, intent: publisher.write(intent, b"value"),
    "WRITTEN": lambda publisher, intent: publisher.make_durable(intent),
    "DURABLE": lambda publisher, intent: publisher.verify(intent),
}
_LAST_PROVEN = {"RESERVED": "EXCLUSIVE_CREATE", "WRITTEN": "PUBLICATION_WRITTEN",
                "DURABLE": "DURABLE_BYTES"}


def _publication_at(supervisor, state, key):
    publisher = ImmutablePublication(supervisor)
    intent = publisher.intent("dest", key, b"value")
    publisher.exclusive_create(intent)
    if state in ("WRITTEN", "DURABLE"):
        publisher.write(intent, b"value")
    if state == "DURABLE":
        publisher.make_durable(intent)
    return publisher, intent


def _fail_late_cleanup_verification(supervisor, artifacts):
    """Substitute artifacts only for the direct verifier call that follows the
    durable CLEANUP_REQUESTED transition."""
    original = supervisor.verifier.verify
    fired = []

    def verify(transition, fence_epoch, session_id):
        if (transition == "CLEANUP_REQUESTED" and not fired and
                any(event.get("state") == "CLEANUP_REQUESTED"
                    for event in supervisor.store.events)):
            fired.append(True)
            artifacts.substitute("policy")
        return original(transition, fence_epoch, session_id)

    supervisor.verifier.verify = verify
    return fired


class LateLifecycleFailureRegressionTests(unittest.TestCase):
    def assert_safety_installed(self, supervisor):
        self.assertTrue(supervisor.store.execution_revoked)
        self.assertTrue(supervisor.store.publication_prohibited)
        self.assertTrue(supervisor.store.containment_only)
        self.assertIn("TAINTED", supervisor.safety_markers)
        self.assertIn("worker-lifecycle-failure", supervisor.store.taint)

    def test_late_lifecycle_verifier_failure_latches_contains_and_survives_restart(self):
        for publication_state in ("RESERVED", "WRITTEN", "DURABLE"):
            supervisor, artifacts, custodian = make_supervisor()
            publisher, intent = _publication_at(
                supervisor, publication_state, "late-" + publication_state.lower())
            supervisor.make_slot_eligible("slot-1-1")
            receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
            fired = _fail_late_cleanup_verification(supervisor, artifacts)
            with self.subTest(state=publication_state):
                with self.assertRaises(AuthorizationDenied):
                    supervisor.complete_worker_lifecycle("slot-1-1")
                self.assertEqual(fired, [True])
                self.assert_safety_installed(supervisor)
                inspection = custodian.inspect_spawn(receipt.spawn_token)
                self.assertFalse(inspection.possibly_live)
                self.assertEqual(inspection.status, "EXITED")
                # Containment is attempted, but reaping is never claimed.
                self.assertIn("CUSTODY_UNCERTAIN", supervisor.safety_markers)
                states = [event.get("state") for event in supervisor.store.events]
                self.assertNotIn("EXIT_OBSERVED", states)
                self.assertNotIn("REAPING_PROVEN", states)
                with self.assertRaises(EvidenceError):
                    _PROMOTE[publication_state](publisher, intent)
                snapshot = supervisor.publication_snapshot(supervisor.publication_binding())
                self.assertEqual(snapshot[-1]["state"], _LAST_PROVEN[publication_state])
                self.assertEqual(snapshot[0]["source_bytes"], b"value")
                restarted = PersistentSupervisor(
                    supervisor.store, supervisor.verifier, custodian,
                    supervisor.authorization, supervisor.session)
                self.assertTrue(restarted.store.execution_revoked)
                self.assertTrue(restarted.store.publication_prohibited)
                self.assertIn("TAINTED", restarted.safety_markers)
                reopened = ImmutablePublication(restarted)
                self.assertEqual(reopened.reconcile(intent), publication_state)
                with self.assertRaises(EvidenceError):
                    _PROMOTE[publication_state](reopened, intent)
                with self.assertRaises(AuthorizationDenied):
                    restarted.make_slot_eligible("slot-1-2")

    def test_durable_failure_record_reinstalls_prohibition_after_volatile_loss(self):
        supervisor, artifacts, custodian = make_supervisor()
        publisher, intent = _publication_at(supervisor, "DURABLE", "volatile-loss")
        supervisor.make_slot_eligible("slot-1-1")
        supervisor.spawn_worker("slot-1-1", digest("launch"))
        _fail_late_cleanup_verification(supervisor, artifacts)
        with self.assertRaises(AuthorizationDenied):
            supervisor.complete_worker_lifecycle("slot-1-1")
        failure = [event for event in supervisor.store.events
                   if event.get("state") == "TAINTED" and
                   event.get("reason") == "worker-lifecycle-failure"]
        self.assertEqual(len(failure), 1)
        self.assertEqual(failure[0]["primary_failure"], "AuthorizationDenied")
        # Simulate loss of the store's volatile latch flags; durable history must
        # re-derive the prohibition on reconstruction.
        store = supervisor.store
        store._publication_prohibited = False
        store._execution_revoked = False
        store.containment_only = False
        store._taint.clear()
        restarted = PersistentSupervisor(store, supervisor.verifier, custodian,
                                         supervisor.authorization, supervisor.session)
        self.assertTrue(restarted.store.publication_prohibited)
        self.assertTrue(restarted.store.execution_revoked)
        with self.assertRaises(EvidenceError):
            ImmutablePublication(restarted).verify(intent)

    def test_late_failure_with_containment_reap_or_diagnostic_failure_keeps_safety_state(self):
        for secondary in ("contain", "diagnostic", "contain-and-diagnostic"):
            supervisor, artifacts, custodian = make_supervisor()
            publisher, intent = _publication_at(supervisor, "DURABLE", "nested-" + secondary)
            supervisor.make_slot_eligible("slot-1-1")
            receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
            _fail_late_cleanup_verification(supervisor, artifacts)
            if secondary.startswith("contain"):
                custodian.contain_spawn = lambda *args, **kwargs: (_ for _ in ()).throw(
                    RuntimeError("containment failed"))
            if secondary.endswith("diagnostic"):
                supervisor._write_failure_record = lambda *args, **kwargs: (
                    _ for _ in ()).throw(RuntimeError("diagnostic failed"))
            with self.subTest(secondary=secondary):
                with self.assertRaises(AuthorizationDenied):
                    supervisor.complete_worker_lifecycle("slot-1-1")
                self.assert_safety_installed(supervisor)
                failure = supervisor.last_lifecycle_failure
                self.assertEqual(failure["primary"], "AuthorizationDenied")
                inspection = custodian.inspect_spawn(receipt.spawn_token)
                self.assertIn("CUSTODY_UNCERTAIN", supervisor.safety_markers)
                self.assertIsNone(custodian.get_reap_receipt(receipt.spawn_token))
                if secondary.startswith("contain"):
                    self.assertTrue(inspection.possibly_live)
                    self.assertTrue(any(item.startswith("contain")
                                        for item in failure["secondary"]))
                else:
                    self.assertEqual(inspection.status, "EXITED")
                if secondary.endswith("diagnostic"):
                    self.assertTrue(any(item.startswith("diagnostic")
                                        for item in failure["secondary"]))
                self.assertFalse(supervisor.synthetic_reap)
                self.assertFalse(supervisor.synthetic_residual_clearance)
                self.assertNotIn("REAPING_PROVEN",
                                 [event.get("state") for event in supervisor.store.events])
                with self.assertRaises(EvidenceError):
                    publisher.verify(intent)

    def test_primary_containment_or_reap_failure_inside_lifecycle_is_contained(self):
        for primary in ("contain", "wait_reap"):
            supervisor, _, custodian = make_supervisor()
            publisher, intent = _publication_at(supervisor, "DURABLE", "primary-" + primary)
            supervisor.make_slot_eligible("slot-1-1")
            receipt = supervisor.spawn_worker("slot-1-1", digest("launch"))
            original = getattr(custodian, primary + ("_spawn" if primary == "contain" else ""))
            name = "contain_spawn" if primary == "contain" else "wait_reap"
            setattr(custodian, name, lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError(primary + " failed")))
            with self.subTest(primary=primary):
                with self.assertRaisesRegex(RuntimeError, primary + " failed"):
                    supervisor.complete_worker_lifecycle("slot-1-1")
                self.assert_safety_installed(supervisor)
                self.assertIn("CUSTODY_UNCERTAIN", supervisor.safety_markers)
                self.assertEqual(supervisor.last_lifecycle_failure["primary"], "RuntimeError")
                self.assertNotIn("REAPING_PROVEN",
                                 [event.get("state") for event in supervisor.store.events])
                self.assertTrue(custodian.inspect_spawn(receipt.spawn_token).possibly_live
                                if primary == "contain" else
                                custodian.get_reap_receipt(receipt.spawn_token) is None)
                with self.assertRaises(EvidenceError):
                    publisher.verify(intent)
            setattr(custodian, name, original)
