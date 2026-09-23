import json
import unittest
import copy

from tools.decision_0009.acer_adapter.evidence import (
    BoundedRawJournal, EvidenceError, EvidencePipeline, ImmutablePublication,
    PublicationAcknowledgementLost, PublicationScheduler,
    build_closure_candidate, canonical_core_bytes, complete_closure,
)
from tools.decision_0009.acer_adapter.contracts import PublicationReceipt
from tools.decision_0009.acer_adapter.supervisor import (
    AuthorizationDenied, PersistentSupervisor,
)
from acer_adapter_fakes import make_supervisor


def _append_unprovenanced(store, fence_epoch, event_id, event):
    """Low-level fixture seam: retain a deliberately unprovenanced,
    nonauthorizing record through the store's control plumbing."""
    record = dict(event)
    record["authorizes_execution"] = False
    return store._append_control(store.revision, fence_epoch, event_id, record)


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
        recovered.make_durable(intent)
        self.assertEqual(recovered.verify(intent).state, "PUBLICATION_VERIFIED")

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
        recovered.exclusive_create(intent)
        reservations = [event for event in supervisor.store.events
                        if event.get("record_type") == "PUBLICATION" and
                        event.get("state") == "EXCLUSIVE_CREATE" and
                        event.get("intent_id") == intent.intent_id]
        self.assertEqual(len(reservations), 1)


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
from acer_adapter_fakes import MutableArtifacts, activation, authorization, session

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
            records = [event for event in store.events
                       if event.get("record_type") == "PUBLICATION" and
                       event.get("object_key") == key]
            self.assertEqual(len(records), 5)
            self.assertEqual({PublicationIdentity.from_record(event) for event in records},
                             {PublicationIdentity(intent.intent_id, "dest", key,
                                                  intent.object_digest, intent.length)})

    def test_initial_window_gates_publication(self):
        artifacts = MutableArtifacts()
        auth = authorization(artifacts)
        store = OfflineDurableStore("store-1", OfflineWitness("witness-1"))
        fence = store.acquire_fence("supervisor-1")
        verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
        supervisor = PersistentSupervisor(store, verifier, OfflineCustodian("custodian-1"),
                                          auth, session(fence))
        publisher = ImmutablePublication(supervisor)
        with self.assertRaises(EvidenceError):
            publisher.intent("dest", "uninitialized", b"value")
        self.assertEqual(store.revision, 0)
        # Interrupted admission: the campaign is admitted but the initial
        # window never registers a result.
        def interrupted(authority, operation_id, receipt):
            raise StoreError("interrupted before initial window result binding")
        store._bind_window_result = interrupted
        with self.assertRaises(StoreError):
            supervisor.admit_campaign(activation())
        del store._bind_window_result
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

                def interrupted(authority, grant_id, receipt):
                    raise StoreError("interrupted before result binding")
                store._bind_publication_grant = interrupted
                try:
                    with self.assertRaises(EvidenceError):
                        _publisher_step(publisher, operation, intent)
                finally:
                    del store._bind_publication_grant
                self.assertTrue(store.publication_prohibited)
                with self.assertRaises(EvidenceError):
                    publisher.reconcile(intent)
                store.crash()
                restarted = _restart(supervisor)
                self.assertIn("consumed-publication-grant-without-result",
                              restarted.reconstruction_violations)
                self.assertIn("unprovenanced-publication-history",
                              restarted.reconstruction_violations)
                with self.assertRaises((EvidenceError, AuthorizationDenied)):
                    ImmutablePublication(restarted)
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
                for operation in OPERATIONS[OPERATIONS.index(next_operation):]:
                    _publisher_step(recovered, operation, intent)
                receipt = recovered.reconcile(intent)
                self.assertEqual(receipt.state, "PUBLICATION_VERIFIED")
                supervisor.store.crash()
                again = _restart(restarted)
                self.assertEqual(again.reconstruction_violations, [])
                self.assertEqual(ImmutablePublication(again).reconcile(intent), receipt)
                states = [event["state"] for event in again.store.events
                          if event.get("record_type") == "PUBLICATION" and
                          event.get("intent_id") == intent.intent_id]
                self.assertEqual(states, ["PUBLICATION_INTENT", "EXCLUSIVE_CREATE",
                                          "PUBLICATION_WRITTEN", "DURABLE_BYTES",
                                          "PUBLICATION_VERIFIED"])

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
        recovered.exclusive_create(intent)
        recovered.write_durable(intent, b"value")
        self.assertEqual(recovered.verify(intent).state, "PUBLICATION_VERIFIED")
        epochs = [event["window_epoch"] for event in restarted.store.events
                  if event.get("record_type") == "PUBLICATION"]
        self.assertEqual(epochs, [1, 3, 3, 3, 3])
