"""Authorization characterization and Revision 6 offline trust tests."""

from dataclasses import replace
import hashlib
import importlib
import json
import unittest

from acer_adapter_fakes import MutableArtifacts, activation, authorization, session
from tools.decision_0009.acer_adapter.custody import OfflineCustodian
from tools.decision_0009.acer_adapter.supervisor import (
    ArtifactVerificationPrimitive, AuthorizationDenied, OfflineDurableStore,
    OfflineWitness, PersistentSupervisor,
)


class U04AuthenticationCharacterizationTests(unittest.TestCase):
    def test_u04_boolean_and_caller_digest_do_not_authenticate(self):
        artifacts = MutableArtifacts()
        auth = authorization(artifacts)
        store = OfflineDurableStore("store-1", OfflineWitness("witness-1"))
        fence = store.acquire_fence("supervisor-1")
        verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
        controller = PersistentSupervisor(store, verifier, OfflineCustodian("custodian-1"),
                                          auth, session(fence))
        with self.assertRaises(AuthorizationDenied):
            controller.admit_campaign(activation())


class AuthorizationV2Tests(unittest.TestCase):
    def foundation(self):
        from tools.decision_0009.acer_adapter import contracts
        self.assertTrue(hasattr(contracts, "canonical_authorization_bytes"),
                        "Revision 6 canonical v2 contract is required")
        return contracts, importlib.import_module(
            "tools.decision_0009.acer_adapter.authorization")

    def payload(self):
        c, _ = self.foundation()
        return replace(authorization(), schema_version=c.AUTHORIZATION_V2_SCHEMA,
                       evidence_operations=("WRITE_EXACT", "ESTABLISH_DURABILITY",
                                            "VERIFY_EXACT", "PUBLISH_RECOVERY_SUPPLEMENT"),
                       exact_byte_recovery_authorized=True,
                       evidence_source_ids=("normalizer-1",),
                       recovery_publisher_ids=("reader-1",),
                       destination_rules=(c.DestinationRule(
                           "destination-rule", "destination-1", "port-1", "evidence",
                           "OBJECT_AND_NAMESPACE", "ALL_LOWER_WRITERS"),),
                       object_rules=(c.ObjectRule("object-rule", "campaign-1",
                                                "CAMPAIGN_EVIDENCE", "destination-1",
                                                "evidence/campaign"),),
                       supplement_rules=())

    def test_canonical_bytes_independent_oracle(self):
        from dataclasses import asdict
        c, _ = self.foundation()
        payload = self.payload()
        expected = asdict(payload)
        expected.pop("authorization_digest")
        encoded = (json.dumps(expected, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False, allow_nan=False) + "\n").encode()
        self.assertEqual(c.canonical_authorization_bytes(payload), encoded)
        self.assertEqual(c.authorization_digest(payload), hashlib.sha256(encoded).hexdigest())

    def test_all_seven_fields_required_and_digest_bound(self):
        c, _ = self.foundation()
        payload = self.payload()
        for name in ("evidence_operations", "exact_byte_recovery_authorized",
                     "evidence_source_ids", "recovery_publisher_ids",
                     "destination_rules", "object_rules", "supplement_rules"):
            with self.subTest(field=name), self.assertRaises(c.ContractError):
                replace(payload, **{name: None})
        self.assertNotEqual(c.authorization_digest(payload), c.authorization_digest(
            replace(payload, exact_byte_recovery_authorized=False)))

    def test_each_v2_policy_mutation_changes_digest_and_requires_distinct_enrollment(self):
        c, a = self.foundation()
        payload = self.payload()
        payload = replace(payload, authorization_digest=c.authorization_digest(payload))
        verifier = a.OfflineChairAuthorizationVerifier(self.root())
        changes = {
            'evidence_operations': ('VERIFY_EXACT',),
            'exact_byte_recovery_authorized': False,
            'evidence_source_ids': ('normalizer-other',),
            'recovery_publisher_ids': ('reader-other',),
            'destination_rules': (replace(payload.destination_rules[0], port_identity='port-other'),),
            'object_rules': (replace(payload.object_rules[0], object_key='evidence/other'),),
            'supplement_rules': (c.SupplementRule('supplement-rule', 'destination-1', 'evidence/supplements',
                ('CAMPAIGN_EVIDENCE',), ('VERIFIED_EFFECT_RESULT',), 'RECOVERY_SUPPLEMENT_V1'),),
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                changed = replace(payload, **{field: value})
                digest = c.authorization_digest(changed)
                self.assertNotEqual(digest, payload.authorization_digest)
                with self.assertRaises(a.OfflineChairAuthenticationError):
                    verifier.verify(changed, store_identity='store-1', campaign_id='campaign-1')
                # Recomputing the digest cannot replace the exact enrolled approval.
                changed = replace(changed, authorization_digest=digest)
                with self.assertRaises(a.OfflineChairAuthenticationError):
                    verifier.verify(changed, store_identity='store-1', campaign_id='campaign-1')
        verifier.verify(payload, store_identity='store-1', campaign_id='campaign-1')

    def test_v1_remains_historical_without_added_defaults(self):
        c, a = self.foundation()
        legacy = authorization()
        self.assertEqual(legacy.schema_version, c.AUTHORIZATION_SCHEMA)
        self.assertIsNone(legacy.evidence_operations)
        with self.assertRaises(c.ContractError):
            c.canonical_authorization_bytes(legacy)
        with self.assertRaises(a.OfflineChairAuthenticationError):
            a.OfflineChairAuthorizationVerifier(self.root()).verify(
                legacy, store_identity="store-1", campaign_id="campaign-1")

    def root(self, store="store-1"):
        c, _ = self.foundation()
        payload = self.payload()
        payload = replace(payload, authorization_digest=c.authorization_digest(payload))
        approval = c.OfflineChairApproval(
            payload.chair_identity, payload.trust_domain, store, payload.campaign_id,
            payload.authorization_id, payload.schema_version,
            c.canonical_authorization_bytes(payload), payload.authorization_digest)
        return c.OfflineChairTrustRoot("root-1", 1, "offline-test", ("chair-1",),
                                       (approval,))

    def test_enrolled_bytes_only_exact_target_and_digest(self):
        c, a = self.foundation()
        payload = self.payload()
        payload = replace(payload, authorization_digest=c.authorization_digest(payload))
        verifier = a.OfflineChairAuthorizationVerifier(self.root())
        result = verifier.verify(payload, store_identity="store-1", campaign_id="campaign-1")
        self.assertEqual(result.canonical_authorization_bytes,
                         c.canonical_authorization_bytes(payload))
        for changes in ({"nonce": "changed"}, {"authorization_digest": "0" * 64},
                        {"authenticated": False}, {"chair_identity": "untrusted"}):
            with self.subTest(changes=changes), self.assertRaises(a.OfflineChairAuthenticationError):
                verifier.verify(replace(payload, **changes), store_identity="store-1",
                                campaign_id="campaign-1")
        for target in (("another-store", "campaign-1"), ("store-1", "another-campaign")):
            with self.subTest(target=target), self.assertRaises(a.OfflineChairAuthenticationError):
                verifier.verify(payload, store_identity=target[0], campaign_id=target[1])

    def test_root_is_deeply_immutable_and_runtime_replacement_denied(self):
        c, a = self.foundation()
        root = self.root()
        verifier = a.OfflineChairAuthorizationVerifier(root)
        with self.assertRaises((AttributeError, TypeError)):
            root.approvals += root.approvals
        with self.assertRaises((AttributeError, TypeError)):
            verifier.root = self.root("another-store")
        with self.assertRaises(c.ContractError):
            replace(root, approvals=root.approvals + root.approvals)

    def test_policy_rejects_aliases_escapes_duplicates_and_wrong_subject(self):
        c, _ = self.foundation()
        payload = self.payload()
        for key in ("evidence/../escape", "evidence//empty", "evidence/%2e", "evidence/\\escape"):
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                replace(payload.object_rules[0], object_key=key)
        with self.assertRaises(c.ContractError):
            replace(payload, evidence_operations=("VERIFY_EXACT", "VERIFY_EXACT"))
        with self.assertRaises(c.ContractError):
            replace(payload, object_rules=(replace(payload.object_rules[0], subject_id="foreign"),))
        with self.assertRaises(c.ContractError):
            replace(payload, destination_rules=payload.destination_rules * 2)

    def test_exact_permission_mapping_and_supplement_overlay(self):
        c, _ = self.foundation()
        payload = self.payload()
        for operation, permission in (
                ("ENSURE_EXACT_OBJECT", "WRITE_EXACT"),
                ("CONTINUE_RESERVED_EXACT", "WRITE_EXACT"),
                ("ESTABLISH_DURABILITY", "ESTABLISH_DURABILITY"),
                ("VERIFY_EXACT_OBJECT", "VERIFY_EXACT"),
                ("QUERY", "VERIFY_EXACT")):
            with self.subTest(operation=operation):
                c.require_recovery_permission(payload, operation)
                restricted = replace(payload, evidence_operations=tuple(
                    item for item in payload.evidence_operations if item != permission))
                with self.assertRaises(c.ContractError):
                    c.require_recovery_permission(restricted, operation)
                restricted = replace(payload, evidence_operations=tuple(
                    item for item in payload.evidence_operations
                    if item != "PUBLISH_RECOVERY_SUPPLEMENT"))
                with self.assertRaises(c.ContractError):
                    c.require_recovery_permission(restricted, operation, supplement=True)

    def test_result_version_dispatch_never_upgrades_legacy_or_mixed_records(self):
        c, _ = self.foundation()
        self.assertTrue(hasattr(c, "parse_effect_result_record"), "explicit RESULT dispatch required")
        legacy = b'{"record_type":"EFFECT_RESULT","effect_id":"effect-1","result":"historical"}\n'
        parsed = c.parse_effect_result_record(legacy)
        self.assertEqual(parsed.raw_bytes, legacy)
        self.assertFalse(parsed.authorizes_execution)
        for raw in (
                b'{"record_type":"EFFECT_RESULT","schema_version":"unknown"}\n',
                b'{"record_type":"EFFECT_RESULT","schema_version":"u04-record/v1","result":"legacy"}\n',
                b'{"record_type":"EFFECT_RESULT","acceptance_ref":null,"result":"legacy"}\n'):
            with self.subTest(raw=raw), self.assertRaises(c.ContractError):
                c.parse_effect_result_record(raw)

    def test_new_result_requires_exact_nonnull_refs_and_closed_result_kind(self):
        c, _ = self.foundation()
        self.assertTrue(hasattr(c, "parse_effect_result_record"))
        value = {"schema_version": "u04-record/v1", "record_type": "EFFECT_RESULT",
            "record_id": "result-1", "store_identity": "store-1",
            "authorization_digest": "1" * 64, "campaign_id": "campaign-1",
            "writer_generation": 1, "writer_incarnation_id": "incarnation-1",
            "writer_session_id": "session-1", "writer_fence": 1,
            "authority_class": "EVIDENCE", "authorizes_execution": False,
            "acceptance_ref": {"event_id": "acceptance-1", "revision": 2,
                               "payload_digest": "2" * 64},
            "effect_id": "effect-1",
            "original_producer_ref": {"event_id": "intent-1", "revision": 1,
                                      "payload_digest": "3" * 64},
            "result": {"object_id": "receipt-1", "sha256": "4" * 64, "length": 10},
            "result_kind": "CUSTODIAN_RECEIPT", "verifier_id": "custodian-1"}
        encode = lambda item: (json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n").encode()
        parsed = c.parse_effect_result_record(encode(value))
        self.assertEqual(parsed.acceptance_ref.event_id, "acceptance-1")
        self.assertFalse(parsed.authorizes_execution)
        for changes in ({"acceptance_ref": None}, {"original_producer_ref": None},
                        {"result_kind": "GENERIC"}, {"authorizes_execution": True},
                        {"unknown": "extra"}):
            with self.subTest(changes=changes), self.assertRaises(c.ContractError):
                c.parse_effect_result_record(encode(dict(value, **changes)))

    def test_independent_port_receipt_is_closed_with_nonnull_original_bindings(self):
        c, _ = self.foundation()
        value = {'effect_id': 'effect-1', 'acceptance_ref': {'event_id': 'acceptance-1', 'revision': 2,
                    'payload_digest': '1' * 64}, 'target_id': 'offline-store', 'original_generation': 1,
                 'original_incarnation_id': 'incarnation-1', 'original_session_id': 'session-1',
                 'original_fence': 1, 'result_object': {'object_id': 'observation-1', 'sha256': '2' * 64,
                                                      'length': 0}, 'port_attestation': '3' * 64}
        encode = lambda item: (json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n').encode()
        parsed = c.parse_effect_port_receipt(encode(value))
        self.assertEqual(parsed.effect_id, 'effect-1')
        for field in value:
            with self.subTest(field=field), self.assertRaises(c.ContractError):
                c.parse_effect_port_receipt(encode(dict(value, **{field: None})))
        with self.assertRaises(c.ContractError):
            c.parse_effect_port_receipt(encode(dict(value, result='unregistered arbitrary result')))
