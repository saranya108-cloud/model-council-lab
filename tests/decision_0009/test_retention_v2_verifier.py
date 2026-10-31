"""Deterministic synthetic/in-memory acceptance tests for V2-1 only."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import unittest

import retention_v2_fixtures as fixtures
from tools.decision_0009.retention_v2 import cjson2
from tools.decision_0009.retention_v2 import verify as verifier


class RetentionV2VerifierTests(unittest.TestCase):
    maxDiff = None

    def require_verifier(self):
        return verifier

    def assert_case_vector(self, name):
        implementation = self.require_verifier()
        case = fixtures.build_v2_1_fixture(name)
        result = implementation.verify_f(case["image"], case["evidence"])
        expected = fixtures.expand_v2_1_vector(case["expected_vector"])
        actual = {field: result[field] for field in fixtures.V2_1_VECTOR_FIELDS}
        self.assertEqual(expected, actual, case["title"])
        self.assertEqual(fixtures.V2_1_RESULT_SCHEMA, result["schema"])
        self.assertEqual(fixtures.R2_SOURCE_SHA256, result["subject"]["specification"])
        self.assertEqual(case["evidence"]["binding_digest"], result["subject"]["binding"])
        self.assertEqual(case["evidence"]["control_reference"], result["subject"]["control"])
        expected_file_digest = fixtures.V2_1_IMAGE_SHA256_ORACLES[name]
        self.assertEqual(expected_file_digest, result["subject"]["file_sha256"])
        return result

    def test_fixture_oracles_are_external_literal_and_complete(self):
        syntax = ast.parse(Path(fixtures.__file__).read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(syntax)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_modules.update(
            alias.name
            for node in ast.walk(syntax)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertFalse(
            any(module.startswith("tools.decision_0009.retention_v2") for module in imported_modules)
        )
        names = [entry[0] for entry in fixtures.V2_1_VECTOR_ORACLES]
        self.assertEqual(48, len(names))
        self.assertEqual(48, len(set(names)))
        actual_digests = {
            name: hashlib.sha256(fixtures.build_v2_1_fixture(name)["image"]).hexdigest()
            for name in names
        }
        self.assertEqual(fixtures.V2_1_IMAGE_SHA256_ORACLES, actual_digests)

    def test_f_checksum_literal_vectors(self):
        implementation = self.require_verifier()
        for vector in fixtures.F_CHECKSUM_LITERAL_VECTORS:
            with self.subTest(vector=vector["name"]):
                digest = implementation.compute_record_checksum(
                    vector["offset"],
                    vector["header"],
                    vector["payload"],
                    vector["padding"],
                )
                self.assertEqual(vector["sha256"], digest.hex())

    def test_r2_exact_fixture_vectors(self):
        for name, _, _, clause in fixtures.V2_1_VECTOR_ORACLES:
            with self.subTest(fixture=name, clause=clause):
                self.assert_case_vector(name)

    def test_verifier_schema_and_precedence(self):
        implementation = self.require_verifier()
        for name in (
            "nonzero_mandatory_headroom",
            "torn_c_final_failed",
            "valid_complete_finalization",
            "writer_still_running",
            "known_stale_current_authority_input",
        ):
            with self.subTest(fixture=name):
                case = fixtures.build_v2_1_fixture(name)
                result = implementation.verify_f(case["image"], case["evidence"])
                self.assertEqual(set(fixtures.V2_1_RESULT_FIELDS), set(result))
                self.assertEqual(set(fixtures.V2_1_SUBJECT_FIELDS), set(result["subject"]))
                self.assertEqual(set(fixtures.V2_1_VALIDATION_FIELDS), set(result["validation"]))
                for field, vocabulary in fixtures.V2_1_RESULT_ENUMS.items():
                    if field == "validation":
                        self.assertTrue(
                            all(value in vocabulary for value in result["validation"].values())
                        )
                    else:
                        self.assertIn(result[field], vocabulary)
                encoded = implementation.encode_result(result)
                self.assertEqual(result, cjson2.loads(encoded))
                self.assertEqual(encoded, cjson2.dumps(result))

    def test_closed_schema_invalids(self):
        for name, expected_stage in (
            ("end_abort_failure", "schema"),
            ("overflowing_item_integer", "schema"),
            ("unknown_semantic_category", "schema"),
            ("invalid_cjson2", "encoding"),
            ("unknown_control_field_or_invalid_role", "schema"),
            ("terminal_item_over_bound", "schema"),
        ):
            with self.subTest(fixture=name):
                result = self.assert_case_vector(name)
                self.assertEqual("invalid", result["validation"][expected_stage])

    def test_semantic_reference_and_lifecycle_invalids(self):
        for name in (
            "end_commit_unresolved_missing_required_role",
            "end_commit_while_item_incomplete",
            "control_history_fork",
            "activation_control_reference_mismatch",
            "stale_abandonment_disposition_used_to_continue",
            "interleaved_excess_data_or_digest_mismatch",
            "ordinary_item_permit_mismatch",
            "terminal_declaration_mismatch",
            "generation_account_record_ceiling_violation",
            "d_without_valid_c",
            "final_outcome_differs_manifest",
        ):
            with self.subTest(fixture=name):
                result = self.assert_case_vector(name)
                self.assertEqual("invalid", result["validation"]["references"])

    def test_branch_reservation_max_path(self):
        implementation = self.require_verifier()
        for name, expected in (
            ("branch_max_path_valid", "valid"),
            ("branch_ordinary_max_path_valid", "valid"),
            ("branch_overlap_not_exclusive", "invalid"),
            ("branch_cumulative_underreserved", "invalid"),
            ("branch_wrong_first_slot", "invalid"),
            ("simultaneous_outstanding_overlap", "invalid"),
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual(expected, result["validation"]["references"])

    def test_ordinary_account_attribution(self):
        implementation = self.require_verifier()
        for name, expected in (
            ("account_exact", "valid"),
            ("account_payload_over", "invalid"),
            ("account_overhead_over", "invalid"),
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual(expected, result["validation"]["references"])

    def test_authorize_replay_consumption_and_second_generation_prohibition(self):
        implementation = self.require_verifier()
        for name in ("authorize_replay", "second_generation_same_authorize"):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])

    def test_genesis_authority_and_false_closeout(self):
        implementation = self.require_verifier()
        for name, stage in (
            ("genesis_true_without_chair_approval", "references"),
            ("genesis_false_forecloses_genesis", "references"),
            ("authorize_generation_zero", "schema"),
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"][stage])
        image, evidence = fixtures.build_v2_1_semantic_fixture("bind_false_valid_closeout")
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["validation"]["references"])
        self.assertEqual("finalized", result["physical_state"])
        self.assertEqual("final", result["progression"])

    def test_bind_true_without_genesis_approval_or_execution(self):
        implementation = self.require_verifier()

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "bind_true_unapproved_no_closeout"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["integrity"])
        self.assertEqual("clean_frontier", result["physical_state"])
        self.assertEqual("valid", result["validation"]["references"])
        self.assertEqual("blocked_pending_disposition", result["progression"])

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "bind_true_unapproved_valid_closeout"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["integrity"])
        self.assertEqual("finalized", result["physical_state"])
        self.assertEqual("unresolved", result["operation_result"])
        self.assertEqual("final", result["progression"])

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "bind_false_valid_closeout"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["integrity"])
        self.assertEqual("finalized", result["physical_state"])
        self.assertEqual("final", result["progression"])

    def test_authorize_is_closed_by_freeze_or_d_attempt(self):
        implementation = self.require_verifier()
        for name in (
            "authorize_after_freeze_ordinary",
            "authorize_after_freeze_f",
            "authorize_after_final_disposition",
            "authorize_after_d_attempt",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])
                self.assertNotEqual("eligible_for_chair_consideration", result["progression"])

    def test_freeze_dispositions_classify_physical_state(self):
        implementation = self.require_verifier()
        for name, expected_state in (
            ("freeze_ordinary_classification", "ordinary_frozen"),
            ("freeze_f_classification", "terminal_frozen"),
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("valid", result["integrity"])
                self.assertEqual(expected_state, result["physical_state"])
                self.assertEqual("blocked_pending_disposition", result["progression"])

    def test_later_generation_requires_preceding_disposition(self):
        implementation = self.require_verifier()

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "next_generation_without_preceding_disposition"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("invalid", result["validation"]["references"])

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "first_generation_without_genesis_disposition"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("invalid", result["validation"]["references"])

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "next_generation_after_valid_disposition"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["integrity"])
        self.assertEqual("valid", result["validation"]["references"])

    def test_pending_authorize_validates_generation_and_genesis_before_begin(self):
        implementation = self.require_verifier()
        for name in (
            "pending_generation_2_without_disposition",
            "pending_generation_3_skips_2",
            "pending_generation_1_reused",
            "pending_generation_1_bind_false",
            "pending_generation_1_before_genesis",
            "pending_generation_1_unadmitted_genesis",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])
                self.assertEqual("invalid", result["authority"])

        for name in (
            "pending_generation_2_after_disposition",
            "pending_generation_1_after_admitted_genesis",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("valid", result["validation"]["references"])
                self.assertEqual("current", result["authority"])

    def test_pending_authorize_validates_remaining_capacity_before_begin(self):
        implementation = self.require_verifier()
        for name in (
            "pending_authorize_a2_exceeds_remaining",
            "pending_authorize_exceeds_remaining_review_correction",
            "pending_authorize_exceeds_item_lifetime",
            "pending_authorize_exceeds_aborted_generation_limit",
            "pending_authorize_conflicts_with_outstanding_reservation",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])
                self.assertEqual("invalid", result["authority"])

        for name in (
            "pending_authorize_a2_exact_remaining",
            "pending_authorize_a2_max_path_not_sum",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("valid", result["validation"]["references"])
                self.assertEqual("current", result["authority"])

    def test_terminal_writing_requires_ordinary_freeze(self):
        implementation = self.require_verifier()

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "terminal_without_ordinary_freeze"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("invalid", result["validation"]["references"])

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "terminal_after_ordinary_freeze"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["integrity"])
        self.assertEqual("valid", result["validation"]["references"])
        self.assertEqual("terminal_frozen", result["physical_state"])

    def test_finality_requires_trusted_current_authority_and_commitment(self):
        implementation = self.require_verifier()

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "final_checkpoint_outside_trusted_history"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("current", result["authority"])
        self.assertNotEqual("final", result["progression"])
        self.assertNotEqual("finalized", result["physical_state"])

        for name, expected_authority in (
            ("invalid_authority_with_final_disposition", "invalid"),
            ("no_trusted_authority_with_final_disposition", "not_established"),
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual(expected_authority, result["authority"])
                self.assertEqual("blocked_authority", result["progression"])

        for name in ("final_commitment_mismatch", "post_finalization_byte_change"):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["integrity"])
                self.assertEqual("blocked_integrity", result["progression"])
                self.assertNotEqual("finalized", result["physical_state"])

    def test_ordinary_accounts_and_limits_are_lifetime_cumulative(self):
        implementation = self.require_verifier()

        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "cumulative_account_capacity_valid"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual("valid", result["validation"]["references"])

        for name in (
            "cumulative_account_capacity_exceeded",
            "remaining_capacity_reservation_exceeded",
            "aborted_bytes_are_not_refunded",
            "genesis_overhead_reduces_reservation",
            "aborted_generation_lifetime_limit",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])

    def test_terminal_ordering_and_frozen_area_reuse(self):
        implementation = self.require_verifier()
        for name in ("terminal_before_ordinary_close", "frozen_area_reuse"):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("terminal_frozen", result["physical_state"])
                self.assertEqual("invalid", result["validation"]["references"])

    def test_record_placement_payload_and_generation_discontinuities(self):
        implementation = self.require_verifier()
        for name in (
            "ordinary_final_wrong_placement",
            "record_payload_over_kind_bound",
            "generation_header_discontinuity",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("blocked_torn", result["integrity"])
                self.assertEqual(
                    {"encoding": "not_checked", "schema": "not_checked", "references": "not_checked"},
                    result["validation"],
                )

    def test_control_lifecycle_and_terminal_prerequisites(self):
        implementation = self.require_verifier()
        image, evidence = fixtures.build_v2_1_semantic_fixture(
            "supplied_specification_mismatch"
        )
        result = implementation.verify_f(image, evidence)
        self.assertEqual(evidence["specification_digest"], result["subject"]["specification"])
        self.assertEqual("invalid", result["validation"]["references"])
        for name in (
            "final_complete_without_c_d",
            "checkpoint_reopens_frozen_area",
            "terminal_c_before_ab_frozen",
            "d_reservation_wrong_shape",
        ):
            with self.subTest(fixture=name):
                image, evidence = fixtures.build_v2_1_semantic_fixture(name)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("invalid", result["validation"]["references"])
                if name == "final_complete_without_c_d":
                    self.assertNotEqual("final", result["progression"])

    def test_checkpoint_subtypes_reject_extra_fields(self):
        implementation = self.require_verifier()
        for disposition in fixtures.CHECKPOINT_SUBTYPE_FIELDS_LITERAL:
            with self.subTest(disposition=disposition):
                image, evidence = fixtures.build_v2_1_checkpoint_extra_fixture(disposition)
                result = implementation.verify_f(image, evidence)
                self.assertEqual("valid", result["validation"]["encoding"])
                self.assertEqual("invalid", result["validation"]["schema"])
                self.assertEqual("not_checked", result["validation"]["references"])

    def test_final_authority_custody_and_admitted_prefix_inputs(self):
        for name in (
            "known_stale_current_authority_input",
            "no_trusted_authority_valid_unadmitted_file",
            "writer_still_running",
            "writer_closure_not_established",
            "wrong_f_identity_identical_bytes",
            "earlier_admitted_prefix_changed",
            "torn_c_final_failed",
            "torn_d_final_unresolved",
            "valid_complete_finalization",
            "valid_unresolved_finalization",
        ):
            with self.subTest(fixture=name):
                self.assert_case_vector(name)


if __name__ == "__main__":
    unittest.main()
