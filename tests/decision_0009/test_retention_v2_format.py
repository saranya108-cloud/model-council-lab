"""Deterministic level-1 acceptance tests for Retention V2-0."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import unittest
from unittest import mock

import retention_v2_fixtures as fixture_module
from retention_v2_fixtures import (
    ACTION_PERMISSION_FIELDS_LITERAL,
    AMENDMENT_1A_SOURCE_SHA256,
    AUTHORIZE_BODY_FIELDS_LITERAL,
    AUTHORIZE_BRANCH_SEMANTICS_LITERAL,
    BIND_BODY_FIELDS_LITERAL,
    BIND_FALSE_CONTROL_SPECIMEN,
    BIND_TRUE_CONTROL_SPECIMEN,
    BRANCH_LIMIT_FIELDS_LITERAL,
    BRANCH_TERMINAL_PAYLOAD_RANGES_LITERAL,
    CANONICAL_CJSON2_VECTORS,
    CATEGORIES_LITERAL,
    CATEGORY_MEANINGS_LITERAL,
    CHECKPOINT_CAUSES_LITERAL,
    CHECKPOINT_COMMON_FIELDS_LITERAL,
    CHECKPOINT_STATE_FIELDS_LITERAL,
    CHECKPOINT_SUBTYPE_FIELDS_LITERAL,
    CONTROL_ARRAY_METADATA_LITERAL,
    CONTROL_CLOSED_SCHEMA_INVALID_ORACLES,
    CONTROL_ENUMS_LITERAL,
    CONTROL_FIELDS_LITERAL,
    CONTROL_FIELD_TYPES_LITERAL,
    CONTROL_LIFECYCLE_DECLARATIONS_LITERAL,
    CONTROL_NULLABLE_FIELDS_LITERAL,
    CONTROL_OBJECT_BYTES_MAX_LITERAL,
    CONTROL_PATTERNS_LITERAL,
    CONTROL_REPRESENTATIONS_LITERAL,
    CONTROL_SCHEMA_SPECIMENS,
    CONTROL_UINT_RANGES_LITERAL,
    CREATE_BODY_FIELDS_LITERAL,
    D_FINAL_DECLARATION_LITERAL,
    DEEP_NESTING_INVALID_VECTOR,
    F_CHECKSUM_LITERAL_VECTORS,
    F_CONSTANTS_LITERAL,
    F_PHYSICAL_MAP_LITERAL,
    FORMAT_LIMITS_LITERAL,
    INTERMEDIATE_STORE_FIELDS_LITERAL,
    INVALID_CJSON2_VECTORS,
    ITEM_FIELDS_LITERAL,
    ORDINARY_ACCOUNT_ATTRIBUTION_LITERAL,
    ORDINARY_ACCOUNT_FIELDS_LITERAL,
    ORDINARY_ROLE_FIELDS_LITERAL,
    OUTCOME_ROLES_FIELDS_LITERAL,
    R2_SOURCE_SHA256,
    RECORD_ENVELOPE_LITERAL,
    RECORD_KINDS_LITERAL,
    RECORD_PLACEMENTS_LITERAL,
    SHARED_DECLARATION_ORACLES,
    SLOT_RESERVATION_FIELDS_LITERAL,
    TERMINAL_BRANCH_FIELDS_LITERAL,
    TERMINAL_ROLE_FIELDS_LITERAL,
    TERMINAL_ROLE_REFERENCE_FIELDS_LITERAL,
)
from tools.decision_0009.retention_v2 import cjson2, spec


class RetentionV2FormatTests(unittest.TestCase):
    def test_f_physical_map_literal(self):
        self.assertEqual(
            F_PHYSICAL_MAP_LITERAL,
            tuple((region.name, region.start, region.end, region.capacity) for region in spec.F_REGIONS),
        )
        self.assertEqual(F_CONSTANTS_LITERAL["file_size"], spec.F_SIZE)
        self.assertEqual(F_CONSTANTS_LITERAL["terminal_total_size"], spec.TERMINAL_TOTAL_SIZE)
        self.assertEqual(F_CONSTANTS_LITERAL["header_size"], spec.HEADER_SIZE)
        self.assertEqual(F_CONSTANTS_LITERAL["ordinary_record_max"], spec.ORDINARY_RECORD_MAX)
        self.assertEqual(F_CONSTANTS_LITERAL["ordinary_data_max"], spec.ORDINARY_DATA_MAX)
        self.assertEqual(F_CONSTANTS_LITERAL["terminal_slot_size"], spec.TERMINAL_SLOT_SIZE)
        self.assertEqual(F_CONSTANTS_LITERAL["terminal_data_max"], spec.TERMINAL_DATA_MAX)
        self.assertEqual(F_CONSTANTS_LITERAL["alignment"], spec.ALIGNMENT)
        self.assertEqual(
            F_CONSTANTS_LITERAL["terminal_slots_per_area"], spec.TERMINAL_SLOTS_PER_AREA
        )
        self.assertEqual(RECORD_ENVELOPE_LITERAL, spec.RECORD_ENVELOPE)
        self.assertEqual(RECORD_KINDS_LITERAL, {kind.name: kind.value for kind in spec.RecordKind})
        self.assertEqual(
            RECORD_PLACEMENTS_LITERAL,
            {kind.name: spec.RECORD_PLACEMENTS[kind] for kind in spec.RecordKind},
        )
        self.assertEqual(CATEGORIES_LITERAL, {category.name: category.value for category in spec.Category})
        self.assertEqual(
            CATEGORY_MEANINGS_LITERAL,
            {category.name: spec.CATEGORY_MEANINGS[category] for category in spec.Category},
        )
        self.assertEqual(ITEM_FIELDS_LITERAL, spec.ITEM_FIELDS)
        self.assertEqual(CONTROL_FIELDS_LITERAL, spec.CONTROL_FIELDS)
        self.assertEqual(CHECKPOINT_COMMON_FIELDS_LITERAL, spec.CHECKPOINT_COMMON_FIELDS)
        self.assertEqual(CHECKPOINT_STATE_FIELDS_LITERAL, spec.CHECKPOINT_STATE_FIELDS)
        self.assertEqual(CHECKPOINT_SUBTYPE_FIELDS_LITERAL, dict(spec.CHECKPOINT_SUBTYPE_FIELDS))
        self.assertEqual(CHECKPOINT_CAUSES_LITERAL, spec.CHECKPOINT_CAUSES)
        self.assertEqual(R2_SOURCE_SHA256, spec.R2_SOURCE_SHA256)
        self.assertEqual(AMENDMENT_1A_SOURCE_SHA256, spec.AMENDMENT_1A_SOURCE_SHA256)
        for name, expected in FORMAT_LIMITS_LITERAL.items():
            with self.subTest(limit=name):
                self.assertEqual(expected, getattr(spec, name.upper()))
        self.assertEqual(spec.F_SIZE, spec.F_REGIONS[-1].end)
        self.assertTrue(all(left.end == right.start for left, right in zip(spec.F_REGIONS, spec.F_REGIONS[1:])))

    def test_f_checksum_literal_vectors(self):
        self.assertEqual(b"MCL-D0009-F2R1-REC", spec.F_CHECKSUM_DOMAIN)
        self.assertEqual(bytes.fromhex("4d434c4439463200"), spec.MAGIC)
        self.assertEqual(2, spec.WIRE_VERSION)
        for vector in F_CHECKSUM_LITERAL_VECTORS:
            with self.subTest(vector=vector["name"]):
                header = vector["header"]
                self.assertEqual(96, len(header))
                self.assertEqual(b"\x00" * 32, header[64:96])
                preimage = (
                    b"MCL-D0009-F2R1-REC\x00"
                    + vector["offset"].to_bytes(8, "little")
                    + header
                    + vector["payload"]
                    + vector["padding"]
                )
                self.assertEqual(
                    vector["sha256"],
                    hashlib.sha256(preimage).hexdigest(),
                    vector["name"],
                )

    def test_shared_declarations_have_independent_literal_oracles(self):
        mapping_declarations = {"ORDINARY_ACCOUNT_BYTES", "OPERATIONAL_CEILINGS"}
        for name, oracle in SHARED_DECLARATION_ORACLES.items():
            with self.subTest(declaration=name, clause=oracle["clause"]):
                actual = getattr(spec, name)
                if name in mapping_declarations:
                    actual = dict(actual)
                self.assertEqual(oracle["expected"], actual)

    def test_cjson2_canonical_and_invalid_vectors(self):
        for encoded, value in CANONICAL_CJSON2_VECTORS:
            with self.subTest(encoded=encoded):
                self.assertEqual(value, cjson2.loads(encoded))
                self.assertEqual(encoded, cjson2.dumps(value))

        for name, encoded in INVALID_CJSON2_VECTORS:
            with self.subTest(vector=name):
                with self.assertRaises(cjson2.CJSON2DecodeError) as raised:
                    cjson2.loads(encoded)
                self.assertEqual(spec.ValidationStage.ENCODING, raised.exception.stage)

        with self.assertRaises(cjson2.CJSON2EncodeError):
            cjson2.dumps({"a": 1})
        with self.assertRaises(cjson2.CJSON2EncodeError):
            cjson2.dumps({"A": None})
        with self.assertRaises(cjson2.CJSON2EncodeError):
            cjson2.dumps({f"a{i:02d}": None for i in range(65)})
        with self.assertRaises(cjson2.CJSON2EncodeError):
            cjson2.dumps({"a": [[[[[[[[None]]]]]]]]})

    def test_cjson2_deep_nesting_is_contained(self):
        vector = DEEP_NESTING_INVALID_VECTOR
        parser = mock.Mock(side_effect=RecursionError("parser recursion limit"))
        with mock.patch.object(cjson2.json, "loads", parser):
            try:
                cjson2.loads(vector["encoded"])
            except RecursionError:
                self.fail("user-controlled CJSON2 nesting reached the recursive parser")
            except cjson2.CJSON2DecodeError as error:
                self.assertEqual(spec.ValidationStage.ENCODING, error.stage)
            else:
                self.fail("over-depth CJSON2 input was accepted")
        parser.assert_not_called()

    def test_control_body_field_declarations_literal(self):
        self.assertEqual(CREATE_BODY_FIELDS_LITERAL, spec.CREATE_BODY_FIELDS)
        self.assertEqual(BIND_BODY_FIELDS_LITERAL, spec.BIND_BODY_FIELDS)
        self.assertEqual(AUTHORIZE_BODY_FIELDS_LITERAL, spec.AUTHORIZE_BODY_FIELDS)

    def test_control_nested_schema_declarations_literal(self):
        expected = {
            "ORDINARY_ROLE_FIELDS": ORDINARY_ROLE_FIELDS_LITERAL,
            "OUTCOME_ROLES_FIELDS": OUTCOME_ROLES_FIELDS_LITERAL,
            "TERMINAL_ROLE_FIELDS": TERMINAL_ROLE_FIELDS_LITERAL,
            "TERMINAL_BRANCH_FIELDS": TERMINAL_BRANCH_FIELDS_LITERAL,
            "SLOT_RESERVATION_FIELDS": SLOT_RESERVATION_FIELDS_LITERAL,
            "BRANCH_LIMIT_FIELDS": BRANCH_LIMIT_FIELDS_LITERAL,
            "INTERMEDIATE_STORE_FIELDS": INTERMEDIATE_STORE_FIELDS_LITERAL,
            "TERMINAL_ROLE_REFERENCE_FIELDS": TERMINAL_ROLE_REFERENCE_FIELDS_LITERAL,
            "ACTION_PERMISSION_FIELDS": ACTION_PERMISSION_FIELDS_LITERAL,
            "ORDINARY_ACCOUNT_FIELDS": ORDINARY_ACCOUNT_FIELDS_LITERAL,
        }
        for name, literal in expected.items():
            with self.subTest(declaration=name):
                self.assertEqual(literal, getattr(spec, name))
        self.assertEqual(CONTROL_FIELD_TYPES_LITERAL, dict(spec.CONTROL_FIELD_TYPES))

    def test_control_scalar_and_nullability_declarations_literal(self):
        self.assertEqual(CONTROL_PATTERNS_LITERAL, dict(spec.CONTROL_PATTERNS))
        self.assertEqual(CONTROL_ENUMS_LITERAL, dict(spec.CONTROL_ENUMS))
        self.assertEqual(CONTROL_NULLABLE_FIELDS_LITERAL, dict(spec.CONTROL_NULLABLE_FIELDS))
        self.assertEqual(CONTROL_UINT_RANGES_LITERAL, dict(spec.CONTROL_UINT_RANGES))
        self.assertEqual(CONTROL_REPRESENTATIONS_LITERAL, dict(spec.CONTROL_REPRESENTATIONS))
        self.assertEqual(CONTROL_OBJECT_BYTES_MAX_LITERAL, spec.CONTROL_OBJECT_BYTES_MAX)
        self.assertEqual(
            CONTROL_LIFECYCLE_DECLARATIONS_LITERAL,
            dict(spec.CONTROL_LIFECYCLE_DECLARATIONS),
        )
        self.assertEqual(
            ORDINARY_ACCOUNT_ATTRIBUTION_LITERAL,
            dict(spec.ORDINARY_ACCOUNT_ATTRIBUTION),
        )
        self.assertEqual(D_FINAL_DECLARATION_LITERAL, dict(spec.D_FINAL_DECLARATION))

    def test_control_array_bounds_and_ordering_literal(self):
        self.assertEqual(CONTROL_ARRAY_METADATA_LITERAL, dict(spec.CONTROL_ARRAY_METADATA))
        self.assertEqual(
            BRANCH_TERMINAL_PAYLOAD_RANGES_LITERAL,
            spec.BRANCH_TERMINAL_PAYLOAD_RANGES,
        )
        self.assertEqual(
            AUTHORIZE_BRANCH_SEMANTICS_LITERAL,
            dict(spec.AUTHORIZE_BRANCH_SEMANTICS),
        )
        self.assertFalse(hasattr(spec, "CONTROL_ARRAY_MAX_ITEMS"))
        unbounded = {
            name
            for name, (_, _, maximum, _) in CONTROL_ARRAY_METADATA_LITERAL.items()
            if maximum is None
        }
        self.assertEqual(
            {
                "authorize_body.abort_actions",
                "authorize_body.branches",
                "authorize_body.cleanup_actions",
                "authorize_body.intermediate_stores",
                "authorize_body.terminal_roles",
                "intermediate_store.terminal_roles",
                "action_permission.branches",
            },
            unbounded,
        )

    def test_control_schema_specimens_cjson2_round_trip(self):
        expected_names = {
            "create",
            "bind_genesis_true",
            "bind_genesis_false",
            "ordinary_authorize",
            "authorize_committed_outcomes",
            "reachable_terminal_branch",
            "terminal_only_authorize",
            "branch_with_d_reservation",
            "branch_without_d_reservation",
        }
        self.assertEqual(expected_names, {name for name, _ in CONTROL_SCHEMA_SPECIMENS})
        for name, specimen in CONTROL_SCHEMA_SPECIMENS:
            with self.subTest(specimen=name):
                encoded = cjson2.dumps(specimen)
                self.assertLessEqual(len(encoded), CONTROL_OBJECT_BYTES_MAX_LITERAL)
                self.assertEqual(specimen, cjson2.loads(encoded))
                self.assertEqual(encoded, cjson2.dumps(cjson2.loads(encoded)))
        self.assertIs(True, BIND_TRUE_CONTROL_SPECIMEN["body"]["genesis_permitted"])
        self.assertIs(False, BIND_FALSE_CONTROL_SPECIMEN["body"]["genesis_permitted"])

    def test_control_schema_oracles_are_independent(self):
        syntax = ast.parse(Path(fixture_module.__file__).read_text(encoding="utf-8"))
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
        self.assertEqual(
            {"closed_schema", "semantic_references"},
            {oracle[-1] for oracle in CONTROL_CLOSED_SCHEMA_INVALID_ORACLES},
        )
        ordinary_roles = [
            role
            for _, specimen in CONTROL_SCHEMA_SPECIMENS
            if specimen["kind"] == "AUTHORIZE"
            for role in specimen["body"]["item_roles"]
        ]
        self.assertTrue(ordinary_roles)
        self.assertTrue(all(role["account"] in ORDINARY_ACCOUNT_FIELDS_LITERAL for role in ordinary_roles))


if __name__ == "__main__":
    unittest.main()
