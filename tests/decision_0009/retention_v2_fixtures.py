"""Independent literal oracles for Decision 0009 Retention V2-0.

This module deliberately does not import the production Retention V2 package.
Expected bytes and declarations remain external to the implementation under test.
"""

from __future__ import annotations


R2_SOURCE_SHA256 = "b9a1ce67aa5c8050a95de324969a25046f13d2f6e4bf56f92832dea96fce6b05"
AMENDMENT_1A_SOURCE_SHA256 = (
    "9869dd6ec374677a8150de725e05e705bc4ac8798ec5b7b20ed705e0a6f49144"
)

F_PHYSICAL_MAP_LITERAL = (
    ("ordinary", 0, 12_582_912, 12_582_912),
    ("headroom", 12_582_912, 14_680_064, 2_097_152),
    ("a", 14_680_064, 15_204_352, 524_288),
    ("b", 15_204_352, 15_728_640, 524_288),
    ("c", 15_728_640, 16_252_928, 524_288),
    ("d", 16_252_928, 16_777_216, 524_288),
)

F_CONSTANTS_LITERAL = {
    "file_size": 16_777_216,
    "terminal_total_size": 2_097_152,
    "header_size": 96,
    "ordinary_record_max": 262_144,
    "ordinary_data_max": 262_048,
    "terminal_slot_size": 4_096,
    "terminal_data_max": 4_000,
    "alignment": 8,
    "terminal_slots_per_area": 128,
}

RECORD_ENVELOPE_LITERAL = (
    ("magic", 0, 8),
    ("wire_version", 8, 2),
    ("record_kind", 10, 2),
    ("payload_length", 12, 4),
    ("sequence", 16, 8),
    ("generation", 24, 4),
    ("reserved", 28, 4),
    ("previous_checksum", 32, 32),
    ("record_checksum", 64, 32),
)

RECORD_KINDS_LITERAL = {
    "GENESIS": 1,
    "BEGIN": 2,
    "ITEM": 3,
    "DATA": 4,
    "END": 5,
    "FINAL": 6,
}

RECORD_PLACEMENTS_LITERAL = {
    "GENESIS": ("ordinary_first",),
    "BEGIN": ("ordinary",),
    "ITEM": ("ordinary", "a", "b", "c"),
    "DATA": ("ordinary", "a", "b", "c"),
    "END": ("ordinary",),
    "FINAL": ("d_slot_0",),
}

CATEGORIES_LITERAL = {
    "RETENTION_CONTROL": 0,
    "SOURCE_PACKAGE_PLIST": 1,
    "PROFILE_TOOLCHAIN": 2,
    "GOVERNANCE_QUALIFICATION": 3,
    "DIRECTORY_GRAPH": 4,
    "CREDENTIALS_BOOT_APFS": 5,
    "PROCESS_TERMINAL_OBSERVATIONS": 6,
    "STDOUT": 7,
    "STDERR": 8,
    "JOURNAL": 9,
    "BOOTSTRAP_PROVISIONING_RECEIPTS": 10,
    "ABORT_CLEANUP_FINAL_VERIFICATION": 11,
}

CATEGORY_MEANINGS_LITERAL = {
    "RETENTION_CONTROL": "Retention control/closing manifest",
    "SOURCE_PACKAGE_PLIST": "Source/package/plist",
    "PROFILE_TOOLCHAIN": "Profile/toolchain",
    "GOVERNANCE_QUALIFICATION": "Governance/qualification",
    "DIRECTORY_GRAPH": "Directory graph",
    "CREDENTIALS_BOOT_APFS": "Credentials/boot/APFS",
    "PROCESS_TERMINAL_OBSERVATIONS": "Process/terminal observations",
    "STDOUT": "Stdout",
    "STDERR": "Stderr",
    "JOURNAL": "Journal",
    "BOOTSTRAP_PROVISIONING_RECEIPTS": "Bootstrap/provisioning receipts",
    "ABORT_CLEANUP_FINAL_VERIFICATION": "Abort/cleanup/final-verification evidence",
}

ITEM_FIELDS_LITERAL = (
    "permit",
    "role",
    "category",
    "encoding",
    "schema",
    "length",
    "sha256",
)

CONTROL_FIELDS_LITERAL = ("schema", "n", "prev", "kind", "body")
CHECKPOINT_COMMON_FIELDS_LITERAL = (
    "disposition",
    "authorization",
    "verification",
    "closure_custody",
    "state",
)
CHECKPOINT_STATE_FIELDS_LITERAL = ("ordinary", "admitted", "terminal")
CHECKPOINT_SUBTYPE_FIELDS_LITERAL = {
    "admit": ("generation", "result", "purposes", "supersedes"),
    "abandon": ("generation",),
    "freeze_ordinary": ("cause",),
    "freeze_terminal_area": ("area", "cause"),
    "freeze_f": ("cause", "file_sha256"),
    "final_complete": ("file_sha256",),
    "final_failed": ("file_sha256",),
    "final_unresolved": ("file_sha256",),
}
CHECKPOINT_CAUSES_LITERAL = (
    "explicit",
    "torn",
    "ambiguous",
    "capacity",
    "io_failure",
    "custody",
    "invalid_state",
)

FORMAT_LIMITS_LITERAL = {
    "genesis_begin_end_payload_max": 1_024,
    "item_payload_max": 512,
    "item_descriptor_max": 357,
    "ordinary_item_max": 524_288,
    "terminal_item_wire_max": 508_000,
    "ordinary_physical_attempts_max": 3_584,
    "generation_numbers_max": 16,
    "records_per_generation_max": 512,
    "items_per_generation_max": 128,
    "ordinary_items_lifetime_max": 1_024,
    "aborted_generations_max": 4,
    "ordinary_generation_bytes_max": 2_097_152,
    "writable_phases_max": 24,
    "terminal_slots_scanned": 512,
    "support_objects_max": 128,
    "support_object_bytes_max": 65_536,
    "support_aggregate_bytes_max": 4_194_304,
}

# Direct, production-independent literals for shared V2-0 declarations.
# Each entry identifies the controlling clause in the accepted r2 text whose
# supplied evidence representation has SHA-256 R2_SOURCE_SHA256 above.
SHARED_DECLARATION_ORACLES = {
    "TERMINAL_GENERATION": {"clause": "r2 §3", "expected": 0xFFFF_FFFF},
    "ORDINARY_LOG_END": {"clause": "r2 §2", "expected": 12_582_912},
    "HEADROOM_END": {"clause": "r2 §2", "expected": 14_680_064},
    "MANDATORY_HEADROOM_SIZE": {"clause": "r2 §2", "expected": 2_097_152},
    "TERMINAL_AREA_SIZE": {"clause": "r2 §2", "expected": 524_288},
    "CONTROL_SCHEMA": {"clause": "r2 §7", "expected": "mcl-d0009-f2r2-control"},
    "CONTROL_KINDS": {
        "clause": "r2 §7",
        "expected": ("CREATE", "BIND", "AUTHORIZE", "CHECKPOINT"),
    },
    "ITEM_ENCODINGS": {"clause": "r2 §5", "expected": ("raw", "cjson2")},
    "ROLE_PATTERN": {"clause": "r2 §5", "expected": r"[a-z][a-z0-9_]{0,63}"},
    "CJSON2_KEY_PATTERN": {"clause": "r2 §4", "expected": r"[a-z][a-z0-9_]*"},
    "ORDINARY_OPEN_FIELDS": {
        "clause": "r2 §7",
        "expected": ("mode", "end", "prefix_sha256"),
    },
    "ORDINARY_FROZEN_FIELDS": {
        "clause": "r2 §7",
        "expected": ("mode", "end", "prefix_sha256", "region_sha256"),
    },
    "ADMITTED_FIELDS": {
        "clause": "r2 §7",
        "expected": ("generation", "end", "prefix_sha256"),
    },
    "TERMINAL_OPEN_FIELDS": {
        "clause": "r2 §7",
        "expected": ("mode", "used_slots", "prefix_sha256"),
    },
    "TERMINAL_FROZEN_FIELDS": {
        "clause": "r2 §7",
        "expected": ("mode", "used_slots", "prefix_sha256", "area_sha256"),
    },
    "CHECKPOINT_RESULTS": {
        "clause": "r2 §7",
        "expected": ("success", "failure", "unresolved"),
    },
    "TERMINAL_AREAS": {"clause": "r2 §7", "expected": ("A", "B", "C", "D")},
    "CJSON2_MAX_INTEGER_DIGITS": {"clause": "r2 §4", "expected": 20},
    "ORDINARY_ACCOUNT_BYTES": {
        "clause": "r2 §9",
        "expected": {
            "four_a1_snapshot_sets": 1_048_576,
            "a1_qualification_profile_governance": 2_097_152,
            "a2_evidence": 1_048_576,
            "gate_b_ordinary_evidence": 3_145_728,
            "descriptors_control_framing_padding": 1_048_576,
            "interruption_abandonment": 2_097_152,
            "review_correction": 2_097_152,
        },
    },
    "OPERATIONAL_CEILINGS": {
        "clause": "r2 §9",
        "expected": {
            "source": 131_072,
            "package": 122_880,
            "plist": 8_192,
            "build_stdout": 32_768,
            "build_stderr": 32_768,
            "object": 1_048_576,
            "executable": 1_048_576,
            "directory_graph": 524_288,
            "gate_b_stdout": 131_072,
            "gate_b_stderr": 32_768,
            "journal": 262_144,
        },
    },
}

# r2 section 3. Each header is a literal 96-byte checksum-zeroed envelope.
# The digests were derived from an independent test-side preimage.
F_CHECKSUM_LITERAL_VECTORS = (
    {
        "clause": "r2 §3",
        "name": "genesis-empty-at-zero",
        "offset": 0,
        "header": bytes.fromhex(
            "4d434c4439463200"
            "0200"
            "0100"
            "00000000"
            "0000000000000000"
            "00000000"
            "00000000"
            + ("00" * 32)
            + ("00" * 32)
        ),
        "payload": b"",
        "padding": b"",
        "sha256": "0eaee0c80d116779a75818d108877a40551e04663f1b483ac5c071fee56db185",
    },
    {
        "clause": "r2 §3",
        "name": "item-abc-at-4096",
        "offset": 4_096,
        "header": bytes.fromhex(
            "4d434c4439463200"
            "0200"
            "0300"
            "03000000"
            "0700000000000000"
            "02000000"
            "00000000"
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
            + ("00" * 32)
        ),
        "payload": b"abc",
        "padding": b"\x00" * 5,
        "sha256": "d32b13a2df2ebaa249192a6bbec1732467c4262a257dac9e4f347e9b4ec8e9b5",
    },
)

CANONICAL_CJSON2_VECTORS = (
    (b"{}", {}),
    (b'{"a":"[[[[[[[[["}', {"a": "[[[[[[[[["}),
    (
        '{"a":null,"b":[true,false,"x"],"c":"\\u000a\\"\\\\é"}'.encode(
            "utf-8"
        ),
        {"a": None, "b": [True, False, "x"], "c": '\n"\\é'},
    ),
    ('{"a":"é","b":"é"}'.encode("utf-8"), {"a": "é", "b": "é"}),
)

INVALID_CJSON2_VECTORS = (
    ("bom", b"\xef\xbb\xbf{}"),
    ("invalid_utf8", b'{"a":"\xff"}'),
    ("whitespace", b'{"a": null}'),
    ("unsorted_keys", b'{"b":null,"a":null}'),
    ("duplicate_key", b'{"a":null,"a":null}'),
    ("numeric_token", b'{"a":1}'),
    ("float_token", b'{"a":1.0}'),
    ("printable_unicode_escape", b'{"a":"\\u0061"}'),
    ("uppercase_control_escape", b'{"a":"\\u000A"}'),
    ("short_control_escape", b'{"a":"\\n"}'),
    ("escaped_solidus", b'{"a":"\\/"}'),
    ("bad_key", b'{"A":null}'),
    ("root_array", b"[]"),
    ("surrogate", b'{"a":"\\ud800"}'),
    ("depth_nine", b'{"a":[[[[[[[[null]]]]]]]]}'),
)

# r2 §4: the root object has depth 1, every nested object or array adds 1,
# and the maximum depth is 8.  This independent fixture is intentionally
# much deeper than either the adopted bound or an ordinary parser call path.
DEEP_NESTING_INVALID_VECTOR = {
    "clause": "r2 §4",
    "name": "depth_100001",
    "nested_arrays": 100_000,
    "encoded": b'{"a":' + (b"[" * 100_000) + b"null" + (b"]" * 100_000) + b"}",
}


# Independent literals for the adopted V2-0 CREATE/BIND/AUTHORIZE
# declarative-schema completion.  These values intentionally do not import the
# production Retention V2 package.
CREATE_BODY_FIELDS_LITERAL = (
    "specification",
    "v1_freeze",
    "f_path_hex",
    "parent_profile",
    "creation_profile",
    "custody_profile",
    "writer_profile",
    "creation_authority",
)
BIND_BODY_FIELDS_LITERAL = (
    "create",
    "identity",
    "qualification",
    "size_verification",
    "zero_verification",
    "allocation",
    "setup_writer_closure",
    "genesis_permitted",
)
AUTHORIZE_BODY_FIELDS_LITERAL = (
    "base",
    "writer",
    "dispatch",
    "operation_plan",
    "generation",
    "outcomes",
    "item_roles",
    "required_roles",
    "terminal_areas",
    "terminal_roles",
    "branches",
    "intermediate_stores",
    "abort_actions",
    "cleanup_actions",
)
ORDINARY_ROLE_FIELDS_LITERAL = (
    "role",
    "category",
    "encoding",
    "schema",
    "max_length",
    "account",
)
OUTCOME_ROLES_FIELDS_LITERAL = ("success", "failure", "unresolved")
TERMINAL_ROLE_FIELDS_LITERAL = (
    "branch",
    "area",
    "role",
    "category",
    "encoding",
    "schema",
    "max_length",
)
TERMINAL_BRANCH_FIELDS_LITERAL = ("branch", "condition", "reservations", "limits")
SLOT_RESERVATION_FIELDS_LITERAL = ("area", "first_slot", "slot_count")
BRANCH_LIMIT_FIELDS_LITERAL = (
    "ordinary_bytes",
    "ordinary_records",
    "ordinary_items",
    "ordinary_aborts",
    "ordinary_accounts",
    "terminal_payload_bytes",
    "writable_phases",
    "support_objects",
    "support_bytes",
)
INTERMEDIATE_STORE_FIELDS_LITERAL = ("store", "ordinary_roles", "terminal_roles")
TERMINAL_ROLE_REFERENCE_FIELDS_LITERAL = ("branch", "area", "role")
ACTION_PERMISSION_FIELDS_LITERAL = ("action", "branches")
ORDINARY_ACCOUNT_FIELDS_LITERAL = (
    "four_a1_snapshot_sets",
    "a1_qualification_profile_governance",
    "a2_evidence",
    "gate_b_ordinary_evidence",
    "descriptors_control_framing_padding",
    "interruption_abandonment",
    "review_correction",
)

CONTROL_PATTERNS_LITERAL = {
    "digest": r"[0-9a-f]{64}",
    "path_hex": r"(?:[0-9a-f]{2})+",
    "plan_ref": r"[a-z][a-z0-9_]{0,63}",
    "role": r"[a-z][a-z0-9_]{0,63}",
    "uint": r"(?:0|[1-9][0-9]*)",
}
CONTROL_ENUMS_LITERAL = {
    "authorize_outcomes": ("success", "failure", "unresolved"),
    "encodings": ("raw", "cjson2"),
    "ordinary_accounts": ORDINARY_ACCOUNT_FIELDS_LITERAL,
    "terminal_areas": ("A", "B", "C", "D"),
    "terminal_item_areas": ("A", "B", "C"),
}
CONTROL_OBJECT_BYTES_MAX_LITERAL = 65_536

CONTROL_FIELD_TYPES_LITERAL = {
    "create_body": (
        ("specification", "ref"),
        ("v1_freeze", "ref"),
        ("f_path_hex", "path_hex"),
        ("parent_profile", "ref"),
        ("creation_profile", "ref"),
        ("custody_profile", "ref"),
        ("writer_profile", "ref"),
        ("creation_authority", "ref"),
    ),
    "bind_body": (
        ("create", "ref"),
        ("identity", "ref"),
        ("qualification", "ref"),
        ("size_verification", "ref"),
        ("zero_verification", "ref"),
        ("allocation", "ref"),
        ("setup_writer_closure", "ref"),
        ("genesis_permitted", "boolean"),
    ),
    "authorize_body": (
        ("base", "ref"),
        ("writer", "ref"),
        ("dispatch", "ref"),
        ("operation_plan", "ref"),
        ("generation", "uint_or_null"),
        ("outcomes", "array[outcome]"),
        ("item_roles", "array[ordinary_role]"),
        ("required_roles", "object[outcome_roles]"),
        ("terminal_areas", "array[terminal_area]"),
        ("terminal_roles", "array[terminal_role]"),
        ("branches", "array[terminal_branch]"),
        ("intermediate_stores", "array[intermediate_store]"),
        ("abort_actions", "array[action_permission]"),
        ("cleanup_actions", "array[action_permission]"),
    ),
    "ordinary_role": (
        ("role", "role"),
        ("category", "uint"),
        ("encoding", "encoding"),
        ("schema", "ref_or_null"),
        ("max_length", "uint"),
        ("account", "ordinary_account"),
    ),
    "outcome_roles": (
        ("success", "array[role]"),
        ("failure", "array[role]"),
        ("unresolved", "array[role]"),
    ),
    "terminal_role": (
        ("branch", "role"),
        ("area", "terminal_item_area"),
        ("role", "role"),
        ("category", "uint"),
        ("encoding", "encoding"),
        ("schema", "ref_or_null"),
        ("max_length", "uint"),
    ),
    "terminal_branch": (
        ("branch", "role"),
        ("condition", "plan_ref"),
        ("reservations", "array[slot_reservation]"),
        ("limits", "object[branch_limits]"),
    ),
    "slot_reservation": (
        ("area", "terminal_area"),
        ("first_slot", "uint"),
        ("slot_count", "uint"),
    ),
    "branch_limits": (
        ("ordinary_bytes", "uint"),
        ("ordinary_records", "uint"),
        ("ordinary_items", "uint"),
        ("ordinary_aborts", "uint"),
        ("ordinary_accounts", "object[ordinary_accounts]"),
        ("terminal_payload_bytes", "array[uint]"),
        ("writable_phases", "uint"),
        ("support_objects", "uint"),
        ("support_bytes", "uint"),
    ),
    "ordinary_accounts": tuple((field, "uint") for field in ORDINARY_ACCOUNT_FIELDS_LITERAL),
    "intermediate_store": (
        ("store", "ref"),
        ("ordinary_roles", "array[role]"),
        ("terminal_roles", "array[terminal_role_reference]"),
    ),
    "terminal_role_reference": (
        ("branch", "role"),
        ("area", "terminal_item_area"),
        ("role", "role"),
    ),
    "action_permission": (("action", "plan_ref"), ("branches", "array[role]")),
}

CONTROL_NULLABLE_FIELDS_LITERAL = {
    "create_body": (),
    "bind_body": (),
    "authorize_body": ("generation",),
    "ordinary_role": ("schema",),
    "outcome_roles": (),
    "terminal_role": ("schema",),
    "terminal_branch": (),
    "slot_reservation": (),
    "branch_limits": (),
    "ordinary_accounts": (),
    "intermediate_store": (),
    "terminal_role_reference": (),
    "action_permission": (),
}

CONTROL_UINT_RANGES_LITERAL = {
    "authorize_body.generation": (1, 15),
    "ordinary_role.category": (0, 11),
    "ordinary_role.max_length": (0, 524_288),
    "terminal_role.category": (0, 11),
    "terminal_role.max_length": (0, 508_000),
    "slot_reservation.first_slot": (0, 127),
    "slot_reservation.slot_count": (1, 128),
    "branch_limits.ordinary_bytes": (0, 2_097_152),
    "branch_limits.ordinary_records": (0, 512),
    "branch_limits.ordinary_items": (0, 128),
    "branch_limits.ordinary_aborts": (0, 1),
    "branch_limits.writable_phases": (0, 24),
    "branch_limits.support_objects": (0, 128),
    "branch_limits.support_bytes": (0, 4_194_304),
    **{
        f"ordinary_accounts.{name}": (0, limit)
        for name, limit in {
            "four_a1_snapshot_sets": 1_048_576,
            "a1_qualification_profile_governance": 2_097_152,
            "a2_evidence": 1_048_576,
            "gate_b_ordinary_evidence": 3_145_728,
            "descriptors_control_framing_padding": 1_048_576,
            "interruption_abandonment": 2_097_152,
            "review_correction": 2_097_152,
        }.items()
    },
}
BRANCH_TERMINAL_PAYLOAD_RANGES_LITERAL = (
    (0, 508_000),
    (0, 131_072),
    (0, 65_536),
    (0, 4_000),
)

CONTROL_ARRAY_METADATA_LITERAL = {
    "authorize_body.outcomes": ("outcome", 0, 3, "outcome_order"),
    "authorize_body.item_roles": ("ordinary_role", 0, 128, "role_ascii"),
    "outcome_roles.success": ("role", 0, 128, "role_ascii"),
    "outcome_roles.failure": ("role", 0, 128, "role_ascii"),
    "outcome_roles.unresolved": ("role", 0, 128, "role_ascii"),
    "authorize_body.terminal_areas": ("terminal_area", 0, 4, "area_abcd"),
    "authorize_body.terminal_roles": (
        "terminal_role",
        0,
        None,
        "branch_ascii_area_abc_declared_role_order",
    ),
    "authorize_body.branches": ("terminal_branch", 1, None, "branch_ascii"),
    "authorize_body.intermediate_stores": ("intermediate_store", 0, None, "store_ascii"),
    "authorize_body.abort_actions": ("action_permission", 0, None, "action_ascii"),
    "authorize_body.cleanup_actions": ("action_permission", 0, None, "action_ascii"),
    "terminal_branch.reservations": ("slot_reservation", 0, 4, "area_abcd"),
    "branch_limits.terminal_payload_bytes": ("uint", 4, 4, "area_abcd"),
    "intermediate_store.ordinary_roles": ("role", 0, 128, "role_ascii"),
    "intermediate_store.terminal_roles": (
        "terminal_role_reference",
        0,
        None,
        "branch_ascii_area_abc_role_ascii",
    ),
    "action_permission.branches": ("role", 1, None, "branch_ascii"),
}

CONTROL_REPRESENTATIONS_LITERAL = {
    "boolean": ("json_boolean", (False, True)),
    "digest": ("string", "lowercase_sha256_hex"),
    "encoding": ("string", ("raw", "cjson2")),
    "outcome": ("string", ("success", "failure", "unresolved")),
    "path_hex": ("string", "exact_absolute_path_bytes_lowercase_hex"),
    "plan_ref": ("string", "role_shaped_operation_plan_identifier"),
    "ref": ("string", "digest_of_exact_externally_supplied_bytes"),
    "role": ("string", "role_grammar"),
    "uint": ("string", "canonical_decimal_at_most_20_digits"),
}

AUTHORIZE_BRANCH_SEMANTICS_LITERAL = {
    "branch_model": "complete_mutually_exclusive_alternative_path",
    "sequential_terminal_use": "within_branch",
    "alternative_demand": "maximum_complete_path",
    "within_path_demand": "cumulative",
    "mutually_exclusive_reservations_may_overlap": True,
    "simultaneously_consumable_reservations_may_overlap": False,
    "first_slot": "deterministic_append_frontier",
}
CONTROL_LIFECYCLE_DECLARATIONS_LITERAL = {
    "create_per_f_lifecycle": 1,
    "bind_per_f_lifecycle": 1,
    "authorize_generation_min": 1,
    "authorize_generation_max": 15,
    "authorize_after_freeze_f": False,
    "authorize_after_final_disposition": False,
    "authorize_after_d_attempt": False,
    "genesis_requires_distinct_bind_digest_approval": True,
    "genesis_permitted_false_is_permanent": True,
}
ORDINARY_ACCOUNT_ATTRIBUTION_LITERAL = {
    "item_descriptor_header_padding": "descriptors_control_framing_padding",
    "data_payload": "declared_role_account",
    "data_header_padding": "descriptors_control_framing_padding",
    "genesis_begin_end_physical": "descriptors_control_framing_padding",
    "terminal_item_data": "terminal_capacity",
}
D_FINAL_DECLARATION_LITERAL = {
    "area": "D",
    "record_kind": "FINAL",
    "first_slot": "0",
    "slot_count": "1",
    "payload_without_reservation": "0",
    "payload_with_reservation": "4000",
    "terminal_item_allowed": False,
}

EMPTY_RAW_ITEM_ORACLE = {
    "length": "0",
    "data_records": 0,
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
CLOSING_MANIFEST_TERMINAL_ROLE_ORACLE = {
    "branch": "final_path",
    "area": "C",
    "role": "closing_manifest",
    "category": "0",
    "encoding": "cjson2",
    "schema": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "max_length": "65536",
}

_ZERO_ACCOUNTS = {
    "four_a1_snapshot_sets": "0",
    "a1_qualification_profile_governance": "0",
    "a2_evidence": "0",
    "gate_b_ordinary_evidence": "0",
    "descriptors_control_framing_padding": "0",
    "interruption_abandonment": "0",
    "review_correction": "0",
}

CREATE_CONTROL_SPECIMEN = {
    "schema": "mcl-d0009-f2r2-control",
    "n": "0",
    "prev": None,
    "kind": "CREATE",
    "body": {
        "specification": "0000000000000000000000000000000000000000000000000000000000000000",
        "v1_freeze": "1111111111111111111111111111111111111111111111111111111111111111",
        "f_path_hex": "2f746d702f66",
        "parent_profile": "2222222222222222222222222222222222222222222222222222222222222222",
        "creation_profile": "3333333333333333333333333333333333333333333333333333333333333333",
        "custody_profile": "4444444444444444444444444444444444444444444444444444444444444444",
        "writer_profile": "5555555555555555555555555555555555555555555555555555555555555555",
        "creation_authority": "6666666666666666666666666666666666666666666666666666666666666666",
    },
}
BIND_TRUE_CONTROL_SPECIMEN = {
    "schema": "mcl-d0009-f2r2-control",
    "n": "1",
    "prev": "7777777777777777777777777777777777777777777777777777777777777777",
    "kind": "BIND",
    "body": {
        "create": "7777777777777777777777777777777777777777777777777777777777777777",
        "identity": "8888888888888888888888888888888888888888888888888888888888888888",
        "qualification": "9999999999999999999999999999999999999999999999999999999999999999",
        "size_verification": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "zero_verification": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "allocation": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "setup_writer_closure": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "genesis_permitted": True,
    },
}
BIND_FALSE_CONTROL_SPECIMEN = {
    "schema": "mcl-d0009-f2r2-control",
    "n": "1",
    "prev": "7777777777777777777777777777777777777777777777777777777777777777",
    "kind": "BIND",
    "body": {
        "create": "7777777777777777777777777777777777777777777777777777777777777777",
        "identity": "8888888888888888888888888888888888888888888888888888888888888888",
        "qualification": "9999999999999999999999999999999999999999999999999999999999999999",
        "size_verification": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "zero_verification": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "allocation": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "setup_writer_closure": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "genesis_permitted": False,
    },
}

ORDINARY_AUTHORIZE_SPECIMEN = {
    "schema": "mcl-d0009-f2r2-control",
    "n": "2",
    "prev": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "kind": "AUTHORIZE",
    "body": {
        "base": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "writer": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "dispatch": "0101010101010101010101010101010101010101010101010101010101010101",
        "operation_plan": "0202020202020202020202020202020202020202020202020202020202020202",
        "generation": "1",
        "outcomes": ["success"],
        "item_roles": [
            {
                "role": "build_stdout",
                "category": "7",
                "encoding": "raw",
                "schema": None,
                "max_length": "32768",
                "account": "a2_evidence",
            }
        ],
        "required_roles": {"success": ["build_stdout"], "failure": [], "unresolved": []},
        "terminal_areas": [],
        "terminal_roles": [],
        "branches": [
            {
                "branch": "success_path",
                "condition": "success_path",
                "reservations": [],
                "limits": {
                    "ordinary_bytes": "33792",
                    "ordinary_records": "4",
                    "ordinary_items": "1",
                    "ordinary_aborts": "0",
                    "ordinary_accounts": {
                        **_ZERO_ACCOUNTS,
                        "a2_evidence": "32768",
                        "descriptors_control_framing_padding": "1024",
                    },
                    "terminal_payload_bytes": ["0", "0", "0", "0"],
                    "writable_phases": "1",
                    "support_objects": "1",
                    "support_bytes": "1024",
                },
            }
        ],
        "intermediate_stores": [
            {
                "store": "0303030303030303030303030303030303030303030303030303030303030303",
                "ordinary_roles": ["build_stdout"],
                "terminal_roles": [],
            }
        ],
        "abort_actions": [],
        "cleanup_actions": [],
    },
}

COMMITTED_OUTCOMES_AUTHORIZE_SPECIMEN = {
    **ORDINARY_AUTHORIZE_SPECIMEN,
    "body": {
        **ORDINARY_AUTHORIZE_SPECIMEN["body"],
        "outcomes": ["success", "failure", "unresolved"],
        "item_roles": [
            {
                "role": "failure_evidence",
                "category": "11",
                "encoding": "raw",
                "schema": None,
                "max_length": "1024",
                "account": "interruption_abandonment",
            },
            {
                "role": "success_evidence",
                "category": "3",
                "encoding": "cjson2",
                "schema": "0404040404040404040404040404040404040404040404040404040404040404",
                "max_length": "1024",
                "account": "a1_qualification_profile_governance",
            },
            {
                "role": "unresolved_evidence",
                "category": "11",
                "encoding": "raw",
                "schema": None,
                "max_length": "1024",
                "account": "review_correction",
            },
        ],
        "required_roles": {
            "success": ["success_evidence"],
            "failure": ["failure_evidence"],
            "unresolved": ["unresolved_evidence"],
        },
        "intermediate_stores": [
            {
                "store": "0303030303030303030303030303030303030303030303030303030303030303",
                "ordinary_roles": [
                    "failure_evidence",
                    "success_evidence",
                    "unresolved_evidence",
                ],
                "terminal_roles": [],
            }
        ],
    },
}

TERMINAL_BRANCH_AUTHORIZE_SPECIMEN = {
    **ORDINARY_AUTHORIZE_SPECIMEN,
    "body": {
        **ORDINARY_AUTHORIZE_SPECIMEN["body"],
        "terminal_areas": ["A"],
        "terminal_roles": [
            {
                "branch": "failure_path",
                "area": "A",
                "role": "failure_bundle",
                "category": "11",
                "encoding": "raw",
                "schema": None,
                "max_length": "4000",
            }
        ],
        "branches": [
            {
                "branch": "failure_path",
                "condition": "failure_path",
                "reservations": [{"area": "A", "first_slot": "0", "slot_count": "2"}],
                "limits": {
                    "ordinary_bytes": "33792",
                    "ordinary_records": "4",
                    "ordinary_items": "1",
                    "ordinary_aborts": "0",
                    "ordinary_accounts": {
                        **_ZERO_ACCOUNTS,
                        "a2_evidence": "32768",
                        "descriptors_control_framing_padding": "1024",
                    },
                    "terminal_payload_bytes": ["4000", "0", "0", "0"],
                    "writable_phases": "2",
                    "support_objects": "1",
                    "support_bytes": "1024",
                },
            },
            {
                "branch": "success_path",
                "condition": "success_path",
                "reservations": [{"area": "A", "first_slot": "0", "slot_count": "2"}],
                "limits": {
                    "ordinary_bytes": "33792",
                    "ordinary_records": "4",
                    "ordinary_items": "1",
                    "ordinary_aborts": "0",
                    "ordinary_accounts": {
                        **_ZERO_ACCOUNTS,
                        "a2_evidence": "32768",
                        "descriptors_control_framing_padding": "1024",
                    },
                    "terminal_payload_bytes": ["4000", "0", "0", "0"],
                    "writable_phases": "2",
                    "support_objects": "1",
                    "support_bytes": "1024",
                },
            },
        ],
        "intermediate_stores": [
            {
                "store": "0303030303030303030303030303030303030303030303030303030303030303",
                "ordinary_roles": ["build_stdout"],
                "terminal_roles": [
                    {"branch": "failure_path", "area": "A", "role": "failure_bundle"},
                    {"branch": "success_path", "area": "A", "role": "failure_bundle"},
                ],
            }
        ],
    },
}

TERMINAL_ONLY_AUTHORIZE_SPECIMEN = {
    **TERMINAL_BRANCH_AUTHORIZE_SPECIMEN,
    "body": {
        **TERMINAL_BRANCH_AUTHORIZE_SPECIMEN["body"],
        "generation": None,
        "outcomes": [],
        "item_roles": [],
        "required_roles": {"success": [], "failure": [], "unresolved": []},
        "branches": [TERMINAL_BRANCH_AUTHORIZE_SPECIMEN["body"]["branches"][0]],
        "intermediate_stores": [
            {
                "store": "0303030303030303030303030303030303030303030303030303030303030303",
                "ordinary_roles": [],
                "terminal_roles": [
                    {"branch": "failure_path", "area": "A", "role": "failure_bundle"}
                ],
            }
        ],
    },
}

D_RESERVED_AUTHORIZE_SPECIMEN = {
    **TERMINAL_ONLY_AUTHORIZE_SPECIMEN,
    "body": {
        **TERMINAL_ONLY_AUTHORIZE_SPECIMEN["body"],
        "terminal_areas": ["D"],
        "terminal_roles": [],
        "branches": [
            {
                "branch": "final_path",
                "condition": "final_path",
                "reservations": [{"area": "D", "first_slot": "0", "slot_count": "1"}],
                "limits": {
                    "ordinary_bytes": "0",
                    "ordinary_records": "0",
                    "ordinary_items": "0",
                    "ordinary_aborts": "0",
                    "ordinary_accounts": _ZERO_ACCOUNTS,
                    "terminal_payload_bytes": ["0", "0", "0", "4000"],
                    "writable_phases": "1",
                    "support_objects": "1",
                    "support_bytes": "1024",
                },
            }
        ],
        "intermediate_stores": [],
    },
}

NO_D_AUTHORIZE_SPECIMEN = {
    **TERMINAL_ONLY_AUTHORIZE_SPECIMEN,
    "body": {
        **TERMINAL_ONLY_AUTHORIZE_SPECIMEN["body"],
        "branches": [
            {
                **TERMINAL_ONLY_AUTHORIZE_SPECIMEN["body"]["branches"][0],
                "limits": {
                    **TERMINAL_ONLY_AUTHORIZE_SPECIMEN["body"]["branches"][0]["limits"],
                    "terminal_payload_bytes": ["4000", "0", "0", "0"],
                },
            }
        ],
    },
}

CONTROL_SCHEMA_SPECIMENS = (
    ("create", CREATE_CONTROL_SPECIMEN),
    ("bind_genesis_true", BIND_TRUE_CONTROL_SPECIMEN),
    ("bind_genesis_false", BIND_FALSE_CONTROL_SPECIMEN),
    ("ordinary_authorize", ORDINARY_AUTHORIZE_SPECIMEN),
    ("authorize_committed_outcomes", COMMITTED_OUTCOMES_AUTHORIZE_SPECIMEN),
    ("reachable_terminal_branch", TERMINAL_BRANCH_AUTHORIZE_SPECIMEN),
    ("terminal_only_authorize", TERMINAL_ONLY_AUTHORIZE_SPECIMEN),
    ("branch_with_d_reservation", D_RESERVED_AUTHORIZE_SPECIMEN),
    ("branch_without_d_reservation", NO_D_AUTHORIZE_SPECIMEN),
)

CONTROL_CLOSED_SCHEMA_INVALID_ORACLES = (
    ("create_missing_specification", "create_body", "specification", "missing", "closed_schema"),
    ("bind_unknown_field", "bind_body", "unexpected", "present", "closed_schema"),
    ("bind_genesis_null", "bind_body", "genesis_permitted", None, "closed_schema"),
    ("authorize_generation_zero", "authorize_body", "generation", "0", "closed_schema"),
    ("ordinary_role_missing_account", "ordinary_role", "account", "missing", "closed_schema"),
    ("ordinary_role_null_account", "ordinary_role", "account", None, "closed_schema"),
    ("ordinary_role_unknown_account", "ordinary_role", "account", "other", "closed_schema"),
    ("terminal_role_in_d", "terminal_role", "area", "D", "closed_schema"),
    ("d_wrong_first_slot", "slot_reservation", "first_slot", "1", "semantic_references"),
    ("closing_manifest_wrong_category", "terminal_role", "category", "11", "semantic_references"),
)
