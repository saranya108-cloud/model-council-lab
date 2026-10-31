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


# Decision 0009 V2-1 independent verifier fixtures and r2 section 18 oracles.
#
# This additive section deliberately uses only Python's standard library and
# literal values from the adopted specification.  It does not import the
# production verifier, traversal, reducer, encoder, or checksum construction.
import hashlib as _v2_hashlib
import json as _v2_json
import struct as _v2_struct


V2_1_RESULT_SCHEMA = "mcl-d0009-f2r2-verification"
V2_1_RESULT_FIELDS = (
    "schema",
    "subject",
    "integrity",
    "physical_state",
    "durability",
    "authority",
    "custody",
    "admitted_prefix",
    "operation_result",
    "progression",
    "validation",
)
V2_1_SUBJECT_FIELDS = (
    "specification",
    "binding",
    "control",
    "file_sha256",
    "identity_matches",
)
V2_1_VALIDATION_FIELDS = ("encoding", "schema", "references")
V2_1_RESULT_ENUMS = {
    "integrity": (
        "valid",
        "invalid",
        "blocked_torn",
        "blocked_ambiguous",
        "not_established",
    ),
    "physical_state": (
        "clean_frontier",
        "committed_tail",
        "incomplete_tail",
        "aborted_tail",
        "ordinary_frozen",
        "terminal_frozen",
        "finalized",
        "malformed_size_or_state",
        "unobserved",
    ),
    "durability": ("established", "not_established", "not_applicable"),
    "authority": ("current", "historical_only", "invalid", "not_established"),
    "custody": ("valid", "invalid", "not_established"),
    "admitted_prefix": ("valid", "invalid", "not_established", "not_applicable"),
    "operation_result": ("success", "failure", "unresolved", "not_applicable"),
    "progression": (
        "eligible_for_chair_consideration",
        "blocked_pending_disposition",
        "blocked_integrity",
        "blocked_custody",
        "blocked_authority",
        "final",
    ),
    "validation": ("valid", "invalid", "not_checked"),
}
V2_1_VECTOR_FIELDS = (
    "integrity",
    "physical_state",
    "durability",
    "authority",
    "custody",
    "admitted_prefix",
    "operation_result",
    "progression",
    "validation",
)
V2_1_VECTOR_ORACLES = (
    ("valid_admitted_genesis", "Valid admitted genesis", "V/C/E/C/V/V/S/E/VVV", "r2 §18"),
    (
        "valid_admitted_successful_generation",
        "Valid admitted successful generation",
        "V/C/E/C/V/V/S/E/VVV",
        "r2 §18",
    ),
    (
        "complete_successful_generation_awaiting_admission",
        "Complete successful generation awaiting admission",
        "V/K/E/C/V/V/S/E/VVV",
        "r2 §18",
    ),
    (
        "complete_failure_package_awaiting_disposition",
        "Complete failure package awaiting disposition",
        "V/K/E/C/V/V/F/P/VVV",
        "r2 §18",
    ),
    (
        "complete_unresolved_package_awaiting_disposition",
        "Complete unresolved package awaiting disposition",
        "V/K/E/C/V/V/U/P/VVV",
        "r2 §18",
    ),
    (
        "valid_incomplete_generation_no_end",
        "Valid incomplete generation, no END",
        "V/I/N/C/V/V/U/P/VVV",
        "r2 §18",
    ),
    ("valid_abort_unresolved", "Valid abort/unresolved", "V/B/E/C/V/V/U/P/VVV", "r2 §18"),
    ("end_abort_failure", "END abort/failure", "X/O/N/C/V/V/U/I/VIN", "r2 §18"),
    (
        "end_commit_unresolved_missing_required_role",
        "END commit/unresolved missing an unresolved-required role",
        "X/O/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "end_commit_while_item_incomplete",
        "END commit while item is incomplete",
        "X/O/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "known_stale_current_authority_input",
        "Known stale current-authority input",
        "V/C/E/H/V/V/S/A/VVV",
        "r2 §18",
    ),
    ("control_history_fork", "Control-history fork", "V/C/E/X/V/V/S/A/VVI", "r2 §18"),
    (
        "activation_control_reference_mismatch",
        "Activation/control reference mismatch",
        "V/C/E/X/V/V/S/A/VVI",
        "r2 §18",
    ),
    (
        "no_trusted_authority_valid_unadmitted_file",
        "No trusted authority; valid unadmitted file supplied",
        "V/K/N/N/V/N/S/A/VVV",
        "r2 §18",
    ),
    (
        "stale_abandonment_disposition_used_to_continue",
        "Stale abandonment disposition used to continue",
        "X/O/N/X/V/V/U/A/VVI",
        "r2 §18",
    ),
    ("writer_still_running", "Writer still running", "V/K/N/C/X/V/S/C/VVV", "r2 §18"),
    (
        "writer_closure_not_established",
        "Writer closure not established",
        "V/K/N/C/N/V/S/C/VVV",
        "r2 §18",
    ),
    (
        "wrong_f_identity_identical_bytes",
        "Wrong F identity with identical bytes",
        "V/C/N/C/X/N/S/C/VVV",
        "r2 §18",
    ),
    ("f_wrong_size", "F truncated or larger than S", "X/M/N/C/V/N/U/I/NNN", "r2 §18"),
    (
        "overflowing_item_integer",
        "Overflowing/unbounded integer string in ITEM",
        "X/O/N/C/V/V/U/I/VIN",
        "r2 §18",
    ),
    (
        "unknown_semantic_category",
        "Validly framed unknown semantic category",
        "X/O/N/C/V/V/U/I/VIN",
        "r2 §18",
    ),
    (
        "unknown_kind_or_reserved",
        "Unknown record kind or nonzero reserved header field",
        "T/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "bad_checksum_or_physical_length",
        "Bad record checksum or malformed physical length",
        "T/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "sequence_predecessor_generation_discontinuity",
        "Sequence/predecessor/generation discontinuity",
        "T/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "invalid_cjson2",
        "Duplicate key, alternate escape, numeric token, malformed UTF-8, or excessive depth",
        "X/O/N/C/V/V/U/I/INN",
        "r2 §18",
    ),
    (
        "unknown_control_field_or_invalid_role",
        "Unknown control field or invalid role grammar",
        "X/O/N/C/V/V/U/I/VIN",
        "r2 §18",
    ),
    (
        "distinct_unicode_normalization_forms",
        "Two separately permitted Unicode-normalization forms, correctly hashed as distinct raw items",
        "V/K/E/C/V/V/S/E/VVV",
        "r2 §18",
    ),
    (
        "interleaved_excess_data_or_digest_mismatch",
        "Interleaved/excess DATA, duplicate role, or full-item digest mismatch",
        "X/O/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "terminal_item_over_bound",
        "Claimed terminal length over role/508,000/remaining-slot bound",
        "X/T/N/C/V/V/U/I/VIN",
        "r2 §18",
    ),
    (
        "ordinary_item_permit_mismatch",
        "Ordinary ITEM permit differs from BEGIN",
        "X/O/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "terminal_declaration_mismatch",
        "Terminal permit/role/category/schema/branch mismatch or wrong area",
        "X/T/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "zero_header_followed_by_nonzero",
        "Zero ordinary header followed by nonzero bytes",
        "A/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "plausible_record_after_invalid_boundary",
        "Plausible record after an invalid ordinary boundary",
        "T/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "nonzero_mandatory_headroom",
        "Nonzero mandatory headroom",
        "X/M/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "earlier_admitted_prefix_changed",
        "Earlier admitted prefix changed",
        "X/O/N/C/V/X/U/I/NNN",
        "r2 §18",
    ),
    (
        "earlier_prefix_intact_torn_later_tail",
        "Earlier prefix intact, torn later tail",
        "T/O/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "generation_account_record_ceiling_violation",
        "Generation/account/record ceiling violation",
        "X/O/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "unexpected_nonzero_unused_terminal_slot",
        "Unexpected raw nonzero unused terminal slot",
        "A/T/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "uncertain_zero_byte_terminal_attempt",
        "Externally established uncertain zero-byte terminal attempt",
        "V/T/N/C/V/V/U/P/VVV",
        "r2 §18",
    ),
    (
        "frozen_abc_bytes_changed",
        "Frozen A/B/C bytes later changed",
        "X/T/N/C/V/V/U/I/NNN",
        "r2 §18",
    ),
    (
        "d_without_valid_c",
        "D attempted without complete valid frozen C",
        "X/T/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "final_outcome_differs_manifest",
        "FINAL outcome differs from manifest",
        "X/T/N/C/V/V/U/I/VVI",
        "r2 §18",
    ),
    (
        "valid_final_without_sync",
        "Valid FINAL but synchronization proof absent, no final checkpoint",
        "V/T/N/C/V/V/S/P/VVV",
        "r2 §18",
    ),
    (
        "torn_c_final_failed",
        "Torn C, D absent, valid external final-failed disposition",
        "T/T/N/C/V/V/U/F/NNN",
        "r2 §18",
    ),
    (
        "torn_d_final_unresolved",
        "Torn D, valid external final-unresolved disposition",
        "T/T/N/C/V/V/U/F/NNN",
        "r2 §18",
    ),
    (
        "valid_complete_finalization",
        "Valid complete finalization and final-complete checkpoint",
        "V/F/E/C/V/V/S/F/VVV",
        "r2 §18",
    ),
    (
        "valid_unresolved_finalization",
        "Valid unresolved finalization and final-unresolved checkpoint",
        "V/F/E/C/V/V/U/F/VVV",
        "r2 §18",
    ),
    (
        "obsolete_whole_file_observation_after_append",
        "Obsolete whole-file observation differs after a valid authorized append",
        "V/K/E/C/V/V/S/E/VVV",
        "r2 §18",
    ),
)


_V2_1_VECTOR_CODES = {
    "integrity": {
        "V": "valid",
        "X": "invalid",
        "T": "blocked_torn",
        "A": "blocked_ambiguous",
    },
    "physical_state": {
        "C": "clean_frontier",
        "K": "committed_tail",
        "I": "incomplete_tail",
        "B": "aborted_tail",
        "O": "ordinary_frozen",
        "T": "terminal_frozen",
        "F": "finalized",
        "M": "malformed_size_or_state",
    },
    "durability": {"E": "established", "N": "not_established"},
    "authority": {
        "C": "current",
        "H": "historical_only",
        "X": "invalid",
        "N": "not_established",
    },
    "custody": {"V": "valid", "X": "invalid", "N": "not_established"},
    "admitted_prefix": {"V": "valid", "X": "invalid", "N": "not_established"},
    "operation_result": {"S": "success", "F": "failure", "U": "unresolved"},
    "progression": {
        "E": "eligible_for_chair_consideration",
        "P": "blocked_pending_disposition",
        "I": "blocked_integrity",
        "C": "blocked_custody",
        "A": "blocked_authority",
        "F": "final",
    },
    "validation": {"V": "valid", "I": "invalid", "N": "not_checked"},
}


def expand_v2_1_vector(vector):
    """Expand adopted r2 shorthand without consulting production code."""

    parts = vector.split("/")
    if len(parts) != 9 or len(parts[-1]) != 3:
        raise AssertionError(f"invalid independent vector literal: {vector}")
    expanded = {}
    for field, code in zip(V2_1_VECTOR_FIELDS[:-1], parts[:-1]):
        expanded[field] = _V2_1_VECTOR_CODES[field][code]
    expanded["validation"] = {
        field: _V2_1_VECTOR_CODES["validation"][code]
        for field, code in zip(V2_1_VALIDATION_FIELDS, parts[-1])
    }
    return expanded


_V2_1_F_SIZE = 16_777_216
_V2_1_ORDINARY_END = 12_582_912
_V2_1_HEADROOM_END = 14_680_064
_V2_1_AREA_STARTS = {
    "A": 14_680_064,
    "B": 15_204_352,
    "C": 15_728_640,
    "D": 16_252_928,
}
_V2_1_MAGIC = bytes.fromhex("4d434c4439463200")
_V2_1_DOMAIN = b"MCL-D0009-F2R1-REC"
_V2_1_ZERO_DIGEST = "0" * 64
_V2_1_EMPTY_SHA256 = _v2_hashlib.sha256(b"").hexdigest()
_V2_1_IDENTITY = "f" * 64
_V2_1_SPECIFICATION = R2_SOURCE_SHA256
_V2_1_CLOSING_SCHEMA = "c" * 64


def _v2_1_cjson(value):
    encoded = _v2_json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if b" " in encoded or b"\n" in encoded:
        raise AssertionError("fixture encoder introduced insignificant whitespace")
    return encoded


def _v2_1_digest(data):
    return _v2_hashlib.sha256(data).hexdigest()


def _v2_1_record(
    offset,
    kind,
    payload,
    sequence,
    generation,
    previous,
    *,
    terminal=False,
    reserved=0,
    payload_length=None,
):
    declared_length = len(payload) if payload_length is None else payload_length
    physical_length = 4_096 if terminal else ((96 + declared_length + 7) // 8) * 8
    header = bytearray(96)
    header[0:8] = _V2_1_MAGIC
    _v2_struct.pack_into("<HHI", header, 8, 2, kind, declared_length)
    _v2_struct.pack_into("<QII", header, 16, sequence, generation, reserved)
    header[32:64] = previous
    padding_length = physical_length - 96 - len(payload)
    if padding_length < 0:
        padding_length = 0
    padding = b"\x00" * padding_length
    checksum = _v2_hashlib.sha256(
        _V2_1_DOMAIN
        + b"\x00"
        + offset.to_bytes(8, "little")
        + bytes(header)
        + payload
        + padding
    ).digest()
    header[64:96] = checksum
    return bytes(header) + payload + padding, checksum


class _V2_1Image:
    def __init__(self):
        self.bytes = bytearray(_V2_1_F_SIZE)
        self.end = 0
        self.sequence = 0
        self.previous = b"\x00" * 32
        self.terminal_used = {area: 0 for area in "ABCD"}

    def ordinary(self, kind, payload, generation, **overrides):
        record, checksum = _v2_1_record(
            self.end,
            overrides.pop("kind", kind),
            payload,
            overrides.pop("sequence", self.sequence),
            overrides.pop("generation", generation),
            overrides.pop("previous", self.previous),
            reserved=overrides.pop("reserved", 0),
            payload_length=overrides.pop("payload_length", None),
        )
        if overrides:
            raise AssertionError(f"unknown ordinary override: {overrides}")
        start = self.end
        self.bytes[start : start + len(record)] = record
        self.end += len(record)
        self.sequence += 1
        self.previous = checksum
        return start, len(record), checksum

    def terminal(self, area, slot, kind, payload, **overrides):
        offset = _V2_1_AREA_STARTS[area] + slot * 4_096
        sequence = "ABCD".index(area) * 128 + slot
        record, checksum = _v2_1_record(
            offset,
            overrides.pop("kind", kind),
            payload,
            overrides.pop("sequence", sequence),
            overrides.pop("generation", 0xFFFF_FFFF),
            overrides.pop("previous", b"\x00" * 32),
            terminal=True,
            reserved=overrides.pop("reserved", 0),
            payload_length=overrides.pop("payload_length", None),
        )
        if overrides:
            raise AssertionError(f"unknown terminal override: {overrides}")
        self.bytes[offset : offset + 4_096] = record[:4_096]
        self.terminal_used[area] = max(self.terminal_used[area], slot + 1)
        return offset, checksum

    def exact(self):
        return bytes(self.bytes)


class _V2_1Controls:
    def __init__(self):
        self.objects = []
        self.values = []
        self.digests = []

    def add(self, kind, body, *, prev=None, extra=None):
        if prev is None and self.digests:
            prev = self.digests[-1]
        value = {
            "schema": "mcl-d0009-f2r2-control",
            "n": str(len(self.objects)),
            "prev": prev,
            "kind": kind,
            "body": body,
        }
        if extra:
            value.update(extra)
        encoded = _v2_1_cjson(value)
        digest = _v2_1_digest(encoded)
        self.objects.append(encoded)
        self.values.append(value)
        self.digests.append(digest)
        return digest


def _v2_1_accounts(**values):
    accounts = {name: "0" for name in ORDINARY_ACCOUNT_FIELDS_LITERAL}
    accounts.update({name: str(value) for name, value in values.items()})
    return accounts


def _v2_1_create_bind(controls, genesis_permitted=True):
    create = controls.add(
        "CREATE",
        {
            "specification": _V2_1_SPECIFICATION,
            "v1_freeze": "1" * 64,
            "f_path_hex": "2f73796e7468657469632f66",
            "parent_profile": "2" * 64,
            "creation_profile": "3" * 64,
            "custody_profile": "4" * 64,
            "writer_profile": "5" * 64,
            "creation_authority": "6" * 64,
        },
    )
    bind = controls.add(
        "BIND",
        {
            "create": create,
            "identity": _V2_1_IDENTITY,
            "qualification": "7" * 64,
            "size_verification": "8" * 64,
            "zero_verification": "9" * 64,
            "allocation": "a" * 64,
            "setup_writer_closure": "b" * 64,
            "genesis_permitted": genesis_permitted,
        },
    )
    return create, bind


def _v2_1_terminal_state(image, frozen=()):
    entries = []
    frozen = set(frozen)
    exact = image.exact()
    for area in "ABCD":
        start = _V2_1_AREA_STARTS[area]
        used = image.terminal_used[area]
        entry = {
            "mode": "frozen" if area in frozen else "open",
            "used_slots": str(used),
            "prefix_sha256": _v2_1_digest(exact[start : start + used * 4_096]),
        }
        if area in frozen:
            entry["area_sha256"] = _v2_1_digest(exact[start : start + 524_288])
        entries.append(entry)
    return entries


def _v2_1_state(image, admitted, *, ordinary_frozen=False, terminal_frozen=()):
    exact = image.exact()
    ordinary = {
        "mode": "frozen" if ordinary_frozen else "open",
        "end": str(image.end),
        "prefix_sha256": _v2_1_digest(exact[: image.end]),
    }
    if ordinary_frozen:
        ordinary["region_sha256"] = _v2_1_digest(exact[:_V2_1_HEADROOM_END])
    return {
        "ordinary": ordinary,
        "admitted": {
            "generation": None if admitted is None else str(admitted[0]),
            "end": "0" if admitted is None else str(admitted[1]),
            "prefix_sha256": _V2_1_EMPTY_SHA256 if admitted is None else admitted[2],
        },
        "terminal": _v2_1_terminal_state(image, terminal_frozen),
    }


def _v2_1_checkpoint(
    controls,
    image,
    disposition,
    authorization,
    admitted,
    *,
    ordinary_frozen=False,
    terminal_frozen=(),
    extra=None,
    unexpected=None,
):
    body = {
        "disposition": disposition,
        "authorization": authorization,
        "verification": "d" * 64,
        "closure_custody": "e" * 64,
        "state": _v2_1_state(
            image,
            admitted,
            ordinary_frozen=ordinary_frozen,
            terminal_frozen=terminal_frozen,
        ),
    }
    if extra:
        body.update(extra)
    if unexpected is not None:
        body["unexpected"] = unexpected
    return controls.add("CHECKPOINT", body)


def _v2_1_role(role="evidence", *, category="3", encoding="raw", schema=None, max_length="1024", account="a2_evidence"):
    return {
        "role": role,
        "category": category,
        "encoding": encoding,
        "schema": schema,
        "max_length": max_length,
        "account": account,
    }


def _v2_1_branch(
    branch="ordinary_path",
    *,
    reservations=None,
    ordinary_records="8",
    ordinary_items="2",
    ordinary_bytes="8192",
    a2_bytes="4096",
    overhead_bytes="4096",
    terminal_payload=None,
):
    return {
        "branch": branch,
        "condition": branch,
        "reservations": [] if reservations is None else reservations,
        "limits": {
            "ordinary_bytes": ordinary_bytes,
            "ordinary_records": ordinary_records,
            "ordinary_items": ordinary_items,
            "ordinary_aborts": "1",
            "ordinary_accounts": _v2_1_accounts(
                a2_evidence=a2_bytes,
                descriptors_control_framing_padding=overhead_bytes,
            ),
            "terminal_payload_bytes": ["0", "0", "0", "0"]
            if terminal_payload is None
            else terminal_payload,
            "writable_phases": "2",
            "support_objects": "4",
            "support_bytes": "4096",
        },
    }


def _v2_1_authorize_body(
    base,
    generation="1",
    *,
    outcomes=None,
    roles=None,
    required=None,
    terminal_areas=None,
    terminal_roles=None,
    branches=None,
):
    roles = [_v2_1_role()] if roles is None else roles
    outcomes = ["success", "failure", "unresolved"] if outcomes is None else outcomes
    required = (
        {"success": ["evidence"], "failure": ["evidence"], "unresolved": ["evidence"]}
        if required is None
        else required
    )
    return {
        "base": base,
        "writer": "1" * 64,
        "dispatch": "2" * 64,
        "operation_plan": "3" * 64,
        "generation": generation,
        "outcomes": outcomes,
        "item_roles": roles,
        "required_roles": required,
        "terminal_areas": [] if terminal_areas is None else terminal_areas,
        "terminal_roles": [] if terminal_roles is None else terminal_roles,
        "branches": [_v2_1_branch()] if branches is None else branches,
        "intermediate_stores": [
            {
                "store": "4" * 64,
                "ordinary_roles": [role["role"] for role in roles],
                "terminal_roles": [],
            }
        ],
        "abort_actions": [],
        "cleanup_actions": [],
    }


class _V2_1Context:
    def __init__(self, *, genesis_permitted=True, write_genesis=True, admit_genesis=True, genesis_approval=True):
        self.image = _V2_1Image()
        self.controls = _V2_1Controls()
        _, self.bind = _v2_1_create_bind(self.controls, genesis_permitted)
        self.admitted = None
        self.authorizations = {}
        self.mutually_exclusive = {}
        if write_genesis:
            self.image.ordinary(1, _v2_1_cjson({"binding": self.bind}), 0)
            self.image.ordinary(5, _v2_1_cjson({"result": "success", "status": "commit"}), 0)
            self.genesis = (0, self.image.end, _v2_1_digest(self.image.exact()[: self.image.end]))
            if admit_genesis:
                self.admitted = self.genesis
                _v2_1_checkpoint(
                    self.controls,
                    self.image,
                    "admit",
                    self.bind,
                    self.admitted,
                    extra={
                        "generation": "0",
                        "result": "success",
                        "purposes": ["genesis"],
                        "supersedes": [],
                    },
                )
        self.genesis_approval = self.bind if genesis_approval else None

    def authorize(self, **body_overrides):
        body = _v2_1_authorize_body(self.controls.digests[-1], **body_overrides)
        digest = self.controls.add("AUTHORIZE", body)
        self.authorizations[digest] = body
        if len(body["branches"]) > 1:
            self.mutually_exclusive[digest] = tuple(
                branch["branch"] for branch in body["branches"]
            )
        return digest

    def generation(
        self,
        permit,
        *,
        generation=1,
        result="success",
        status="commit",
        role="evidence",
        data=b"synthetic-evidence",
        descriptor=None,
        no_end=False,
        no_data=False,
        extra_data=False,
        interleave=False,
        end_payload=None,
    ):
        self.image.ordinary(2, _v2_1_cjson({"permit": permit}), generation)
        if descriptor is None:
            descriptor = {
                "permit": permit,
                "role": role,
                "category": "3",
                "encoding": "raw",
                "schema": None,
                "length": str(len(data)),
                "sha256": _v2_1_digest(data),
            }
        self.image.ordinary(3, _v2_1_cjson(descriptor), generation)
        if interleave:
            other = {
                "permit": permit,
                "role": "other",
                "category": "3",
                "encoding": "raw",
                "schema": None,
                "length": "0",
                "sha256": _V2_1_EMPTY_SHA256,
            }
            self.image.ordinary(3, _v2_1_cjson(other), generation)
        if not no_data and data:
            for start in range(0, len(data), 262_048):
                self.image.ordinary(4, data[start : start + 262_048], generation)
        if extra_data:
            self.image.ordinary(4, b"extra", generation)
        if not no_end:
            payload = (
                {"result": result, "status": status}
                if end_payload is None
                else end_payload
            )
            self.image.ordinary(5, _v2_1_cjson(payload), generation)
        return (generation, self.image.end, _v2_1_digest(self.image.exact()[: self.image.end]))

    def admit(self, generation, result="success"):
        self.admitted = (generation, self.image.end, _v2_1_digest(self.image.exact()[: self.image.end]))
        return _v2_1_checkpoint(
            self.controls,
            self.image,
            "admit",
            self.controls.digests[-1],
            self.admitted,
            extra={
                "generation": str(generation),
                "result": result,
                "purposes": ["verification"],
                "supersedes": [],
            },
        )

    def evidence(self, **overrides):
        evidence = {
            "control_objects": tuple(self.controls.objects),
            "control_reference": self.controls.digests[-1],
            "trusted_current_control": self.controls.digests[-1],
            "specification_digest": _V2_1_SPECIFICATION,
            "binding_digest": self.bind,
            "expected_identity": _V2_1_IDENTITY,
            "observed_identity": _V2_1_IDENTITY,
            "custody_evidence": True,
            "writer_closed": True,
            "synchronized": True,
            "genesis_approval_bind_digest": self.genesis_approval,
            "mutually_exclusive_branches": dict(self.mutually_exclusive),
            "uncertain_terminal_attempts": (),
            "consumed_authorizations": (),
            "outstanding_reservations": (),
            "obsolete_file_observation": None,
        }
        evidence.update(overrides)
        return evidence


def _v2_1_fixture(name, image, evidence):
    oracle = next(entry for entry in V2_1_VECTOR_ORACLES if entry[0] == name)
    exact = image if isinstance(image, bytes) else image.exact()
    return {
        "name": name,
        "title": oracle[1],
        "clause": oracle[3],
        "image": exact,
        "evidence": evidence,
        "expected_vector": oracle[2],
    }


def _v2_1_committed_context(result="success", *, admit=False, **generation_options):
    context = _V2_1Context()
    permit = context.authorize()
    context.generation(permit, result=result, **generation_options)
    if admit:
        context.admit(1, result)
    return context, permit


def _v2_1_terminal_authorization(
    context,
    *,
    areas,
    roles,
    reservations,
    branch="terminal_path",
    terminal_payload=None,
):
    terminal_roles = []
    terminal_references = []
    for role in roles:
        terminal_roles.append(role)
        terminal_references.append(
            {"branch": role["branch"], "area": role["area"], "role": role["role"]}
        )
    body = _v2_1_authorize_body(
        context.controls.digests[-1],
        generation=None,
        outcomes=[],
        roles=[],
        required={"success": [], "failure": [], "unresolved": []},
        terminal_areas=areas,
        terminal_roles=terminal_roles,
        branches=[
            _v2_1_branch(
                branch,
                reservations=reservations,
                ordinary_records="0",
                ordinary_items="0",
                ordinary_bytes="0",
                a2_bytes="0",
                overhead_bytes="0",
                terminal_payload=terminal_payload,
            )
        ],
    )
    body["intermediate_stores"] = [
        {
            "store": "4" * 64,
            "ordinary_roles": [],
            "terminal_roles": terminal_references,
        }
    ]
    digest = context.controls.add("AUTHORIZE", body)
    context.authorizations[digest] = body
    return digest


def _v2_1_freeze_area(context, area, authorization, frozen):
    return _v2_1_checkpoint(
        context.controls,
        context.image,
        "freeze_terminal_area",
        authorization,
        context.admitted,
        ordinary_frozen=True,
        terminal_frozen=frozen,
        extra={"area": area, "cause": "explicit"},
    )


def _v2_1_final_context(
    *,
    manifest_outcome="complete",
    final_outcome=None,
    disposition=None,
    corrupt_c=False,
    corrupt_d=False,
    omit_c=False,
    freeze_c=True,
    freeze_ab=True,
):
    context, ordinary_authorization = _v2_1_committed_context(admit=True)
    if freeze_ab:
        _v2_1_freeze_area(context, "A", ordinary_authorization, ("A",))
        _v2_1_freeze_area(context, "B", ordinary_authorization, ("A", "B"))
    terminal_role = {
        "branch": "final_path",
        "area": "C",
        "role": "closing_manifest",
        "category": "0",
        "encoding": "cjson2",
        "schema": _V2_1_CLOSING_SCHEMA,
        "max_length": "65536",
    }
    terminal_authorization = _v2_1_terminal_authorization(
        context,
        areas=["C", "D"],
        roles=[terminal_role],
        reservations=[
            {"area": "C", "first_slot": "0", "slot_count": "18"},
            {"area": "D", "first_slot": "0", "slot_count": "1"},
        ],
        branch="final_path",
        terminal_payload=["0", "0", "65536", "4000"],
    )
    manifest_bytes = None
    if not omit_c:
        exact_before_c = context.image.exact()
        manifest = {
            "authority": terminal_authorization,
            "outcome": manifest_outcome,
            "ordinary_end": str(context.image.end),
            "ordinary_sha256": _v2_1_digest(exact_before_c[:_V2_1_HEADROOM_END]),
            "generations": ["0", "1"],
            "a_sha256": _v2_1_digest(
                exact_before_c[_V2_1_AREA_STARTS["A"] : _V2_1_AREA_STARTS["B"]]
            ),
            "b_sha256": _v2_1_digest(
                exact_before_c[_V2_1_AREA_STARTS["B"] : _V2_1_AREA_STARTS["C"]]
            ),
            "cleanup_references": [],
        }
        manifest_bytes = _v2_1_cjson(manifest)
        descriptor = {
            "permit": terminal_authorization,
            "role": "closing_manifest",
            "category": "0",
            "encoding": "cjson2",
            "schema": _V2_1_CLOSING_SCHEMA,
            "length": str(len(manifest_bytes)),
            "sha256": _v2_1_digest(manifest_bytes),
        }
        context.image.terminal("C", 0, 3, _v2_1_cjson(descriptor))
        context.image.terminal("C", 1, 4, manifest_bytes)
        if corrupt_c:
            context.image.bytes[_V2_1_AREA_STARTS["C"] + 64] ^= 1
        if freeze_c and not corrupt_c:
            _v2_1_freeze_area(
                context,
                "C",
                terminal_authorization,
                ("A", "B", "C"),
            )
    if final_outcome is not None:
        exact_before_d = context.image.exact()
        final_payload = _v2_1_cjson(
            {
                "authority": terminal_authorization,
                "outcome": final_outcome,
                "ordinary_sha256": _v2_1_digest(exact_before_d[:_V2_1_HEADROOM_END]),
                "abc_sha256": _v2_1_digest(
                    exact_before_d[_V2_1_AREA_STARTS["A"] : _V2_1_AREA_STARTS["D"]]
                ),
                "manifest_sha256": _V2_1_ZERO_DIGEST
                if manifest_bytes is None
                else _v2_1_digest(manifest_bytes),
            }
        )
        context.image.terminal("D", 0, 6, final_payload)
        if corrupt_d:
            context.image.bytes[_V2_1_AREA_STARTS["D"] + 64] ^= 1
    if disposition is not None:
        _v2_1_checkpoint(
            context.controls,
            context.image,
            disposition,
            terminal_authorization,
            context.admitted,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={"file_sha256": _v2_1_digest(context.image.exact())},
        )
    return context, terminal_authorization


def build_v2_1_fixture(name):
    """Build one exact in-memory r2 section 18 fixture independently."""

    if name == "valid_admitted_genesis":
        context = _V2_1Context()
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "valid_admitted_successful_generation":
        context, _ = _v2_1_committed_context(admit=True)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name in {
        "complete_successful_generation_awaiting_admission",
        "complete_failure_package_awaiting_disposition",
        "complete_unresolved_package_awaiting_disposition",
        "writer_still_running",
        "writer_closure_not_established",
        "no_trusted_authority_valid_unadmitted_file",
        "obsolete_whole_file_observation_after_append",
    }:
        result = {
            "complete_failure_package_awaiting_disposition": "failure",
            "complete_unresolved_package_awaiting_disposition": "unresolved",
        }.get(name, "success")
        context, _ = _v2_1_committed_context(result)
        overrides = {}
        if name == "writer_still_running":
            overrides["writer_closed"] = False
        elif name == "writer_closure_not_established":
            overrides["writer_closed"] = None
        elif name == "no_trusted_authority_valid_unadmitted_file":
            overrides["trusted_current_control"] = None
        elif name == "obsolete_whole_file_observation_after_append":
            overrides["obsolete_file_observation"] = _V2_1_ZERO_DIGEST
        return _v2_1_fixture(name, context.image, context.evidence(**overrides))

    if name == "valid_incomplete_generation_no_end":
        context = _V2_1Context()
        permit = context.authorize()
        context.generation(permit, no_end=True)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "valid_abort_unresolved":
        context = _V2_1Context()
        permit = context.authorize()
        context.generation(permit, status="abort", result="unresolved")
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "end_abort_failure":
        context = _V2_1Context()
        permit = context.authorize()
        context.generation(permit, status="abort", result="failure")
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "end_commit_unresolved_missing_required_role":
        context = _V2_1Context()
        roles = [_v2_1_role(), _v2_1_role("unresolved_evidence")]
        permit = context.authorize(
            roles=roles,
            required={
                "success": ["evidence"],
                "failure": ["evidence"],
                "unresolved": ["unresolved_evidence"],
            },
        )
        context.generation(permit, result="unresolved")
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "end_commit_while_item_incomplete":
        context = _V2_1Context()
        permit = context.authorize()
        context.generation(permit, no_data=True)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "known_stale_current_authority_input":
        context = _V2_1Context()
        historical = context.controls.digests[-1]
        context.authorize()
        return _v2_1_fixture(
            name,
            context.image,
            context.evidence(control_reference=historical),
        )

    if name == "control_history_fork":
        context = _V2_1Context()
        value = dict(context.controls.values[-1])
        value["prev"] = _V2_1_ZERO_DIGEST
        encoded = _v2_1_cjson(value)
        digest = _v2_1_digest(encoded)
        context.controls.objects[-1] = encoded
        context.controls.values[-1] = value
        context.controls.digests[-1] = digest
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "activation_control_reference_mismatch":
        context = _V2_1Context()
        return _v2_1_fixture(
            name,
            context.image,
            context.evidence(binding_digest=_V2_1_ZERO_DIGEST),
        )

    if name == "stale_abandonment_disposition_used_to_continue":
        context = _V2_1Context()
        first = context.authorize()
        context.generation(first, status="abort", result="unresolved")
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "abandon",
            first,
            context.admitted,
            extra={"generation": "1"},
        )
        body = _v2_1_authorize_body(first, generation="2")
        second = context.controls.add("AUTHORIZE", body)
        context.image.ordinary(2, _v2_1_cjson({"permit": second}), 2)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "wrong_f_identity_identical_bytes":
        context = _V2_1Context()
        return _v2_1_fixture(
            name,
            context.image,
            context.evidence(observed_identity="0" * 64),
        )

    if name == "f_wrong_size":
        context = _V2_1Context()
        return _v2_1_fixture(name, context.image.exact()[:-1], context.evidence())

    if name in {"overflowing_item_integer", "unknown_semantic_category"}:
        context = _V2_1Context()
        permit = context.authorize()
        data = b"synthetic-evidence"
        descriptor = {
            "permit": permit,
            "role": "evidence",
            "category": "12" if name == "unknown_semantic_category" else "3",
            "encoding": "raw",
            "schema": None,
            "length": "9" * 21 if name == "overflowing_item_integer" else str(len(data)),
            "sha256": _v2_1_digest(data),
        }
        context.generation(permit, descriptor=descriptor, no_data=name == "overflowing_item_integer")
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "unknown_kind_or_reserved":
        context = _V2_1Context()
        context.image.ordinary(99, b"", 1)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "bad_checksum_or_physical_length":
        context = _V2_1Context()
        start, _, _ = context.image.ordinary(2, _v2_1_cjson({"permit": "1" * 64}), 1)
        context.image.bytes[start + 64] ^= 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "sequence_predecessor_generation_discontinuity":
        context = _V2_1Context()
        context.image.ordinary(
            2,
            _v2_1_cjson({"permit": "1" * 64}),
            1,
            sequence=context.image.sequence + 1,
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "invalid_cjson2":
        context = _V2_1Context()
        permit = context.authorize()
        context.image.ordinary(2, _v2_1_cjson({"permit": permit}), 1)
        context.image.ordinary(3, b'{"category":1}', 1)
        context.image.ordinary(5, _v2_1_cjson({"result": "success", "status": "commit"}), 1)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "unknown_control_field_or_invalid_role":
        context = _V2_1Context()
        body = _v2_1_authorize_body(context.controls.digests[-1])
        permit = context.controls.add("AUTHORIZE", body, extra={"unexpected": None})
        context.generation(permit)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "distinct_unicode_normalization_forms":
        context = _V2_1Context()
        roles = [_v2_1_role("unicode_nfc"), _v2_1_role("unicode_nfd")]
        permit = context.authorize(
            roles=roles,
            required={
                "success": ["unicode_nfc", "unicode_nfd"],
                "failure": [],
                "unresolved": [],
            },
        )
        context.image.ordinary(2, _v2_1_cjson({"permit": permit}), 1)
        for role, data in (("unicode_nfc", "é".encode()), ("unicode_nfd", "é".encode())):
            descriptor = {
                "permit": permit,
                "role": role,
                "category": "3",
                "encoding": "raw",
                "schema": None,
                "length": str(len(data)),
                "sha256": _v2_1_digest(data),
            }
            context.image.ordinary(3, _v2_1_cjson(descriptor), 1)
            context.image.ordinary(4, data, 1)
        context.image.ordinary(5, _v2_1_cjson({"result": "success", "status": "commit"}), 1)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "interleaved_excess_data_or_digest_mismatch":
        context = _V2_1Context()
        permit = context.authorize()
        data = b"synthetic-evidence"
        descriptor = {
            "permit": permit,
            "role": "evidence",
            "category": "3",
            "encoding": "raw",
            "schema": None,
            "length": str(len(data)),
            "sha256": _V2_1_ZERO_DIGEST,
        }
        context.generation(permit, descriptor=descriptor)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "ordinary_item_permit_mismatch":
        context = _V2_1Context()
        permit = context.authorize()
        data = b"synthetic-evidence"
        descriptor = {
            "permit": "0" * 64,
            "role": "evidence",
            "category": "3",
            "encoding": "raw",
            "schema": None,
            "length": str(len(data)),
            "sha256": _v2_1_digest(data),
        }
        context.generation(permit, descriptor=descriptor)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "generation_account_record_ceiling_violation":
        context = _V2_1Context()
        body = _v2_1_authorize_body(context.controls.digests[-1])
        body["branches"][0]["limits"]["ordinary_records"] = "1"
        permit = context.controls.add("AUTHORIZE", body)
        context.generation(permit)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name in {"zero_header_followed_by_nonzero", "plausible_record_after_invalid_boundary"}:
        context = _V2_1Context()
        frontier = context.image.end
        if name == "zero_header_followed_by_nonzero":
            context.image.bytes[frontier + 100] = 1
        else:
            context.image.bytes[frontier] = 1
            later = frontier + 4_096
            record, _ = _v2_1_record(
                later,
                2,
                _v2_1_cjson({"permit": "1" * 64}),
                context.image.sequence,
                1,
                context.image.previous,
            )
            context.image.bytes[later : later + len(record)] = record
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "nonzero_mandatory_headroom":
        context = _V2_1Context()
        context.image.bytes[_V2_1_ORDINARY_END] = 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "earlier_admitted_prefix_changed":
        context = _V2_1Context()
        context.image.bytes[96] ^= 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "earlier_prefix_intact_torn_later_tail":
        context = _V2_1Context()
        start, _, _ = context.image.ordinary(2, _v2_1_cjson({"permit": "1" * 64}), 1)
        context.image.bytes[start + 64] ^= 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "unexpected_nonzero_unused_terminal_slot":
        context = _V2_1Context()
        context.image.bytes[_V2_1_AREA_STARTS["A"]] = 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "uncertain_zero_byte_terminal_attempt":
        context = _V2_1Context()
        return _v2_1_fixture(
            name,
            context.image,
            context.evidence(uncertain_terminal_attempts=("A",)),
        )

    if name in {"terminal_item_over_bound", "terminal_declaration_mismatch"}:
        context, ordinary = _v2_1_committed_context(admit=True)
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "freeze_ordinary",
            ordinary,
            context.admitted,
            ordinary_frozen=True,
            extra={"cause": "explicit"},
        )
        role = {
            "branch": "terminal_path",
            "area": "A",
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "max_length": "4000",
        }
        permit = _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["4000", "0", "0", "0"],
        )
        descriptor = {
            "permit": permit,
            "role": "terminal_evidence",
            "category": "3" if name == "terminal_declaration_mismatch" else "11",
            "encoding": "raw",
            "schema": None,
            "length": "508001" if name == "terminal_item_over_bound" else "1",
            "sha256": _v2_1_digest(b"x"),
        }
        context.image.terminal("A", 0, 3, _v2_1_cjson(descriptor))
        if name == "terminal_declaration_mismatch":
            context.image.terminal("A", 1, 4, b"x")
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "frozen_abc_bytes_changed":
        context, _ = _v2_1_final_context(manifest_outcome="complete", freeze_c=True)
        context.image.bytes[_V2_1_AREA_STARTS["C"] + 96] ^= 1
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "d_without_valid_c":
        context, _ = _v2_1_final_context(omit_c=True, final_outcome="complete", freeze_c=False)
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "final_outcome_differs_manifest":
        context, _ = _v2_1_final_context(
            manifest_outcome="complete",
            final_outcome="unresolved",
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "valid_final_without_sync":
        context, _ = _v2_1_final_context(
            manifest_outcome="complete",
            final_outcome="complete",
        )
        return _v2_1_fixture(
            name,
            context.image,
            context.evidence(synchronized=False),
        )

    if name == "torn_c_final_failed":
        context, _ = _v2_1_final_context(
            manifest_outcome="failed",
            corrupt_c=True,
            freeze_c=False,
            disposition="final_failed",
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "torn_d_final_unresolved":
        context, _ = _v2_1_final_context(
            manifest_outcome="unresolved",
            final_outcome="unresolved",
            corrupt_d=True,
            disposition="final_unresolved",
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "valid_complete_finalization":
        context, _ = _v2_1_final_context(
            manifest_outcome="complete",
            final_outcome="complete",
            disposition="final_complete",
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    if name == "valid_unresolved_finalization":
        context, _ = _v2_1_final_context(
            manifest_outcome="unresolved",
            final_outcome="unresolved",
            disposition="final_unresolved",
        )
        return _v2_1_fixture(name, context.image, context.evidence())

    raise KeyError(name)


def build_v2_1_semantic_fixture(name):
    """Build focused non-section-18 semantic cases for V2-1 tests."""

    if name in {
        "pending_generation_1_after_admitted_genesis",
        "pending_generation_1_before_genesis",
        "pending_generation_1_bind_false",
        "pending_generation_1_reused",
        "pending_generation_1_unadmitted_genesis",
        "pending_generation_2_after_disposition",
        "pending_generation_2_without_disposition",
        "pending_generation_3_skips_2",
    }:
        if name == "pending_generation_1_bind_false":
            context = _V2_1Context(
                genesis_permitted=False,
                write_genesis=False,
                admit_genesis=False,
                genesis_approval=False,
            )
            context.authorize()
        elif name == "pending_generation_1_before_genesis":
            context = _V2_1Context(
                genesis_permitted=True,
                write_genesis=False,
                admit_genesis=False,
                genesis_approval=True,
            )
            context.authorize()
        elif name == "pending_generation_1_unadmitted_genesis":
            context = _V2_1Context(admit_genesis=False)
            context.authorize()
        elif name == "pending_generation_1_after_admitted_genesis":
            context = _V2_1Context()
            context.authorize()
        else:
            context = _V2_1Context()
            first = context.authorize()
            context.generation(first, result="unresolved")
            if name != "pending_generation_2_without_disposition":
                context.admit(1, "unresolved")
            if name == "pending_generation_1_reused":
                context.authorize(generation="1")
            elif name == "pending_generation_3_skips_2":
                context.authorize(generation="3")
            else:
                context.authorize(generation="2")
        return context.image.exact(), context.evidence()
    if name in {
        "pending_authorize_a2_exact_remaining",
        "pending_authorize_a2_exceeds_remaining",
        "pending_authorize_a2_max_path_not_sum",
    }:
        context = _V2_1Context()

        def add_a2_generation(generation):
            role = _v2_1_role(max_length="400000")
            branch = _v2_1_branch(
                ordinary_records="8",
                ordinary_items="1",
                ordinary_bytes="450000",
                a2_bytes="400000",
                overhead_bytes="50000",
            )
            permit = context.authorize(
                generation=str(generation), roles=[role], branches=[branch]
            )
            context.generation(permit, generation=generation, data=b"x" * 400_000)
            context.admit(generation)

        add_a2_generation(1)
        add_a2_generation(2)
        if name == "pending_authorize_a2_max_path_not_sum":
            branches = [
                _v2_1_branch(
                    "failure_path",
                    ordinary_records="4",
                    ordinary_items="1",
                    ordinary_bytes="230000",
                    a2_bytes="220000",
                    overhead_bytes="10000",
                ),
                _v2_1_branch(
                    "success_path",
                    ordinary_records="4",
                    ordinary_items="1",
                    ordinary_bytes="210000",
                    a2_bytes="200000",
                    overhead_bytes="10000",
                ),
            ]
            context.authorize(
                generation="3",
                roles=[_v2_1_role(max_length="220000")],
                branches=branches,
            )
        else:
            reservation = (
                248_576 if name == "pending_authorize_a2_exact_remaining" else 300_000
            )
            context.authorize(
                generation="3",
                roles=[_v2_1_role(max_length=str(reservation))],
                branches=[
                    _v2_1_branch(
                        ordinary_records="4",
                        ordinary_items="1",
                        ordinary_bytes=str(reservation + 10_000),
                        a2_bytes=str(reservation),
                        overhead_bytes="10000",
                    )
                ],
            )
        return context.image.exact(), context.evidence()
    if name == "pending_authorize_exceeds_remaining_review_correction":
        context = _V2_1Context()
        role = _v2_1_role(max_length="400000", account="review_correction")
        branch = _v2_1_branch(
            ordinary_records="8",
            ordinary_items="1",
            ordinary_bytes="450000",
            a2_bytes="0",
            overhead_bytes="50000",
        )
        branch["limits"]["ordinary_accounts"]["review_correction"] = "400000"
        first = context.authorize(roles=[role], branches=[branch])
        context.generation(first, data=b"x" * 400_000)
        context.admit(1)
        pending_role = _v2_1_role(max_length="524288", account="review_correction")
        pending_branch = _v2_1_branch(
            ordinary_records="4",
            ordinary_items="1",
            ordinary_bytes="1850000",
            a2_bytes="0",
            overhead_bytes="50000",
        )
        pending_branch["limits"]["ordinary_accounts"]["review_correction"] = "1800000"
        context.authorize(
            generation="2", roles=[pending_role], branches=[pending_branch]
        )
        return context.image.exact(), context.evidence()
    if name == "pending_authorize_exceeds_item_lifetime":
        context = _V2_1Context()

        def add_zero_items_generation(generation, item_count):
            role_names = [f"item_{index:03d}" for index in range(item_count)]
            roles = [_v2_1_role(role, max_length="0") for role in role_names]
            branch = _v2_1_branch(
                ordinary_records=str(item_count + 2),
                ordinary_items=str(item_count),
                ordinary_bytes="100000",
                a2_bytes="0",
                overhead_bytes="100000",
            )
            required = {outcome: role_names for outcome in ("success", "failure", "unresolved")}
            permit = context.authorize(
                generation=str(generation),
                roles=roles,
                required=required,
                branches=[branch],
            )
            context.image.ordinary(2, _v2_1_cjson({"permit": permit}), generation)
            for role in role_names:
                descriptor = {
                    "permit": permit,
                    "role": role,
                    "category": "3",
                    "encoding": "raw",
                    "schema": None,
                    "length": "0",
                    "sha256": _V2_1_EMPTY_SHA256,
                }
                context.image.ordinary(3, _v2_1_cjson(descriptor), generation)
            context.image.ordinary(
                5,
                _v2_1_cjson({"result": "success", "status": "commit"}),
                generation,
            )
            context.admit(generation)

        for generation in range(1, 8):
            add_zero_items_generation(generation, 128)
        add_zero_items_generation(8, 1)
        context.authorize(
            generation="9",
            branches=[
                _v2_1_branch(
                    ordinary_records="130",
                    ordinary_items="128",
                    ordinary_bytes="100000",
                    a2_bytes="0",
                    overhead_bytes="100000",
                )
            ],
        )
        return context.image.exact(), context.evidence()
    if name == "pending_authorize_exceeds_aborted_generation_limit":
        context = _V2_1Context()
        for generation in range(1, 5):
            permit = context.authorize(generation=str(generation))
            context.generation(
                permit,
                generation=generation,
                data=b"",
                status="abort",
                result="unresolved",
            )
            _v2_1_checkpoint(
                context.controls,
                context.image,
                "abandon",
                permit,
                context.admitted,
                extra={"generation": str(generation)},
            )
        context.authorize(generation="5")
        return context.image.exact(), context.evidence()
    if name == "pending_authorize_conflicts_with_outstanding_reservation":
        context = _V2_1Context()
        role = {
            "branch": "terminal_path",
            "area": "A",
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "max_length": "4000",
        }
        first = _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["4000", "0", "0", "0"],
        )
        _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["4000", "0", "0", "0"],
        )
        outstanding = (
            {
                "operation": "phase_one",
                "authorization": first,
                "branch": "terminal_path",
                "area": "A",
                "first_slot": "0",
                "slot_count": "2",
            },
        )
        return context.image.exact(), context.evidence(outstanding_reservations=outstanding)
    if name in {
        "cumulative_account_capacity_valid",
        "cumulative_account_capacity_exceeded",
        "remaining_capacity_reservation_exceeded",
        "aborted_bytes_are_not_refunded",
    }:
        context = _V2_1Context()

        def add_generation(generation, data_length, reservation, *, status="commit"):
            role = _v2_1_role(max_length=str(reservation))
            branch = _v2_1_branch(
                ordinary_records="8",
                ordinary_items="1",
                ordinary_bytes=str(reservation + 50_000),
                a2_bytes=str(reservation),
                overhead_bytes="50000",
            )
            permit = context.authorize(
                generation=str(generation),
                roles=[role],
                branches=[branch],
            )
            context.generation(
                permit,
                generation=generation,
                data=b"x" * data_length,
                status=status,
                result="unresolved" if status == "abort" else "success",
            )
            return permit

        first_status = "abort" if name == "aborted_bytes_are_not_refunded" else "commit"
        first = add_generation(1, 400_000, 400_000, status=first_status)
        if first_status == "abort":
            _v2_1_checkpoint(
                context.controls,
                context.image,
                "abandon",
                first,
                context.admitted,
                extra={"generation": "1"},
            )
        else:
            context.admit(1)
        add_generation(2, 400_000, 400_000)
        if name == "cumulative_account_capacity_valid":
            return context.image.exact(), context.evidence()
        context.admit(2)
        if name == "remaining_capacity_reservation_exceeded":
            add_generation(3, 100_000, 300_000)
        else:
            add_generation(3, 400_000, 400_000)
        return context.image.exact(), context.evidence()
    if name == "genesis_overhead_reduces_reservation":
        context = _V2_1Context()
        role = _v2_1_role(max_length="0")
        branch = _v2_1_branch(
            ordinary_records="4",
            ordinary_items="1",
            ordinary_bytes="1048576",
            a2_bytes="0",
            overhead_bytes="1048576",
        )
        permit = context.authorize(roles=[role], branches=[branch])
        context.generation(permit, data=b"")
        return context.image.exact(), context.evidence()
    if name == "aborted_generation_lifetime_limit":
        context = _V2_1Context()
        for generation in range(1, 6):
            permit = context.authorize(generation=str(generation))
            context.generation(
                permit,
                generation=generation,
                data=b"",
                status="abort",
                result="unresolved",
            )
            if generation < 5:
                _v2_1_checkpoint(
                    context.controls,
                    context.image,
                    "abandon",
                    permit,
                    context.admitted,
                    extra={"generation": str(generation)},
                )
        return context.image.exact(), context.evidence()
    if name in {
        "final_checkpoint_outside_trusted_history",
        "invalid_authority_with_final_disposition",
        "no_trusted_authority_with_final_disposition",
        "final_commitment_mismatch",
        "post_finalization_byte_change",
    }:
        context = _V2_1Context(
            genesis_permitted=False,
            write_genesis=False,
            admit_genesis=False,
            genesis_approval=False,
        )
        before_final = context.bind
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "final_unresolved",
            context.bind,
            None,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={
                "file_sha256": _V2_1_ZERO_DIGEST
                if name == "final_commitment_mismatch"
                else _v2_1_digest(context.image.exact())
            },
        )
        overrides = {}
        if name == "final_checkpoint_outside_trusted_history":
            overrides.update(
                control_reference=before_final,
                trusted_current_control=before_final,
            )
        elif name == "invalid_authority_with_final_disposition":
            overrides["control_reference"] = _V2_1_ZERO_DIGEST
        elif name == "no_trusted_authority_with_final_disposition":
            overrides["trusted_current_control"] = None
        if name == "post_finalization_byte_change":
            context.image.bytes[_V2_1_AREA_STARTS["A"]] = 1
        return context.image.exact(), context.evidence(**overrides)
    if name in {
        "terminal_without_ordinary_freeze",
        "terminal_after_ordinary_freeze",
    }:
        context, ordinary = _v2_1_committed_context(admit=True)
        if name == "terminal_after_ordinary_freeze":
            _v2_1_checkpoint(
                context.controls,
                context.image,
                "freeze_ordinary",
                ordinary,
                context.admitted,
                ordinary_frozen=True,
                extra={"cause": "explicit"},
            )
        role = {
            "branch": "terminal_path",
            "area": "A",
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "max_length": "1",
        }
        permit = _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["1", "0", "0", "0"],
        )
        descriptor = {
            "permit": permit,
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "length": "1",
            "sha256": _v2_1_digest(b"x"),
        }
        context.image.terminal("A", 0, 3, _v2_1_cjson(descriptor))
        context.image.terminal("A", 1, 4, b"x")
        return context.image.exact(), context.evidence()
    if name in {
        "first_generation_without_genesis_disposition",
        "next_generation_without_preceding_disposition",
        "next_generation_after_valid_disposition",
    }:
        context = _V2_1Context(
            admit_genesis=name != "first_generation_without_genesis_disposition"
        )
        first = context.authorize()
        context.generation(first, result="unresolved")
        if name == "first_generation_without_genesis_disposition":
            return context.image.exact(), context.evidence()
        if name == "next_generation_after_valid_disposition":
            context.admit(1, "unresolved")
        second = context.authorize(generation="2")
        context.generation(second, generation=2)
        return context.image.exact(), context.evidence()
    if name in {
        "authorize_after_freeze_ordinary",
        "freeze_ordinary_classification",
    }:
        context = _V2_1Context()
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "freeze_ordinary",
            context.bind,
            context.admitted,
            ordinary_frozen=True,
            extra={"cause": "explicit"},
        )
        if name == "authorize_after_freeze_ordinary":
            context.authorize()
        return context.image.exact(), context.evidence()
    if name in {
        "authorize_after_freeze_f",
        "freeze_f_classification",
    }:
        context = _V2_1Context()
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "freeze_f",
            context.bind,
            context.admitted,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={
                "cause": "explicit",
                "file_sha256": _v2_1_digest(context.image.exact()),
            },
        )
        if name == "authorize_after_freeze_f":
            context.authorize()
        return context.image.exact(), context.evidence()
    if name == "authorize_after_final_disposition":
        context = _V2_1Context(
            genesis_permitted=False,
            write_genesis=False,
            admit_genesis=False,
            genesis_approval=False,
        )
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "final_unresolved",
            context.bind,
            None,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={"file_sha256": _v2_1_digest(context.image.exact())},
        )
        context.authorize()
        return context.image.exact(), context.evidence()
    if name == "authorize_after_d_attempt":
        context, _ = _v2_1_final_context(
            manifest_outcome="unresolved",
            final_outcome="unresolved",
        )
        _v2_1_terminal_authorization(
            context,
            areas=["D"],
            roles=[],
            reservations=[{"area": "D", "first_slot": "0", "slot_count": "1"}],
            branch="post_d_path",
            terminal_payload=["0", "0", "0", "4000"],
        )
        return context.image.exact(), context.evidence()
    if name in {
        "bind_true_unapproved_no_closeout",
        "bind_true_unapproved_valid_closeout",
    }:
        context = _V2_1Context(
            genesis_permitted=True,
            write_genesis=False,
            admit_genesis=False,
            genesis_approval=False,
        )
        if name == "bind_true_unapproved_valid_closeout":
            _v2_1_checkpoint(
                context.controls,
                context.image,
                "final_unresolved",
                context.bind,
                None,
                ordinary_frozen=True,
                terminal_frozen=("A", "B", "C", "D"),
                extra={"file_sha256": _v2_1_digest(context.image.exact())},
            )
        return context.image.exact(), context.evidence()
    if name == "genesis_true_without_chair_approval":
        context = _V2_1Context(genesis_approval=False)
        return context.image.exact(), context.evidence()
    if name == "genesis_false_forecloses_genesis":
        context = _V2_1Context(genesis_permitted=False)
        return context.image.exact(), context.evidence()
    if name == "bind_false_valid_closeout":
        context = _V2_1Context(
            genesis_permitted=False,
            write_genesis=False,
            admit_genesis=False,
            genesis_approval=False,
        )
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "final_unresolved",
            context.bind,
            None,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={"file_sha256": _v2_1_digest(context.image.exact())},
        )
        return context.image.exact(), context.evidence()
    if name == "authorize_generation_zero":
        context = _V2_1Context()
        body = _v2_1_authorize_body(context.controls.digests[-1], generation="0")
        context.controls.add("AUTHORIZE", body)
        return context.image.exact(), context.evidence()
    if name == "supplied_specification_mismatch":
        context = _V2_1Context()
        return context.image.exact(), context.evidence(specification_digest="0" * 64)
    if name == "ordinary_final_wrong_placement":
        context = _V2_1Context()
        context.image.ordinary(
            6,
            _v2_1_cjson(
                {
                    "authority": "1" * 64,
                    "outcome": "complete",
                    "ordinary_sha256": "2" * 64,
                    "abc_sha256": "3" * 64,
                    "manifest_sha256": "4" * 64,
                }
            ),
            1,
        )
        return context.image.exact(), context.evidence()
    if name == "record_payload_over_kind_bound":
        context = _V2_1Context()
        context.image.ordinary(2, b"x" * 1_025, 1)
        return context.image.exact(), context.evidence()
    if name == "generation_header_discontinuity":
        context = _V2_1Context()
        context.image.ordinary(2, _v2_1_cjson({"permit": "1" * 64}), 2)
        return context.image.exact(), context.evidence()
    if name == "final_complete_without_c_d":
        context = _V2_1Context()
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "final_complete",
            context.bind,
            context.admitted,
            ordinary_frozen=True,
            terminal_frozen=("A", "B", "C", "D"),
            extra={"file_sha256": _v2_1_digest(context.image.exact())},
        )
        return context.image.exact(), context.evidence()
    if name == "checkpoint_reopens_frozen_area":
        context = _V2_1Context()
        _v2_1_freeze_area(context, "A", context.bind, ("A",))
        _v2_1_checkpoint(
            context.controls,
            context.image,
            "freeze_ordinary",
            context.bind,
            context.admitted,
            ordinary_frozen=True,
            terminal_frozen=(),
            extra={"cause": "explicit"},
        )
        return context.image.exact(), context.evidence()
    if name == "terminal_c_before_ab_frozen":
        context, _ = _v2_1_final_context(
            manifest_outcome="complete",
            final_outcome="complete",
            freeze_ab=False,
        )
        return context.image.exact(), context.evidence()
    if name == "d_reservation_wrong_shape":
        context = _V2_1Context()
        _v2_1_terminal_authorization(
            context,
            areas=["D"],
            roles=[],
            reservations=[{"area": "D", "first_slot": "0", "slot_count": "2"}],
            branch="final_path",
            terminal_payload=["0", "0", "0", "4000"],
        )
        return context.image.exact(), context.evidence()
    if name in {
        "branch_max_path_valid",
        "branch_ordinary_max_path_valid",
        "branch_overlap_not_exclusive",
        "branch_cumulative_underreserved",
        "branch_wrong_first_slot",
        "simultaneous_outstanding_overlap",
    }:
        context = _V2_1Context()
        branches = [
            _v2_1_branch(
                "failure_path",
                reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
                terminal_payload=["4000", "0", "0", "0"],
            ),
            _v2_1_branch(
                "success_path",
                reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
                terminal_payload=["4000", "0", "0", "0"],
            ),
        ]
        if name == "branch_cumulative_underreserved":
            branches[0]["limits"]["terminal_payload_bytes"][0] = "8000"
            branches[0]["reservations"][0]["slot_count"] = "2"
        if name == "branch_ordinary_max_path_valid":
            branches[0]["limits"]["ordinary_records"] = "3"
        if name == "branch_wrong_first_slot":
            branches = [branches[0]]
            branches[0]["reservations"][0]["first_slot"] = "1"
        if name == "simultaneous_outstanding_overlap":
            branches = [branches[0]]
        roles = [
            {
                "branch": branch,
                "area": "A",
                "role": "terminal_evidence",
                "category": "11",
                "encoding": "raw",
                "schema": None,
                "max_length": "4000",
            }
            for branch in (entry["branch"] for entry in branches)
        ]
        body = _v2_1_authorize_body(
            context.controls.digests[-1],
            terminal_areas=["A"],
            terminal_roles=roles,
            branches=branches,
        )
        body["intermediate_stores"][0]["terminal_roles"] = [
            {"branch": role["branch"], "area": "A", "role": "terminal_evidence"}
            for role in roles
        ]
        permit = context.controls.add("AUTHORIZE", body)
        context.generation(permit)
        if name in {"branch_max_path_valid", "branch_ordinary_max_path_valid"}:
            context.mutually_exclusive[permit] = ("failure_path", "success_path")
        evidence = context.evidence()
        if name == "simultaneous_outstanding_overlap":
            reservation = {
                "authorization": permit,
                "branch": "failure_path",
                "area": "A",
                "first_slot": "0",
                "slot_count": "2",
            }
            evidence["outstanding_reservations"] = (
                {"operation": "phase_one", **reservation},
                {"operation": "phase_two", **reservation},
            )
        return context.image.exact(), evidence
    if name in {"account_exact", "account_payload_over", "account_overhead_over"}:
        context = _V2_1Context()
        body = _v2_1_authorize_body(context.controls.digests[-1])
        body["branches"][0]["limits"]["ordinary_accounts"]["a2_evidence"] = (
            "1" if name == "account_payload_over" else "18"
        )
        if name == "account_overhead_over":
            body["branches"][0]["limits"]["ordinary_accounts"][
                "descriptors_control_framing_padding"
            ] = "1"
        permit = context.controls.add("AUTHORIZE", body)
        context.generation(permit)
        return context.image.exact(), context.evidence()
    if name in {"authorize_replay", "second_generation_same_authorize"}:
        context = _V2_1Context()
        permit = context.authorize()
        context.generation(permit)
        context.generation(permit, generation=2, role="evidence_two", data=b"two")
        return context.image.exact(), context.evidence()
    if name == "terminal_before_ordinary_close":
        context = _V2_1Context()
        ordinary = context.authorize()
        context.image.ordinary(2, _v2_1_cjson({"permit": ordinary}), 1)
        role = {
            "branch": "terminal_path",
            "area": "A",
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "max_length": "1",
        }
        permit = _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["1", "0", "0", "0"],
        )
        descriptor = {
            "permit": permit,
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "length": "1",
            "sha256": _v2_1_digest(b"x"),
        }
        context.image.terminal("A", 0, 3, _v2_1_cjson(descriptor))
        context.image.terminal("A", 1, 4, b"x")
        return context.image.exact(), context.evidence()
    if name == "frozen_area_reuse":
        context = _V2_1Context()
        role = {
            "branch": "terminal_path",
            "area": "A",
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "max_length": "1",
        }
        permit = _v2_1_terminal_authorization(
            context,
            areas=["A"],
            roles=[role],
            reservations=[{"area": "A", "first_slot": "0", "slot_count": "2"}],
            terminal_payload=["1", "0", "0", "0"],
        )
        descriptor = {
            "permit": permit,
            "role": "terminal_evidence",
            "category": "11",
            "encoding": "raw",
            "schema": None,
            "length": "1",
            "sha256": _v2_1_digest(b"x"),
        }
        context.image.terminal("A", 0, 3, _v2_1_cjson(descriptor))
        context.image.terminal("A", 1, 4, b"x")
        return context.image.exact(), context.evidence(uncertain_terminal_attempts=("A",))
    raise KeyError(name)


def build_v2_1_checkpoint_extra_fixture(disposition):
    context = _V2_1Context()
    extras = {
        "admit": {
            "generation": "0",
            "result": "success",
            "purposes": ["genesis"],
            "supersedes": [],
        },
        "abandon": {"generation": "1"},
        "freeze_ordinary": {"cause": "explicit"},
        "freeze_terminal_area": {"area": "A", "cause": "explicit"},
        "freeze_f": {"cause": "explicit", "file_sha256": _v2_1_digest(context.image.exact())},
        "final_complete": {"file_sha256": _v2_1_digest(context.image.exact())},
        "final_failed": {"file_sha256": _v2_1_digest(context.image.exact())},
        "final_unresolved": {"file_sha256": _v2_1_digest(context.image.exact())},
    }
    _v2_1_checkpoint(
        context.controls,
        context.image,
        disposition,
        context.bind,
        context.admitted,
        ordinary_frozen=disposition.startswith("freeze") or disposition.startswith("final"),
        terminal_frozen=("A", "B", "C", "D") if disposition.startswith("final") else (),
        extra=extras[disposition],
        unexpected="forbidden",
    )
    return context.image.exact(), context.evidence()


# Independently observed SHA-256 values for the exact synthetic image bytes.
# These values are literal and are not computed by the production verifier.
V2_1_IMAGE_SHA256_ORACLES = {
    "activation_control_reference_mismatch": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "bad_checksum_or_physical_length": "3a8e3b5bd0a874f22a5f23a7888020edd6f59f193d1be930719525285613b521",
    "complete_failure_package_awaiting_disposition": "a7edf68b2e20afc0b4d92e6a3274ae0eba72ec69f7b2563610533f4513095657",
    "complete_successful_generation_awaiting_admission": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "complete_unresolved_package_awaiting_disposition": "cf6a5f36ba75e466766100e73377632cd5745713f6ab3b96284e57910c3318a4",
    "control_history_fork": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "d_without_valid_c": "c5195610800e180eaa35752b5cf3c4a33d6c59916d7a638115cc6099c39c63ba",
    "distinct_unicode_normalization_forms": "a496271dc5c0003df8724102e9a2d82900bcc83242d990bbe76c6b0ab6243ceb",
    "earlier_admitted_prefix_changed": "eb976ecdabdf27c509c33a488c128c618228e6211e86a4aa9a0a3681121736f1",
    "earlier_prefix_intact_torn_later_tail": "3a8e3b5bd0a874f22a5f23a7888020edd6f59f193d1be930719525285613b521",
    "end_abort_failure": "7a6edacadb3d56ca6530eb91be86c25dcfc89d96e3bc66d0e2ee3f237132a4f5",
    "end_commit_unresolved_missing_required_role": "f18b28db0e64053bcaa19080000150c036864424d505fa7e04bc1833055eb9ce",
    "end_commit_while_item_incomplete": "c7f87f115d7eac28a7f8b35e6dfb40d9ffd796148c85fff595782e272df26d5a",
    "f_wrong_size": "6264661693c2dc2c0727a60401e70c786bcacf2dd4abfdde0efaa10a0ac24423",
    "final_outcome_differs_manifest": "e1e64639be854c32495447ec3697d6ff4679ed6b72ef26a6571ec620e01f7788",
    "frozen_abc_bytes_changed": "d71ad1ca14e5619faf07e2993061474c8e0dce0f69ca18e14048a8fc9ad9b7d2",
    "generation_account_record_ceiling_violation": "237fdc8a30b5b579714ae4e585c078a2805819ab9cadc2850a82cd25315ad786",
    "interleaved_excess_data_or_digest_mismatch": "a83788647204eece26080fbb0c9bf5cce569650054416da1269d3419722dfabe",
    "invalid_cjson2": "ad9858d2d540b1f50adf3a37a08c73c7e57ee13c339a7b87eefdc510af3ebf28",
    "known_stale_current_authority_input": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "no_trusted_authority_valid_unadmitted_file": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "nonzero_mandatory_headroom": "d903eef2687a3c5c34553395b095aa0474fd7f2c3374146178ce9e2dd7899687",
    "obsolete_whole_file_observation_after_append": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "ordinary_item_permit_mismatch": "b2130a4d6c25233e1422899d2ebdeb969f87cd6f1bb1753029c86299f37e95eb",
    "overflowing_item_integer": "b631efa447faf32823bfaac7a0ef4bd49f2f1f42443820037f380ee54da22bb5",
    "plausible_record_after_invalid_boundary": "8343d26591330b084a86947dda9d7830d44fea5796227ad1fcbbdbb3411f0566",
    "sequence_predecessor_generation_discontinuity": "b4e6852aad9375fa7a5fafe020fd7546d92710fdc90fb7fbcd2ab2a463c77aca",
    "stale_abandonment_disposition_used_to_continue": "6fa97dd3c705371ed13af53bd261af430e3bfb77a19bdd05c2db6be7aceccc6f",
    "terminal_declaration_mismatch": "08c32dcfad2a8dcfc080a5f84dab0cb94ff9dab1acb2c48021607a1cac4c1ecc",
    "terminal_item_over_bound": "2e6c147f339629888945876d0718865600bdf9ddffca8663f3590ee95c4640af",
    "torn_c_final_failed": "5267146b244a67cd14684ce886397c4e925eb35b155604b90e754d612d083341",
    "torn_d_final_unresolved": "4b8f264df9a83b74c7b9f2ef01e861c3485c4850eef0134c7803da479e53907f",
    "uncertain_zero_byte_terminal_attempt": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "unexpected_nonzero_unused_terminal_slot": "efcbebe39368c9d154a0d06c687aa05e829d59531792cd9da2d3e16e4e377a49",
    "unknown_control_field_or_invalid_role": "b1c6bc6fc241d090aa82040a54c1b6c328ed04f2bd1b087e7fb7f136fccae2e6",
    "unknown_kind_or_reserved": "53a01e4b8d2c6ced50c865e7f481f4a9828d44e3247b0205f5f34bc467327945",
    "unknown_semantic_category": "d18268653a77a753835f3fa107a13f47e9811872f826170689e1220344fc6a0f",
    "valid_abort_unresolved": "2125779d626645cec00bbbe487efc93bb5bc5e7e7c5625296ec1dd9d3b05ad68",
    "valid_admitted_genesis": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "valid_admitted_successful_generation": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "valid_complete_finalization": "aa38a1f1b551b1763d0c3312c0920e15f0aafa3df8abecf2dbad18ede06b7936",
    "valid_final_without_sync": "aa38a1f1b551b1763d0c3312c0920e15f0aafa3df8abecf2dbad18ede06b7936",
    "valid_incomplete_generation_no_end": "0f9e1f4c3dfa98d5f1908a6f601135d7d703ae893b4f1622c4e6c3366883c43f",
    "valid_unresolved_finalization": "8973d34e59f2cfe20968e08d9fe8bac2928ecd5b20dc5284c55cb2dc44cb3c0b",
    "writer_closure_not_established": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "writer_still_running": "c68bb698ef05094f1cd49783f6eb014e1ec6094248bb3880afa76b066779a637",
    "wrong_f_identity_identical_bytes": "a1cec3887c53a7ce9e3d8c12bdf95da485f95e0e44d7aa367a93090bb6120ab6",
    "zero_header_followed_by_nonzero": "16118cd43a1031cae484180bec13a4673c9f348cd494126237d284350dca173d",
}
