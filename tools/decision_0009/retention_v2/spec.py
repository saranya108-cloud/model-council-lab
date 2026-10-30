"""Immutable Decision 0009 Retention V2 format declarations.

This module contains level-1 format facts only.  It makes no lifecycle,
authority, host-qualification, or operational decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from types import MappingProxyType


R2_SPECIFICATION = "mcl-d0009-retention-v2-astra-r2"
R2_SOURCE_SHA256 = "b9a1ce67aa5c8050a95de324969a25046f13d2f6e4bf56f92832dea96fce6b05"
AMENDMENT_1A_SPECIFICATION = "mcl-d0009-m0-custody-amendment-1a"
AMENDMENT_1A_SOURCE_SHA256 = (
    "9869dd6ec374677a8150de725e05e705bc4ac8798ec5b7b20ed705e0a6f49144"
)

F_SIZE = 16_777_216
TERMINAL_TOTAL_SIZE = 2_097_152
HEADER_SIZE = 96
ORDINARY_RECORD_MAX = 262_144
ORDINARY_DATA_MAX = 262_048
TERMINAL_SLOT_SIZE = 4_096
TERMINAL_DATA_MAX = 4_000
ALIGNMENT = 8
TERMINAL_SLOTS_PER_AREA = 128

ORDINARY_LOG_END = 12_582_912
HEADROOM_END = 14_680_064
MANDATORY_HEADROOM_SIZE = 2_097_152
TERMINAL_AREA_SIZE = 524_288

MAGIC = bytes.fromhex("4d434c4439463200")
WIRE_VERSION = 2
F_CHECKSUM_DOMAIN = b"MCL-D0009-F2R1-REC"
TERMINAL_GENERATION = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class Region:
    """One half-open region in the adopted F physical map."""

    name: str
    start: int
    end: int

    @property
    def capacity(self) -> int:
        return self.end - self.start


F_REGIONS = (
    Region("ordinary", 0, 12_582_912),
    Region("headroom", 12_582_912, 14_680_064),
    Region("a", 14_680_064, 15_204_352),
    Region("b", 15_204_352, 15_728_640),
    Region("c", 15_728_640, 16_252_928),
    Region("d", 16_252_928, 16_777_216),
)
F_REGION_BY_NAME = MappingProxyType({region.name: region for region in F_REGIONS})

RECORD_ENVELOPE = (
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


class RecordKind(IntEnum):
    GENESIS = 1
    BEGIN = 2
    ITEM = 3
    DATA = 4
    END = 5
    FINAL = 6


RECORD_PLACEMENTS = MappingProxyType(
    {
        RecordKind.GENESIS: ("ordinary_first",),
        RecordKind.BEGIN: ("ordinary",),
        RecordKind.ITEM: ("ordinary", "a", "b", "c"),
        RecordKind.DATA: ("ordinary", "a", "b", "c"),
        RecordKind.END: ("ordinary",),
        RecordKind.FINAL: ("d_slot_0",),
    }
)

GENESIS_BEGIN_END_PAYLOAD_MAX = 1_024
ITEM_PAYLOAD_MAX = 512
ITEM_DESCRIPTOR_MAX = 357
ORDINARY_ITEM_MAX = 524_288
TERMINAL_ITEM_WIRE_MAX = 508_000


class Category(IntEnum):
    RETENTION_CONTROL = 0
    SOURCE_PACKAGE_PLIST = 1
    PROFILE_TOOLCHAIN = 2
    GOVERNANCE_QUALIFICATION = 3
    DIRECTORY_GRAPH = 4
    CREDENTIALS_BOOT_APFS = 5
    PROCESS_TERMINAL_OBSERVATIONS = 6
    STDOUT = 7
    STDERR = 8
    JOURNAL = 9
    BOOTSTRAP_PROVISIONING_RECEIPTS = 10
    ABORT_CLEANUP_FINAL_VERIFICATION = 11


CATEGORY_MEANINGS = MappingProxyType(
    {
        Category.RETENTION_CONTROL: "Retention control/closing manifest",
        Category.SOURCE_PACKAGE_PLIST: "Source/package/plist",
        Category.PROFILE_TOOLCHAIN: "Profile/toolchain",
        Category.GOVERNANCE_QUALIFICATION: "Governance/qualification",
        Category.DIRECTORY_GRAPH: "Directory graph",
        Category.CREDENTIALS_BOOT_APFS: "Credentials/boot/APFS",
        Category.PROCESS_TERMINAL_OBSERVATIONS: "Process/terminal observations",
        Category.STDOUT: "Stdout",
        Category.STDERR: "Stderr",
        Category.JOURNAL: "Journal",
        Category.BOOTSTRAP_PROVISIONING_RECEIPTS: "Bootstrap/provisioning receipts",
        Category.ABORT_CLEANUP_FINAL_VERIFICATION: "Abort/cleanup/final-verification evidence",
    }
)

ITEM_FIELDS = (
    "permit",
    "role",
    "category",
    "encoding",
    "schema",
    "length",
    "sha256",
)
ITEM_ENCODINGS = ("raw", "cjson2")
ROLE_PATTERN = r"[a-z][a-z0-9_]{0,63}"

CONTROL_SCHEMA = "mcl-d0009-f2r2-control"
CONTROL_FIELDS = ("schema", "n", "prev", "kind", "body")
CONTROL_KINDS = ("CREATE", "BIND", "AUTHORIZE", "CHECKPOINT")

CHECKPOINT_COMMON_FIELDS = (
    "disposition",
    "authorization",
    "verification",
    "closure_custody",
    "state",
)
CHECKPOINT_STATE_FIELDS = ("ordinary", "admitted", "terminal")
ORDINARY_OPEN_FIELDS = ("mode", "end", "prefix_sha256")
ORDINARY_FROZEN_FIELDS = ORDINARY_OPEN_FIELDS + ("region_sha256",)
ADMITTED_FIELDS = ("generation", "end", "prefix_sha256")
TERMINAL_OPEN_FIELDS = ("mode", "used_slots", "prefix_sha256")
TERMINAL_FROZEN_FIELDS = TERMINAL_OPEN_FIELDS + ("area_sha256",)

CHECKPOINT_SUBTYPE_FIELDS = MappingProxyType(
    {
        "admit": ("generation", "result", "purposes", "supersedes"),
        "abandon": ("generation",),
        "freeze_ordinary": ("cause",),
        "freeze_terminal_area": ("area", "cause"),
        "freeze_f": ("cause", "file_sha256"),
        "final_complete": ("file_sha256",),
        "final_failed": ("file_sha256",),
        "final_unresolved": ("file_sha256",),
    }
)
CHECKPOINT_CAUSES = (
    "explicit",
    "torn",
    "ambiguous",
    "capacity",
    "io_failure",
    "custody",
    "invalid_state",
)
CHECKPOINT_RESULTS = ("success", "failure", "unresolved")
TERMINAL_AREAS = ("A", "B", "C", "D")


class ValidationStage(Enum):
    ENCODING = "encoding"
    CLOSED_SCHEMA = "closed_schema"
    SEMANTIC_REFERENCES = "semantic_references"


CJSON2_KEY_PATTERN = r"[a-z][a-z0-9_]*"
CJSON2_MAX_DEPTH = 8
CJSON2_MAX_OBJECT_MEMBERS = 64
CJSON2_MAX_INTEGER_DIGITS = 20

ORDINARY_ACCOUNT_BYTES = MappingProxyType(
    {
        "four_a1_snapshot_sets": 1_048_576,
        "a1_qualification_profile_governance": 2_097_152,
        "a2_evidence": 1_048_576,
        "gate_b_ordinary_evidence": 3_145_728,
        "descriptors_control_framing_padding": 1_048_576,
        "interruption_abandonment": 2_097_152,
        "review_correction": 2_097_152,
    }
)

ORDINARY_PHYSICAL_ATTEMPTS_MAX = 3_584
GENERATION_NUMBERS_MAX = 16
RECORDS_PER_GENERATION_MAX = 512
ITEMS_PER_GENERATION_MAX = 128
ORDINARY_ITEMS_LIFETIME_MAX = 1_024
ABORTED_GENERATIONS_MAX = 4
ORDINARY_GENERATION_BYTES_MAX = 2_097_152
WRITABLE_PHASES_MAX = 24
TERMINAL_SLOTS_SCANNED = 512

SUPPORT_OBJECTS_MAX = 128
SUPPORT_OBJECT_BYTES_MAX = 65_536
SUPPORT_AGGREGATE_BYTES_MAX = 4_194_304

OPERATIONAL_CEILINGS = MappingProxyType(
    {
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
    }
)


# Adopted additive V2-0 CREATE/BIND/AUTHORIZE schema declarations.  These are
# immutable level-1 facts only; V2-1 applies closed schemas, joins, branch
# semantics, lifecycle history, authority, and reservation sufficiency.
CREATE_BODY_FIELDS = (
    "specification",
    "v1_freeze",
    "f_path_hex",
    "parent_profile",
    "creation_profile",
    "custody_profile",
    "writer_profile",
    "creation_authority",
)
BIND_BODY_FIELDS = (
    "create",
    "identity",
    "qualification",
    "size_verification",
    "zero_verification",
    "allocation",
    "setup_writer_closure",
    "genesis_permitted",
)
AUTHORIZE_BODY_FIELDS = (
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
ORDINARY_ROLE_FIELDS = (
    "role",
    "category",
    "encoding",
    "schema",
    "max_length",
    "account",
)
OUTCOME_ROLES_FIELDS = ("success", "failure", "unresolved")
TERMINAL_ROLE_FIELDS = (
    "branch",
    "area",
    "role",
    "category",
    "encoding",
    "schema",
    "max_length",
)
TERMINAL_BRANCH_FIELDS = ("branch", "condition", "reservations", "limits")
SLOT_RESERVATION_FIELDS = ("area", "first_slot", "slot_count")
BRANCH_LIMIT_FIELDS = (
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
INTERMEDIATE_STORE_FIELDS = ("store", "ordinary_roles", "terminal_roles")
TERMINAL_ROLE_REFERENCE_FIELDS = ("branch", "area", "role")
ACTION_PERMISSION_FIELDS = ("action", "branches")
ORDINARY_ACCOUNT_FIELDS = (
    "four_a1_snapshot_sets",
    "a1_qualification_profile_governance",
    "a2_evidence",
    "gate_b_ordinary_evidence",
    "descriptors_control_framing_padding",
    "interruption_abandonment",
    "review_correction",
)

CONTROL_DIGEST_PATTERN = r"[0-9a-f]{64}"
CONTROL_PATH_HEX_PATTERN = r"(?:[0-9a-f]{2})+"
CONTROL_UINT_PATTERN = r"(?:0|[1-9][0-9]*)"
PLAN_REF_PATTERN = ROLE_PATTERN
AUTHORIZE_OUTCOMES = ("success", "failure", "unresolved")
TERMINAL_ITEM_AREAS = ("A", "B", "C")
ORDINARY_ACCOUNTS = ORDINARY_ACCOUNT_FIELDS
CONTROL_OBJECT_BYTES_MAX = SUPPORT_OBJECT_BYTES_MAX

CONTROL_PATTERNS = MappingProxyType(
    {
        "digest": CONTROL_DIGEST_PATTERN,
        "path_hex": CONTROL_PATH_HEX_PATTERN,
        "plan_ref": PLAN_REF_PATTERN,
        "role": ROLE_PATTERN,
        "uint": CONTROL_UINT_PATTERN,
    }
)
CONTROL_ENUMS = MappingProxyType(
    {
        "authorize_outcomes": AUTHORIZE_OUTCOMES,
        "encodings": ITEM_ENCODINGS,
        "ordinary_accounts": ORDINARY_ACCOUNTS,
        "terminal_areas": TERMINAL_AREAS,
        "terminal_item_areas": TERMINAL_ITEM_AREAS,
    }
)

CONTROL_FIELD_TYPES = MappingProxyType(
    {
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
        "ordinary_accounts": (
            ("four_a1_snapshot_sets", "uint"),
            ("a1_qualification_profile_governance", "uint"),
            ("a2_evidence", "uint"),
            ("gate_b_ordinary_evidence", "uint"),
            ("descriptors_control_framing_padding", "uint"),
            ("interruption_abandonment", "uint"),
            ("review_correction", "uint"),
        ),
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
)

CONTROL_NULLABLE_FIELDS = MappingProxyType(
    {
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
)

CONTROL_UINT_RANGES = MappingProxyType(
    {
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
        "ordinary_accounts.four_a1_snapshot_sets": (0, 1_048_576),
        "ordinary_accounts.a1_qualification_profile_governance": (0, 2_097_152),
        "ordinary_accounts.a2_evidence": (0, 1_048_576),
        "ordinary_accounts.gate_b_ordinary_evidence": (0, 3_145_728),
        "ordinary_accounts.descriptors_control_framing_padding": (0, 1_048_576),
        "ordinary_accounts.interruption_abandonment": (0, 2_097_152),
        "ordinary_accounts.review_correction": (0, 2_097_152),
    }
)
BRANCH_TERMINAL_PAYLOAD_RANGES = (
    (0, 508_000),
    (0, 131_072),
    (0, 65_536),
    (0, 4_000),
)

CONTROL_ARRAY_METADATA = MappingProxyType(
    {
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
        "authorize_body.intermediate_stores": (
            "intermediate_store",
            0,
            None,
            "store_ascii",
        ),
        "authorize_body.abort_actions": ("action_permission", 0, None, "action_ascii"),
        "authorize_body.cleanup_actions": (
            "action_permission",
            0,
            None,
            "action_ascii",
        ),
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
)

CONTROL_REPRESENTATIONS = MappingProxyType(
    {
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
)

AUTHORIZE_BRANCH_SEMANTICS = MappingProxyType(
    {
        "branch_model": "complete_mutually_exclusive_alternative_path",
        "sequential_terminal_use": "within_branch",
        "alternative_demand": "maximum_complete_path",
        "within_path_demand": "cumulative",
        "mutually_exclusive_reservations_may_overlap": True,
        "simultaneously_consumable_reservations_may_overlap": False,
        "first_slot": "deterministic_append_frontier",
    }
)
CONTROL_LIFECYCLE_DECLARATIONS = MappingProxyType(
    {
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
)
ORDINARY_ACCOUNT_ATTRIBUTION = MappingProxyType(
    {
        "item_descriptor_header_padding": "descriptors_control_framing_padding",
        "data_payload": "declared_role_account",
        "data_header_padding": "descriptors_control_framing_padding",
        "genesis_begin_end_physical": "descriptors_control_framing_padding",
        "terminal_item_data": "terminal_capacity",
    }
)
D_FINAL_DECLARATION = MappingProxyType(
    {
        "area": "D",
        "record_kind": "FINAL",
        "first_slot": "0",
        "slot_count": "1",
        "payload_without_reservation": "0",
        "payload_with_reservation": "4000",
        "terminal_item_allowed": False,
    }
)
