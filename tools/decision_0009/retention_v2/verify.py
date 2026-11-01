"""Independent in-memory F verifier for Decision 0009 Retention V2-1.

The verifier evaluates supplied bytes and supplied evidence only.  It performs
no filesystem, host, process, provider, or protected-source observation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import struct
from typing import Any, Mapping, Sequence

from . import cjson2, spec


RESULT_SCHEMA = "mcl-d0009-f2r2-verification"
RESULT_FIELDS = {
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
}
SUBJECT_FIELDS = {
    "specification",
    "binding",
    "control",
    "file_sha256",
    "identity_matches",
}
VALIDATION_FIELDS = {"encoding", "schema", "references"}
RESULT_ENUMS = {
    "integrity": {
        "valid",
        "invalid",
        "blocked_torn",
        "blocked_ambiguous",
        "not_established",
    },
    "physical_state": {
        "clean_frontier",
        "committed_tail",
        "incomplete_tail",
        "aborted_tail",
        "ordinary_frozen",
        "terminal_frozen",
        "finalized",
        "malformed_size_or_state",
        "unobserved",
    },
    "durability": {"established", "not_established", "not_applicable"},
    "authority": {"current", "historical_only", "invalid", "not_established"},
    "custody": {"valid", "invalid", "not_established"},
    "admitted_prefix": {"valid", "invalid", "not_established", "not_applicable"},
    "operation_result": {"success", "failure", "unresolved", "not_applicable"},
    "progression": {
        "eligible_for_chair_consideration",
        "blocked_pending_disposition",
        "blocked_integrity",
        "blocked_custody",
        "blocked_authority",
        "final",
    },
    "validation": {"valid", "invalid", "not_checked"},
}

_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z", re.ASCII)
_ROLE_RE = re.compile(rf"\A(?:{spec.ROLE_PATTERN})\Z", re.ASCII)
_PATH_HEX_RE = re.compile(rf"\A(?:{spec.CONTROL_PATH_HEX_PATTERN})\Z", re.ASCII)
_UINT_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\Z", re.ASCII)
_AREA_STARTS = {name.upper(): region.start for name, region in spec.F_REGION_BY_NAME.items() if name in "abcd"}
_AREA_ENDS = {name.upper(): region.end for name, region in spec.F_REGION_BY_NAME.items() if name in "abcd"}
_ZERO32 = b"\x00" * 32


class _SchemaError(ValueError):
    pass


class _ReferenceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _Record:
    offset: int
    physical_length: int
    kind: int
    payload_length: int
    sequence: int
    generation: int
    previous: bytes
    checksum: bytes
    payload: bytes
    area: str | None = None
    slot: int | None = None


@dataclass(slots=True)
class _PhysicalScan:
    ordinary: list[_Record] = field(default_factory=list)
    terminal: dict[str, list[_Record]] = field(
        default_factory=lambda: {area: [] for area in "ABCD"}
    )
    frontier: int = 0
    torn: bool = False
    ambiguous: bool = False
    terminal_torn: bool = False
    terminal_ambiguous: bool = False
    terminal_activity: bool = False
    malformed_size: bool = False
    headroom_nonzero: bool = False


@dataclass(slots=True)
class _Controls:
    values: list[dict[str, Any]] = field(default_factory=list)
    raw: list[bytes] = field(default_factory=list)
    digests: list[str] = field(default_factory=list)
    by_digest: dict[str, dict[str, Any]] = field(default_factory=dict)
    encoding_invalid: bool = False
    schema_invalid: bool = False
    references_invalid: bool = False
    authority_invalid: bool = False
    semantic_references_invalid: bool = False
    bind_digest: str | None = None
    bind: dict[str, Any] | None = None
    authorizations: dict[str, dict[str, Any]] = field(default_factory=dict)
    checkpoints: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    latest_checkpoint: dict[str, Any] | None = None
    trusted_index: int | None = None
    trusted_checkpoint: dict[str, Any] | None = None
    invalid_authorizations: set[str] = field(default_factory=set)
    frozen_before_authorization: dict[str, frozenset[str]] = field(default_factory=dict)
    ordinary_frozen_before_authorization: dict[str, bool] = field(default_factory=dict)
    frontier_before_authorization: dict[str, dict[str, int]] = field(default_factory=dict)
    outstanding_reservations: list[tuple[str, str, str, int, int]] = field(
        default_factory=list
    )


@dataclass(slots=True)
class _Semantic:
    encoding_invalid: bool = False
    schema_invalid: bool = False
    references_invalid: bool = False
    tail: str = "clean_frontier"
    operation_result: str = "unresolved"
    last_generation: int | None = None
    last_committed_generation: int | None = None
    terminal_manifest: dict[str, Any] | None = None
    terminal_final: dict[str, Any] | None = None
    terminal_activity: bool = False


def compute_record_checksum(offset: int, header: bytes, payload: bytes, padding: bytes) -> bytes:
    """Construct the adopted F checksum preimage independently."""

    if not isinstance(offset, int) or offset < 0:
        raise ValueError("record offset must be a nonnegative integer")
    if not isinstance(header, bytes) or len(header) != spec.HEADER_SIZE:
        raise ValueError("record header must be exactly 96 bytes")
    if not isinstance(payload, bytes) or not isinstance(padding, bytes):
        raise ValueError("record payload and padding must be exact bytes")
    zeroed = bytearray(header)
    zeroed[64:96] = _ZERO32
    return hashlib.sha256(
        spec.F_CHECKSUM_DOMAIN
        + b"\x00"
        + offset.to_bytes(8, "little")
        + bytes(zeroed)
        + payload
        + padding
    ).digest()


def _require_keys(value: Any, expected: Sequence[str] | set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _SchemaError(f"{label} must be an object")
    expected_set = set(expected)
    if set(value) != expected_set:
        raise _SchemaError(f"{label} fields are not closed")
    return value


def _digest(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise _SchemaError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _role(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ROLE_RE.fullmatch(value) is None:
        raise _SchemaError(f"{label} does not match the role grammar")
    return value


def _uint(value: Any, label: str, minimum: int = 0, maximum: int | None = None) -> int:
    if not isinstance(value, str) or len(value) > spec.CJSON2_MAX_INTEGER_DIGITS:
        raise _SchemaError(f"{label} is not a bounded canonical integer")
    if _UINT_RE.fullmatch(value) is None:
        raise _SchemaError(f"{label} is not a canonical integer")
    number = int(value)
    if number < minimum or (maximum is not None and number > maximum):
        raise _SchemaError(f"{label} is outside its adopted range")
    return number


def _sorted_unique_strings(values: Any, label: str, *, maximum: int | None = None) -> list[str]:
    if not isinstance(values, list) or (maximum is not None and len(values) > maximum):
        raise _SchemaError(f"{label} is not a bounded array")
    for value in values:
        _role(value, label)
    if len(set(values)) != len(values) or values != sorted(values, key=lambda item: item.encode("ascii")):
        raise _SchemaError(f"{label} must be unique and ASCII sorted")
    return values


def _schema_ordinary_role(value: Any) -> None:
    role = _require_keys(value, spec.ORDINARY_ROLE_FIELDS, "ordinary role")
    _role(role["role"], "ordinary role")
    _uint(role["category"], "ordinary role category", 0, 11)
    if role["encoding"] not in spec.ITEM_ENCODINGS:
        raise _SchemaError("ordinary role encoding is invalid")
    if role["encoding"] == "raw":
        if role["schema"] is not None:
            _digest(role["schema"], "ordinary raw schema")
    else:
        _digest(role["schema"], "ordinary CJSON2 schema")
    _uint(role["max_length"], "ordinary role max_length", 0, spec.ORDINARY_ITEM_MAX)
    if role["account"] not in spec.ORDINARY_ACCOUNTS:
        raise _SchemaError("ordinary role account is invalid")


def _schema_terminal_role(value: Any) -> None:
    role = _require_keys(value, spec.TERMINAL_ROLE_FIELDS, "terminal role")
    _role(role["branch"], "terminal branch")
    if role["area"] not in spec.TERMINAL_ITEM_AREAS:
        raise _SchemaError("terminal ITEM role area is invalid")
    _role(role["role"], "terminal role")
    _uint(role["category"], "terminal role category", 0, 11)
    if role["encoding"] not in spec.ITEM_ENCODINGS:
        raise _SchemaError("terminal role encoding is invalid")
    if role["encoding"] == "raw":
        if role["schema"] is not None:
            _digest(role["schema"], "terminal raw schema")
    else:
        _digest(role["schema"], "terminal CJSON2 schema")
    _uint(role["max_length"], "terminal role max_length", 0, spec.TERMINAL_ITEM_WIRE_MAX)


def _schema_branch(value: Any) -> None:
    branch = _require_keys(value, spec.TERMINAL_BRANCH_FIELDS, "terminal branch")
    _role(branch["branch"], "branch")
    _role(branch["condition"], "branch condition")
    reservations = branch["reservations"]
    if not isinstance(reservations, list) or len(reservations) > 4:
        raise _SchemaError("branch reservations are not bounded")
    areas = []
    for reservation in reservations:
        reservation = _require_keys(reservation, spec.SLOT_RESERVATION_FIELDS, "slot reservation")
        if reservation["area"] not in spec.TERMINAL_AREAS:
            raise _SchemaError("reservation area is invalid")
        first = _uint(reservation["first_slot"], "reservation first_slot", 0, 127)
        count = _uint(reservation["slot_count"], "reservation slot_count", 1, 128)
        if first + count > 128:
            raise _SchemaError("reservation extends beyond its area")
        areas.append(reservation["area"])
    if len(set(areas)) != len(areas) or areas != sorted(areas):
        raise _SchemaError("reservations must be unique and area sorted")
    limits = _require_keys(branch["limits"], spec.BRANCH_LIMIT_FIELDS, "branch limits")
    ranges = {
        "ordinary_bytes": (0, spec.ORDINARY_GENERATION_BYTES_MAX),
        "ordinary_records": (0, spec.RECORDS_PER_GENERATION_MAX),
        "ordinary_items": (0, spec.ITEMS_PER_GENERATION_MAX),
        "ordinary_aborts": (0, 1),
        "writable_phases": (0, spec.WRITABLE_PHASES_MAX),
        "support_objects": (0, spec.SUPPORT_OBJECTS_MAX),
        "support_bytes": (0, spec.SUPPORT_AGGREGATE_BYTES_MAX),
    }
    for field_name, (minimum, maximum) in ranges.items():
        _uint(limits[field_name], f"branch {field_name}", minimum, maximum)
    accounts = _require_keys(
        limits["ordinary_accounts"], spec.ORDINARY_ACCOUNT_FIELDS, "ordinary accounts"
    )
    for name, ceiling in spec.ORDINARY_ACCOUNT_BYTES.items():
        _uint(accounts[name], f"ordinary account {name}", 0, ceiling)
    terminal = limits["terminal_payload_bytes"]
    if not isinstance(terminal, list) or len(terminal) != 4:
        raise _SchemaError("terminal payload limits must contain A-D")
    for index, value in enumerate(terminal):
        minimum, maximum = spec.BRANCH_TERMINAL_PAYLOAD_RANGES[index]
        _uint(value, f"terminal payload limit {index}", minimum, maximum)


def _schema_authorize(body: Any) -> None:
    body = _require_keys(body, spec.AUTHORIZE_BODY_FIELDS, "AUTHORIZE body")
    for name in ("base", "writer", "dispatch", "operation_plan"):
        _digest(body[name], f"AUTHORIZE {name}")
    if body["generation"] is not None:
        _uint(body["generation"], "AUTHORIZE generation", 1, 15)
    outcomes = body["outcomes"]
    if not isinstance(outcomes, list) or len(outcomes) > 3:
        raise _SchemaError("AUTHORIZE outcomes are not bounded")
    order = {name: index for index, name in enumerate(spec.AUTHORIZE_OUTCOMES)}
    if any(value not in order for value in outcomes):
        raise _SchemaError("AUTHORIZE outcome is invalid")
    if len(set(outcomes)) != len(outcomes) or outcomes != sorted(outcomes, key=order.get):
        raise _SchemaError("AUTHORIZE outcomes are not unique and ordered")
    roles = body["item_roles"]
    if not isinstance(roles, list) or len(roles) > spec.ITEMS_PER_GENERATION_MAX:
        raise _SchemaError("AUTHORIZE item roles are not bounded")
    for role in roles:
        _schema_ordinary_role(role)
    role_names = [role["role"] for role in roles]
    if len(set(role_names)) != len(role_names) or role_names != sorted(role_names):
        raise _SchemaError("ordinary roles are not unique and sorted")
    required = _require_keys(body["required_roles"], spec.OUTCOME_ROLES_FIELDS, "required roles")
    for outcome in spec.AUTHORIZE_OUTCOMES:
        _sorted_unique_strings(required[outcome], f"required roles for {outcome}", maximum=128)
    areas = body["terminal_areas"]
    if not isinstance(areas, list) or any(area not in spec.TERMINAL_AREAS for area in areas):
        raise _SchemaError("terminal areas are invalid")
    if len(set(areas)) != len(areas) or areas != sorted(areas):
        raise _SchemaError("terminal areas are not unique and ordered")
    terminal_roles = body["terminal_roles"]
    if not isinstance(terminal_roles, list):
        raise _SchemaError("terminal roles must be an array")
    for role in terminal_roles:
        _schema_terminal_role(role)
    terminal_keys = [(role["branch"], role["area"], role["role"]) for role in terminal_roles]
    if len(set(terminal_keys)) != len(terminal_keys) or terminal_keys != sorted(terminal_keys):
        raise _SchemaError("terminal roles are not unique and ordered")
    branches = body["branches"]
    if not isinstance(branches, list) or not branches:
        raise _SchemaError("AUTHORIZE requires at least one branch")
    for branch in branches:
        _schema_branch(branch)
    branch_names = [branch["branch"] for branch in branches]
    if len(set(branch_names)) != len(branch_names) or branch_names != sorted(branch_names):
        raise _SchemaError("branches are not unique and sorted")
    stores = body["intermediate_stores"]
    if not isinstance(stores, list):
        raise _SchemaError("intermediate stores must be an array")
    store_names = []
    for store in stores:
        store = _require_keys(store, spec.INTERMEDIATE_STORE_FIELDS, "intermediate store")
        store_names.append(_digest(store["store"], "intermediate store digest"))
        _sorted_unique_strings(store["ordinary_roles"], "intermediate ordinary roles", maximum=128)
        refs = store["terminal_roles"]
        if not isinstance(refs, list):
            raise _SchemaError("intermediate terminal roles must be an array")
        keys = []
        for reference in refs:
            reference = _require_keys(
                reference, spec.TERMINAL_ROLE_REFERENCE_FIELDS, "terminal role reference"
            )
            _role(reference["branch"], "terminal role reference branch")
            if reference["area"] not in spec.TERMINAL_ITEM_AREAS:
                raise _SchemaError("terminal role reference area is invalid")
            _role(reference["role"], "terminal role reference role")
            keys.append((reference["branch"], reference["area"], reference["role"]))
        if len(set(keys)) != len(keys) or keys != sorted(keys):
            raise _SchemaError("terminal role references are not unique and ordered")
    if len(set(store_names)) != len(store_names) or store_names != sorted(store_names):
        raise _SchemaError("intermediate stores are not unique and ordered")
    for field_name in ("abort_actions", "cleanup_actions"):
        actions = body[field_name]
        if not isinstance(actions, list):
            raise _SchemaError(f"{field_name} must be an array")
        action_names = []
        for action in actions:
            action = _require_keys(action, spec.ACTION_PERMISSION_FIELDS, field_name)
            action_names.append(_role(action["action"], f"{field_name} action"))
            branches_for_action = _sorted_unique_strings(
                action["branches"], f"{field_name} branches"
            )
            if not branches_for_action:
                raise _SchemaError(f"{field_name} branches cannot be empty")
        if len(set(action_names)) != len(action_names) or action_names != sorted(action_names):
            raise _SchemaError(f"{field_name} are not unique and ordered")


def _schema_state(state: Any) -> None:
    state = _require_keys(state, spec.CHECKPOINT_STATE_FIELDS, "CHECKPOINT state")
    ordinary = state["ordinary"]
    if not isinstance(ordinary, dict) or ordinary.get("mode") not in {"open", "frozen"}:
        raise _SchemaError("ordinary state mode is invalid")
    expected = spec.ORDINARY_OPEN_FIELDS if ordinary["mode"] == "open" else spec.ORDINARY_FROZEN_FIELDS
    _require_keys(ordinary, expected, "ordinary state")
    _uint(ordinary["end"], "ordinary state end", 0, spec.ORDINARY_LOG_END)
    _digest(ordinary["prefix_sha256"], "ordinary prefix digest")
    if ordinary["mode"] == "frozen":
        _digest(ordinary["region_sha256"], "ordinary region digest")
    admitted = _require_keys(state["admitted"], spec.ADMITTED_FIELDS, "admitted state")
    if admitted["generation"] is not None:
        _uint(admitted["generation"], "admitted generation", 0, 15)
    _uint(admitted["end"], "admitted end", 0, spec.ORDINARY_LOG_END)
    _digest(admitted["prefix_sha256"], "admitted prefix digest")
    terminal = state["terminal"]
    if not isinstance(terminal, list) or len(terminal) != 4:
        raise _SchemaError("terminal state must contain A-D")
    for index, entry in enumerate(terminal):
        if not isinstance(entry, dict) or entry.get("mode") not in {"open", "frozen"}:
            raise _SchemaError(f"terminal state {index} mode is invalid")
        expected = (
            spec.TERMINAL_OPEN_FIELDS
            if entry["mode"] == "open"
            else spec.TERMINAL_FROZEN_FIELDS
        )
        _require_keys(entry, expected, f"terminal state {index}")
        _uint(entry["used_slots"], f"terminal state {index} used slots", 0, 128)
        _digest(entry["prefix_sha256"], f"terminal state {index} prefix digest")
        if entry["mode"] == "frozen":
            _digest(entry["area_sha256"], f"terminal state {index} area digest")


def _schema_checkpoint(body: Any) -> None:
    if not isinstance(body, dict) or body.get("disposition") not in spec.CHECKPOINT_SUBTYPE_FIELDS:
        raise _SchemaError("CHECKPOINT disposition is invalid")
    disposition = body["disposition"]
    expected = set(spec.CHECKPOINT_COMMON_FIELDS) | set(spec.CHECKPOINT_SUBTYPE_FIELDS[disposition])
    _require_keys(body, expected, f"CHECKPOINT {disposition}")
    for name in ("authorization", "verification", "closure_custody"):
        _digest(body[name], f"CHECKPOINT {name}")
    _schema_state(body["state"])
    if disposition == "admit":
        _uint(body["generation"], "admitted generation", 0, 15)
        if body["result"] not in spec.CHECKPOINT_RESULTS:
            raise _SchemaError("admit result is invalid")
        _sorted_unique_strings(body["purposes"], "admit purposes")
        if not isinstance(body["supersedes"], list):
            raise _SchemaError("admit supersedes must be an array")
    elif disposition == "abandon":
        _uint(body["generation"], "abandoned generation", 1, 15)
    elif disposition in {"freeze_ordinary", "freeze_terminal_area", "freeze_f"}:
        if body["cause"] not in spec.CHECKPOINT_CAUSES:
            raise _SchemaError("freeze cause is invalid")
        if disposition == "freeze_terminal_area" and body["area"] not in spec.TERMINAL_AREAS:
            raise _SchemaError("frozen terminal area is invalid")
        if disposition == "freeze_f":
            _digest(body["file_sha256"], "freeze_f file digest")
    elif disposition.startswith("final_"):
        _digest(body["file_sha256"], "final file digest")


def _schema_control(value: dict[str, Any], raw: bytes) -> None:
    if len(raw) > spec.CONTROL_OBJECT_BYTES_MAX:
        raise _SchemaError("control object exceeds its byte ceiling")
    value = _require_keys(value, spec.CONTROL_FIELDS, "control envelope")
    if value["schema"] != spec.CONTROL_SCHEMA:
        raise _SchemaError("control schema identifier is invalid")
    _uint(value["n"], "control n")
    _digest(value["prev"], "control prev", nullable=True)
    if value["kind"] not in spec.CONTROL_KINDS:
        raise _SchemaError("control kind is invalid")
    body = value["body"]
    if value["kind"] == "CREATE":
        body = _require_keys(body, spec.CREATE_BODY_FIELDS, "CREATE body")
        for name in spec.CREATE_BODY_FIELDS:
            if name == "f_path_hex":
                if not isinstance(body[name], str) or _PATH_HEX_RE.fullmatch(body[name]) is None:
                    raise _SchemaError("CREATE path is not exact lowercase hex")
            else:
                _digest(body[name], f"CREATE {name}")
    elif value["kind"] == "BIND":
        body = _require_keys(body, spec.BIND_BODY_FIELDS, "BIND body")
        for name in spec.BIND_BODY_FIELDS:
            if name == "genesis_permitted":
                if not isinstance(body[name], bool):
                    raise _SchemaError("BIND genesis_permitted must be boolean")
            else:
                _digest(body[name], f"BIND {name}")
    elif value["kind"] == "AUTHORIZE":
        _schema_authorize(body)
    else:
        _schema_checkpoint(body)


def _load_controls(evidence: Mapping[str, Any]) -> _Controls:
    controls = _Controls()
    raw_values = evidence.get("control_objects", ())
    if not isinstance(raw_values, (tuple, list)):
        controls.schema_invalid = True
        return controls
    for raw in raw_values:
        if not isinstance(raw, bytes):
            controls.schema_invalid = True
            continue
        digest = hashlib.sha256(raw).hexdigest()
        controls.raw.append(raw)
        controls.digests.append(digest)
        try:
            value = cjson2.loads(raw)
        except cjson2.CJSON2Error:
            controls.encoding_invalid = True
            continue
        controls.values.append(value)
        controls.by_digest[digest] = value
        try:
            _schema_control(value, raw)
        except _SchemaError:
            controls.schema_invalid = True
    if controls.encoding_invalid:
        return controls
    previous = None
    create_digest = None
    latest_base = None
    frozen_areas: set[str] = set()
    ordinary_frozen = False
    terminal_frontier = {area: 0 for area in "ABCD"}
    admitted_generation: int | None = None
    admitted_end = 0
    admitted_digest: str | None = None
    final_seen = False
    f_frozen = False
    for index, (raw, digest, value) in enumerate(zip(controls.raw, controls.digests, controls.values)):
        if value.get("n") != str(index) or value.get("prev") != previous:
            controls.references_invalid = True
            controls.authority_invalid = True
        kind = value.get("kind")
        body = value.get("body") if isinstance(value.get("body"), dict) else {}
        if index == 0:
            if kind != "CREATE" or value.get("prev") is not None:
                controls.references_invalid = True
                controls.authority_invalid = True
            create_digest = digest
            latest_base = digest
        elif kind == "CREATE":
            controls.references_invalid = True
            controls.authority_invalid = True
        if kind == "BIND":
            if controls.bind is not None or body.get("create") != create_digest or index != 1:
                controls.references_invalid = True
                controls.authority_invalid = True
            controls.bind = body
            controls.bind_digest = digest
            latest_base = digest
        elif kind == "AUTHORIZE":
            controls.authorizations[digest] = body
            controls.frozen_before_authorization[digest] = frozenset(frozen_areas)
            controls.ordinary_frozen_before_authorization[digest] = ordinary_frozen
            controls.frontier_before_authorization[digest] = dict(terminal_frontier)
            if (
                controls.bind is None
                or final_seen
                or f_frozen
                or (body.get("generation") is not None and ordinary_frozen)
                or body.get("base") != latest_base
            ):
                controls.references_invalid = True
                controls.authority_invalid = True
                controls.invalid_authorizations.add(digest)
            latest_base = digest
        elif kind == "CHECKPOINT":
            controls.checkpoints.append((digest, body))
            controls.latest_checkpoint = body
            authorization = body.get("authorization")
            if authorization not in controls.authorizations and authorization != controls.bind_digest:
                controls.references_invalid = True
                controls.authority_invalid = True
            state = body.get("state") if isinstance(body.get("state"), dict) else {}
            ordinary = state.get("ordinary") if isinstance(state.get("ordinary"), dict) else {}
            if ordinary_frozen and ordinary.get("mode") == "open":
                controls.references_invalid = True
                controls.semantic_references_invalid = True
            if ordinary.get("mode") == "frozen":
                ordinary_frozen = True
            admitted = state.get("admitted") if isinstance(state.get("admitted"), dict) else {}
            try:
                next_generation = (
                    None
                    if admitted.get("generation") is None
                    else int(admitted["generation"])
                )
                next_end = int(admitted.get("end", "0"))
                next_digest = admitted.get("prefix_sha256")
                if admitted_generation is not None:
                    if next_generation is None or next_generation < admitted_generation:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                    if next_end < admitted_end:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                    if next_generation == admitted_generation and (
                        next_end != admitted_end or next_digest != admitted_digest
                    ):
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                admitted_generation = next_generation
                admitted_end = next_end
                admitted_digest = next_digest
            except (KeyError, TypeError, ValueError):
                pass
            terminal = state.get("terminal") if isinstance(state.get("terminal"), list) else []
            for area, entry in zip("ABCD", terminal):
                if isinstance(entry, dict):
                    try:
                        terminal_frontier[area] = int(entry.get("used_slots", "0"))
                    except (TypeError, ValueError):
                        pass
                    if entry.get("mode") == "frozen":
                        frozen_areas.add(area)
                    elif area in frozen_areas:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
            disposition = body.get("disposition")
            if isinstance(disposition, str) and disposition.startswith("final_"):
                final_seen = True
                f_frozen = True
            elif disposition == "freeze_f":
                f_frozen = True
            latest_base = digest
        previous = digest
    if controls.bind_digest != evidence.get("binding_digest"):
        controls.references_invalid = True
        controls.authority_invalid = True
    if controls.values:
        create_body = controls.values[0].get("body", {})
        if create_body.get("specification") != evidence.get("specification_digest"):
            controls.references_invalid = True
            controls.authority_invalid = True
    exclusivity = evidence.get("mutually_exclusive_branches", {})
    if not isinstance(exclusivity, dict):
        controls.references_invalid = True
        exclusivity = {}
    for digest, body in controls.authorizations.items():
        try:
            branch_names = [branch["branch"] for branch in body["branches"]]
            if len(branch_names) > 1:
                established = tuple(exclusivity.get(digest, ()))
                if set(established) != set(branch_names):
                    controls.references_invalid = True
                    controls.semantic_references_invalid = True
            declared_roles = {role["role"] for role in body["item_roles"]}
            for roles in body["required_roles"].values():
                if not set(roles).issubset(declared_roles):
                    controls.references_invalid = True
                    controls.semantic_references_invalid = True
            declared_terminal = {
                (role["branch"], role["area"], role["role"])
                for role in body["terminal_roles"]
            }
            branch_set = set(branch_names)
            area_set = set(body["terminal_areas"])
            if any(key[0] not in branch_set or key[1] not in area_set for key in declared_terminal):
                controls.references_invalid = True
                controls.semantic_references_invalid = True
            stored_ordinary = {
                role
                for store in body["intermediate_stores"]
                for role in store["ordinary_roles"]
            }
            stored_terminal = {
                (role["branch"], role["area"], role["role"])
                for store in body["intermediate_stores"]
                for role in store["terminal_roles"]
            }
            if declared_roles - stored_ordinary or declared_terminal - stored_terminal:
                controls.references_invalid = True
                controls.semantic_references_invalid = True
            for branch in body["branches"]:
                limits = branch["limits"]
                account_total = sum(int(value) for value in limits["ordinary_accounts"].values())
                if account_total > int(limits["ordinary_bytes"]):
                    controls.references_invalid = True
                    controls.semantic_references_invalid = True
                reservations = {reservation["area"]: reservation for reservation in branch["reservations"]}
                frontiers = controls.frontier_before_authorization.get(
                    digest, {area: 0 for area in "ABCD"}
                )
                for area, reservation in reservations.items():
                    if int(reservation["first_slot"]) != frontiers[area]:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                    if area == "D" and (
                        int(reservation["first_slot"]) != 0
                        or int(reservation["slot_count"]) != 1
                    ):
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                for area in controls.frozen_before_authorization.get(digest, ()):
                    if area in reservations:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                for index, area in enumerate("ABCD"):
                    payload = int(limits["terminal_payload_bytes"][index])
                    reservation = reservations.get(area)
                    if payload == 0:
                        continue
                    if reservation is None:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                        continue
                    slots = int(reservation["slot_count"])
                    capacity = 4_000 * (slots if area == "D" else max(0, slots - 1))
                    if payload > capacity:
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
                d_payload = int(limits["terminal_payload_bytes"][3])
                if ("D" in reservations and d_payload != 4_000) or (
                    "D" not in reservations and d_payload != 0
                ):
                    controls.references_invalid = True
                    controls.semantic_references_invalid = True
                for role in body["terminal_roles"]:
                    if role["branch"] != branch["branch"]:
                        continue
                    index = "ABCD".index(role["area"])
                    if int(role["max_length"]) > int(limits["terminal_payload_bytes"][index]):
                        controls.references_invalid = True
                        controls.semantic_references_invalid = True
        except (KeyError, TypeError, ValueError):
            if not controls.schema_invalid:
                controls.references_invalid = True
                controls.semantic_references_invalid = True
    outstanding = evidence.get("outstanding_reservations", ())
    parsed_outstanding: list[tuple[str, str, str, int, int]] = []
    if not isinstance(outstanding, (tuple, list)):
        controls.references_invalid = True
        controls.semantic_references_invalid = True
    else:
        for entry in outstanding:
            try:
                entry = _require_keys(
                    entry,
                    {"operation", "authorization", "branch", "area", "first_slot", "slot_count"},
                    "outstanding reservation",
                )
                operation = _role(entry["operation"], "outstanding operation")
                authorization = _digest(entry["authorization"], "outstanding authorization")
                branch_name = _role(entry["branch"], "outstanding branch")
                if entry["area"] not in spec.TERMINAL_AREAS:
                    raise _SchemaError("outstanding reservation area is invalid")
                first = _uint(entry["first_slot"], "outstanding first_slot", 0, 127)
                count = _uint(entry["slot_count"], "outstanding slot_count", 1, 128)
                if first + count > 128:
                    raise _SchemaError("outstanding reservation exceeds its area")
                body = controls.authorizations.get(authorization)
                declared = False
                if body:
                    declared = any(
                        branch["branch"] == branch_name
                        and any(
                            reservation["area"] == entry["area"]
                            and int(reservation["first_slot"]) == first
                            and int(reservation["slot_count"]) == count
                            for reservation in branch["reservations"]
                        )
                        for branch in body["branches"]
                    )
                if not declared:
                    raise _ReferenceError("outstanding reservation is not declared")
                parsed_outstanding.append(
                    (operation, authorization, entry["area"], first, first + count)
                )
            except (_SchemaError, _ReferenceError, KeyError, TypeError, ValueError):
                controls.references_invalid = True
                controls.semantic_references_invalid = True
        for index, left in enumerate(parsed_outstanding):
            for right in parsed_outstanding[index + 1 :]:
                if (
                    left[0] != right[0]
                    and left[2] == right[2]
                    and max(left[3], right[3]) < min(left[4], right[4])
                ):
                    controls.references_invalid = True
                    controls.semantic_references_invalid = True
    controls.outstanding_reservations = parsed_outstanding
    return controls


def _establish_trusted_lifecycle(
    controls: _Controls, evidence: Mapping[str, Any]
) -> None:
    trusted = evidence.get("trusted_current_control")
    if trusted not in controls.digests:
        return
    controls.trusted_index = controls.digests.index(trusted)
    for digest, body in controls.checkpoints:
        if controls.digests.index(digest) <= controls.trusted_index:
            controls.trusted_checkpoint = body


def _within_trusted_history(controls: _Controls, digest: Any) -> bool:
    if controls.trusted_index is None:
        return True
    return digest in controls.digests and controls.digests.index(digest) <= controls.trusted_index


def _invalidate_authorization(controls: _Controls, digest: str) -> None:
    controls.invalid_authorizations.add(digest)
    controls.references_invalid = True
    controls.authority_invalid = True
    controls.semantic_references_invalid = True


def _ordinary_generation_facts(
    image: bytes, scan: _PhysicalScan, controls: _Controls
) -> dict[int, dict[str, Any]]:
    facts: dict[int, dict[str, Any]] = {}
    current_accounts: dict[int, str] = {}
    for record in scan.ordinary:
        fact = facts.setdefault(
            record.generation,
            {
                "genesis": False,
                "permit": None,
                "status": None,
                "result": None,
                "end": None,
                "prefix_sha256": None,
                "physical_end": 0,
                "record_count": 0,
                "item_count": 0,
                "accounts": {name: 0 for name in spec.ORDINARY_ACCOUNTS},
            },
        )
        fact["physical_end"] = max(
            fact["physical_end"], record.offset + record.physical_length
        )
        fact["record_count"] += 1
        if record.kind == spec.RecordKind.DATA:
            fact["accounts"]["descriptors_control_framing_padding"] += (
                record.physical_length - record.payload_length
            )
            account = current_accounts.get(record.generation)
            if account in fact["accounts"]:
                fact["accounts"][account] += record.payload_length
            continue
        fact["accounts"]["descriptors_control_framing_padding"] += record.physical_length
        if record.kind == spec.RecordKind.GENESIS:
            fact["genesis"] = True
        elif record.kind == spec.RecordKind.BEGIN:
            try:
                begin = cjson2.loads(record.payload)
            except cjson2.CJSON2Error:
                continue
            if isinstance(begin, dict):
                fact["permit"] = begin.get("permit")
        elif record.kind == spec.RecordKind.ITEM:
            fact["item_count"] += 1
            try:
                descriptor = cjson2.loads(record.payload)
            except cjson2.CJSON2Error:
                continue
            if not isinstance(descriptor, dict):
                continue
            authorization = controls.authorizations.get(descriptor.get("permit"), {})
            declaration = next(
                (
                    role
                    for role in authorization.get("item_roles", ())
                    if role.get("role") == descriptor.get("role")
                ),
                None,
            )
            if declaration is not None:
                current_accounts[record.generation] = declaration["account"]
        elif record.kind == spec.RecordKind.END:
            try:
                end = cjson2.loads(record.payload)
            except cjson2.CJSON2Error:
                continue
            if isinstance(end, dict):
                fact["status"] = end.get("status")
                fact["result"] = end.get("result")
                fact["end"] = record.offset + record.physical_length
                fact["prefix_sha256"] = hashlib.sha256(
                    image[: fact["end"]]
                ).hexdigest()
    return facts


def _maximum_authorization_limit(
    authorization: Mapping[str, Any], field: str
) -> int:
    return max(int(branch["limits"][field]) for branch in authorization["branches"])


def _maximum_authorization_account(
    authorization: Mapping[str, Any], account: str
) -> int:
    return max(
        int(branch["limits"]["ordinary_accounts"][account])
        for branch in authorization["branches"]
    )


def _ordinary_usage_before_generation(
    facts: Mapping[int, Mapping[str, Any]], generation: int
) -> dict[str, Any]:
    usage = {
        "physical_end": 0,
        "record_count": 0,
        "item_count": 0,
        "aborted_generations": 0,
        "accounts": {name: 0 for name in spec.ORDINARY_ACCOUNTS},
    }
    for number, fact in facts.items():
        if number >= generation:
            continue
        usage["physical_end"] = max(usage["physical_end"], fact["physical_end"])
        usage["record_count"] += fact["record_count"]
        usage["item_count"] += fact["item_count"]
        if fact.get("status") == "abort":
            usage["aborted_generations"] += 1
        for account, charged in fact["accounts"].items():
            usage["accounts"][account] += charged
    return usage


def _authorization_reservation_fits(
    authorization: Mapping[str, Any], usage: Mapping[str, Any]
) -> bool:
    if usage["physical_end"] + _maximum_authorization_limit(
        authorization, "ordinary_bytes"
    ) > spec.ORDINARY_LOG_END:
        return False
    if usage["record_count"] + _maximum_authorization_limit(
        authorization, "ordinary_records"
    ) > spec.ORDINARY_PHYSICAL_ATTEMPTS_MAX:
        return False
    if usage["item_count"] + _maximum_authorization_limit(
        authorization, "ordinary_items"
    ) > spec.ORDINARY_ITEMS_LIFETIME_MAX:
        return False
    if usage["aborted_generations"] + _maximum_authorization_limit(
        authorization, "ordinary_aborts"
    ) > spec.ABORTED_GENERATIONS_MAX:
        return False
    return all(
        usage["accounts"][account]
        + _maximum_authorization_account(authorization, account)
        <= spec.ORDINARY_ACCOUNT_BYTES[account]
        for account in spec.ORDINARY_ACCOUNTS
    )


def _authorization_conflicts_with_outstanding(
    controls: _Controls,
    digest: str,
    index: int,
    authorization: Mapping[str, Any],
) -> bool:
    for _, prior_authorization, area, first, last in controls.outstanding_reservations:
        if prior_authorization == digest or prior_authorization not in controls.digests:
            continue
        if controls.digests.index(prior_authorization) >= index:
            continue
        for branch in authorization.get("branches", ()):
            for reservation in branch.get("reservations", ()):
                reservation_first = int(reservation["first_slot"])
                reservation_last = reservation_first + int(reservation["slot_count"])
                if (
                    reservation["area"] == area
                    and max(first, reservation_first) < min(last, reservation_last)
                ):
                    return True
    return False


def _matching_preceding_disposition(
    controls: _Controls,
    authorization_index: int,
    authorization: Mapping[str, Any],
    generation: int,
    preceding: Mapping[str, Any],
    preceding_authority: str | None,
) -> bool:
    base = authorization.get("base")
    for digest, body in controls.checkpoints:
        if digest != base or controls.digests.index(digest) >= authorization_index:
            continue
        if (
            body.get("authorization") != preceding_authority
            or body.get("generation") != str(generation - 1)
        ):
            return False
        if preceding.get("status") == "commit":
            admitted = body.get("state", {}).get("admitted", {})
            return (
                body.get("disposition") == "admit"
                and body.get("result") == preceding.get("result")
                and admitted.get("generation") == str(generation - 1)
                and admitted.get("end") == str(preceding.get("end"))
                and admitted.get("prefix_sha256") == preceding.get("prefix_sha256")
            )
        checkpoint_index = controls.digests.index(digest)
        previous_admitted = None
        for prior_digest, prior_body in controls.checkpoints:
            if controls.digests.index(prior_digest) >= checkpoint_index:
                break
            previous_admitted = prior_body.get("state", {}).get("admitted")
        return (
            preceding.get("status") == "abort"
            and preceding.get("result") == "unresolved"
            and body.get("disposition") == "abandon"
            and previous_admitted is not None
            and body.get("state", {}).get("admitted") == previous_admitted
        )
    return False


def _validate_authorizations_at_control_time(
    image: bytes,
    scan: _PhysicalScan,
    controls: _Controls,
    evidence: Mapping[str, Any],
) -> None:
    if controls.encoding_invalid or controls.schema_invalid:
        return
    facts = _ordinary_generation_facts(image, scan, controls)
    seen_generations: dict[int, str] = {}
    consumed = set(evidence.get("consumed_authorizations", ()))
    for index, (digest, value) in enumerate(zip(controls.digests, controls.values)):
        if value.get("kind") != "AUTHORIZE":
            continue
        body = value.get("body") if isinstance(value.get("body"), dict) else {}
        invalid = _authorization_conflicts_with_outstanding(
            controls, digest, index, body
        )
        raw_generation = body.get("generation")
        if raw_generation is None:
            if invalid:
                _invalidate_authorization(controls, digest)
            continue
        try:
            generation = int(raw_generation)
        except (TypeError, ValueError):
            continue
        invalid |= digest in consumed or generation in seen_generations
        seen_generations.setdefault(generation, digest)
        preceding = facts.get(generation - 1)
        if generation == 1:
            preceding_authority = controls.bind_digest
            invalid |= (
                controls.bind is None
                or controls.bind.get("genesis_permitted") is not True
                or evidence.get("genesis_approval_bind_digest") != controls.bind_digest
                or preceding is None
                or preceding.get("genesis") is not True
            )
        else:
            preceding_authority = None if preceding is None else preceding.get("permit")
            invalid |= (
                preceding is None
                or preceding_authority not in controls.authorizations
            )
        invalid |= (
            preceding is None
            or preceding.get("end") is None
            or not _matching_preceding_disposition(
                controls,
                index,
                body,
                generation,
                preceding or {},
                preceding_authority,
            )
        )
        usage = _ordinary_usage_before_generation(facts, generation)
        invalid |= not _authorization_reservation_fits(body, usage)
        current = facts.get(generation)
        if current is not None and current.get("permit") != digest:
            invalid = True
        if invalid:
            _invalidate_authorization(controls, digest)


def _parse_record(image: bytes, offset: int, *, terminal: bool, area: str | None = None, slot: int | None = None) -> _Record:
    header = image[offset : offset + spec.HEADER_SIZE]
    if len(header) != spec.HEADER_SIZE:
        raise ValueError("short header")
    if header[0:8] != spec.MAGIC:
        raise ValueError("bad magic")
    wire, kind, payload_length = struct.unpack_from("<HHI", header, 8)
    sequence, generation, reserved = struct.unpack_from("<QII", header, 16)
    previous = header[32:64]
    checksum = header[64:96]
    if wire != spec.WIRE_VERSION or reserved != 0:
        raise ValueError("bad envelope field")
    if kind not in {kind.value for kind in spec.RecordKind}:
        raise ValueError("unknown record kind")
    if kind in {spec.RecordKind.GENESIS, spec.RecordKind.BEGIN, spec.RecordKind.END}:
        if payload_length > spec.GENESIS_BEGIN_END_PAYLOAD_MAX:
            raise ValueError("boundary-record payload too large")
    elif kind == spec.RecordKind.ITEM and payload_length > spec.ITEM_PAYLOAD_MAX:
        raise ValueError("ITEM descriptor payload too large")
    if terminal:
        physical_length = spec.TERMINAL_SLOT_SIZE
        if payload_length > spec.TERMINAL_DATA_MAX:
            raise ValueError("terminal payload too large")
    else:
        if payload_length > spec.ORDINARY_DATA_MAX:
            raise ValueError("ordinary payload too large")
        physical_length = (spec.HEADER_SIZE + payload_length + spec.ALIGNMENT - 1) // spec.ALIGNMENT * spec.ALIGNMENT
        if physical_length > spec.ORDINARY_RECORD_MAX or offset + physical_length > spec.ORDINARY_LOG_END:
            raise ValueError("ordinary physical length invalid")
    payload = image[offset + spec.HEADER_SIZE : offset + spec.HEADER_SIZE + payload_length]
    padding = image[offset + spec.HEADER_SIZE + payload_length : offset + physical_length]
    if len(payload) != payload_length or len(padding) != physical_length - spec.HEADER_SIZE - payload_length:
        raise ValueError("short record")
    if any(padding):
        raise ValueError("nonzero padding")
    if compute_record_checksum(offset, header, payload, padding) != checksum:
        raise ValueError("checksum mismatch")
    return _Record(
        offset,
        physical_length,
        kind,
        payload_length,
        sequence,
        generation,
        previous,
        checksum,
        payload,
        area,
        slot,
    )


def _scan_image(image: bytes) -> _PhysicalScan:
    scan = _PhysicalScan()
    if len(image) != spec.F_SIZE:
        scan.malformed_size = True
        return scan
    offset = 0
    expected_sequence = 0
    expected_previous = _ZERO32
    open_generation: int | None = None
    last_closed_generation = -1
    while offset < spec.ORDINARY_LOG_END:
        remaining = spec.ORDINARY_LOG_END - offset
        if remaining < spec.HEADER_SIZE:
            if any(image[offset:spec.ORDINARY_LOG_END]):
                scan.ambiguous = True
            scan.frontier = offset
            break
        header = image[offset : offset + spec.HEADER_SIZE]
        if not any(header):
            if any(image[offset:spec.ORDINARY_LOG_END]):
                scan.ambiguous = True
            scan.frontier = offset
            break
        try:
            record = _parse_record(image, offset, terminal=False)
            if record.sequence != expected_sequence or record.previous != expected_previous:
                raise ValueError("sequence or predecessor discontinuity")
            if record.kind == spec.RecordKind.FINAL:
                raise ValueError("FINAL is not an ordinary record")
            if record.kind == spec.RecordKind.GENESIS:
                if offset != 0 or record.generation != 0 or open_generation is not None:
                    raise ValueError("GENESIS placement or generation is invalid")
                open_generation = 0
            elif record.kind == spec.RecordKind.BEGIN:
                if open_generation is not None or record.generation != last_closed_generation + 1:
                    raise ValueError("BEGIN generation is discontinuous")
                open_generation = record.generation
            elif record.kind in {spec.RecordKind.ITEM, spec.RecordKind.DATA}:
                if open_generation is None or record.generation != open_generation:
                    raise ValueError("ITEM/DATA generation is discontinuous")
            elif record.kind == spec.RecordKind.END:
                if open_generation is None or record.generation != open_generation:
                    raise ValueError("END generation is discontinuous")
                last_closed_generation = open_generation
                open_generation = None
            scan.ordinary.append(record)
            offset += record.physical_length
            expected_sequence += 1
            expected_previous = record.checksum
        except ValueError:
            scan.torn = True
            scan.frontier = offset
            break
    else:
        scan.frontier = spec.ORDINARY_LOG_END
    scan.headroom_nonzero = any(image[spec.ORDINARY_LOG_END : spec.HEADROOM_END])
    for area in "ABCD":
        start = _AREA_STARTS[area]
        saw_free = False
        for slot in range(spec.TERMINAL_SLOTS_PER_AREA):
            offset = start + slot * spec.TERMINAL_SLOT_SIZE
            slot_bytes = image[offset : offset + spec.TERMINAL_SLOT_SIZE]
            header = slot_bytes[: spec.HEADER_SIZE]
            if not any(header):
                if any(slot_bytes):
                    scan.terminal_ambiguous = True
                    scan.terminal_activity = True
                saw_free = True
                continue
            scan.terminal_activity = True
            if saw_free or header[:8] != spec.MAGIC:
                scan.terminal_ambiguous = True
                continue
            try:
                record = _parse_record(image, offset, terminal=True, area=area, slot=slot)
                expected = "ABCD".index(area) * 128 + slot
                if (
                    record.sequence != expected
                    or record.generation != spec.TERMINAL_GENERATION
                    or record.previous != _ZERO32
                ):
                    raise ValueError("terminal envelope discontinuity")
                if area == "D":
                    if slot != 0 or record.kind != spec.RecordKind.FINAL:
                        raise ValueError("invalid D placement")
                elif record.kind not in {spec.RecordKind.ITEM, spec.RecordKind.DATA}:
                    raise ValueError("invalid A-C placement")
                scan.terminal[area].append(record)
            except ValueError:
                scan.terminal_torn = True
    return scan


def _decode_structured(record: _Record, semantic: _Semantic) -> dict[str, Any] | None:
    try:
        value = cjson2.loads(record.payload)
    except cjson2.CJSON2Error:
        semantic.encoding_invalid = True
        return None
    try:
        if record.kind == spec.RecordKind.GENESIS:
            _require_keys(value, {"binding"}, "GENESIS")
            _digest(value["binding"], "GENESIS binding")
        elif record.kind == spec.RecordKind.BEGIN:
            _require_keys(value, {"permit"}, "BEGIN")
            _digest(value["permit"], "BEGIN permit")
        elif record.kind == spec.RecordKind.ITEM:
            _require_keys(value, spec.ITEM_FIELDS, "ITEM")
            _digest(value["permit"], "ITEM permit")
            _role(value["role"], "ITEM role")
            _uint(value["category"], "ITEM category", 0, 11)
            if value["encoding"] not in spec.ITEM_ENCODINGS:
                raise _SchemaError("ITEM encoding is invalid")
            if value["schema"] is not None:
                _digest(value["schema"], "ITEM schema")
            length_max = spec.TERMINAL_ITEM_WIRE_MAX if record.area else spec.ORDINARY_ITEM_MAX
            _uint(value["length"], "ITEM length", 0, length_max)
            _digest(value["sha256"], "ITEM digest")
        elif record.kind == spec.RecordKind.END:
            _require_keys(value, {"status", "result"}, "END")
            allowed = {
                ("commit", "success"),
                ("commit", "failure"),
                ("commit", "unresolved"),
                ("abort", "unresolved"),
            }
            if (value["status"], value["result"]) not in allowed:
                raise _SchemaError("END status/result combination is invalid")
        elif record.kind == spec.RecordKind.FINAL:
            _require_keys(
                value,
                {"authority", "outcome", "ordinary_sha256", "abc_sha256", "manifest_sha256"},
                "FINAL",
            )
            _digest(value["authority"], "FINAL authority")
            for name in ("ordinary_sha256", "abc_sha256", "manifest_sha256"):
                _digest(value[name], f"FINAL {name}")
            if value["outcome"] not in {"complete", "failed", "unresolved"}:
                raise _SchemaError("FINAL outcome is invalid")
    except _SchemaError:
        semantic.schema_invalid = True
    return value


def _collect_item(
    records: list[_Record],
    index: int,
    descriptor: dict[str, Any],
    semantic: _Semantic,
) -> tuple[int, bytes, bool]:
    try:
        target = int(descriptor["length"])
    except (KeyError, TypeError, ValueError):
        return index + 1, b"", False
    data = bytearray()
    cursor = index + 1
    while cursor < len(records) and records[cursor].kind == spec.RecordKind.DATA and len(data) < target:
        chunk = records[cursor].payload
        remaining = target - len(data)
        if len(chunk) > remaining:
            semantic.references_invalid = True
        if len(chunk) < remaining:
            maximum = spec.TERMINAL_DATA_MAX if records[cursor].area else spec.ORDINARY_DATA_MAX
            if len(chunk) != maximum:
                semantic.references_invalid = True
        data.extend(chunk)
        cursor += 1
    complete = len(data) == target
    if complete and cursor < len(records) and records[cursor].kind == spec.RecordKind.DATA:
        semantic.references_invalid = True
        while cursor < len(records) and records[cursor].kind == spec.RecordKind.DATA:
            cursor += 1
    if complete and hashlib.sha256(bytes(data)).hexdigest() != descriptor.get("sha256"):
        semantic.references_invalid = True
    if descriptor.get("encoding") == "cjson2" and complete:
        try:
            cjson2.loads(bytes(data))
        except cjson2.CJSON2Error:
            semantic.encoding_invalid = True
    return cursor, bytes(data), complete


def _evaluate_ordinary(
    scan: _PhysicalScan,
    controls: _Controls,
    evidence: Mapping[str, Any],
    semantic: _Semantic,
) -> None:
    records = scan.ordinary
    if not records:
        if controls.bind is not None:
            semantic.tail = "clean_frontier"
            semantic.operation_result = "unresolved"
            return
        semantic.references_invalid = True
        semantic.tail = "ordinary_frozen"
        return
    decoded: dict[int, dict[str, Any] | None] = {}
    for index, record in enumerate(records):
        if record.kind in {
            spec.RecordKind.GENESIS,
            spec.RecordKind.BEGIN,
            spec.RecordKind.ITEM,
            spec.RecordKind.END,
        }:
            decoded[index] = _decode_structured(record, semantic)
    if semantic.encoding_invalid or semantic.schema_invalid:
        semantic.tail = "ordinary_frozen"
        return
    first = records[0]
    if first.kind != spec.RecordKind.GENESIS or first.generation != 0:
        semantic.references_invalid = True
    genesis = decoded.get(0) or {}
    if genesis.get("binding") != controls.bind_digest:
        semantic.references_invalid = True
    bind_permitted = bool(controls.bind and controls.bind.get("genesis_permitted"))
    if not bind_permitted or evidence.get("genesis_approval_bind_digest") != controls.bind_digest:
        semantic.references_invalid = True
    if len(records) < 2 or records[1].kind != spec.RecordKind.END or records[1].generation != 0:
        semantic.references_invalid = True
    else:
        end0 = decoded.get(1) or {}
        if (end0.get("status"), end0.get("result")) != ("commit", "success"):
            semantic.references_invalid = True
    semantic.last_generation = 0
    semantic.last_committed_generation = 0
    semantic.operation_result = "success"
    lifetime_accounts = {name: 0 for name in spec.ORDINARY_ACCOUNTS}
    lifetime_accounts["descriptors_control_framing_padding"] = sum(
        record.physical_length for record in records[:2]
    )
    lifetime_records = min(2, len(records))
    lifetime_items = 0
    aborted_generations = 0

    def maximum_limit(authorization: Mapping[str, Any], field: str) -> int:
        return _maximum_authorization_limit(authorization, field)

    def maximum_account_limit(authorization: Mapping[str, Any], account: str) -> int:
        return _maximum_authorization_account(authorization, account)

    def reservation_fits_remaining(
        authorization: Mapping[str, Any], generation_start: int
    ) -> bool:
        return _authorization_reservation_fits(
            authorization,
            {
                "physical_end": generation_start,
                "record_count": lifetime_records,
                "item_count": lifetime_items,
                "aborted_generations": aborted_generations,
                "accounts": lifetime_accounts,
            },
        )

    def charge_generation(
        authorization: Mapping[str, Any] | None,
        generation_start: int,
        generation_end: int,
        generation_records: int,
        generation_items: int,
        accounts: Mapping[str, int],
    ) -> None:
        nonlocal lifetime_records, lifetime_items
        generation_bytes = generation_end - generation_start
        if authorization is not None:
            if generation_records > maximum_limit(authorization, "ordinary_records"):
                semantic.references_invalid = True
            if generation_items > maximum_limit(authorization, "ordinary_items"):
                semantic.references_invalid = True
            if generation_bytes > maximum_limit(authorization, "ordinary_bytes"):
                semantic.references_invalid = True
            for account, charged in accounts.items():
                if charged > maximum_account_limit(authorization, account):
                    semantic.references_invalid = True
        if generation_records > spec.RECORDS_PER_GENERATION_MAX:
            semantic.references_invalid = True
        if generation_items > spec.ITEMS_PER_GENERATION_MAX:
            semantic.references_invalid = True
        if generation_bytes > spec.ORDINARY_GENERATION_BYTES_MAX:
            semantic.references_invalid = True
        lifetime_records += generation_records
        lifetime_items += generation_items
        for account, charged in accounts.items():
            lifetime_accounts[account] += charged
            if lifetime_accounts[account] > spec.ORDINARY_ACCOUNT_BYTES[account]:
                semantic.references_invalid = True

    used_permits: set[str] = set()
    cursor = 2
    expected_generation = 1
    preceding_status = "commit"
    preceding_result = "success"
    preceding_permit: str | None = controls.bind_digest
    while cursor < len(records):
        begin = records[cursor]
        if begin.kind != spec.RecordKind.BEGIN or begin.generation != expected_generation:
            semantic.references_invalid = True
            break
        begin_value = decoded.get(cursor) or {}
        permit = begin_value.get("permit")
        authorization = controls.authorizations.get(permit)
        if authorization is None or authorization.get("generation") != str(expected_generation):
            semantic.references_invalid = True
        if authorization is not None and not _within_trusted_history(controls, permit):
            semantic.references_invalid = True
        if authorization is not None and not reservation_fits_remaining(
            authorization, begin.offset
        ):
            semantic.references_invalid = True
        if authorization is not None:
            base_value = controls.by_digest.get(authorization.get("base"))
            base_body = (
                base_value.get("body")
                if isinstance(base_value, dict) and isinstance(base_value.get("body"), dict)
                else {}
            )
            disposition_matches = (
                base_value is not None
                and base_value.get("kind") == "CHECKPOINT"
                and base_body.get("authorization") == preceding_permit
                and base_body.get("generation") == str(expected_generation - 1)
                and (
                    (
                        preceding_status == "commit"
                        and base_body.get("disposition") == "admit"
                        and base_body.get("result") == preceding_result
                    )
                    or (
                        preceding_status == "abort"
                        and preceding_result == "unresolved"
                        and base_body.get("disposition") == "abandon"
                    )
                )
            )
            if not disposition_matches:
                semantic.references_invalid = True
        if permit in controls.invalid_authorizations:
            semantic.references_invalid = True
        if permit in used_permits or permit in set(evidence.get("consumed_authorizations", ())):
            semantic.references_invalid = True
        if isinstance(permit, str):
            used_permits.add(permit)
        generation_start = begin.offset
        generation_records = 1
        generation_items = 0
        accounts = {name: 0 for name in spec.ORDINARY_ACCOUNTS}
        accounts["descriptors_control_framing_padding"] += begin.physical_length
        roles_seen: set[str] = set()
        incomplete_item = False
        cursor += 1
        end_value = None
        while cursor < len(records) and records[cursor].generation == expected_generation:
            record = records[cursor]
            if record.kind == spec.RecordKind.END:
                end_value = decoded.get(cursor) or {}
                accounts["descriptors_control_framing_padding"] += record.physical_length
                generation_records += 1
                cursor += 1
                break
            if record.kind != spec.RecordKind.ITEM:
                semantic.references_invalid = True
                cursor += 1
                generation_records += 1
                continue
            descriptor = decoded.get(cursor) or {}
            role_name = descriptor.get("role")
            if role_name in roles_seen:
                semantic.references_invalid = True
            if isinstance(role_name, str):
                roles_seen.add(role_name)
            if descriptor.get("permit") != permit:
                semantic.references_invalid = True
            declarations = {
                role["role"]: role for role in authorization.get("item_roles", [])
            } if authorization else {}
            declaration = declarations.get(role_name)
            if declaration is None:
                semantic.references_invalid = True
                account = "descriptors_control_framing_padding"
            else:
                account = declaration["account"]
                for name in ("category", "encoding", "schema"):
                    if descriptor.get(name) != declaration[name]:
                        semantic.references_invalid = True
                try:
                    if int(descriptor["length"]) > int(declaration["max_length"]):
                        semantic.references_invalid = True
                except (KeyError, TypeError, ValueError):
                    pass
            accounts["descriptors_control_framing_padding"] += record.physical_length
            generation_records += 1
            next_cursor, data, complete = _collect_item(records, cursor, descriptor, semantic)
            for data_record in records[cursor + 1 : next_cursor]:
                generation_records += 1
                accounts["descriptors_control_framing_padding"] += (
                    data_record.physical_length - data_record.payload_length
                )
                if account in accounts:
                    accounts[account] += data_record.payload_length
            if not complete:
                incomplete_item = True
            generation_items += 1
            cursor = next_cursor
        semantic.last_generation = expected_generation
        generation_end = records[cursor - 1].offset + records[cursor - 1].physical_length
        charge_generation(
            authorization,
            generation_start,
            generation_end,
            generation_records,
            generation_items,
            accounts,
        )
        if end_value is None:
            semantic.tail = "incomplete_tail"
            semantic.operation_result = "unresolved"
            break
        status = end_value.get("status")
        result = end_value.get("result")
        if incomplete_item and status == "commit":
            semantic.references_invalid = True
        if status == "commit" and authorization:
            required = set(authorization["required_roles"].get(result, []))
            if not required.issubset(roles_seen):
                semantic.references_invalid = True
            if result not in authorization["outcomes"]:
                semantic.references_invalid = True
        semantic.operation_result = result if result in {"success", "failure", "unresolved"} else "unresolved"
        if status == "abort":
            semantic.tail = "aborted_tail"
            aborted_generations += 1
            if aborted_generations > spec.ABORTED_GENERATIONS_MAX:
                semantic.references_invalid = True
        else:
            semantic.tail = "committed_tail"
            semantic.last_committed_generation = expected_generation
        preceding_status = status
        preceding_result = result
        preceding_permit = permit if isinstance(permit, str) else None
        expected_generation += 1
    if expected_generation > spec.GENERATION_NUMBERS_MAX:
        semantic.references_invalid = True
    if len(records) > spec.ORDINARY_PHYSICAL_ATTEMPTS_MAX:
        semantic.references_invalid = True
    if lifetime_items > spec.ORDINARY_ITEMS_LIFETIME_MAX:
        semantic.references_invalid = True


def _evaluate_terminal(
    image: bytes,
    scan: _PhysicalScan,
    controls: _Controls,
    evidence: Mapping[str, Any],
    semantic: _Semantic,
) -> None:
    semantic.terminal_activity = scan.terminal_activity or bool(evidence.get("uncertain_terminal_attempts"))
    if semantic.terminal_activity and semantic.tail == "incomplete_tail":
        semantic.references_invalid = True
    uncertain = set(evidence.get("uncertain_terminal_attempts", ()))
    if any(scan.terminal[area] for area in uncertain):
        semantic.references_invalid = True
    terminal_first_exception = (
        scan.torn
        or scan.ambiguous
        or scan.frontier >= spec.ORDINARY_LOG_END
    )
    manifests: list[tuple[dict[str, Any], bytes]] = []
    for area in "ABC":
        records = scan.terminal[area]
        cursor = 0
        roles_seen: set[str] = set()
        while cursor < len(records):
            record = records[cursor]
            if record.kind != spec.RecordKind.ITEM:
                semantic.references_invalid = True
                cursor += 1
                continue
            descriptor = _decode_structured(record, semantic)
            if descriptor is None:
                cursor += 1
                continue
            role = descriptor.get("role")
            if role in roles_seen:
                semantic.references_invalid = True
            if isinstance(role, str):
                roles_seen.add(role)
            permit = descriptor.get("permit")
            authorization = controls.authorizations.get(permit)
            if (
                permit in controls.invalid_authorizations
                or not _within_trusted_history(controls, permit)
                or (
                    not controls.ordinary_frozen_before_authorization.get(permit, False)
                    and not terminal_first_exception
                )
            ):
                semantic.references_invalid = True
            candidates = [] if authorization is None else [
                declared
                for declared in authorization["terminal_roles"]
                if declared["area"] == area and declared["role"] == role
            ]
            if not candidates:
                semantic.references_invalid = True
            else:
                if not any(
                    all(descriptor.get(name) == declared[name] for name in ("category", "encoding", "schema"))
                    and int(descriptor["length"]) <= int(declared["max_length"])
                    for declared in candidates
                ):
                    semantic.references_invalid = True
            next_cursor, data, complete = _collect_item(records, cursor, descriptor, semantic)
            if not complete:
                semantic.references_invalid = True
            if authorization:
                covered = False
                for branch in authorization["branches"]:
                    if candidates and branch["branch"] not in {item["branch"] for item in candidates}:
                        continue
                    for reservation in branch["reservations"]:
                        first = int(reservation["first_slot"])
                        last = first + int(reservation["slot_count"])
                        if reservation["area"] == area and first <= record.slot < last and next_cursor <= last:
                            covered = True
                if not covered:
                    semantic.references_invalid = True
            if role == "closing_manifest" and complete:
                try:
                    manifest = cjson2.loads(data)
                    manifests.append((manifest, data))
                except cjson2.CJSON2Error:
                    semantic.encoding_invalid = True
            cursor = next_cursor
    if manifests:
        semantic.terminal_manifest = manifests[-1][0]
        authority = semantic.terminal_manifest.get("authority")
        if not isinstance(authority, str) or not {"A", "B"}.issubset(
            controls.frozen_before_authorization.get(authority, frozenset())
        ):
            semantic.references_invalid = True
        semantic.operation_result = {
            "complete": "success",
            "failed": "failure",
            "unresolved": "unresolved",
        }.get(semantic.terminal_manifest.get("outcome"), "unresolved")
    d_records = scan.terminal["D"]
    if d_records:
        final = _decode_structured(d_records[0], semantic)
        semantic.terminal_final = final
        frozen_c = any(
            body.get("disposition") == "freeze_terminal_area"
            and body.get("area") == "C"
            and _within_trusted_history(controls, digest)
            for digest, body in controls.checkpoints
        )
        if semantic.terminal_manifest is None or not frozen_c:
            semantic.references_invalid = True
        if final and (
            final.get("authority") not in controls.authorizations
            or not _within_trusted_history(controls, final.get("authority"))
        ):
            semantic.references_invalid = True
        elif final:
            authority_index = controls.digests.index(final["authority"])
            for digest in controls.authorizations:
                if controls.digests.index(digest) > authority_index:
                    controls.invalid_authorizations.add(digest)
                    controls.references_invalid = True
                    controls.authority_invalid = True
                    controls.semantic_references_invalid = True
        if final and semantic.terminal_manifest:
            manifest_bytes = manifests[-1][1]
            if final.get("outcome") != semantic.terminal_manifest.get("outcome"):
                semantic.references_invalid = True
            if final.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest():
                semantic.references_invalid = True
            if final.get("ordinary_sha256") != hashlib.sha256(image[: spec.HEADROOM_END]).hexdigest():
                semantic.references_invalid = True
            if final.get("abc_sha256") != hashlib.sha256(
                image[_AREA_STARTS["A"] : _AREA_STARTS["D"]]
            ).hexdigest():
                semantic.references_invalid = True
            semantic.operation_result = {
                "complete": "success",
                "failed": "failure",
                "unresolved": "unresolved",
            }.get(final.get("outcome"), "unresolved")


def _commitment_status(image: bytes, controls: _Controls) -> tuple[str, bool]:
    checkpoint = controls.trusted_checkpoint
    if not checkpoint or not isinstance(checkpoint.get("state"), dict):
        return "not_established", False
    state = checkpoint["state"]
    admitted = state.get("admitted", {})
    generation = admitted.get("generation")
    if generation is None:
        admitted_status = "not_applicable"
    else:
        try:
            end = int(admitted["end"])
            admitted_status = (
                "valid"
                if hashlib.sha256(image[:end]).hexdigest() == admitted["prefix_sha256"]
                else "invalid"
            )
        except (KeyError, TypeError, ValueError):
            admitted_status = "invalid"
    frozen_mismatch = False
    ordinary = state.get("ordinary", {})
    if ordinary.get("mode") == "frozen":
        frozen_mismatch |= hashlib.sha256(image[: spec.HEADROOM_END]).hexdigest() != ordinary.get(
            "region_sha256"
        )
    for area, entry in zip("ABCD", state.get("terminal", [])):
        if isinstance(entry, dict) and entry.get("mode") == "frozen":
            frozen_mismatch |= hashlib.sha256(
                image[_AREA_STARTS[area] : _AREA_ENDS[area]]
            ).hexdigest() != entry.get("area_sha256")
    disposition = checkpoint.get("disposition")
    if isinstance(disposition, str) and (disposition.startswith("final_") or disposition == "freeze_f"):
        frozen_mismatch |= hashlib.sha256(image).hexdigest() != checkpoint.get("file_sha256")
    return admitted_status, frozen_mismatch


def _authority(controls: _Controls, evidence: Mapping[str, Any]) -> str:
    trusted = evidence.get("trusted_current_control")
    supplied = evidence.get("control_reference")
    if trusted is None:
        return "not_established"
    if controls.authority_invalid:
        return "invalid"
    if supplied == trusted and supplied in controls.digests:
        return "current"
    if supplied in controls.digests and trusted in controls.digests:
        if controls.digests.index(supplied) < controls.digests.index(trusted):
            return "historical_only"
    return "invalid"


def _custody(evidence: Mapping[str, Any]) -> tuple[str, bool | None]:
    expected = evidence.get("expected_identity")
    observed = evidence.get("observed_identity")
    identity_matches = None if expected is None or observed is None else expected == observed
    custody = evidence.get("custody_evidence")
    writer_closed = evidence.get("writer_closed")
    if identity_matches is False or custody is False or writer_closed is False:
        return "invalid", identity_matches
    if identity_matches is None or custody is None or writer_closed is None:
        return "not_established", identity_matches
    return "valid", identity_matches


def _validation(controls: _Controls, semantic: _Semantic, physical_blocked: bool) -> dict[str, str]:
    if physical_blocked:
        return {"encoding": "not_checked", "schema": "not_checked", "references": "not_checked"}
    if controls.encoding_invalid or semantic.encoding_invalid:
        return {"encoding": "invalid", "schema": "not_checked", "references": "not_checked"}
    if controls.schema_invalid or semantic.schema_invalid:
        return {"encoding": "valid", "schema": "invalid", "references": "not_checked"}
    if controls.references_invalid or semantic.references_invalid:
        return {"encoding": "valid", "schema": "valid", "references": "invalid"}
    return {"encoding": "valid", "schema": "valid", "references": "valid"}


def verify_f(image: bytes, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Verify one supplied synthetic/in-memory F image and supplied evidence."""

    if not isinstance(image, bytes):
        raise TypeError("F image must be supplied as exact bytes")
    if not isinstance(evidence, Mapping):
        raise TypeError("verification evidence must be a mapping")
    controls = _load_controls(evidence)
    _establish_trusted_lifecycle(controls, evidence)
    scan = _scan_image(image)
    semantic = _Semantic()
    if not scan.malformed_size:
        _validate_authorizations_at_control_time(image, scan, controls, evidence)
    if not scan.malformed_size and not scan.torn and not scan.ambiguous:
        _evaluate_ordinary(scan, controls, evidence, semantic)
    if not scan.malformed_size and not scan.terminal_torn and not scan.terminal_ambiguous:
        _evaluate_terminal(image, scan, controls, evidence, semantic)
    latest_disposition = (
        controls.trusted_checkpoint.get("disposition") if controls.trusted_checkpoint else None
    )
    if latest_disposition == "final_complete":
        if (
            semantic.terminal_manifest is None
            or semantic.terminal_final is None
            or semantic.terminal_manifest.get("outcome") != "complete"
            or semantic.terminal_final.get("outcome") != "complete"
        ):
            semantic.references_invalid = True
    authority = _authority(controls, evidence)
    custody, identity_matches = _custody(evidence)
    admitted, frozen_mismatch = (
        ("not_established", False)
        if scan.malformed_size
        else _commitment_status(image, controls)
    )
    if identity_matches is False or authority == "not_established":
        admitted = "not_established"
    if admitted == "valid" and controls.trusted_checkpoint is not None:
        admitted_state = controls.trusted_checkpoint.get("state", {}).get("admitted", {})
        try:
            if (
                admitted_state.get("generation") is not None
                and int(admitted_state["generation"]) == semantic.last_committed_generation
                and int(admitted_state["end"]) == scan.frontier
            ):
                semantic.tail = "clean_frontier"
        except (KeyError, TypeError, ValueError):
            pass
    commitment_invalid = admitted == "invalid" or frozen_mismatch
    malformed = scan.malformed_size or scan.headroom_nonzero
    framing_torn = scan.torn or scan.terminal_torn
    framing_ambiguous = scan.ambiguous or scan.terminal_ambiguous
    physical_blocked = malformed or framing_torn or framing_ambiguous or commitment_invalid
    validation = _validation(controls, semantic, physical_blocked)
    semantic_invalid = (
        controls.encoding_invalid
        or controls.schema_invalid
        or controls.semantic_references_invalid
        or semantic.encoding_invalid
        or semantic.schema_invalid
        or semantic.references_invalid
    )
    if malformed or commitment_invalid:
        integrity = "invalid"
    elif framing_ambiguous:
        integrity = "blocked_ambiguous"
    elif framing_torn:
        integrity = "blocked_torn"
    elif semantic_invalid:
        integrity = "invalid"
    else:
        integrity = "valid"
    final_disposition = isinstance(latest_disposition, str) and latest_disposition.startswith("final_")
    terminal_activity = semantic.terminal_activity or scan.terminal_activity
    if malformed:
        physical_state = "malformed_size_or_state"
    elif final_disposition and integrity == "valid":
        physical_state = "finalized"
    elif (
        terminal_activity
        or final_disposition
        or latest_disposition in {"freeze_terminal_area", "freeze_f"}
        or scan.terminal_torn
        or scan.terminal_ambiguous
    ):
        physical_state = "terminal_frozen"
    elif latest_disposition == "freeze_ordinary":
        physical_state = "ordinary_frozen"
    elif integrity != "valid":
        physical_state = "ordinary_frozen"
    else:
        physical_state = semantic.tail
    operation_result = semantic.operation_result
    if evidence.get("uncertain_terminal_attempts"):
        operation_result = "unresolved"
    if final_disposition:
        if latest_disposition == "final_complete":
            operation_result = "success"
        elif latest_disposition == "final_unresolved":
            operation_result = "unresolved"
        elif latest_disposition == "final_failed" and operation_result != "failure":
            operation_result = "unresolved"
    if integrity != "valid" and custody == "valid":
        operation_result = "unresolved"
    synchronized = evidence.get("synchronized")
    closed_complete = physical_state not in {"incomplete_tail", "terminal_frozen"} or (
        physical_state == "terminal_frozen" and semantic.terminal_final is not None
    )
    if (
        integrity == "valid"
        and custody == "valid"
        and evidence.get("writer_closed") is True
        and synchronized is True
        and evidence.get("trusted_current_control") is not None
        and closed_complete
        and not evidence.get("uncertain_terminal_attempts")
    ):
        durability = "established"
    else:
        durability = "not_established"
    if custody != "valid":
        progression = "blocked_custody"
    elif authority != "current":
        progression = "blocked_authority"
    elif commitment_invalid:
        progression = "blocked_integrity"
    elif (
        final_disposition
        and controls.schema_invalid is False
        and controls.authority_invalid is False
        and controls.semantic_references_invalid is False
        and semantic.references_invalid is False
    ):
        progression = "final"
    elif integrity != "valid" or admitted == "invalid":
        progression = "blocked_integrity"
    elif physical_state in {
        "incomplete_tail",
        "aborted_tail",
        "ordinary_frozen",
        "terminal_frozen",
    } or operation_result in {
        "failure",
        "unresolved",
    }:
        progression = "blocked_pending_disposition"
    else:
        progression = "eligible_for_chair_consideration"
    subject = {
        "specification": evidence.get("specification_digest"),
        "binding": evidence.get("binding_digest"),
        "control": evidence.get("control_reference"),
        "file_sha256": hashlib.sha256(image).hexdigest(),
        "identity_matches": identity_matches,
    }
    result = {
        "schema": RESULT_SCHEMA,
        "subject": subject,
        "integrity": integrity,
        "physical_state": physical_state,
        "durability": durability,
        "authority": authority,
        "custody": custody,
        "admitted_prefix": admitted,
        "operation_result": operation_result,
        "progression": progression,
        "validation": validation,
    }
    _validate_result(result)
    return result


def _validate_result(result: Mapping[str, Any]) -> None:
    if set(result) != RESULT_FIELDS or result.get("schema") != RESULT_SCHEMA:
        raise ValueError("verifier result does not match the closed result schema")
    subject = result.get("subject")
    if not isinstance(subject, dict) or set(subject) != SUBJECT_FIELDS:
        raise ValueError("verifier subject does not match the closed subject schema")
    _digest(subject["specification"], "result specification")
    _digest(subject["binding"], "result binding")
    _digest(subject["control"], "result control", nullable=True)
    _digest(subject["file_sha256"], "result file digest", nullable=True)
    if subject["identity_matches"] not in {True, False, None}:
        raise ValueError("result identity_matches is not tri-state")
    for field_name, vocabulary in RESULT_ENUMS.items():
        if field_name == "validation":
            validation = result[field_name]
            if not isinstance(validation, dict) or set(validation) != VALIDATION_FIELDS:
                raise ValueError("result validation object is not closed")
            if any(value not in vocabulary for value in validation.values()):
                raise ValueError("result validation vocabulary is invalid")
        elif result[field_name] not in vocabulary:
            raise ValueError(f"result {field_name} vocabulary is invalid")


def encode_result(result: Mapping[str, Any]) -> bytes:
    """Validate and encode one closed verifier result as canonical CJSON2."""

    _validate_result(result)
    return cjson2.dumps(dict(result))


# M0-1: Python evidence adapter, not an additional F/Q wire schema.
# The operation's map/acquisition/composite schemas are external inputs.  A
# trusted external map attestation binds its exact bytes AND the normalized
# declarations used below.  This module never interprets Q as authority.
_Q_RECEIPT_KEYS = {
    "format", "map", "binding", "lifecycle", "authorization", "producer",
    "writer", "encoding", "schema", "length", "sha256", "completeness",
}
_Q_LIFECYCLE_RE = re.compile(r"\A[0-9a-f]{32}\Z", re.ASCII)
_Q_DECLARATION_KEYS = {
    "number", "offset", "capacity", "role", "category", "account", "operation",
    "branch", "acquisition", "authorization", "producer", "writer", "encoding",
    "schema", "required_complete", "dependencies",
}
_Q_TRACE = (
    "validate", "zero", "payload", "payload_fsync", "receipt",
    "receipt_fsync", "readback", "close",
)


def compute_q_checksum(
    capture: int, offset: int, capacity: int, cell: bytes, payload: bytes,
    map_digest: str, binding_digest: str, lifecycle: str,
) -> bytes:
    """Amendment §5 preimage, independently assembled; no writer dependency."""
    if type(capture) is not int or not 0 <= capture < 108:
        raise ValueError("unassigned capture")
    if type(offset) is not int or type(capacity) is not int or offset < 0 or capacity < 0:
        raise ValueError("invalid extent")
    if not isinstance(cell, bytes) or len(cell) != 1024:
        raise ValueError("incomplete cell")
    if not isinstance(payload, bytes) or len(payload) > capacity:
        raise ValueError("invalid payload")
    _digest(map_digest, "Q map")
    _digest(binding_digest, "Q binding")
    if not isinstance(lifecycle, str) or not _Q_LIFECYCLE_RE.fullmatch(lifecycle):
        raise ValueError("invalid lifecycle")
    preimage = (
        b"MCL-D0009-M0-CAPTURE-1A\x00"
        + bytes.fromhex(map_digest) + bytes.fromhex(binding_digest)
        + bytes.fromhex(lifecycle) + struct.pack("<IQQ", capture, offset, capacity)
        + cell[:16] + bytes(32) + cell[48:] + payload
    )
    return hashlib.sha256(preimage).digest()


def _q_reference(evidence, reference, *, before=None, current=False):
    _digest(reference, "external reference")
    value = evidence.get("references", {}).get(reference)
    if not isinstance(value, Mapping) or value.get("established") is not True:
        raise _ReferenceError("unestablished external reference")
    if current and value.get("current") is not True:
        raise _ReferenceError("external reference is not current")
    if before is not None and (
        type(value.get("order")) is not int or value["order"] >= before
    ):
        raise _ReferenceError("reference does not predate capture")
    return value


def _q_schema(value, rule, depth=0):
    """Apply a supplied closed shape; this is an input adapter, not a wire DSL.

    Shape nodes use type=object/array/string/uint/digest/boolean/null/enum.
    Object fields are exact; array limits and string maxima are supplied.
    Its exact CJSON2 bytes must hash to the map's approved schema digest.
    """
    if depth > 8 or not isinstance(rule, dict):
        raise _SchemaError("missing or excessively nested payload schema")
    kind = rule.get("type")
    if kind == "object":
        _require_keys(rule, {"type", "fields"}, "shape")
        fields = rule["fields"]
        if not isinstance(fields, dict) or len(fields) > 64:
            raise _SchemaError("invalid closed shape")
        _require_keys(value, set(fields), "Q payload")
        for key, child in fields.items():
            _q_schema(value[key], child, depth + 1)
    elif kind == "array":
        _require_keys(rule, {"type", "items", "max"}, "shape")
        if not isinstance(value, list) or len(value) > _uint(rule["max"], "array max"):
            raise _SchemaError("payload array")
        for child in value:
            _q_schema(child, rule["items"], depth + 1)
    elif kind in ("string", "uint"):
        _require_keys(rule, {"type", "max"}, "shape")
        maximum = _uint(rule["max"], "shape max")
        if kind == "uint":
            _uint(value, "payload integer", maximum=maximum)
        elif not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
            raise _SchemaError("payload string")
    elif kind == "digest":
        _require_keys(rule, {"type"}, "shape")
        _digest(value, "payload digest")
    elif kind == "boolean":
        _require_keys(rule, {"type"}, "shape")
        if type(value) is not bool:
            raise _SchemaError("payload boolean")
    elif kind == "null":
        _require_keys(rule, {"type"}, "shape")
        if value is not None:
            raise _SchemaError("payload null")
    elif kind == "enum":
        _require_keys(rule, {"type", "values"}, "shape")
        if not isinstance(rule["values"], list) or value not in rule["values"]:
            raise _SchemaError("payload enum")
    else:
        raise _SchemaError("unsupported supplied payload shape")


def _q_map(evidence):
    raw, view = evidence.get("map_bytes"), evidence.get("map_view")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 65_536:
        raise _ReferenceError("missing/oversized approved map")
    if not isinstance(view, list) or len(view) != 108:
        raise _ReferenceError("missing exact map projection")
    digest = hashlib.sha256(raw).hexdigest()
    attestation = _q_reference(evidence, evidence.get("map_attestation"), current=True)
    if (attestation.get("map") != digest or attestation.get("projection") !=
            hashlib.sha256(cjson2.dumps({"captures": view})).hexdigest()):
        raise _ReferenceError("unbound map projection")
    binding = _q_reference(evidence, evidence.get("binding"), current=True)
    lifecycle = evidence.get("lifecycle")
    if not isinstance(lifecycle, str) or not _Q_LIFECYCLE_RE.fullmatch(lifecycle):
        raise _ReferenceError("missing lifecycle")
    if (binding.get("map") != digest or binding.get("lifecycle") != lifecycle
            or binding.get("size") != 3_145_728
            or binding.get("object") != evidence.get("object")
            or not binding.get("object") or not binding.get("parent")
            or binding.get("creation_custody_established") is not True
            or attestation.get("immutable") is not True):
        raise _ReferenceError("Q binding mismatch")
    for number, (entry, extent) in enumerate(zip(view, spec.Q_CAPTURES)):
        _require_keys(entry, _Q_DECLARATION_KEYS, "normalized map declaration")
        if (_uint(entry["number"], "capture") != number
                or _uint(entry["offset"], "offset") != extent.offset
                or _uint(entry["capacity"], "capacity") != extent.capacity
                or entry["role"] != spec.Q_CAPTURE_ROLES[number]):
            raise _ReferenceError("immutable capture assignment mismatch")
        _uint(entry["category"], "category", maximum=11)
        if entry["account"] not in spec.ORDINARY_ACCOUNT_BYTES:
            raise _SchemaError("unknown account")
        for key in ("operation", "acquisition", "authorization", "producer", "writer"):
            _digest(entry[key], key)
        _role(entry["branch"], "branch")
        if entry["encoding"] not in ("raw", "cjson2"):
            raise _SchemaError("unknown encoding")
        _digest(entry["schema"], "schema", nullable=entry["encoding"] == "raw")
        if type(entry["required_complete"]) is not bool:
            raise _SchemaError("missing completeness requirement")
        if not isinstance(entry["dependencies"], list):
            raise _SchemaError("missing dependencies")
        deps = [_uint(n, "dependency", maximum=107) for n in entry["dependencies"]]
        if len(set(deps)) != len(deps) or number in deps:
            raise _ReferenceError("invalid dependency set")
    return digest, view


def _q_physical(image, number, entry, evidence, map_digest):
    extent = spec.Q_CAPTURES[number]
    start, capacity = extent.offset, extent.capacity
    result = {"physical_state": "INVALID", "dispatch": "uncertain",
              "closure": "not_established", "usable": False, "errors": []}
    if not isinstance(image, bytes) or len(image) != 3_145_728:
        result["errors"].append("unreadable_or_wrong_size")
        return result, None, b"", b""
    cell = image[number * 1024:(number + 1) * 1024]
    payload_extent = image[start:start + capacity]
    if not any(cell):
        result["physical_state"] = "ORPHAN" if any(payload_extent) else "EMPTY"
        return result, None, cell, payload_extent
    try:
        magic, physical_number, length = struct.unpack("<8sII", cell[:16])
        if magic != b"D9M0CAP\x00" or physical_number != number or not 0 < length <= 976:
            raise _SchemaError("invalid receipt header")
        if any(cell[48 + length:]):
            raise _SchemaError("nonzero receipt padding")
        receipt = cjson2.loads(cell[48:48 + length])
        _require_keys(receipt, _Q_RECEIPT_KEYS, "Q receipt")
        if receipt["format"] != "mcl-d0009-q1a":
            raise _SchemaError("receipt format")
        for key in ("map", "binding", "authorization", "producer", "writer", "sha256"):
            _digest(receipt[key], key)
        if not isinstance(receipt["lifecycle"], str) or not _Q_LIFECYCLE_RE.fullmatch(receipt["lifecycle"]):
            raise _SchemaError("receipt lifecycle")
        if receipt["encoding"] not in ("raw", "cjson2"):
            raise _SchemaError("receipt encoding")
        _digest(receipt["schema"], "schema", nullable=receipt["encoding"] == "raw")
        if receipt["completeness"] not in ("complete", "partial", "unresolved"):
            raise _SchemaError("receipt completeness")
        claimed = _uint(receipt["length"], "payload length", maximum=capacity)
        payload = payload_extent[:claimed]
        if any(payload_extent[claimed:]):
            raise _SchemaError("nonzero unused extent suffix")
        if receipt["sha256"] != hashlib.sha256(payload).hexdigest():
            raise _SchemaError("payload digest")
        if (receipt["map"] != map_digest or receipt["binding"] != evidence.get("binding")
                or receipt["lifecycle"] != evidence.get("lifecycle")):
            raise _ReferenceError("receipt object/map/lifecycle binding")
        if entry is None:
            raise _ReferenceError("unestablished map")
        for key in ("authorization", "producer", "writer", "encoding", "schema"):
            if receipt[key] != entry[key]:
                raise _ReferenceError("receipt declaration binding")
        expected = compute_q_checksum(number, start, capacity, cell, payload,
                                      map_digest, evidence["binding"], evidence["lifecycle"])
        if expected != cell[16:48]:
            raise _SchemaError("receipt checksum")
        if receipt["schema"] is not None:
            raw_schema = evidence.get("schemas", {}).get(receipt["schema"])
            if not isinstance(raw_schema, bytes) or hashlib.sha256(raw_schema).hexdigest() != receipt["schema"]:
                raise _SchemaError("missing exact approved payload schema")
            # Partial raw prefixes are retained without claiming schema compliance.
            if receipt["completeness"] == "complete":
                if receipt["encoding"] != "cjson2":
                    raise _SchemaError("opaque raw schema needs external acquisition-specific validation")
                _q_schema(cjson2.loads(payload), cjson2.loads(raw_schema))
        elif receipt["encoding"] == "cjson2":
            raise _SchemaError("structured payload without approved schema")
        result["physical_state"] = "RECEIPTED_" + receipt["completeness"].upper()
        return result, receipt, cell, payload
    except (ValueError, TypeError, KeyError, OverflowError, struct.error) as exc:
        result["errors"].append(str(exc))
        return result, None, cell, payload_extent


def _q_capture_evidence(number, entry, state, receipt, evidence):
    """Qualify dispatch, ordering and closure without observing the host."""
    observation = evidence.get("captures", {}).get(number, {})
    if not isinstance(observation, Mapping):
        observation = {}
    try:
        proof = _q_reference(evidence, observation.get("reference"), current=True)
        if (proof.get("capture") != number or proof.get("map") != evidence.get("map_digest")
                or proof.get("binding") != evidence.get("binding")
                or proof.get("lifecycle") != evidence.get("lifecycle")):
            raise _ReferenceError("unbound capture evidence")
        dispatch = proof.get("dispatch")
        if dispatch not in ("dispatched", "not_dispatched", "uncertain"):
            raise _ReferenceError("dispatch not established")
        state["dispatch"] = dispatch
        if number in (100, 101, 102) and dispatch != "not_dispatched":
            raise _ReferenceError("W/work is not eligible")
        if dispatch == "not_dispatched":
            if state["physical_state"] != "EMPTY":
                raise _ReferenceError("bytes contradict proven non-dispatch")
            state["closure"] = "not_applicable"
            return
        if dispatch != "dispatched" or receipt is None or entry is None:
            raise _ReferenceError("dispatched/uncertain capture lacks usable evidence")
        order = proof.get("order")
        if type(order) is not int:
            raise _ReferenceError("missing capture ordering")
        for key in ("authorization", "producer", "writer", "operation", "acquisition"):
            _q_reference(evidence, entry[key], before=order, current=True)
        if proof.get("branch") != entry["branch"]:
            raise _ReferenceError("wrong authorized branch")
        for key in ("authority", "identity", "custody", "map", "reservations", "f_closed"):
            if proof.get("checks", {}).get(key) is not True:
                raise _ReferenceError("capture precondition: " + key)
        extent = spec.Q_CAPTURES[number]
        if proof.get("zero_cell") != bytes(1024) or proof.get("zero_extent") != bytes(extent.capacity):
            raise _ReferenceError("whole capture target not proven zero")
        if proof.get("trace") != list(_Q_TRACE):
            raise _ReferenceError("capture ordering/synchronization/closure unproven")
        if (proof.get("readback_cell_sha256") != observation.get("cell_sha256")
                or state.get("observation_mismatch")):
            raise _ReferenceError("receipt/payload readback mismatch")
        if proof.get("readback_payload_sha256") != receipt["sha256"]:
            raise _ReferenceError("payload readback mismatch")
        if proof.get("payload_written") != int(receipt["length"]) or proof.get("receipt_written") != 1024:
            raise _ReferenceError("short/uncertain write")
        if proof.get("io_uncertain") is not False:
            raise _ReferenceError("write/synchronization outcome uncertain")
        state["closure"] = "established"
        state["usable"] = receipt["completeness"] == "complete" or not entry["required_complete"]
    except (ValueError, TypeError, KeyError) as exc:
        state["errors"].append(str(exc))
        if receipt is not None:
            state["closure"] = "closure_unproven"


def _q_history(evidence, states, declarations):
    errors = []
    history = evidence.get("history")
    if not isinstance(history, list):
        return ["missing lifecycle history"], True
    seen, frozen = set(), evidence.get("prior_freeze") is not False
    closed_at = {}
    previous_order = -1
    for event in history:
        if not isinstance(event, Mapping):
            errors.append("malformed history")
            frozen = True
            continue
        number, order = event.get("capture"), event.get("order")
        if type(number) is not int or not 0 <= number < 108 or type(order) is not int or order <= previous_order:
            errors.append("invalid capture history/order")
            frozen = True
            continue
        previous_order = order
        if frozen or number in seen or number in (100, 101, 102):
            errors.append("capture after freeze, reuse, or prohibited assignment")
            frozen = True
        seen.add(number)
        state = states[number]
        observation = evidence.get("captures", {}).get(number, {})
        proof = evidence.get("references", {}).get(observation.get("reference"), {})
        if state["dispatch"] != "dispatched" or proof.get("order") != order:
            errors.append("history/dispatch disagreement")
            frozen = True
        entry = declarations[number] if declarations else None
        if entry is not None:
            for dependency in entry["dependencies"]:
                dep = int(dependency)
                if dep not in closed_at or closed_at[dep] >= order or not states[dep]["usable"]:
                    errors.append("intent/dependency not closed before dispatch")
                    frozen = True
        if state["closure"] == "established":
            closed_at[number] = order
        else:
            frozen = True
        if state["physical_state"] in ("ORPHAN", "INVALID"):
            frozen = True
    for number, state in states.items():
        if state["dispatch"] == "dispatched" and number not in seen:
            errors.append("dispatched capture missing from history")
            frozen = True
    return errors, frozen


def _q_build_and_j(evidence, states):
    errors = []
    def capture_scope_matches(reference, numbers):
        expected = [(number, evidence["captures"][number]["payload_sha256"])
                    for number in numbers if states[number]["dispatch"] == "dispatched"]
        return reference.get("capture_scope") == expected
    build = evidence.get("build")
    if any(states[n]["dispatch"] == "dispatched" for n in range(3, 12)):
        if not isinstance(build, Mapping):
            errors.append("missing original build evidence")
        else:
            try:
                reference = _q_reference(evidence, build.get("reference"), current=True)
                if reference.get("binding") != evidence.get("binding") or reference.get("kind") != "build":
                    raise _ReferenceError("unbound build evidence")
                if not capture_scope_matches(reference, range(3, 12)):
                    raise _ReferenceError("build projection does not bind exact Q capture bytes")
                for key in ("compile_attempts", "link_attempts"):
                    if (key not in reference or key not in build
                            or type(reference[key]) is not int or type(build[key]) is not int
                            or reference[key] != build[key]):
                        raise _ReferenceError("missing/contradictory trusted build fact: " + key)
                compile_success = build.get("compile_status") == {"kind": "exit", "value": 0}
                if reference.get("compile_status") != build.get("compile_status"):
                    raise _ReferenceError("original compile status changed")
                linked = any(states[n]["dispatch"] == "dispatched" for n in range(6, 12))
                if linked and not compile_success:
                    raise _ReferenceError("failed/abnormal compile prevents link")
                if build.get("compile_attempts") != 1 or build.get("link_attempts") != int(linked):
                    raise _ReferenceError("build replay/retry")
                for name in ("stdout", "stderr"):
                    stream = build[name]
                    data, end = stream["bytes"], stream["compile_end"]
                    if (not isinstance(data, bytes) or len(data) > 32768
                            or type(end) is not int or not 0 <= end <= len(data)
                            or stream.get("start") != 0
                            or hashlib.sha256(data[:end]).hexdigest() != stream["compile_sha256"]
                            or stream["compile_sha256"] != reference.get(name + "_compile_sha256")):
                        raise _ReferenceError("compile stream prefix/boundary mismatch")
                    if linked:
                        if (stream.get("link_start") != end or stream.get("final_end") != len(data)
                                or hashlib.sha256(data).hexdigest() != stream.get("final_sha256")
                                or reference.get(name + "_final_sha256") != stream.get("final_sha256")):
                            raise _ReferenceError("link stream boundary/digest mismatch")
                    elif len(data) != end:
                        raise _ReferenceError("post-failure stream append")
                if linked and reference.get("link_status") != build.get("link_status"):
                    raise _ReferenceError("original link status changed")
            except (ValueError, TypeError, KeyError) as exc:
                errors.append(str(exc))
    journal = evidence.get("j")
    if any(states[n]["dispatch"] == "dispatched" for n in range(13, 19)) or journal is not None:
        try:
            if not isinstance(journal, Mapping):
                raise _ReferenceError("missing independent J bootstrap evidence")
            ref = _q_reference(evidence, journal.get("reference"), current=True)
            if ref.get("binding") != evidence.get("binding") or ref.get("kind") != "journal":
                raise _ReferenceError("unbound J evidence")
            if not capture_scope_matches(ref, range(13, 19)):
                raise _ReferenceError("J comparison does not bind exact Q capture bytes")
            for key, kind in (("bootstrap_source", str), ("conflict", bool),
                              ("reopened", bool), ("active_j_intents_duplicated_in_q", bool)):
                if (key not in ref or key not in journal or type(ref[key]) is not kind
                        or type(journal[key]) is not kind or ref[key] != journal[key]):
                    raise _ReferenceError("missing/contradictory trusted J fact: " + key)
            if journal.get("bootstrap_source") not in ("original_acquisition", "authorized_bootstrap_source"):
                raise _ReferenceError("J bootstrap cannot derive from Q")
            if (journal.get("bootstrap_bytes") != journal.get("independent_bytes")
                    or not isinstance(journal.get("bootstrap_bytes"), bytes)
                    or ref.get("bootstrap_sha256") != hashlib.sha256(journal["bootstrap_bytes"]).hexdigest()
                    or journal.get("conflict") is not False):
                raise _ReferenceError("J/Q conflict or unproved independent source")
            if ref["reopened"] is not False:
                raise _ReferenceError("J cannot reopen")
            if journal.get("active_j_intents_duplicated_in_q") is not False:
                raise _ReferenceError("J/Q intent duplication")
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(str(exc))
    return errors


def _q_cleanup(evidence, states, physical, declarations, frozen):
    """Preserve each evaluation; factual dispatch never grants permission.

    Each target maps to an ordered list of the existing result objects. This
    in-memory report container introduces no F/Q wire field or disposition.
    """
    results, seen_targets, seen_captures = {}, set(), set()

    def closed_order(capture, label, *, before=None):
        state = states[capture]
        if (state["dispatch"] != "dispatched" or state["closure"] != "established"
                or not state["usable"]):
            raise _ReferenceError(label + " capture not established/closed")
        observation = evidence["captures"][capture]
        reference = _q_reference(evidence, observation.get("reference"),
                                 before=before, current=True)
        if type(reference.get("order")) is not int:
            raise _ReferenceError(label + " capture lacks chronology")
        return reference["order"]

    for action in evidence.get("cleanup", []):
        target = action.get("target")
        if not isinstance(target, str):
            target = "invalid_target_" + str(len(results))
        result = {"dispatch": "uncertain", "errors": [], "absence_established": False}
        results.setdefault(target, []).append(result)
        if target in seen_targets:
            result["errors"].append("second cleanup action/target reuse is prohibited")
        seen_targets.add(target)
        number, proof, claim = None, None, None
        predicate_errors = []
        failed_observation_preserved = False
        result_order = None
        try:
            if target not in spec.Q_CLEANUP_TARGETS:
                raise _ReferenceError("ineligible cleanup target")
            number = 47 + 3 * spec.Q_CLEANUP_TARGETS.index(target)
            reused = number in seen_captures
            seen_captures.add(number)
            proof = _q_reference(evidence, action.get("reference"), current=True)
            claimed_capture = proof.get("capture")
            if type(claimed_capture) is int:
                reused |= claimed_capture != number and claimed_capture in seen_captures
                seen_captures.add(claimed_capture)
            if reused:
                result["errors"].append("cleanup result capture reuse is prohibited")
            if (proof.get("binding") != evidence.get("binding") or proof.get("target") != target
                    or claimed_capture != number):
                raise _ReferenceError("unbound cleanup evidence")
            # Preserve attested facts before evaluating whether dispatch was valid.
            claim = proof.get("dispatch")
            if claim != "not_dispatched" and "original_status" in proof:
                result["original_status"] = proof["original_status"]
            if claim == "dispatched":
                result["dispatch"] = "dispatched"
                if "original_status" not in proof:
                    result["errors"].append("dispatched action lacks original status")
            elif claim != "not_dispatched":
                result["errors"].append("cleanup dispatch is uncertain")
            raw = action.get("composite")
            if not isinstance(raw, bytes) or len(raw) > 1024 or not raw:
                raise _ReferenceError("composite does not fit assigned result")
            if (declarations is None or not states[number]["usable"]
                    or physical[number][2] != raw
                    or declarations[number]["schema"] != action.get("schema")):
                raise _ReferenceError("composite differs from bound result capture")
            if proof.get("composite_sha256") != hashlib.sha256(raw).hexdigest():
                raise _ReferenceError("composite projection not bound")
            schema_digest = action.get("schema")
            _digest(schema_digest, "composite schema")
            schema = evidence.get("schemas", {}).get(schema_digest)
            if not isinstance(schema, bytes) or hashlib.sha256(schema).hexdigest() != schema_digest:
                raise _ReferenceError("missing exact composite schema")
            _q_schema(cjson2.loads(raw), cjson2.loads(schema))
            if proof.get("schema") != schema_digest:
                raise _ReferenceError("wrong composite schema binding")
            local = proof.get("local_observation_bytes")
            if (not isinstance(local, bytes) or not local
                    or local.hex() not in raw.decode("utf-8")):
                raise _ReferenceError("required local observations not preserved in composite")
            failed_observation_preserved = proof.get("all_preconditions_passed") is False

            if frozen:
                result["errors"].append("Q freeze blocks post-handoff cleanup")
            if target == "W/work":
                predicate_errors.append("ineligible cleanup target W/work")
            for key in ("f_admitted_target", "checkpoint", "specific_chair_authority",
                        "f_closed", "no_remaining_required_use", "fresh_identity_custody"):
                if proof.get(key) is not True:
                    predicate_errors.append("cleanup precondition: " + key)
            if target in ("O", "I/private", "I", "P") and proof.get("fresh_population") is not True:
                predicate_errors.append("missing immediately preceding population evidence")

            # Capture-order evidence is independent of result/dispatch interpretation.
            try:
                result_order = closed_order(number, "result")
                closed_order(number - 1, "intent", before=result_order)
                for reference in (evidence.get("binding"), evidence.get("map_attestation")):
                    _q_reference(evidence, reference, before=result_order, current=True)
            except (ValueError, TypeError, KeyError) as exc:
                result["errors"].append(str(exc))

            if target in ("temporary_account", "temporary_group"):
                try:
                    references = proof.get("eligibility")
                    if not isinstance(references, list) or not references:
                        raise _ReferenceError("missing capture 103/104 reference")
                    for ref in references:
                        if not isinstance(ref, Mapping):
                            raise _ReferenceError("malformed cleanup eligibility reference")
                        capture = ref.get("capture")
                        if type(capture) is not int or capture not in (103, 104):
                            raise _ReferenceError("incomplete cleanup eligibility capture")
                        if result_order is None:
                            raise _ReferenceError("cleanup result chronology unestablished")
                        closed_order(capture, "eligibility", before=result_order)
                        if (ref.get("binding") != evidence.get("binding")
                                or ref.get("map") != evidence.get("map_digest")
                                or ref.get("lifecycle") != evidence.get("lifecycle")
                                or ref.get("fresh") is not True or ref.get("conflict") is not False
                                or ref.get("sha256") != evidence["captures"][capture].get("payload_sha256")):
                            raise _ReferenceError("stale/conflicting cleanup eligibility reference")
                except (ValueError, TypeError, KeyError) as exc:
                    predicate_errors.append(str(exc))
            try:
                if result_order is None:
                    raise _ReferenceError("cleanup reference chronology unestablished")
                admission = _q_reference(evidence, proof.get("target_admission"),
                                         before=result_order, current=True)
                authority = _q_reference(evidence, proof.get("chair_authority"),
                                         before=result_order, current=True)
                identity = _digest(proof.get("target_identity"), "cleanup target identity")
                if (admission.get("kind") != "admit" or admission.get("binding") != evidence.get("binding")
                        or admission.get("independently_verified") is not True
                        or admission.get("closed") is not True
                        or (target, identity) not in admission.get("targets", [])):
                    raise _ReferenceError("target lacks exact F CHECKPOINT admission")
                if (authority.get("kind") != "cleanup_authority" or authority.get("binding") != evidence.get("binding")
                        or authority.get("target") != target or authority.get("identity") != identity
                        or proof.get("observed_identity") != identity):
                    raise _ReferenceError("target lacks exact specific Chair authority/fresh identity")
            except (ValueError, TypeError, KeyError) as exc:
                predicate_errors.append(str(exc))
            result["errors"].extend(predicate_errors)
            if proof.get("all_preconditions_passed") is not True:
                result["errors"].append("cleanup preconditions did not all pass")
            if claim == "not_dispatched":
                if failed_observation_preserved and predicate_errors:
                    result["dispatch"] = "not_dispatched"
                else:
                    result["errors"].append("not_dispatched lacks required failed-precondition evidence")
                if "original_status" in proof:
                    result["errors"].append("undispatched action cannot have an original action status")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            result["errors"].append(str(exc))
        if number is not None and states[number + 1]["dispatch"] == "dispatched":
            if result["dispatch"] != "dispatched":
                result["errors"].append("absence capture dispatched without a dispatched cleanup action")
            else:
                try:
                    if result_order is None:
                        raise _ReferenceError("result must close before absence capture")
                    absence_order = closed_order(number + 1, "absence")
                    if absence_order <= result_order:
                        raise _ReferenceError("result must close before absence capture")
                except (ValueError, TypeError, KeyError) as exc:
                    result["errors"].append(str(exc))
        if result["dispatch"] == "dispatched" and result["errors"]:
            result["errors"].append("violation: cleanup dispatched despite failed/unproven prerequisites")
        # No result proves absence merely because the action was blocked.
    return results


def _q_accounting(evidence, retention_usage):
    errors = []
    ledger = evidence.get("accounting")
    if not isinstance(ledger, Mapping):
        return ["missing accounting/reservation ledger"]
    limits = {
        "generations": 16, "aborted_generations": 4, "items": 1024,
        "physical_attempts": 3584, "phases": 24,
    }
    for key, maximum in limits.items():
        value = ledger.get(key)
        if type(value) is not int or not 0 <= value <= maximum:
            errors.append("lifetime bound: " + key)
    accounts = ledger.get("accounts")
    if not isinstance(accounts, Mapping) or set(accounts) != set(spec.ORDINARY_ACCOUNT_BYTES):
        errors.append("missing exact account ledger")
    else:
        for key, maximum in spec.ORDINARY_ACCOUNT_BYTES.items():
            value = accounts[key]
            if type(value) is not int or not 0 <= value <= maximum:
                errors.append("account bound: " + key)
            elif value < retention_usage.get(key, 0):
                errors.append("retention undercharged: " + key)
    generations = ledger.get("generation_usage")
    if not isinstance(generations, list):
        errors.append("missing per-generation ledger")
    else:
        ids, total_items, total_records = set(), 0, 0
        for generation in generations:
            number = generation.get("generation")
            if type(number) is not int or not 0 <= number < 16 or number in ids:
                errors.append("generation number/reuse")
                continue
            ids.add(number)
            for key, maximum in (("items", 128), ("records", 512), ("bytes", 2097152)):
                count = generation.get(key)
                if type(count) is not int or not 0 <= count <= maximum:
                    errors.append("per-generation bound: " + key)
            if type(generation.get("items")) is int:
                total_items += generation["items"]
            if type(generation.get("records")) is int:
                total_records += generation["records"]
        for key, minimum in (("items", total_items), ("physical_attempts", total_records),
                             ("generations", len(ids))):
            if type(ledger.get(key)) is not int or ledger[key] < minimum:
                errors.append("lifetime undercounts generations: " + key)
    support = ledger.get("support")
    if (not isinstance(support, list) or len(support) > 128
            or any(not isinstance(raw, bytes) or len(raw) > 65536 for raw in support)
            or sum(len(raw) for raw in support if isinstance(raw, bytes)) > 4194304):
        errors.append("independent support bounds")
    return errors


def _q_retention(evidence, states, physical, declarations):
    errors, covered, usage = [], set(), {key: 0 for key in spec.ORDINARY_ACCOUNT_BYTES}
    generation_totals = {}
    for item in evidence.get("retention", []):
        try:
            number = item["capture"]
            if type(number) is not int or number not in physical or declarations is None:
                raise _ReferenceError("unassigned retained capture")
            state = states[number]
            receipt, cell, payload = physical[number]
            if state["physical_state"] == "EMPTY":
                raise _ReferenceError("unused/proven-undispatched Q is not routine retention")
            if item.get("cell") != cell or item.get("payload") != payload:
                raise _ReferenceError("source-to-F bytes differ")
            if receipt is None and item.get("unresolved_raw") is not True:
                raise _ReferenceError("invalid/orphan cannot be promoted")
            qualification = item.get("qualification")
            if (state["closure"] == "closure_unproven" and qualification != "closure_unproven"
                    or receipt is not None and receipt["completeness"] != "complete" and qualification != receipt["completeness"]):
                raise _ReferenceError("retained closure/completeness qualification missing")
            read = _q_reference(evidence, item.get("read_reference"), current=True)
            if (read.get("kind") != "q_retention_read" or read.get("binding") != evidence.get("binding")
                    or read.get("map") != evidence.get("map_digest")
                    or read.get("lifecycle") != evidence.get("lifecycle")
                    or read.get("capture") != number or read.get("object") != evidence.get("object")
                    or read.get("identity_matches") is not True or read.get("custody_valid") is not True
                    or read.get("writers_closed") is not True
                    or read.get("cell_sha256") != hashlib.sha256(cell).hexdigest()
                    or read.get("payload_sha256") != hashlib.sha256(payload).hexdigest()):
                raise _ReferenceError("Q retention read identity/custody/closure mismatch")
            account = declarations[number]["account"]
            usage["review_correction"] += len(cell)
            usage[account] += len(payload)
            descriptors = (item["cell_descriptor"], item["payload_descriptor"])
            roles = []
            physical_bytes, records = 0, 0
            for raw, data, encoding, schema in (
                (descriptors[0], cell, "raw", None),
                (descriptors[1], payload, declarations[number]["encoding"] if receipt else "raw",
                 declarations[number]["schema"] if receipt else None),
            ):
                if not isinstance(raw, bytes) or len(raw) > 357:
                    raise _ReferenceError("retention descriptor bound")
                desc = cjson2.loads(raw)
                _require_keys(desc, spec.ITEM_FIELDS, "retained ITEM")
                _digest(desc["permit"], "retention permit")
                _role(desc["role"], "retention role")
                if (desc["encoding"] != encoding or desc["schema"] != schema
                        or _uint(desc["length"], "retained length") != len(data)
                        or desc["sha256"] != hashlib.sha256(data).hexdigest()):
                    raise _ReferenceError("retained descriptor differs from source")
                _uint(desc["category"], "retained category", maximum=11)
                roles.append(desc["role"])
                physical_bytes += (96 + len(raw) + 7) // 8 * 8
                records += 1
                for offset in range(0, len(data), 262048):
                    chunk = data[offset:offset + 262048]
                    physical_bytes += (96 + len(chunk) + 7) // 8 * 8
                    records += 1
            if roles != ["q_cell_" + str(number), "q_payload_" + str(number)] or roles != item.get("roles"):
                raise _ReferenceError("receipt/payload roles not distinct/exact")
            usage["descriptors_control_framing_padding"] += physical_bytes - len(cell) - len(payload)
            generation = item.get("generation")
            if type(generation) is not int or not 1 <= generation < 16:
                raise _ReferenceError("invalid retention generation")
            total = generation_totals.setdefault(generation, [0, 0, 0])
            total[0] += 2
            total[1] += records
            total[2] += physical_bytes
            checkpoint = _q_reference(evidence, item.get("checkpoint"), current=True)
            if (checkpoint.get("kind") != "admit" or checkpoint.get("generation") != generation
                    or checkpoint.get("binding") != evidence.get("binding")
                    or checkpoint.get("independently_verified") is not True
                    or checkpoint.get("closed") is not True):
                raise _ReferenceError("missing independent F CHECKPOINT admission")
            expected = [(roles[0], hashlib.sha256(cell).hexdigest()),
                        (roles[1], hashlib.sha256(payload).hexdigest())]
            if not all(pair in checkpoint.get("scope", []) for pair in expected):
                raise _ReferenceError("admission does not cover exact bytes/roles")
            covered.update((number, role, digest) for role, digest in expected)
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(str(exc))
    for generation, (items, records, size) in generation_totals.items():
        ledger = next((row for row in evidence.get("accounting", {}).get("generation_usage", [])
                       if row.get("generation") == generation), {})
        if (ledger.get("items", -1) < items or ledger.get("records", -1) < records + 2
                or ledger.get("bytes", -1) < size + 192):
            errors.append("generation retention/framing undercharged")
    errors.extend(_q_accounting(evidence, usage))
    return errors, covered, usage


def _q_release(evidence, covered, required, retention_valid, scope_complete):
    """Eligibility only. No deletion authority, admission, outcome or F reopening."""
    outstanding = set(required) - covered
    result = {"normal_eligible": False, "exceptional_scope": [],
              "preserve": sorted(outstanding, key=repr), "deletion_authorized": False,
              "scope_established": scope_complete}
    if not scope_complete:
        return result
    for release in evidence.get("chair_releases", []):
        try:
            ref = _q_reference(evidence, release, current=True)
            if (ref.get("kind") != "chair_release" or ref.get("binding") != evidence.get("binding")
                    or ref.get("object") != evidence.get("object")
                    or not ref.get("reason_terminal_unavailable")
                    or not ref.get("administrative_action")
                    or ref.get("fresh_identity_custody") is not True):
                raise _ReferenceError("incomplete exact exceptional Chair release")
            scope = set(tuple(item) for item in ref.get("scope", []))
            remaining = set(tuple(item) for item in ref.get("remaining", []))
            if not scope or not scope <= set(required) or remaining != set(required) - scope:
                raise _ReferenceError("exceptional release loses other required evidence")
            if ref.get("evidence_ceasing") != ref.get("scope"):
                raise _ReferenceError("missing exact evidence-loss disclosure")
            action_scope = set(tuple(item) for item in ref.get("action_scope", []))
            if (action_scope != scope or type(ref.get("destroys_object")) is not bool
                    or ref["destroys_object"] and remaining):
                raise _ReferenceError("release action exceeds exact evidence scope")
            outstanding -= scope
            result["exceptional_scope"].extend(sorted(scope, key=repr))
        except (ValueError, TypeError, KeyError):
            continue
    terminal = evidence.get("terminal")
    try:
        ref = _q_reference(evidence, terminal, current=True)
        valid_terminal = (ref.get("kind") in ("final_complete", "final_failed", "final_unresolved")
                          and ref.get("binding") == evidence.get("binding")
                          and ref.get("r2_terminal_established") is True)
    except (ValueError, TypeError, KeyError):
        valid_terminal = False
    result["normal_eligible"] = retention_valid and not outstanding and valid_terminal
    result["preserve"] = sorted(outstanding, key=repr)
    return result


def verify_q(image: bytes, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Level-1, supplied-bytes-only Q evaluation (Amendment 1a §§3–13).

    Evidence is a Python adapter of independently established external facts:
    map_bytes/map_view/map_attestation, binding/lifecycle/object, a trusted
    references registry, exact schemas, captures/history, optional build/J and
    cleanup projections, retention/CHECKPOINT scope, accounting and releases.
    Neither the adapter vocabulary nor its synthetic test schemas are adopted
    operational wire formats. Missing facts never establish a positive result.
    No paths, callbacks, clocks, processes, services or filesystem objects are
    consulted. The F entry point and its closed result schema are independent.
    """
    input_errors = []
    if not isinstance(evidence, Mapping):
        evidence = {}
        input_errors.append("missing evidence mapping")
    evidence = dict(evidence)
    original_scope_supplied = isinstance(evidence.get("originals"), list)
    for key in ("references", "captures", "schemas", "accounting"):
        if not isinstance(evidence.get(key, {}), Mapping):
            input_errors.append("malformed evidence mapping: " + key)
            evidence[key] = {}
    for key in ("history", "retention", "cleanup", "originals", "chair_releases"):
        if not isinstance(evidence.get(key, []), list):
            input_errors.append("malformed evidence list: " + key)
            evidence[key] = []
    for key in ("references", "captures"):
        source = evidence.get(key, {})
        evidence[key] = {name: value if isinstance(value, Mapping) else {}
                         for name, value in source.items()}
        if any(not isinstance(value, Mapping) for value in source.values()):
            input_errors.append("malformed evidence entries: " + key)
    for key in ("retention", "cleanup", "originals"):
        if any(not isinstance(value, Mapping) for value in evidence.get(key, [])):
            input_errors.append("malformed evidence entries: " + key)
        evidence[key] = [value if isinstance(value, Mapping) else {} for value in evidence.get(key, [])]
    ledger = dict(evidence.get("accounting", {}))
    if "generation_usage" in ledger:
        if not isinstance(ledger["generation_usage"], list):
            input_errors.append("malformed generation ledger")
            ledger["generation_usage"] = []
        elif any(not isinstance(row, Mapping) for row in ledger["generation_usage"]):
            input_errors.append("malformed generation entries")
            ledger["generation_usage"] = [row for row in ledger["generation_usage"] if isinstance(row, Mapping)]
    evidence["accounting"] = ledger
    errors = list(input_errors)
    try:
        map_digest, declarations = _q_map(evidence)
    except (ValueError, TypeError, KeyError) as exc:
        errors.append(str(exc))
        map_digest, declarations = None, None
    # Local projection only: caller evidence is never mutated.
    supplied = dict(evidence, map_digest=map_digest)
    states, physical = {}, {}
    valid_image = isinstance(image, bytes) and len(image) == 3_145_728
    frozen = evidence.get("prior_freeze") is not False
    if valid_image:
        for start, end in ((110592, 131072), (524288, 655360), (2883584, 3145728)):
            if any(image[start:end]):
                errors.append("nonzero unassigned/nonborrowable space")
                frozen = True
    else:
        errors.append("required Q bytes unreadable or wrong size")
        frozen = True
    for number in range(108):
        entry = declarations[number] if declarations else None
        state, receipt, cell, payload = _q_physical(image, number, entry, supplied, map_digest)
        observation = supplied.get("captures", {}).get(number, {})
        if isinstance(observation, Mapping) and (
                observation.get("cell_sha256") != hashlib.sha256(cell).hexdigest()
                or observation.get("payload_sha256") != hashlib.sha256(payload if receipt else b"").hexdigest()
                and state["physical_state"] not in ("INVALID", "ORPHAN")):
            state["errors"].append("capture observation does not match supplied bytes")
            state["observation_mismatch"] = True
            if receipt is not None:
                frozen = True
        _q_capture_evidence(number, entry, state, receipt, supplied)
        if state["errors"]:
            state["usable"] = False
        states[number] = state
        physical[number] = receipt, cell, payload
        if state["physical_state"] in ("INVALID", "ORPHAN") or state["closure"] == "closure_unproven":
            frozen = True
    history_errors, history_frozen = _q_history(supplied, states, declarations)
    errors.extend(history_errors)
    frozen |= history_frozen
    errors.extend(_q_build_and_j(supplied, states))
    retention_errors, covered, usage = _q_retention(supplied, states, physical, declarations)
    errors.extend(retention_errors)
    required = set()
    for number, state in states.items():
        if state["physical_state"] != "EMPTY":
            _, cell, payload = physical[number]
            required.add((number, "q_cell_" + str(number), hashlib.sha256(cell).hexdigest()))
            required.add((number, "q_payload_" + str(number), hashlib.sha256(payload).hexdigest()))
    # Other originals stay preserved unless their exact bytes/roles are supplied
    # and admitted by the corresponding externally established CHECKPOINT.
    release_scope_complete = original_scope_supplied and not input_errors
    for original in evidence.get("originals", []):
        try:
            identity, role, data = original["identity"], original["role"], original["bytes"]
            if not isinstance(identity, str) or not isinstance(data, bytes):
                raise _ReferenceError("unobserved required original")
            _role(role, "original role")
            key = (identity, role, hashlib.sha256(data).hexdigest())
            required.add(key)
            cp = _q_reference(supplied, original.get("checkpoint"), current=True)
            if (cp.get("kind") == "admit" and cp.get("independently_verified") is True
                    and cp.get("closed") is True and cp.get("binding") == evidence.get("binding")
                    and (role, key[2]) in cp.get("scope", [])):
                covered.add(key)
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(str(exc))
            if not isinstance(original.get("bytes"), bytes) or not isinstance(original.get("identity"), str):
                release_scope_complete = False
    cleanup = _q_cleanup(supplied, states, physical, declarations, frozen)
    blocked = bool(errors or frozen or any(result["errors"] for attempts in cleanup.values() for result in attempts) or any(
        state["errors"] or state["dispatch"] == "uncertain"
        or state["dispatch"] == "dispatched" and not state["usable"]
        for state in states.values()
    ))
    stop = False
    try:
        ref = _q_reference(supplied, evidence.get("independent_stop"), current=True)
        stop = (ref.get("kind") == "independent_stop" and ref.get("binding") == evidence.get("binding")
                and ref.get("f_identity_custody_valid") is True
                and ref.get("requires_new_q_capture") is False)
    except (ValueError, TypeError, KeyError):
        pass
    return {
        "level": 1, "captures": states, "errors": errors,
        "q_frozen": frozen, "progression_blocked": blocked,
        "independent_stop_available": stop, "j_reopen_allowed": False,
        "cleanup": cleanup, "retention_valid": not retention_errors and not input_errors,
        "retention_usage": usage,
        "release": _q_release(
            supplied, covered, required,
            not retention_errors and not input_errors and declarations is not None and valid_image
            and all(s["dispatch"] == "not_dispatched" or s["physical_state"] != "EMPTY"
                    for s in states.values()),
            release_scope_complete,
        ),
        "authorizes_action": False,
    }
