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
