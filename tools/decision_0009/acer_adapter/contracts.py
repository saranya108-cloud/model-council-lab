"""Closed, offline-only contracts for the Decision 0009 Acer adapter.

This module contains data and validation only.  It has no host, process, CUDA,
NVML, filesystem-publication, network, or model-loading implementation.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Mapping, Optional, Tuple


CORE_EXECUTION_COMMIT = "de04b26c14f7e7d60173f463e9d79f9b7134a700"
PROVENANCE_CANONICAL_HEAD = "724700217f8d7183757768fb2a856872b64a3cf3"
AUTHORIZATION_SCHEMA = "decision-0009-acer-authorization/v1"
AUTHORIZATION_V2_SCHEMA = "decision-0009-acer-authorization/v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


AUTHORIZATION_STATES = frozenset(("AUTHORIZATION_ADMITTED",))
LOCAL_EVIDENCE_STATES = frozenset((
    "RAW_CAPTURED", "NORMALIZATION_BOUND", "IMMUTABLE_BYTES_STORED",
    "READBACK_VERIFIED", "ATTEMPT_EVIDENCE_FINALIZED",
))
PUBLICATION_STATES = frozenset((
    "PUBLICATION_INTENT", "EXCLUSIVE_CREATE", "PUBLICATION_WRITTEN",
    "DURABLE_BYTES", "PUBLICATION_VERIFIED",
))
ATTEMPT_STATES = frozenset((
    "SLOT_SPAWN_ELIGIBLE", "SPAWN_INTENT_PERSISTED",
    "WORKER_CREATION_IN_PROGRESS", "WORKER_IDENTITY_ESTABLISHED",
    "WORKER_IDENTITY_DURABLY_RECORDED", "RELEASE_ELIGIBLE",
    "RELEASE_INTENT", "RELEASED_OR_POSSIBLY_RELEASED",
    "CUDA_CALL_GATE_PASSED", "CLEANUP_REQUESTED", "EXIT_OBSERVED",
    "REAPING_PROVEN", "RESIDUAL_CLEARANCE_PROVEN", "ATTEMPT_COMPLETE",
))
BOOT_STATES = frozenset((
    "BOOT_CUSTODY_ESTABLISHED", "BOOT_CUSTODY_COMPLETE",
    "BOOT_CLOSURE_CANDIDATE_FINALIZED", "BOOT_COMPLETE",
    "BOOT_HANDOFF_PENDING",
))
CAMPAIGN_STATES = frozenset((
    "CAMPAIGN_ADMITTED", "CAMPAIGN_CLOSURE_CANDIDATE_FINALIZED",
    "CAMPAIGN_COMPLETE", "CAMPAIGN_CLOSED_FAILED",
))
SAFETY_MARKERS = frozenset((
    "ABORTED", "TAINTED", "CUSTODY_UNCERTAIN", "CONTAINMENT_ONLY_RECOVERY",
))
STATE_DOMAINS = {
    "authorization": AUTHORIZATION_STATES,
    "local_evidence": LOCAL_EVIDENCE_STATES,
    "publication": PUBLICATION_STATES,
    "attempt": ATTEMPT_STATES,
    "boot": BOOT_STATES,
    "campaign": CAMPAIGN_STATES,
    "safety": SAFETY_MARKERS,
}
REMOVED_STATES = frozenset((
    "LOCAL_ATTEMPT_FINALIZED", "LOCAL_READBACK_VERIFIED",
    "VALID_ADAPTER_ATTEMPT_COMPLETE", "EXCLUSIVE_WRITE",
    "DURABLE_EXTERNAL_BYTES", "INDEPENDENT_READBACK",
    "EXTERNAL_READBACK_VERIFIED",
))


class ContractError(ValueError):
    """A closed adapter contract was malformed or used in the wrong domain."""


class CustodyError(ContractError):
    """A custody receipt or token violated its closed contract."""


def _string(name, value, *, digest=False):
    if type(value) is not str or not value:
        raise ContractError(name + " must be a nonempty string")
    if digest:
        if SHA256_RE.fullmatch(value) is None:
            raise ContractError(name + " must be a lowercase sha256")
    elif TOKEN_RE.fullmatch(value) is None and not value.startswith("/"):
        raise ContractError(name + " is not a closed identifier or absolute path")
    return value


def _integer(name, value, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise ContractError(name + " must be an integer >= %d" % minimum)
    return value


def _boolean(name, value):
    if type(value) is not bool:
        raise ContractError(name + " must be boolean")
    return value


def _tuple(name, value):
    if type(value) is not tuple:
        raise ContractError(name + " must be a tuple")
    return value


def parse_state(domain, name):
    if type(domain) is not str or domain not in STATE_DOMAINS:
        raise ContractError("unknown state domain")
    if type(name) is not str or name not in STATE_DOMAINS[domain]:
        raise ContractError("unknown or wrong-domain state: %r" % (name,))
    return name


@dataclass(frozen=True)
class SlotSpec:
    slot_id: str
    attempt_id: str
    boot_ordinal: int
    worker_ordinal: int
    thermal_state: str
    handle_order: str

    def __post_init__(self):
        _string("slot_id", self.slot_id)
        _string("attempt_id", self.attempt_id)
        _integer("boot_ordinal", self.boot_ordinal, minimum=1)
        _integer("worker_ordinal", self.worker_ordinal, minimum=1)
        if self.thermal_state not in ("boot-cold", "same-boot-warm"):
            raise ContractError("thermal_state")
        if self.handle_order not in ("BL", "LB"):
            raise ContractError("handle_order")


@dataclass(frozen=True)
class Authorization:
    schema_version: str
    authorization_id: str
    campaign_id: str
    nonce: str
    authorization_digest: str
    core_commit: str
    core_manifest_digest: str
    adapter_manifest_digest: str
    policy_digest: str
    schema_digest: str
    chair_identity: str
    trust_domain: str
    authenticated: bool
    offline_only: bool
    retry_authorized: bool
    reboot_authorized: bool
    expansion_authorized: bool
    tranche_b_authorized: bool
    slots: Tuple[SlotSpec, ...]
    # None is solely the historical v1 absence marker. Every v2 field is
    # mandatory and checked below; no v2 permissions are inferred from v1.
    evidence_operations: Optional[tuple] = None
    exact_byte_recovery_authorized: Optional[bool] = None
    evidence_source_ids: Optional[tuple] = None
    recovery_publisher_ids: Optional[tuple] = None
    destination_rules: Optional[tuple] = None
    object_rules: Optional[tuple] = None
    supplement_rules: Optional[tuple] = None

    def __post_init__(self):
        if self.schema_version not in (AUTHORIZATION_SCHEMA, AUTHORIZATION_V2_SCHEMA):
            raise ContractError("authorization schema")
        for name in ("authorization_id", "campaign_id", "nonce", "chair_identity",
                     "trust_domain"):
            _string(name, getattr(self, name))
        for name in ("authorization_digest", "core_manifest_digest",
                     "adapter_manifest_digest", "policy_digest", "schema_digest"):
            _string(name, getattr(self, name), digest=True)
        if self.core_commit != CORE_EXECUTION_COMMIT:
            raise ContractError("execution authorization must bind the accepted core commit")
        for name in ("authenticated", "offline_only", "retry_authorized",
                     "reboot_authorized", "expansion_authorized", "tranche_b_authorized"):
            _boolean(name, getattr(self, name))
        if (not self.offline_only or
                (self.schema_version == AUTHORIZATION_SCHEMA and not self.authenticated)):
            raise ContractError("offline authorization authentication/domain")
        if any((self.retry_authorized, self.reboot_authorized,
                self.expansion_authorized, self.tranche_b_authorized)):
            raise ContractError("forbidden authority enabled")
        _tuple("slots", self.slots)
        if len(self.slots) != 12:
            raise ContractError("initial matrix must contain twelve slots")
        if (len({slot.slot_id for slot in self.slots}) != 12 or
                len({slot.attempt_id for slot in self.slots}) != 12):
            raise ContractError("slot and attempt identities must be unique")
        orders = (("BL", "LB", "BL"), ("LB", "BL", "LB"),
                  ("BL", "BL", "LB"), ("LB", "LB", "BL"))
        expected = tuple(
            ("slot-%d-%d" % (boot, worker), "attempt-%d-%d" % (boot, worker),
             boot, worker, "boot-cold" if worker == 1 else "same-boot-warm",
             orders[boot - 1][worker - 1])
            for boot in range(1, 5) for worker in range(1, 4)
        )
        actual = tuple((slot.slot_id, slot.attempt_id, slot.boot_ordinal,
                        slot.worker_ordinal, slot.thermal_state, slot.handle_order)
                       for slot in self.slots)
        if actual != expected:
            raise ContractError("unsupported ordered matrix")
        if self.schema_version == AUTHORIZATION_V2_SCHEMA:
            validate_authorization_policy(self)
        elif any(getattr(self, name) is not None for name in AUTHORIZATION_V2_FIELDS):
            raise ContractError("v1 cannot carry v2 policy")


AUTHORIZATION_V2_FIELDS = (
    "evidence_operations", "exact_byte_recovery_authorized", "evidence_source_ids",
    "recovery_publisher_ids", "destination_rules", "object_rules", "supplement_rules",
)
EVIDENCE_PERMISSIONS = frozenset((
    "WRITE_EXACT", "ESTABLISH_DURABILITY", "VERIFY_EXACT", "PUBLISH_RECOVERY_SUPPLEMENT",
))
EVIDENCE_KINDS = frozenset((
    "ATTEMPT_EVIDENCE", "BOOT_CLOSURE_EVIDENCE", "CAMPAIGN_EVIDENCE", "FAILURE_EVIDENCE",
))
SUPPLEMENT_KINDS = frozenset((
    "VERIFIED_EFFECT_RESULT", "CONTAINMENT_EVIDENCE", "REAP_EVIDENCE",
    "FAILURE_ENVELOPE", "PUBLICATION_READBACK",
))


def _logical_key(value):
    if (type(value) is not str or not value or
            any(ch in value for ch in ("\\", "%", "\x00", "?", "#")) or
            any(segment in ("", ".", "..") for segment in value.split("/"))):
        raise ContractError("noncanonical logical key")
    return value


@dataclass(frozen=True)
class DestinationRule:
    rule_id: str
    destination_id: str
    port_identity: str
    namespace_prefix: str
    durability_policy: str
    fencing_policy: str

    def __post_init__(self):
        for name in ("rule_id", "destination_id", "port_identity"):
            _string(name, getattr(self, name))
        _logical_key(self.namespace_prefix)
        if (self.durability_policy != "OBJECT_AND_NAMESPACE" or
                self.fencing_policy != "ALL_LOWER_WRITERS"):
            raise ContractError("destination policy")


@dataclass(frozen=True)
class ObjectRule:
    rule_id: str
    subject_id: str
    evidence_kind: str
    destination_id: str
    object_key: str

    def __post_init__(self):
        for name in ("rule_id", "subject_id", "destination_id"):
            _string(name, getattr(self, name))
        _logical_key(self.object_key)
        if self.evidence_kind not in EVIDENCE_KINDS:
            raise ContractError("evidence kind")


@dataclass(frozen=True)
class SupplementRule:
    rule_id: str
    destination_id: str
    namespace_prefix: str
    parent_evidence_kinds: tuple
    supplement_kinds: tuple
    key_policy: str

    def __post_init__(self):
        _string("rule_id", self.rule_id)
        _string("destination_id", self.destination_id)
        _logical_key(self.namespace_prefix)
        _closed_unique_tuple("parent kinds", self.parent_evidence_kinds, EVIDENCE_KINDS)
        _closed_unique_tuple("supplement kinds", self.supplement_kinds, SUPPLEMENT_KINDS)
        if self.key_policy != "RECOVERY_SUPPLEMENT_V1":
            raise ContractError("supplement key policy")


def _closed_unique_tuple(name, value, allowed=None):
    _tuple(name, value)
    if any(type(item) is not str or not TOKEN_RE.fullmatch(item) for item in value):
        raise ContractError(name + " identities")
    if len(set(value)) != len(value) or (allowed is not None and not set(value) <= allowed):
        raise ContractError(name + " duplicates or unknown values")


def validate_authorization_policy(authorization):
    if authorization.schema_version != AUTHORIZATION_V2_SCHEMA:
        raise ContractError("v2 policy required")
    _closed_unique_tuple("evidence operations", authorization.evidence_operations,
                         EVIDENCE_PERMISSIONS)
    _boolean("exact_byte_recovery_authorized", authorization.exact_byte_recovery_authorized)
    _closed_unique_tuple("evidence sources", authorization.evidence_source_ids)
    _closed_unique_tuple("recovery publishers", authorization.recovery_publisher_ids)
    all_rules = []
    for name, expected in (("destination_rules", DestinationRule),
                           ("object_rules", ObjectRule), ("supplement_rules", SupplementRule)):
        rules = _tuple(name, getattr(authorization, name))
        if any(type(rule) is not expected for rule in rules):
            raise ContractError(name + " closed rules required")
        all_rules.extend(rules)
    if len({rule.rule_id for rule in all_rules}) != len(all_rules):
        raise ContractError("duplicate policy rule ID")
    destinations = {rule.destination_id: rule for rule in authorization.destination_rules}
    if len(destinations) != len(authorization.destination_rules):
        raise ContractError("ambiguous destination mapping")
    ports = [rule.port_identity for rule in authorization.destination_rules]
    if len(set(ports)) != len(ports):
        raise ContractError("destination port alias")
    keys = set()
    subjects = {authorization.campaign_id}
    subjects.update(slot.slot_id for slot in authorization.slots)
    subjects.update(slot.attempt_id for slot in authorization.slots)
    subjects.update("boot-%d" % i for i in (1, 2, 3, 4))
    for rule in authorization.object_rules:
        destination = destinations.get(rule.destination_id)
        if (destination is None or rule.subject_id not in subjects or
                not rule.object_key.startswith(destination.namespace_prefix + "/")):
            raise ContractError("object target/subject/prefix binding")
        pair = (rule.destination_id, rule.object_key)
        if pair in keys:
            raise ContractError("ambiguous object mapping")
        keys.add(pair)
    prefixes = []
    for rule in authorization.supplement_rules:
        destination = destinations.get(rule.destination_id)
        if (destination is None or not (
                rule.namespace_prefix == destination.namespace_prefix or
                rule.namespace_prefix.startswith(destination.namespace_prefix + "/"))):
            raise ContractError("supplement destination binding")
        for dest, prefix in prefixes:
            if dest == rule.destination_id and (prefix == rule.namespace_prefix or
                    prefix.startswith(rule.namespace_prefix + "/") or
                    rule.namespace_prefix.startswith(prefix + "/")):
                raise ContractError("ambiguous supplement mapping")
        prefixes.append((rule.destination_id, rule.namespace_prefix))
    for dest, key in keys:
        if any(dest == sd and key.startswith(prefix + "/recovery/")
               for sd, prefix in prefixes):
            raise ContractError("object/supplement key overlap")


def canonical_authorization_bytes(authorization):
    if type(authorization) is not Authorization or authorization.schema_version != AUTHORIZATION_V2_SCHEMA:
        raise ContractError("canonical authorization requires v2")
    validate_authorization_policy(authorization)
    value = asdict(authorization)
    value.pop("authorization_digest")
    # The closed dataclasses above contain only str/bool/int/tuple. This walk
    # also rejects unexpected numeric forms independently of json.dumps.
    def validate(item):
        if type(item) in (str, bool, int) or item is None:
            return
        if type(item) in (tuple, list):
            for child in item:
                validate(child)
            return
        if type(item) is dict and all(type(key) is str for key in item):
            for child in item.values():
                validate(child)
            return
        raise ContractError("noncanonical authorization value")
    validate(value)
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def authorization_digest(authorization):
    return hashlib.sha256(canonical_authorization_bytes(authorization)).hexdigest()


RECOVERY_PERMISSION_MAP = {
    "ENSURE_EXACT_OBJECT": "WRITE_EXACT",
    "CONTINUE_RESERVED_EXACT": "WRITE_EXACT",
    "ESTABLISH_DURABILITY": "ESTABLISH_DURABILITY",
    "VERIFY_EXACT_OBJECT": "VERIFY_EXACT",
    "QUERY": "VERIFY_EXACT",
}


def require_recovery_permission(authorization, operation, *, supplement=False):
    validate_authorization_policy(authorization)
    permission = RECOVERY_PERMISSION_MAP.get(operation)
    if (permission is None or not authorization.exact_byte_recovery_authorized or
            permission not in authorization.evidence_operations or
            (supplement and "PUBLISH_RECOVERY_SUPPLEMENT" not in authorization.evidence_operations)):
        raise ContractError("recovery permission unavailable")
    # Pure policy validation. No operational RP capability is issued here.


@dataclass(frozen=True)
class OfflineChairApproval:
    chair_identity: str
    trust_domain: str
    store_identity: str
    campaign_id: str
    authorization_id: str
    authorization_schema: str
    canonical_authorization_bytes: bytes
    authorization_digest: str

    def __post_init__(self):
        for name in ("chair_identity", "trust_domain", "store_identity", "campaign_id",
                     "authorization_id"):
            _string(name, getattr(self, name))
        if self.authorization_schema != AUTHORIZATION_V2_SCHEMA:
            raise ContractError("only fresh v2 enrollment")
        raw = self.canonical_authorization_bytes
        if type(raw) is not bytes:
            raise ContractError("exact enrolled bytes required")
        _string("authorization_digest", self.authorization_digest, digest=True)
        try:
            value = json.loads(raw)
            # Parse the complete carrier under its actual closed schema.
            payload = authorization_from_record(dict(value, authorization_digest=self.authorization_digest))
        except (ValueError, TypeError, KeyError) as exc:
            raise ContractError("malformed enrolled authorization") from exc
        if (canonical_authorization_bytes(payload) != raw or
                authorization_digest(payload) != self.authorization_digest or
                any(getattr(payload, name) != getattr(self, name)
                    for name in ("chair_identity", "trust_domain", "campaign_id", "authorization_id"))):
            raise ContractError("enrollment identity/bytes/digest mismatch")


@dataclass(frozen=True)
class OfflineChairTrustRoot:
    root_id: str
    root_version: int
    trust_domain: str
    trusted_chair_ids: tuple
    approvals: tuple

    def __post_init__(self):
        _string("root_id", self.root_id)
        _integer("root_version", self.root_version, minimum=1)
        if self.trust_domain != "offline-test":
            raise ContractError("offline trust domain")
        _closed_unique_tuple("trusted Chairs", self.trusted_chair_ids)
        _tuple("approvals", self.approvals)
        identities = set()
        for approval in self.approvals:
            if (type(approval) is not OfflineChairApproval or
                    approval.chair_identity not in self.trusted_chair_ids or
                    approval.trust_domain != self.trust_domain):
                raise ContractError("untrusted enrollment")
            identity = (approval.store_identity, approval.campaign_id, approval.authorization_id)
            if identity in identities:
                raise ContractError("duplicate/conflicting enrollment")
            identities.add(identity)


def authorization_from_record(value):
    """Explicit closed dispatch. Legacy bytes gain no v2 fields or permissions."""
    if type(value) is not dict:
        raise ContractError("authorization record")
    version = value.get("schema_version")
    base = set(Authorization.__dataclass_fields__) - set(AUTHORIZATION_V2_FIELDS)
    required = base if version == AUTHORIZATION_SCHEMA else base | set(AUTHORIZATION_V2_FIELDS)
    if version not in (AUTHORIZATION_SCHEMA, AUTHORIZATION_V2_SCHEMA) or set(value) != required:
        raise ContractError("closed authorization schema fields")
    record = dict(value)
    try:
        record["slots"] = tuple(SlotSpec(**slot) for slot in value["slots"])
        if version == AUTHORIZATION_V2_SCHEMA:
            for name in ("evidence_operations", "evidence_source_ids", "recovery_publisher_ids"):
                record[name] = tuple(value[name])
            record["destination_rules"] = tuple(DestinationRule(**r) for r in value["destination_rules"])
            record["object_rules"] = tuple(ObjectRule(**r) for r in value["object_rules"])
            record["supplement_rules"] = tuple(SupplementRule(
                **dict(r, parent_evidence_kinds=tuple(r["parent_evidence_kinds"]),
                       supplement_kinds=tuple(r["supplement_kinds"]))) for r in value["supplement_rules"])
        return Authorization(**record)
    except (TypeError, KeyError) as exc:
        raise ContractError("closed authorization nested fields") from exc


@dataclass(frozen=True)
class JournalReference:
    event_id: str
    revision: int
    payload_digest: str

    def __post_init__(self):
        _string("event_id", self.event_id)
        _integer("revision", self.revision, minimum=1)
        _string("payload_digest", self.payload_digest, digest=True)


@dataclass(frozen=True)
class ImmutableObjectReference:
    object_id: str
    sha256: str
    length: int

    def __post_init__(self):
        _string("object_id", self.object_id)
        _string("sha256", self.sha256, digest=True)
        _integer("length", self.length)


@dataclass(frozen=True)
class EffectPortReceipt:
    effect_id: str
    acceptance_ref: JournalReference
    target_id: str
    original_generation: int
    original_incarnation_id: str
    original_session_id: str
    original_fence: int
    result_object: ImmutableObjectReference
    port_attestation: str

    def __post_init__(self):
        for name in ('effect_id', 'target_id', 'original_incarnation_id', 'original_session_id'):
            _string(name, getattr(self, name))
        _integer('original_generation', self.original_generation, minimum=1)
        _integer('original_fence', self.original_fence, minimum=1)
        _string('port_attestation', self.port_attestation, digest=True)
        if (type(self.acceptance_ref) is not JournalReference or
                type(self.result_object) is not ImmutableObjectReference):
            raise ContractError('nonnull exact independent port receipt references required')


def parse_effect_port_receipt(raw):
    try:
        value = json.loads(raw)
        if type(value) is not dict or set(value) != set(EffectPortReceipt.__dataclass_fields__):
            raise ContractError('closed independent effect port receipt required')
        value['acceptance_ref'] = JournalReference(**value['acceptance_ref'])
        value['result_object'] = ImmutableObjectReference(**value['result_object'])
        return EffectPortReceipt(**value)
    except (ValueError, TypeError, KeyError) as exc:
        raise ContractError('malformed independent effect port receipt') from exc


@dataclass(frozen=True)
class HistoricalEffectResultRecord:
    """Exact legacy bytes only; never a RESULT writer or execution credential."""
    raw_bytes: bytes
    authorizes_execution: bool = False


@dataclass(frozen=True)
class U04EffectResultRecord:
    schema_version: str
    record_type: str
    record_id: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    writer_generation: int
    writer_incarnation_id: str
    writer_session_id: str
    writer_fence: int
    authority_class: str
    authorizes_execution: bool
    acceptance_ref: JournalReference
    effect_id: str
    original_producer_ref: JournalReference
    result: ImmutableObjectReference
    result_kind: str
    verifier_id: str

    def __post_init__(self):
        if (self.schema_version != "u04-record/v1" or self.record_type != "EFFECT_RESULT" or
                self.authority_class != "EVIDENCE" or self.authorizes_execution is not False or
                self.result_kind not in ("CUSTODIAN_RECEIPT", "EFFECT_PORT_RECEIPT")):
            raise ContractError("closed U-04 result kind/schema/class")
        for name in ("record_id", "store_identity", "campaign_id", "writer_incarnation_id",
                     "writer_session_id", "effect_id", "verifier_id"):
            _string(name, getattr(self, name))
        _string("authorization_digest", self.authorization_digest, digest=True)
        _integer("writer_generation", self.writer_generation, minimum=1)
        _integer("writer_fence", self.writer_fence, minimum=1)
        if (type(self.acceptance_ref) is not JournalReference or
                type(self.original_producer_ref) is not JournalReference or
                type(self.result) is not ImmutableObjectReference):
            raise ContractError("nonnull exact result references required")


def parse_effect_result_record(raw):
    """Schema parsing alone never validates a receipt or enables a writer."""
    if type(raw) is not bytes:
        raise ContractError("exact result bytes required")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("duplicate result key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("nonfinite result")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ContractError("malformed result bytes") from exc
    if type(value) is not dict or value.get("record_type") != "EFFECT_RESULT":
        raise ContractError("not an effect result")
    version = value.get("schema_version")
    if version is None and "schema_version" not in value:
        if any(name in value for name in ("acceptance_ref", "original_producer_ref",
                                         "result_kind", "writer_incarnation_id")):
            raise ContractError("mixed legacy/U-04 result")
        return HistoricalEffectResultRecord(raw)
    if version != "u04-record/v1" or set(value) != set(U04EffectResultRecord.__dataclass_fields__):
        raise ContractError("closed explicit U-04 result schema required")
    try:
        return U04EffectResultRecord(**dict(value,
            acceptance_ref=JournalReference(**value["acceptance_ref"]),
            original_producer_ref=JournalReference(**value["original_producer_ref"]),
            result=ImmutableObjectReference(**value["result"])))
    except (KeyError, TypeError) as exc:
        raise ContractError("closed exact nested result references required") from exc


@dataclass(frozen=True)
class BootActivation:
    activation_id: str
    authorization_digest: str
    boot_ordinal: int
    observed_boot_id: str
    predecessor_closure_digest: Optional[str]
    chair_identity: str
    authenticated: bool

    def __post_init__(self):
        _string("activation_id", self.activation_id)
        _string("authorization_digest", self.authorization_digest, digest=True)
        _integer("boot_ordinal", self.boot_ordinal, minimum=1)
        if self.boot_ordinal > 4:
            raise ContractError("boot ordinal")
        _string("observed_boot_id", self.observed_boot_id)
        _string("chair_identity", self.chair_identity)
        _boolean("authenticated", self.authenticated)
        if not self.authenticated:
            raise ContractError("boot activation authentication")
        if self.boot_ordinal == 1 and self.predecessor_closure_digest is not None:
            raise ContractError("first boot has no predecessor closure")
        if self.boot_ordinal > 1:
            _string("predecessor_closure_digest", self.predecessor_closure_digest,
                    digest=True)


@dataclass(frozen=True)
class ArtifactBinding:
    verification_id: str
    verifier_identity: str
    authorization_digest: str
    transition: str
    fence_epoch: int
    session_id: str
    core_digest: str
    adapter_digest: str
    policy_digest: str
    schema_digest: str
    immutable: bool

    def __post_init__(self):
        for name in ("verification_id", "verifier_identity", "session_id"):
            _string(name, getattr(self, name))
        _string("transition", self.transition)
        for name in ("authorization_digest", "core_digest", "adapter_digest",
                     "policy_digest", "schema_digest"):
            _string(name, getattr(self, name), digest=True)
        _integer("fence_epoch", self.fence_epoch, minimum=1)
        _boolean("immutable", self.immutable)
        if not self.immutable:
            raise ContractError("artifact binding must be immutable")

    def manifest(self):
        return {"core": self.core_digest, "adapter": self.adapter_digest,
                "policy": self.policy_digest, "schema": self.schema_digest}


@dataclass(frozen=True)
class EffectCapability:
    capability_id: str
    transition_event_id: str
    transition_revision: int
    transition_event_digest: str
    artifact_binding: ArtifactBinding
    authorization_digest: str
    fence_epoch: int
    session_id: str
    target: str
    operation: str
    effect_id: str
    supervisor_generation: int
    consumed: bool

    def __post_init__(self):
        for name in ("capability_id", "transition_event_id", "session_id", "target",
                     "operation", "effect_id"):
            _string(name, getattr(self, name))
        _integer("transition_revision", self.transition_revision, minimum=1)
        _integer("fence_epoch", self.fence_epoch, minimum=1)
        _integer("supervisor_generation", self.supervisor_generation, minimum=1)
        for name in ("transition_event_digest", "authorization_digest"):
            _string(name, getattr(self, name), digest=True)
        if not isinstance(self.artifact_binding, ArtifactBinding):
            raise ContractError("effect artifact binding")
        _boolean("consumed", self.consumed)
        if (not self.consumed or self.fence_epoch != self.artifact_binding.fence_epoch or
                self.authorization_digest != self.artifact_binding.authorization_digest):
            raise ContractError("effect capability binding")


@dataclass(frozen=True)
class FenceSession:
    fence_epoch: int
    session_id: str
    owner_identity: str
    boot_ordinal: int
    execution_live: bool

    def __post_init__(self):
        _integer("fence_epoch", self.fence_epoch, minimum=1)
        _integer("boot_ordinal", self.boot_ordinal, minimum=1)
        _string("session_id", self.session_id)
        _string("owner_identity", self.owner_identity)
        _boolean("execution_live", self.execution_live)


@dataclass(frozen=True)
class SlotCapability:
    capability_id: str
    authorization_digest: str
    campaign_id: str
    boot_id: str
    slot_id: str
    attempt_id: str
    spawn_token: str
    launch_spec_digest: str
    fence_epoch: int
    session_id: str
    proof_digest: str
    effect_id: str
    transition: str
    target: str
    operation: str
    consumed: bool

    def __post_init__(self):
        for name in ("capability_id", "campaign_id", "boot_id", "slot_id",
                     "attempt_id", "spawn_token", "session_id", "effect_id",
                     "transition", "target", "operation"):
            _string(name, getattr(self, name))
        for name in ("authorization_digest", "launch_spec_digest", "proof_digest"):
            _string(name, getattr(self, name), digest=True)
        _integer("fence_epoch", self.fence_epoch, minimum=1)
        _boolean("consumed", self.consumed)


@dataclass(frozen=True)
class SpawnToken:
    token_id: str
    campaign_id: str
    boot_id: str
    slot_id: str
    attempt_id: str
    launch_spec_digest: str
    custodian_id: str
    supervisor_generation: int

    def __post_init__(self):
        for name in ("token_id", "campaign_id", "boot_id", "slot_id",
                     "attempt_id", "custodian_id"):
            _string(name, getattr(self, name))
        _string("launch_spec_digest", self.launch_spec_digest, digest=True)
        _integer("supervisor_generation", self.supervisor_generation, minimum=1)


@dataclass(frozen=True)
class ProcessIdentity:
    host_id: str
    boot_id: str
    host_pid: int
    pid_namespace: str
    namespace_pid: int
    process_start_ticks: int
    executable_path: str
    executable_device: int
    executable_inode: int
    executable_digest: str
    cgroup_path: str
    cgroup_device: int
    cgroup_inode: int
    cgroup_members: Tuple[int, ...]
    custodian_id: str
    spawn_token: str
    gpu_uuid: str
    alive: bool

    def __post_init__(self):
        for name in ("host_id", "boot_id", "pid_namespace", "executable_path",
                     "cgroup_path", "custodian_id", "spawn_token", "gpu_uuid"):
            _string(name, getattr(self, name))
        for name in ("host_pid", "namespace_pid", "process_start_ticks",
                     "executable_device", "executable_inode", "cgroup_device",
                     "cgroup_inode"):
            _integer(name, getattr(self, name), minimum=1)
        _string("executable_digest", self.executable_digest, digest=True)
        _tuple("cgroup_members", self.cgroup_members)
        if not self.cgroup_members or any(type(pid) is not int or pid < 1
                                          for pid in self.cgroup_members):
            raise ContractError("cgroup_members")
        _boolean("alive", self.alive)


@dataclass(frozen=True)
class CustodianReceipt:
    receipt_id: str
    custodian_id: str
    spawn_token: str
    launch_spec_digest: str
    status: str
    process_identity: Optional[ProcessIdentity]
    possibly_live: bool

    def __post_init__(self):
        for name in ("receipt_id", "custodian_id", "spawn_token"):
            _string(name, getattr(self, name))
        _string("launch_spec_digest", self.launch_spec_digest, digest=True)
        if self.status not in ("BLOCKED", "IN_PROGRESS", "FAILED_NO_CHILD",
                               "UNKNOWN", "EXITED", "REAPED"):
            raise CustodyError("custodian status")
        if self.process_identity is not None and not isinstance(self.process_identity, ProcessIdentity):
            raise CustodyError("process identity")
        _boolean("possibly_live", self.possibly_live)


@dataclass(frozen=True)
class HistoricalEffectReceipt:
    effect_id: str
    supervisor_generation: int
    transition_event_digest: str
    receipt: CustodianReceipt

    def __post_init__(self):
        _string("effect_id", self.effect_id)
        _integer("supervisor_generation", self.supervisor_generation, minimum=1)
        _string("transition_event_digest", self.transition_event_digest, digest=True)
        if not isinstance(self.receipt, CustodianReceipt):
            raise ContractError("historical custodian receipt")


@dataclass(frozen=True)
class ReapReceipt:
    receipt_id: str
    custodian_id: str
    spawn_token: str
    host_pid: int
    process_start_ticks: int
    exit_status: int
    waited: bool

    def __post_init__(self):
        for name in ("receipt_id", "custodian_id", "spawn_token"):
            _string(name, getattr(self, name))
        for name in ("host_pid", "process_start_ticks"):
            _integer(name, getattr(self, name), minimum=1)
        _integer("exit_status", self.exit_status)
        _boolean("waited", self.waited)
        if not self.waited:
            raise CustodyError("reap receipt requires actual wait")


@dataclass(frozen=True)
class GPUAttribution:
    available: bool
    used_bytes: Optional[int]
    reason: Optional[str]
    raw_entry_count: int
    gpu_uuid: str
    host_pid: int
    process_start_ticks: int

    def __post_init__(self):
        _boolean("available", self.available)
        _integer("raw_entry_count", self.raw_entry_count)
        _integer("host_pid", self.host_pid, minimum=1)
        _integer("process_start_ticks", self.process_start_ticks, minimum=1)
        _string("gpu_uuid", self.gpu_uuid)
        if self.available:
            _integer("used_bytes", self.used_bytes)
            if self.reason is not None:
                raise ContractError("available attribution reason")
        else:
            if self.used_bytes is not None:
                raise ContractError("unavailable attribution cannot report bytes")
            _string("reason", self.reason)


@dataclass(frozen=True)
class EvidenceObject:
    object_id: str
    digest: str
    length: int
    bytes: bytes

    def __post_init__(self):
        _string("object_id", self.object_id)
        _string("digest", self.digest, digest=True)
        _integer("length", self.length)
        if type(self.bytes) is not bytes or len(self.bytes) != self.length:
            raise ContractError("evidence bytes")


# ---- canonical publication and measurement-window contracts ---------------
#
# Creation (grant issuance, result records), consumption (grant redemption),
# and reconstruction (historical provenance, chain validation) all derive the
# publication identity and operation binding from these closed contracts.  No
# other module maintains its own list of identity or binding fields.

PUBLICATION_OPERATIONS = ("intent", "create", "write", "durable", "verify")
PUBLICATION_OPERATION_STATES = {
    "intent": "PUBLICATION_INTENT",
    "create": "EXCLUSIVE_CREATE",
    "write": "PUBLICATION_WRITTEN",
    "durable": "DURABLE_BYTES",
    "verify": "PUBLICATION_VERIFIED",
}
PUBLICATION_REQUIRED_PRIOR = {
    "intent": None,
    "create": "PUBLICATION_INTENT",
    "write": "EXCLUSIVE_CREATE",
    "durable": "PUBLICATION_WRITTEN",
    "verify": "DURABLE_BYTES",
}
MEASUREMENT_WINDOWS = frozenset((
    "MEASURED_PREPARATION", "DWELL", "RESIDUAL_CLEARANCE", "OUTSIDE_MEASURED_WINDOWS",
))
OUTSIDE_MEASURED_WINDOWS = "OUTSIDE_MEASURED_WINDOWS"
WINDOW_OPERATION = "set-measurement-window"
PUBLICATION_BINDING_CONTRACT = "decision-0009-publication-operation-binding/v1"


def _contract_digest(value):
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _record_field(record, name):
    if type(record) is not dict or name not in record:
        raise ContractError("record field missing: " + name)
    return record[name]


def _optional_state(name, value, domain):
    if value is not None:
        parse_state(domain, value)
    return value


@dataclass(frozen=True)
class PublicationIdentity:
    """Closed, immutable identity of one publication intent.

    Every field participates in equality: equal intent IDs and digests with a
    different destination or object key are a different intent.
    """
    intent_id: str
    destination: str
    object_key: str
    object_digest: str
    length: int

    def __post_init__(self):
        for name in ("intent_id", "destination", "object_key"):
            _string(name, getattr(self, name))
        _string("object_digest", self.object_digest, digest=True)
        _integer("length", self.length)

    @classmethod
    def from_record(cls, record):
        return cls(_record_field(record, "intent_id"),
                   _record_field(record, "destination"),
                   _record_field(record, "object_key"),
                   _record_field(record, "object_digest"),
                   _record_field(record, "length"))

    def fields(self):
        return {"intent_id": self.intent_id, "destination": self.destination,
                "object_key": self.object_key, "object_digest": self.object_digest,
                "length": self.length}

    def verify_source(self, source):
        """Source bytes must match both the digest and the length."""
        if (type(source) is not bytes or len(source) != self.length or
                hashlib.sha256(source).hexdigest() != self.object_digest):
            raise ContractError("publication source bytes do not match identity")
        return source


@dataclass(frozen=True)
class PublicationOperationBinding:
    """Immutable request for exactly one publication operation.

    Result registration is deliberately not part of this contract: a
    consumed request is bound to its single result by ``OperationResultBinding``.
    """
    identity: PublicationIdentity
    store_identity: str
    grant_id: str
    operation: str
    expected_prior_state: Optional[str]
    window_epoch: int
    authorization_digest: str
    campaign_id: str
    boot_id: str
    boot_ordinal: int
    closure_candidate_event_digest: Optional[str]
    supervisor_generation: int
    session_id: str
    fence_epoch: int

    def __post_init__(self):
        if not isinstance(self.identity, PublicationIdentity):
            raise ContractError("closed publication identity required")
        for name in ("store_identity", "grant_id", "campaign_id", "boot_id",
                     "session_id"):
            _string(name, getattr(self, name))
        if type(self.operation) is not str or self.operation not in PUBLICATION_OPERATIONS:
            raise ContractError("unknown publication operation")
        _optional_state("expected_prior_state", self.expected_prior_state, "publication")
        if self.expected_prior_state != PUBLICATION_REQUIRED_PRIOR[self.operation]:
            raise ContractError("publication prior state does not match operation")
        _integer("window_epoch", self.window_epoch, minimum=1)
        _string("authorization_digest", self.authorization_digest, digest=True)
        _integer("boot_ordinal", self.boot_ordinal, minimum=1)
        if self.closure_candidate_event_digest is not None:
            _string("closure_candidate_event_digest",
                    self.closure_candidate_event_digest, digest=True)
        _integer("supervisor_generation", self.supervisor_generation, minimum=1)
        _integer("fence_epoch", self.fence_epoch, minimum=1)

    @property
    def state(self):
        return PUBLICATION_OPERATION_STATES[self.operation]

    def canonical(self):
        value = self.identity.fields()
        value.update({
            "store_identity": self.store_identity,
            "grant_id": self.grant_id,
            "operation": self.operation,
            "expected_prior_state": self.expected_prior_state,
            "window_epoch": self.window_epoch,
            "authorization_digest": self.authorization_digest,
            "campaign_id": self.campaign_id,
            "boot_id": self.boot_id,
            "boot_ordinal": self.boot_ordinal,
            "closure_candidate_event_digest": self.closure_candidate_event_digest,
            "supervisor_generation": self.supervisor_generation,
            "session_id": self.session_id,
            "fence_epoch": self.fence_epoch,
        })
        return value

    def attestation_digest(self):
        return _contract_digest({"contract": PUBLICATION_BINDING_CONTRACT,
                                 "binding": self.canonical()})

    def record_fields(self):
        """Fields of the single result record this operation may produce.

        The store identity is the store's own and is supplied again when the
        record is read back (``from_record``); it is bound by the attestation.
        """
        value = self.identity.fields()
        value.update({
            "record_type": "PUBLICATION",
            "authorizes_execution": False,
            "state": self.state,
            "operation": self.operation,
            "operation_id": self.grant_id,
            "prior_state": self.expected_prior_state,
            "window_epoch": self.window_epoch,
            "authorization_digest": self.authorization_digest,
            "campaign_id": self.campaign_id,
            "boot_id": self.boot_id,
            "boot_ordinal": self.boot_ordinal,
            "closure_candidate_event_digest": self.closure_candidate_event_digest,
            "supervisor_generation": self.supervisor_generation,
            "session_id": self.session_id,
            "fence_epoch": self.fence_epoch,
        })
        return value

    @classmethod
    def from_record(cls, store_identity, record):
        if (_record_field(record, "record_type") != "PUBLICATION" or
                _record_field(record, "authorizes_execution") is not False):
            raise ContractError("not a nonauthorizing publication record")
        binding = cls(
            PublicationIdentity.from_record(record), store_identity,
            _record_field(record, "operation_id"), _record_field(record, "operation"),
            _record_field(record, "prior_state"), _record_field(record, "window_epoch"),
            _record_field(record, "authorization_digest"),
            _record_field(record, "campaign_id"), _record_field(record, "boot_id"),
            _record_field(record, "boot_ordinal"),
            _record_field(record, "closure_candidate_event_digest"),
            _record_field(record, "supervisor_generation"),
            _record_field(record, "session_id"), _record_field(record, "fence_epoch"))
        if _record_field(record, "state") != binding.state:
            raise ContractError("publication record state does not match operation")
        return binding

    def chain_invariant(self):
        """Binding parts every record of one publication chain must share."""
        return (self.identity, self.store_identity, self.authorization_digest,
                self.campaign_id, self.boot_id, self.boot_ordinal)


@dataclass(frozen=True)
class PublicationOperationGrant:
    """Store-issued, single-use grant for one ``PublicationOperationBinding``."""
    binding: PublicationOperationBinding
    attestation: str

    def __post_init__(self):
        if not isinstance(self.binding, PublicationOperationBinding):
            raise ContractError("closed publication operation binding required")
        _string("attestation", self.attestation, digest=True)

    def attestation_valid(self):
        return self.attestation == self.binding.attestation_digest()

    @property
    def grant_id(self):
        return self.binding.grant_id

    @property
    def operation(self):
        return self.binding.operation

    @property
    def identity(self):
        return self.binding.identity

    @property
    def expected_prior_state(self):
        return self.binding.expected_prior_state

    @property
    def window_epoch(self):
        return self.binding.window_epoch

    @property
    def supervisor_generation(self):
        return self.binding.supervisor_generation

    @property
    def session_id(self):
        return self.binding.session_id

    @property
    def fence_epoch(self):
        return self.binding.fence_epoch


@dataclass(frozen=True)
class OperationResultBinding:
    """The single durable result a started operation produced."""
    event_id: str
    revision: int
    event_digest: str

    def __post_init__(self):
        _string("event_id", self.event_id)
        _integer("revision", self.revision, minimum=1)
        _string("event_digest", self.event_digest, digest=True)


_MEASUREMENT_WINDOW_RECORD_FIELDS = frozenset((
    "record_type", "authorizes_execution", "operation", "operation_id",
    "previous_window", "previous_window_epoch", "window", "window_epoch",
    "authorization_digest", "campaign_id", "supervisor_generation", "session_id",
    "fence_epoch",
))


@dataclass(frozen=True)
class MeasurementWindowTransition:
    """Closed request for one measurement-window transition.

    ``operation`` is the constant operation name; ``operation_id`` is unique per
    invocation.  The only transition from the uninitialized ``(None, 0)`` state
    is the initial ``(OUTSIDE_MEASURED_WINDOWS, 1)``.
    """
    store_identity: str
    operation: str
    operation_id: str
    event_id: str
    previous_window: Optional[str]
    previous_window_epoch: int
    window: str
    window_epoch: int
    authorization_digest: str
    campaign_id: str
    supervisor_generation: int
    session_id: str
    fence_epoch: int

    def __post_init__(self):
        for name in ("store_identity", "operation_id", "event_id", "campaign_id",
                     "session_id"):
            _string(name, getattr(self, name))
        if self.operation != WINDOW_OPERATION:
            raise ContractError("measurement-window operation name")
        if type(self.window) is not str or self.window not in MEASUREMENT_WINDOWS:
            raise ContractError("unknown measurement window")
        _integer("previous_window_epoch", self.previous_window_epoch)
        _integer("window_epoch", self.window_epoch, minimum=1)
        if self.window_epoch != self.previous_window_epoch + 1:
            raise ContractError("measurement-window epoch must advance by one")
        if self.previous_window is None:
            if (self.previous_window_epoch != 0 or
                    self.window != OUTSIDE_MEASURED_WINDOWS):
                raise ContractError("initial measurement window transition")
        elif (type(self.previous_window) is not str or
              self.previous_window not in MEASUREMENT_WINDOWS or
              self.previous_window_epoch < 1):
            raise ContractError("previous measurement window")
        _string("authorization_digest", self.authorization_digest, digest=True)
        _integer("supervisor_generation", self.supervisor_generation, minimum=1)
        _integer("fence_epoch", self.fence_epoch, minimum=1)

    @property
    def initial(self):
        return self.previous_window is None

    def record(self):
        """The exact nonauthorizing record this transition may produce."""
        return {
            "record_type": "MEASUREMENT_WINDOW",
            "authorizes_execution": False,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "previous_window": self.previous_window,
            "previous_window_epoch": self.previous_window_epoch,
            "window": self.window,
            "window_epoch": self.window_epoch,
            "authorization_digest": self.authorization_digest,
            "campaign_id": self.campaign_id,
            "supervisor_generation": self.supervisor_generation,
            "session_id": self.session_id,
            "fence_epoch": self.fence_epoch,
        }

    @classmethod
    def from_record(cls, store_identity, event_id, record):
        if (type(record) is not dict or set(record) != _MEASUREMENT_WINDOW_RECORD_FIELDS or
                record["record_type"] != "MEASUREMENT_WINDOW" or
                record["authorizes_execution"] is not False):
            raise ContractError("closed measurement-window record required")
        return cls(store_identity, record["operation"], record["operation_id"], event_id,
                   record["previous_window"], record["previous_window_epoch"],
                   record["window"], record["window_epoch"],
                   record["authorization_digest"], record["campaign_id"],
                   record["supervisor_generation"], record["session_id"],
                   record["fence_epoch"])


@dataclass(frozen=True)
class PublicationReceipt:
    receipt_id: str
    destination: str
    object_key: str
    object_digest: str
    length: int
    state: str
    readback_digest: str

    def __post_init__(self):
        for name in ("receipt_id", "destination", "object_key"):
            _string(name, getattr(self, name))
        for name in ("object_digest", "readback_digest"):
            _string(name, getattr(self, name), digest=True)
        _integer("length", self.length)
        parse_state("publication", self.state)
        if self.state != "PUBLICATION_VERIFIED" or self.object_digest != self.readback_digest:
            raise ContractError("publication receipt not verified")


@dataclass(frozen=True)
class ClosureCandidate:
    kind: str
    digest: str
    bytes: bytes
    object_digests: Tuple[str, ...]

    def __post_init__(self):
        if self.kind not in ("boot", "campaign"):
            raise ContractError("closure candidate kind")
        _string("digest", self.digest, digest=True)
        if type(self.bytes) is not bytes:
            raise ContractError("closure candidate bytes")
        _tuple("object_digests", self.object_digests)
        for value in self.object_digests:
            _string("object_digest", value, digest=True)


@dataclass(frozen=True)
class ReapEvidence:
    receipt_digest: Optional[str]
    actual_wait: bool

    def __post_init__(self):
        if self.receipt_digest is not None:
            _string("reap receipt digest", self.receipt_digest, digest=True)
        _boolean("actual_wait", self.actual_wait)

    @property
    def proven(self):
        return self.receipt_digest is not None and self.actual_wait


@dataclass(frozen=True)
class ResidualEvidence:
    evidence_digest: Optional[str]
    sample_digests: Tuple[str, ...]
    span_ns: int
    complete_gpu_coverage: bool
    empty_cgroup: bool
    no_owned_descendants: bool

    def __post_init__(self):
        if self.evidence_digest is not None:
            _string("residual evidence digest", self.evidence_digest, digest=True)
        _tuple("sample_digests", self.sample_digests)
        for value in self.sample_digests:
            _string("residual sample digest", value, digest=True)
        _integer("span_ns", self.span_ns)
        for name in ("complete_gpu_coverage", "empty_cgroup", "no_owned_descendants"):
            _boolean(name, getattr(self, name))

    @property
    def proven(self):
        return (self.evidence_digest is not None and len(set(self.sample_digests)) >= 3 and
                self.span_ns >= 2_000_000_000 and self.complete_gpu_coverage and
                self.empty_cgroup and self.no_owned_descendants)


@dataclass(frozen=True)
class LocalAttemptEvidence:
    attempt_id: str
    core_bytes_digest: Optional[str]
    raw_evidence_digests: Tuple[str, ...]
    reap: ReapEvidence
    residual: ResidualEvidence
    immutable_storage_digest: Optional[str]
    readback_digest: Optional[str]
    completion_digest: Optional[str]
    disposition: str
    witnessed: bool
    durable: bool
    no_unresolved_worker: bool

    def __post_init__(self):
        _string("attempt_id", self.attempt_id)
        for name in ("core_bytes_digest", "immutable_storage_digest",
                     "readback_digest", "completion_digest"):
            value = getattr(self, name)
            if value is not None:
                _string(name, value, digest=True)
        _tuple("raw_evidence_digests", self.raw_evidence_digests)
        for value in self.raw_evidence_digests:
            _string("raw evidence digest", value, digest=True)
        if not isinstance(self.reap, ReapEvidence) or not isinstance(self.residual, ResidualEvidence):
            raise ContractError("reap and residual evidence")
        if self.disposition not in ("valid", "failed"):
            raise ContractError("attempt completion disposition")
        for name in ("witnessed", "durable", "no_unresolved_worker"):
            _boolean(name, getattr(self, name))

    @property
    def successor_eligible(self):
        return (self.disposition == "valid" and self.core_bytes_digest is not None and
                bool(self.raw_evidence_digests) and self.reap.proven and
                self.residual.proven and self.immutable_storage_digest is not None and
                self.readback_digest == self.immutable_storage_digest and
                self.completion_digest is not None and self.witnessed and self.durable and
                self.no_unresolved_worker)


# Revision 6 section 7.3: syntax only. Independent provenance is checked by RW.
RECOVERY_RECORD_FIELDS = {
    'RECOVERY_ENTRY': {'entry_refs', 'health_at_entry', 'latch_state', 'checkpoint_ref'},
    'RECOVERY_OBLIGATION': {'obligation_id', 'kind', 'reason_code', 'subject_refs', 'target_ref', 'status'},
    'RECOVERY_SUPPLEMENT': {'parent_ref', 'parent_digest', 'obligation_ref', 'obligation_link',
                            'supplement_kind', 'evidence', 'source_id', 'verifier_id'},
}
RECOVERY_OBLIGATION_REASONS = {
    'CONTAINMENT_UNAVAILABLE': frozenset(('CUSTODIAN_UNAVAILABLE', 'OWNERSHIP_UNPROVEN',
        'CAPABILITY_MISMATCH', 'ARTIFACT_MISMATCH', 'TARGET_IDENTITY_MISMATCH', 'REAP_UNPROVEN')),
    'PUBLICATION_UNVERIFIED': frozenset(('AUTHORIZATION_MISSING', 'DESTINATION_UNAUTHORIZED',
        'INTENT_UNPROVEN', 'RESERVATION_OWNER_MISMATCH', 'PARTIAL_OBJECT', 'CONTENT_MISMATCH',
        'DESTINATION_UNKNOWN', 'DESTINATION_REGISTRY_UNAVAILABLE', 'WRITER_FENCE_UNPROVEN',
        'READBACK_UNAVAILABLE', 'DURABILITY_UNPROVEN', 'OUTCOME_UNKNOWN')),
    'EFFECT_RESULT_UNRESOLVED': frozenset(('OUTCOME_UNKNOWN', 'ACCEPTED_NOT_STARTED',
        'RESULT_UNAVAILABLE', 'RESULT_PROVENANCE_MISMATCH')),
    'EVIDENCE_SERIALIZATION_FAILED': frozenset(('SERIALIZATION_FAILED', 'SOURCE_UNAVAILABLE',
        'SOURCE_PROVENANCE_MISMATCH')),
}
RECOVERY_SUPPLEMENT_KINDS = frozenset(('VERIFIED_EFFECT_RESULT', 'CONTAINMENT_EVIDENCE',
    'REAP_EVIDENCE', 'FAILURE_ENVELOPE', 'PUBLICATION_READBACK'))
RECOVERY_COMMON_FIELDS = frozenset(('schema_version', 'record_type', 'record_id',
    'store_identity', 'authorization_digest', 'campaign_id', 'writer_generation',
    'writer_incarnation_id', 'writer_session_id', 'writer_fence', 'authority_class',
    'authorizes_execution'))


def closed_canonical_bytes(value):
    def validate(x):
        if x is None or type(x) in (str, bool, int):
            return
        if type(x) in (list, tuple):
            for child in x: validate(child)
            return
        if type(x) is dict and all(type(k) is str for k in x):
            for child in x.values(): validate(child)
            return
        raise ContractError('closed canonical JSON value required')
    validate(value)
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def parse_closed_canonical(raw):
    if type(raw) is not bytes:
        raise ContractError('exact canonical bytes required')
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out: raise ContractError('duplicate key')
            out[k] = v
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
        if closed_canonical_bytes(value) != raw:
            raise ContractError('noncanonical encoding')
        return value
    except (ValueError, UnicodeError) as exc:
        raise ContractError('invalid canonical JSON') from exc


def _closed_reference(value, kind):
    cls = JournalReference if kind == 'Ref' else ImmutableObjectReference
    if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
        raise ContractError('closed nonnull ' + kind)
    return cls(**value)


def validate_recovery_record(value):
    if type(value) is not dict:
        raise ContractError('closed recovery record')
    kind = value.get('record_type')
    fields = RECOVERY_RECORD_FIELDS.get(kind)
    if (fields is None or set(value) != RECOVERY_COMMON_FIELDS | fields or
            value['schema_version'] != 'u04-record/v1' or
            value['authority_class'] != 'EVIDENCE' or value['authorizes_execution'] is not False):
        raise ContractError('closed RW record/class/schema')
    for n in ('record_id', 'store_identity', 'campaign_id', 'writer_incarnation_id', 'writer_session_id'):
        _string(n, value[n])
    _string('authorization_digest', value['authorization_digest'], digest=True)
    for n in ('writer_generation', 'writer_fence'): _integer(n, value[n], minimum=1)
    def refs(n):
        if type(value[n]) is not list: raise ContractError('canonical reference tuple')
        for r in value[n]: _closed_reference(r, 'Ref')
    if kind == 'RECOVERY_ENTRY':
        refs('entry_refs'); _closed_reference(value['checkpoint_ref'], 'Ref')
        if value['health_at_entry'] != 'HEALTHY' or value['latch_state'] not in ('CLEAR', 'SET'):
            raise ContractError('closed entry evidence state')
    elif kind == 'RECOVERY_OBLIGATION':
        _string('obligation_id', value['obligation_id']); refs('subject_refs')
        if (value['status'] != 'OPEN' or value['reason_code'] not in
                RECOVERY_OBLIGATION_REASONS.get(value['kind'], ())):
            raise ContractError('closed obligation kind/reason')
        target = value['target_ref']
        if type(target) is not dict or set(target) != {'kind', 'identity', 'destination_id',
                'object_key', 'subject_ref', 'subject_state', 'evidence_ref', 'evidence_state'}:
            raise ContractError('closed recovery Target')
        _string('target identity', target['identity'])
        if target['kind'] not in ('DESTINATION', 'CUSTODIAN', 'EFFECT', 'LOCAL_EVIDENCE'):
            raise ContractError('target kind')
        if target['kind'] == 'DESTINATION':
            _string('destination', target['destination_id']); _string('key', target['object_key'])
        elif target['destination_id'] is not None or target['object_key'] is not None:
            raise ContractError('target destination nullability')
        for state, ref, positive, negative, typ in (
                ('subject_state', 'subject_ref', 'KNOWN', 'UNKNOWN', 'Ref'),
                ('evidence_state', 'evidence_ref', 'AVAILABLE', 'UNAVAILABLE', 'Obj')):
            if target[state] == positive: _closed_reference(target[ref], typ)
            elif target[state] != negative or target[ref] is not None:
                raise ContractError('target reference nullability')
    else:
        _closed_reference(value['parent_ref'], 'Ref')
        _string('parent_digest', value['parent_digest'], digest=True)
        _closed_reference(value['evidence'], 'Obj')
        for n in ('source_id', 'verifier_id'): _string(n, value[n])
        if value['supplement_kind'] not in RECOVERY_SUPPLEMENT_KINDS:
            raise ContractError('closed supplement kind')
        if value['obligation_link'] == 'LINKED': _closed_reference(value['obligation_ref'], 'Ref')
        elif value['obligation_link'] != 'NONE' or value['obligation_ref'] is not None:
            raise ContractError('obligation link nullability')
    return value


SURVIVOR_DESCRIPTOR_FIELDS = frozenset(('schema_version', 'delegation_id', 'capability_id',
    'store_identity', 'authorization_digest', 'campaign_id', 'source_custodian_id',
    'source_custodian_incarnation', 'spawn_token', 'original_ownership_ref', 'original_creation_receipt',
    'process_identity', 'handle_domain_id', 'factory_identity', 'factory_epoch',
    'survivor_incarnation_number', 'original_generation', 'original_incarnation_id',
    'original_session_id', 'original_fence', 'artifact_binding', 'containment_port_id',
    'evidence_verifier_id', 'operation_id', 'action', 'may_wait', 'authorizes_execution'))
SURVIVOR_TRIGGER_FIELDS = frozenset(('schema_version', 'trigger_id', 'trigger_type',
    'store_identity', 'campaign_id', 'authorization_digest', 'spawn_token', 'target_identity_digest',
    'descriptor_digest', 'delegation_id', 'operation_id', 'survivor_incarnation',
    'source_custodian_id', 'source_custodian_incarnation', 'original_generation',
    'original_incarnation_id', 'original_session_id', 'original_fence', 'producer_id',
    'producer_epoch', 'trigger_sequence', 'observer_id', 'verifier_id', 'evidence_id',
    'evidence_sequence', 'evidence_digest', 'authorizes_execution'))
SURVIVOR_EVIDENCE_FIELDS = frozenset(('schema_version', 'evidence_id', 'evidence_sequence',
    'producer_id', 'producer_epoch', 'observer_id', 'verifier_id', 'descriptor_digest',
    'operation_id', 'event_kind', 'facts', 'authorizes_execution'))
SURVIVOR_EVENT_FACTS = {
    'SUPERVISOR_TERMINAL': frozenset(('lifetime_binding_id', 'lifetime_event_sequence',
        'original_generation', 'original_incarnation_id', 'original_session_id',
        'original_fence', 'terminal_state')),
    'CUSTODIAN_TERMINAL': frozenset(('lifetime_binding_id', 'lifetime_event_sequence',
        'source_custodian_id', 'source_custodian_incarnation', 'original_ownership_ref', 'terminal_state')),
    'REQUIRED_OWNERSHIP_INVALIDATED': frozenset(('ownership_binding_id', 'ownership_event_sequence',
        'source_custodian_id', 'source_custodian_incarnation', 'original_ownership_ref', 'binding_state')),
    'ORIGINAL_CLEANUP_REQUEST': frozenset(('request_id', 'request_sequence', 'failure_ref',
        'failure_payload_digest', 'original_generation', 'original_incarnation_id',
        'original_session_id', 'original_fence', 'requested_action')),
}


def survivor_digest(label, value):
    return hashlib.sha256(label.encode('ascii') + b'\0' + closed_canonical_bytes(value)).hexdigest()


def _closed_dataclass_record(value, cls):
    if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
        raise ContractError('exact closed ' + cls.__name__)
    value = dict(value)
    if cls is ProcessIdentity:
        if type(value['cgroup_members']) is not list:
            raise ContractError('canonical cgroup member tuple')
        value['cgroup_members'] = tuple(value['cgroup_members'])
    return cls(**value)


def validate_survivor_descriptor(raw):
    d = parse_closed_canonical(raw)
    if (type(d) is not dict or set(d) != SURVIVOR_DESCRIPTOR_FIELDS or
            d['schema_version'] != 'b-survivor-binding/v1' or d['action'] != 'CONTAIN_TOKEN_DOMAIN' or
            d['may_wait'] is not False or d['authorizes_execution'] is not False):
        raise ContractError('closed survivor descriptor')
    for n in SURVIVOR_DESCRIPTOR_FIELDS - {'spawn_token', 'process_identity', 'original_ownership_ref',
            'original_creation_receipt', 'artifact_binding', 'survivor_incarnation_number',
            'original_generation', 'original_fence', 'may_wait', 'authorizes_execution', 'schema_version'}:
        _string(n, d[n], digest=n=='authorization_digest')
    for n in ('survivor_incarnation_number', 'original_generation', 'original_fence'):
        _integer(n, d[n], minimum=1)
    token = _closed_dataclass_record(d['spawn_token'], SpawnToken)
    process = _closed_dataclass_record(d['process_identity'], ProcessIdentity)
    binding = _closed_dataclass_record(d['artifact_binding'], ArtifactBinding)
    _closed_reference(d['original_ownership_ref'], 'Ref')
    _closed_reference(d['original_creation_receipt'], 'Obj')
    if (token.token_id != process.spawn_token or token.custodian_id != d['source_custodian_id'] or
            process.custodian_id != token.custodian_id or token.campaign_id != d['campaign_id'] or
            process.boot_id != token.boot_id or token.supervisor_generation != d['original_generation'] or
            binding.authorization_digest != d['authorization_digest'] or binding.fence_epoch != d['original_fence'] or
            binding.session_id != d['original_session_id']):
        raise ContractError('descriptor subject/ownership/artifact substitution')
    incarnation = [d['factory_identity'], d['factory_epoch'], d['survivor_incarnation_number']]
    target = survivor_digest('b-survivor-target/v1', d['process_identity'])
    if d['operation_id'] != survivor_digest('b-survivor-operation/v1',
            [d['delegation_id'], incarnation, d['spawn_token'], target, d['action']]):
        raise ContractError('exact fixed survivor operation identity required')
    return d


def validate_survivor_trigger(trigger_raw, evidence_raw, descriptor_raw):
    d = validate_survivor_descriptor(descriptor_raw)
    t, e = parse_closed_canonical(trigger_raw), parse_closed_canonical(evidence_raw)
    if (type(t) is not dict or set(t) != SURVIVOR_TRIGGER_FIELDS or
            type(e) is not dict or set(e) != SURVIVOR_EVIDENCE_FIELDS or
            t['schema_version'] != 'b-survivor-trigger/v1' or
            e['schema_version'] != 'b-survivor-trigger-evidence/v1' or
            t['authorizes_execution'] is not False or e['authorizes_execution'] is not False):
        raise ContractError('closed survivor trigger/evidence')
    mapping = {'SUPERVISOR_TERMINAL': 'SUPERVISOR_LOSS', 'CUSTODIAN_TERMINAL': 'CUSTODIAN_LOSS',
        'REQUIRED_OWNERSHIP_INVALIDATED': 'CUSTODIAN_LOSS', 'ORIGINAL_CLEANUP_REQUEST': 'ORIGINAL_CLEANUP'}
    kind=e['event_kind']
    if kind not in mapping or t['trigger_type'] != mapping[kind]:
        raise ContractError('trigger/evidence discriminator')
    incarnation=[d['factory_identity'],d['factory_epoch'],d['survivor_incarnation_number']]
    producer=incarnation+['ORIGINAL_CLEANUP_BOUNDARY' if kind=='ORIGINAL_CLEANUP_REQUEST' else 'LIFECYCLE_OBSERVER']
    for n in ('trigger_sequence', 'evidence_sequence'):
        _integer(n,t[n],minimum=1)
    _integer('evidence_sequence',e['evidence_sequence'],minimum=1)
    for n in ('store_identity', 'campaign_id', 'authorization_digest', 'spawn_token', 'delegation_id',
              'operation_id', 'source_custodian_id', 'source_custodian_incarnation', 'original_generation',
              'original_incarnation_id', 'original_session_id', 'original_fence'):
        if t[n] != d[n]: raise ContractError('trigger subject substitution: '+n)
    for obj in (t,e):
        if (obj['producer_id'] != producer or obj['producer_epoch'] != d['factory_epoch'] or
                obj['observer_id'] != producer or obj['verifier_id'] != d['evidence_verifier_id'] or
                obj['descriptor_digest'] != survivor_digest('b-survivor-descriptor/v1',d) or
                obj['operation_id'] != d['operation_id']):
            raise ContractError('trigger producer/descriptor binding')
    if (t['survivor_incarnation'] != incarnation or
            t['target_identity_digest'] != survivor_digest('b-survivor-target/v1',d['process_identity']) or
            t['trigger_id'] != survivor_digest('b-survivor-trigger-id/v1',[producer,d['factory_epoch'],t['trigger_sequence']]) or
            e['evidence_id'] != survivor_digest('b-survivor-evidence-id/v1',[producer,d['factory_epoch'],e['evidence_sequence']]) or
            t['evidence_id'] != e['evidence_id'] or t['evidence_sequence'] != e['evidence_sequence'] or
            t['evidence_digest'] != survivor_digest('b-survivor-trigger-evidence/v1',e)):
        raise ContractError('trigger identity/evidence substitution')
    facts=e['facts']
    if type(facts) is not dict or set(facts) != SURVIVOR_EVENT_FACTS[kind]:
        raise ContractError('closed positive evidence facts')
    for n,v in facts.items():
        if n.endswith('_sequence') or n in ('original_generation','original_fence'):
            _integer(n,v,minimum=1)
        elif n.endswith('_ref'): _closed_reference(v,'Ref')
        else: _string(n,v)
        if n in d and v != d[n]: raise ContractError('evidence subject substitution')
    if kind in ('SUPERVISOR_TERMINAL','CUSTODIAN_TERMINAL') and facts['terminal_state'] != 'TERMINATED':
        raise ContractError('positive terminal fact required')
    if kind == 'REQUIRED_OWNERSHIP_INVALIDATED' and facts['binding_state'] != 'IRREVERSIBLY_INVALIDATED':
        raise ContractError('positive irreversible ownership invalidation required')
    if kind == 'ORIGINAL_CLEANUP_REQUEST' and (facts['requested_action'] != d['action'] or
            facts['failure_payload_digest'] != facts['failure_ref']['payload_digest']):
        raise ContractError('original exact failure proof required')
    return t,e
