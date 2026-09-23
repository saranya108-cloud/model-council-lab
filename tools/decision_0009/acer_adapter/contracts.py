"""Closed, offline-only contracts for the Decision 0009 Acer adapter.

This module contains data and validation only.  It has no host, process, CUDA,
NVML, filesystem-publication, network, or model-loading implementation.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping, Optional, Tuple


CORE_EXECUTION_COMMIT = "de04b26c14f7e7d60173f463e9d79f9b7134a700"
PROVENANCE_CANONICAL_HEAD = "724700217f8d7183757768fb2a856872b64a3cf3"
AUTHORIZATION_SCHEMA = "decision-0009-acer-authorization/v1"
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

    def __post_init__(self):
        if self.schema_version != AUTHORIZATION_SCHEMA:
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
        if not self.authenticated or not self.offline_only:
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
