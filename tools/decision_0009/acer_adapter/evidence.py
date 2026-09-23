"""Offline evidence, attribution, and immutable-publication models."""

from dataclasses import dataclass
import hashlib
import json

from .contracts import (
    ClosureCandidate, ContractError, EvidenceObject, GPUAttribution,
    ProcessIdentity, PublicationReceipt,
)


class EvidenceError(ValueError):
    pass


class AttributionUnavailable(EvidenceError):
    pass


class PublicationAcknowledgementLost(EvidenceError):
    def __init__(self, receipt):
        super().__init__("publication verification acknowledgement lost")
        self.receipt = receipt


def _sha(value):
    if type(value) is str:
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def canonical_core_bytes(value):
    try:
        _validate_shape(value)
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise EvidenceError("core evidence serialization failed") from exc


@dataclass(frozen=True)
class RawReference:
    object_id: str
    source_identity: str
    sequence: int
    received_ns: int
    declared_length: int
    retained_length: int
    retained_digest: str
    truncated: bool


@dataclass(frozen=True)
class NormalizedReference:
    raw_object_id: str
    raw_digest: str
    source_identity: str
    acquisition_sequence: int
    normalization_policy_digest: str
    value: bytes


@dataclass(frozen=True)
class PublicationIntent:
    intent_id: str
    destination: str
    object_key: str
    object_digest: str
    length: int
    bytes: bytes


class BoundedRawJournal:
    def __init__(self, max_frame_bytes=1_048_576, max_attempt_bytes=268_435_456):
        if (type(max_frame_bytes) is not int or type(max_attempt_bytes) is not int or
                max_frame_bytes < 1 or max_attempt_bytes < max_frame_bytes):
            raise EvidenceError("raw evidence bounds")
        self.max_frame_bytes = max_frame_bytes
        self.max_attempt_bytes = max_attempt_bytes
        self._bytes = {}
        self._retained = 0

    def capture(self, source_identity, raw, sequence, received_ns, declared_length=None):
        if (type(source_identity) is not str or type(raw) is not bytes or
                type(sequence) is not int or type(received_ns) is not int or
                sequence < 1 or received_ns < 0):
            raise EvidenceError("raw acquisition record")
        declared = len(raw) if declared_length is None else declared_length
        if type(declared) is not int or declared < len(raw):
            raise EvidenceError("declared frame length")
        remaining = self.max_attempt_bytes - self._retained
        retained = raw[:min(self.max_frame_bytes, max(0, remaining))]
        if not retained and raw:
            raise EvidenceError("raw evidence capacity exhausted")
        object_id = "raw-%d" % sequence
        if object_id in self._bytes:
            raise EvidenceError("raw acquisition sequence reused")
        self._bytes[object_id] = retained
        self._retained += len(retained)
        return RawReference(object_id, source_identity, sequence, received_ns,
                            declared, len(retained), _sha(retained),
                            len(retained) != declared)

    def read(self, reference):
        raw = self._bytes.get(reference.object_id)
        if raw is None or _sha(raw) != reference.retained_digest:
            raise EvidenceError("raw evidence readback mismatch")
        return raw


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def _validate_shape(value, depth=0):
    if depth > 32:
        raise EvidenceError("decoded nesting limit")
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise EvidenceError("invalid Unicode scalar value") from exc
        if len(encoded) > 65_536:
            raise EvidenceError("decoded string limit")
    elif type(value) in (list, tuple):
        if len(value) > 4_096:
            raise EvidenceError("decoded array limit")
        for item in value:
            _validate_shape(item, depth + 1)
    elif type(value) is dict:
        if len(value) > 4_096:
            raise EvidenceError("decoded object limit")
        for key, item in value.items():
            if type(key) is not str:
                raise EvidenceError("non-string key")
            _validate_shape(key, depth + 1)
            _validate_shape(item, depth + 1)
    elif type(value) is int:
        if value.bit_length() > 13_621:
            raise EvidenceError("decoded integer limit")
    elif value is not None and type(value) is not bool:
        raise EvidenceError("unsupported decoded value")


class EvidencePipeline:
    """Raw bytes -> normalized sidecar -> exact immutable core bytes."""

    def __init__(self, max_frame_bytes=1_048_576, max_attempt_bytes=268_435_456,
                 normalization_policy_digest=None):
        self.raw = BoundedRawJournal(max_frame_bytes, max_attempt_bytes)
        self.normalization_policy_digest = normalization_policy_digest or _sha("acer-normalization-v1")
        self._objects = {}

    def capture(self, *args, **kwargs):
        return self.raw.capture(*args, **kwargs)

    def decode(self, reference):
        if reference.truncated:
            raise EvidenceError("truncated raw frame is not decodable evidence")
        raw = self.raw.read(reference)
        try:
            text = raw.decode("utf-8", errors="strict")
            value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs,
                               parse_int=lambda value: int(value) if len(value.lstrip("-")) <= 4096
                               else (_ for _ in ()).throw(EvidenceError("decoded integer limit")),
                               parse_float=lambda value: (_ for _ in ()).throw(
                                   EvidenceError("floats are not accepted")),
                               parse_constant=lambda value: (_ for _ in ()).throw(
                                   EvidenceError("nonfinite values are not accepted")))
        except EvidenceError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise EvidenceError("malformed raw bytes") from exc
        _validate_shape(value)
        return value

    def normalize(self, reference, value):
        if type(value) is not dict:
            raise EvidenceError("normalized core input must be a closed mapping")
        _validate_shape(value)
        decoded = self.decode(reference)
        normalized_bytes = canonical_core_bytes(value)
        if canonical_core_bytes(decoded) != normalized_bytes:
            raise EvidenceError("normalized value does not correspond to retained raw bytes")
        return NormalizedReference(
            reference.object_id, reference.retained_digest,
            reference.source_identity, reference.sequence,
            self.normalization_policy_digest, normalized_bytes,
        )

    def freeze_core(self, value, normalized_reference):
        if not isinstance(normalized_reference, NormalizedReference):
            raise EvidenceError("normalization binding required")
        encoded = canonical_core_bytes(value)
        raw = self.raw._bytes.get(normalized_reference.raw_object_id)
        if (type(normalized_reference.value) is not bytes or raw is None or
                _sha(raw) != normalized_reference.raw_digest or
                canonical_core_bytes(self.decode(RawReference(
                    normalized_reference.raw_object_id,
                    normalized_reference.source_identity,
                    normalized_reference.acquisition_sequence, 0, len(raw), len(raw),
                    normalized_reference.raw_digest, False))) != normalized_reference.value or
                encoded != normalized_reference.value):
            raise EvidenceError("frozen core bytes do not match normalized input")
        digest = _sha(encoded)
        existing = self._objects.get(digest)
        if existing is not None and existing.bytes != encoded:
            raise EvidenceError("immutable digest collision")
        obj = EvidenceObject("core-" + digest[:16], digest, len(encoded), encoded)
        self._objects[digest] = obj
        return obj

    def readback(self, digest):
        obj = self._objects.get(digest)
        if obj is None or _sha(obj.bytes) != obj.digest:
            raise EvidenceError("local immutable readback failed")
        return obj.bytes


def _same_incarnation(left, right):
    fields = (
        "host_id", "boot_id", "host_pid", "pid_namespace", "namespace_pid",
        "process_start_ticks", "executable_path", "executable_device",
        "executable_inode", "executable_digest", "cgroup_path", "cgroup_device",
        "cgroup_inode", "cgroup_members", "custodian_id", "spawn_token", "gpu_uuid",
    )
    return all(getattr(left, name) == getattr(right, name) for name in fields)


def normalize_gpu_attribution(pre_identity, query, post_identity):
    """F8 exact worker attribution; unavailable observations raise explicitly."""
    if not isinstance(pre_identity, ProcessIdentity) or not isinstance(post_identity, ProcessIdentity):
        raise AttributionUnavailable("closed identity brackets required")
    if not pre_identity.alive or not post_identity.alive:
        raise AttributionUnavailable("worker exit during query")
    if not _same_incarnation(pre_identity, post_identity):
        raise AttributionUnavailable("PID, namespace, cgroup, executable, or GPU identity changed")
    if pre_identity.cgroup_members != (pre_identity.host_pid,):
        raise AttributionUnavailable("unaccounted helper or child in admitted worker cgroup")
    required = {"entries", "complete", "gpu_uuid", "api_families", "api_identity",
                "api_version", "error", "pre_observed_ns", "start_ns", "end_ns",
                "post_observed_ns", "received_ns", "pid_namespace", "namespace_pid",
                "cgroup_path", "domain_members"}
    if type(query) is not dict or set(query) != required:
        raise AttributionUnavailable("closed GPU query record required")
    if (type(query["complete"]) is not bool or not query["complete"] or
            query["error"] is not None):
        raise AttributionUnavailable("GPU accounting unavailable or partial")
    if query["gpu_uuid"] != pre_identity.gpu_uuid:
        raise AttributionUnavailable("wrong GPU UUID")
    if (query["pid_namespace"] != pre_identity.pid_namespace or
            query["namespace_pid"] != pre_identity.namespace_pid or
            query["cgroup_path"] != pre_identity.cgroup_path or
            query["domain_members"] != pre_identity.cgroup_members):
        raise AttributionUnavailable("namespace translation or admitted membership mismatch")
    if (type(query["api_families"]) is not tuple or
            set(query["api_families"]) != {"nvml-compute", "nvml-graphics"} or
            type(query["entries"]) is not tuple or
            type(query["api_identity"]) is not str or not query["api_identity"] or
            type(query["api_version"]) is not str or not query["api_version"] or
            any(type(query[name]) is not int for name in
                ("pre_observed_ns", "start_ns", "end_ns", "post_observed_ns", "received_ns")) or
            not (query["pre_observed_ns"] <= query["start_ns"] <= query["end_ns"] <=
                 query["post_observed_ns"] <= query["received_ns"])):
        raise AttributionUnavailable("GPU API coverage or query bracket")
    matches = []
    for entry in query["entries"]:
        if type(entry) is not dict or set(entry) != {
                "host_pid", "start_ticks", "gpu_uuid", "context_id", "used_bytes"}:
            raise AttributionUnavailable("malformed GPU accounting entry")
        if entry["host_pid"] == pre_identity.host_pid:
            if (entry["start_ticks"] != pre_identity.process_start_ticks or
                    entry["gpu_uuid"] != pre_identity.gpu_uuid):
                raise AttributionUnavailable("PID reuse or GPU identity conflict")
            if type(entry["context_id"]) is not str or not entry["context_id"]:
                raise AttributionUnavailable("context identity unavailable")
            if type(entry["used_bytes"]) is not int or entry["used_bytes"] < 0:
                raise AttributionUnavailable("accounting sentinel or unsupported field")
            matches.append(entry)
        else:
            raise AttributionUnavailable("unaccounted helper or child in worker domain")
    if not matches:
        raise AttributionUnavailable("exact worker accounting absent")
    unique = {(entry["context_id"], entry["used_bytes"]) for entry in matches}
    if len(unique) != 1:
        raise AttributionUnavailable("multiple or conflicting worker accounting entries")
    _, used_bytes = next(iter(unique))
    return GPUAttribution(True, used_bytes, None, len(query["entries"]),
                          pre_identity.gpu_uuid, pre_identity.host_pid,
                          pre_identity.process_start_ticks)


def enforce_f5_mapping(expected, observed):
    families = {"libcudart", "libcublasLt", "libcublas", "libcuda"}
    if type(expected) is not dict or type(observed) is not dict:
        raise AttributionUnavailable("mapping proof structures")
    if set(expected) != families or set(observed) != families:
        raise AttributionUnavailable("mapping families must be exact")
    for family in families:
        if (type(observed[family]) is not str or not observed[family] or
                observed[family] != expected[family]):
            raise AttributionUnavailable("observed mapping proof unavailable or mismatched")
    return True


class ImmutablePublication:
    """Lifecycle-bound exclusive publication with explicit durability states."""

    def __init__(self, authority=None):
        if (authority is None or not callable(getattr(authority, "publication_binding", None)) or
                not callable(getattr(authority, "perform_publication", None)) or
                not callable(getattr(authority, "publication_snapshot", None))):
            raise EvidenceError("authoritative publication supervisor required")
        self._intents = {}
        self._objects = {}
        self._durable = set()
        self._receipts = {}
        self._states = {}
        self._authority = authority
        self._authority_binding = authority.publication_binding()
        self._restore(authority.publication_snapshot(self._authority_binding))

    def _restore(self, records):
        if type(records) is not list:
            raise EvidenceError("authoritative publication snapshot required")
        self._intents = {}
        self._objects = {}
        self._durable = set()
        self._receipts = {}
        self._states = {}
        for record in records:
            if type(record) is not dict:
                raise EvidenceError("malformed publication snapshot")
            state = record.get("state")
            key = (record.get("destination"), record.get("object_key"))
            if state == "PUBLICATION_INTENT":
                source = record.get("source_bytes")
                if (type(source) is not bytes or len(source) != record.get("length") or
                        _sha(source) != record.get("object_digest")):
                    raise EvidenceError("publication source reconstruction failed")
                intent = PublicationIntent(
                    record["intent_id"], key[0], key[1], record["object_digest"],
                    record["length"], source)
                prior = self._intents.get(key)
                if prior is not None and prior != intent:
                    raise EvidenceError("publication intent reconstruction collision")
                self._intents[key] = intent
                continue
            intent = self._intents.get(key)
            if intent is None or record.get("intent_id") != intent.intent_id:
                raise EvidenceError("publication transition lacks exact intent")
            if state == "EXCLUSIVE_CREATE":
                if self._states.get(key) is not None:
                    raise EvidenceError("exclusive reservation reconstruction failed")
                self._states[key] = "RESERVED"
            elif state == "PUBLICATION_WRITTEN":
                if self._states.get(key) != "RESERVED" or type(record.get("written_bytes")) is not bytes:
                    raise EvidenceError("written publication reconstruction failed")
                self._objects[key] = record["written_bytes"]
                self._states[key] = "WRITTEN"
            elif state == "DURABLE_BYTES":
                if self._states.get(key) != "WRITTEN" or key not in self._objects:
                    raise EvidenceError("durable publication reconstruction failed")
                self._durable.add(key)
                self._states[key] = "DURABLE"
            elif state == "PUBLICATION_VERIFIED":
                if (self._states.get(key) != "DURABLE" or key not in self._durable or
                        self._objects.get(key) != intent.bytes):
                    raise EvidenceError("verified publication reconstruction failed")
                receipt = PublicationReceipt(
                    "publication-receipt-" + intent.object_digest[:16],
                    intent.destination, intent.object_key, intent.object_digest,
                    intent.length, "PUBLICATION_VERIFIED", intent.object_digest)
                self._receipts[key] = receipt
                self._states[key] = "VERIFIED"
            else:
                raise EvidenceError("unknown publication reconstruction state")

    def _operate(self, operation, intent, interlock=None, payload=None):
        try:
            grant = self._authority.issue_publication_grant(
                self._authority_binding, operation, intent)
            result = self._authority.perform_publication(
                self._authority_binding, grant, intent, payload=payload,
                interlock=interlock)
            self._restore(self._authority.publication_snapshot(
                self._authority_binding))
            return result
        except (ContractError, RuntimeError) as exc:
            raise EvidenceError("publication authority rejected operation") from exc

    def _require_intent(self, intent):
        if not isinstance(intent, PublicationIntent):
            raise EvidenceError("authorized publication intent required")
        key = (intent.destination, intent.object_key)
        if self._intents.get(key) != intent:
            raise EvidenceError("authorized publication intent required")
        return key

    def intent(self, destination, object_key, bytes_value, interlock=None):
        if type(destination) is not str or type(object_key) is not str or type(bytes_value) is not bytes:
            raise EvidenceError("publication intent")
        digest = _sha(bytes_value)
        identity = _sha(destination + "\0" + object_key + "\0" + digest)
        intent = PublicationIntent("publish-" + identity[:16], destination, object_key,
                                   digest, len(bytes_value), bytes_value)
        previous = self._intents.get((destination, object_key))
        if previous is not None and previous != intent:
            raise EvidenceError("publication intent collision")
        if previous is not None:
            return previous
        self._operate("intent", intent, interlock=interlock,
                      payload=bytes_value)
        return intent

    def exclusive_create(self, intent, interlock=None):
        key = self._require_intent(intent)
        if key in self._states:
            raise EvidenceError("exclusive object already exists")
        return self._operate("create", intent, interlock=interlock)

    def write(self, intent, bytes_value, allow_partial=False, interlock=None):
        key = self._require_intent(intent)
        if self._states.get(key) != "RESERVED":
            raise EvidenceError("exclusive create required")
        if not allow_partial and bytes_value != intent.bytes:
            raise EvidenceError("publication bytes differ from intent")
        return self._operate("write", intent, interlock=interlock,
                             payload=bytes_value)

    def make_durable(self, intent, interlock=None):
        key = self._require_intent(intent)
        if self._states.get(key) != "WRITTEN" or key not in self._objects:
            raise EvidenceError("written publication required")
        return self._operate("durable", intent, interlock=interlock)

    def write_durable(self, intent, bytes_value, allow_partial=False):
        self.write(intent, bytes_value, allow_partial=allow_partial)
        return self.make_durable(intent)

    def verify(self, intent, lose_ack=False, interlock=None):
        key = self._require_intent(intent)
        if key not in self._durable or self._states.get(key) != "DURABLE":
            raise EvidenceError("durable publication acknowledgement missing")
        readback = self._objects.get(key)
        if readback != intent.bytes or _sha(readback) != intent.object_digest:
            raise EvidenceError("external publication readback mismatch")
        receipt = self._operate("verify", intent, interlock=interlock)
        if lose_ack:
            raise PublicationAcknowledgementLost(receipt)
        return receipt

    def reconcile(self, intent, interlock=None):
        key = self._require_intent(intent)
        try:
            self._restore(self._authority.publication_snapshot(
                self._authority_binding))
        except (ContractError, RuntimeError) as exc:
            raise EvidenceError("publication authority rejected reconciliation") from exc
        if key in self._receipts:
            return self._receipts[key]
        return self._states.get(key, "INTENT")


class PublicationScheduler:
    MEASURED_WINDOWS = frozenset(("MEASURED_PREPARATION", "DWELL", "RESIDUAL_CLEARANCE"))

    def schedule(self, window, publication_operation):
        if window in self.MEASURED_WINDOWS:
            raise EvidenceError("external publication prohibited during measured window")
        if window != "OUTSIDE_MEASURED_WINDOWS":
            raise EvidenceError("unknown scheduling window")
        return publication_operation


def build_closure_candidate(kind, payload):
    if kind not in ("boot", "campaign") or type(payload) is not dict:
        raise EvidenceError("closure candidate")
    forbidden = {"BOOT_COMPLETE", "CAMPAIGN_COMPLETE", "publication_receipt"}
    _validate_shape(payload)
    encoded_payload = canonical_core_bytes(payload)
    if any(name.encode("utf-8") in encoded_payload for name in forbidden):
        raise EvidenceError("closure candidate circularity")
    object_values = payload.get("objects")
    if type(object_values) not in (list, tuple) or not object_values:
        raise EvidenceError("closure object manifest")
    object_digests = tuple(_sha(canonical_core_bytes(value)) for value in object_values)
    record = {"candidate_type": kind, "payload": payload,
              "object_digests": list(object_digests)}
    encoded = canonical_core_bytes(record)
    return ClosureCandidate(kind, _sha(encoded), encoded, object_digests)


def complete_closure(candidate, publication_receipt, revision, fence_epoch, tainted):
    if not isinstance(candidate, ClosureCandidate):
        raise EvidenceError("persisted closure candidate required")
    receipts = (publication_receipt,) if isinstance(publication_receipt, PublicationReceipt) else publication_receipt
    if (type(receipts) is not tuple or
            any(not isinstance(receipt, PublicationReceipt) for receipt in receipts)):
        raise EvidenceError("verified publication receipts required")
    if type(revision) is not int or type(fence_epoch) is not int or type(tainted) is not bool:
        raise EvidenceError("closure revision/fence/taint types")
    if tainted:
        raise EvidenceError("intervening taint prevents closure")
    digests = [receipt.object_digest for receipt in receipts]
    required = [candidate.digest, *candidate.object_digests]
    if len(digests) != len(required) or sorted(digests) != sorted(required):
        raise EvidenceError("publication receipts do not cover exact candidate manifest")
    candidate_receipt = next(receipt for receipt in receipts
                             if receipt.object_digest == candidate.digest)
    return {"state": "BOOT_COMPLETE" if candidate.kind == "boot" else "CAMPAIGN_COMPLETE",
            "candidate_digest": candidate.digest,
            "candidate_kind": candidate.kind,
            "publication_receipt_id": candidate_receipt.receipt_id,
            "publication_manifest": sorted(digests),
            "revision": revision, "fence_epoch": fence_epoch}
