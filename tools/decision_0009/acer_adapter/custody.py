"""Offline custodian model for Decision 0009.

The classes here simulate ownership and failure semantics.  They never create a
real process, send a signal, touch a cgroup, or call a host/vendor API.
"""

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import threading

from .contracts import (
    ArtifactBinding, CustodianReceipt, CustodyError, EffectCapability,
    ProcessIdentity, ReapReceipt, SpawnToken,
)


class ContainmentUnavailable(CustodyError):
    pass


@dataclass(frozen=True)
class ContainmentEvidence:
    evidence_id: str
    actor_identity: str
    spawn_token: str
    action: str
    target_pid: int
    target_start_ticks: int
    custody_uncertain: bool


@dataclass(frozen=True)
class SurvivorTransfer:
    transfer_id: str
    source_custodian: str
    survivor_identity: str
    spawn_token: str
    process_identity: ProcessIdentity
    authority_digest: str
    fence_epoch: int
    session_id: str
    artifact_binding: ArtifactBinding
    recovery_capability_digest: str


@dataclass(frozen=True)
class BootCustodyAttestation:
    """Custodian-issued boot custody evidence.

    It names the live custodian bound to the authoritative store, that
    custodian's ready watchdog, and a separately identified isolated observer,
    and it is bound to the exact store, authorization, campaign, boot, supervisor
    generation, session, and fence.  The custodian registry retains it, so the
    custody-state boundary and reconstruction can re-check it.
    """
    attestation_id: str
    custodian_id: str
    watchdog_id: str
    observer_id: str
    store_identity: str
    authorization_digest: str
    campaign_id: str
    boot_id: str
    boot_ordinal: int
    supervisor_generation: int
    session_id: str
    fence_epoch: int
    custody_proof_digest: str
    observer_isolated: bool
    watchdog_ready: bool

    def record(self):
        return asdict(self)


@dataclass
class _Worker:
    token: SpawnToken
    identity: ProcessIdentity
    status: str = "BLOCKED"
    possibly_live: bool = True
    released: bool = False
    contained: bool = False
    reaped: bool = False
    receipt: CustodianReceipt = None
    reap_receipt: ReapReceipt = None


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class OfflineCustodian:
    """Independent-lifetime fake with a durable token registry."""

    def __init__(self, identity):
        if type(identity) is not str or not identity:
            raise CustodyError("custodian identity")
        self.identity = identity
        self._registry = {}
        self._create_counts = {}
        self._lock = threading.Lock()
        self.alive = True
        self.current_store_revision = 0
        self.first_create_observed_store_revision = None
        self._store = None
        self._loss_callback = None
        self._boot_custody = {}

    @property
    def watchdog_identity(self):
        return self.identity + "/watchdog"

    def bind_authority(self, store, loss_callback):
        if store is None or not callable(loss_callback):
            raise CustodyError("custodian authority binding")
        if self._store is not None and self._store is not store:
            raise CustodyError("custodian authority already bound")
        bind_custodian = getattr(store, "bind_custodian", None)
        if callable(bind_custodian):
            try:
                bind_custodian(self)
            except Exception as exc:
                raise CustodyError("store is bound to another custodian") from exc
        self._store = store
        self._loss_callback = loss_callback

    def attest_boot_custody(self, *, store_identity, authorization_digest, campaign_id,
                            boot_id, boot_ordinal, supervisor_generation, session_id,
                            fence_epoch, observer_id, custody_proof, observer_isolated,
                            watchdog_ready):
        """Issue and retain boot custody evidence for the bound store."""
        if self._store is None or getattr(self._store, "identity", None) != store_identity:
            raise CustodyError("custody attestation requires the bound authoritative store")
        self._ensure_live()
        if observer_isolated is not True or watchdog_ready is not True:
            raise CustodyError("custody readiness")
        for value in (store_identity, authorization_digest, campaign_id, boot_id,
                      session_id, observer_id, custody_proof):
            if type(value) is not str or not value:
                raise CustodyError("custody attestation identity")
        for value in (boot_ordinal, supervisor_generation, fence_epoch):
            if type(value) is not int or value < 1:
                raise CustodyError("custody attestation identity")
        if observer_id in (self.identity, self.watchdog_identity):
            raise CustodyError("observer is not isolated from custody")
        fields = {
            "custodian_id": self.identity, "watchdog_id": self.watchdog_identity,
            "observer_id": observer_id, "store_identity": store_identity,
            "authorization_digest": authorization_digest, "campaign_id": campaign_id,
            "boot_id": boot_id, "boot_ordinal": boot_ordinal,
            "supervisor_generation": supervisor_generation, "session_id": session_id,
            "fence_epoch": fence_epoch, "custody_proof_digest": _digest(custody_proof),
            "observer_isolated": True, "watchdog_ready": True,
        }
        attestation_id = "boot-custody-" + _digest(
            json.dumps(fields, sort_keys=True, separators=(",", ":")))[:24]
        attestation = BootCustodyAttestation(attestation_id=attestation_id, **fields)
        with self._lock:
            existing = self._boot_custody.get(attestation_id)
            if existing is not None and existing != attestation:
                raise CustodyError("custody attestation collision")
            self._boot_custody[attestation_id] = attestation
        return attestation

    def boot_custody_attestation(self, attestation_id):
        return self._boot_custody.get(attestation_id)

    def observe_store_revision(self, revision):
        if type(revision) is not int or revision < 0:
            raise CustodyError("store revision")
        self.current_store_revision = revision

    def _ensure_live(self):
        if not self.alive:
            raise ContainmentUnavailable("custodian ownership is unavailable")

    def create_once(self, token, launch_spec_digest, consumed_capability_receipt,
                    artifact_binding, fault=None):
        if self._store is None:
            raise CustodyError("authoritative durable store binding required")
        if not isinstance(token, SpawnToken) or token.custodian_id != self.identity:
            raise CustodyError("spawn token custodian")
        if not isinstance(consumed_capability_receipt, EffectCapability):
            raise CustodyError("consumed capability receipt")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("fresh artifact binding required")
        if (not consumed_capability_receipt.consumed or
                consumed_capability_receipt.target != self.identity or
                consumed_capability_receipt.operation != "blocked-create" or
                consumed_capability_receipt.artifact_binding != artifact_binding or
                consumed_capability_receipt.fence_epoch != artifact_binding.fence_epoch or
                consumed_capability_receipt.session_id != artifact_binding.session_id or
                consumed_capability_receipt.supervisor_generation !=
                token.supervisor_generation):
            raise CustodyError("capability is not bound to this durable create")
        self._ensure_live()
        with self._store.authorization_lock:
            try:
                intent = self._store.effect_intent(consumed_capability_receipt)
            except Exception as exc:
                raise CustodyError("healthy witnessed effect intent required") from exc
            if (intent.get("state") != "SPAWN_INTENT_PERSISTED" or
                    intent.get("spawn_token") != token.token_id or
                    intent.get("campaign_id") != token.campaign_id or
                    intent.get("boot_id") != token.boot_id or
                    intent.get("slot_id") != token.slot_id or
                    intent.get("attempt_id") != token.attempt_id or
                    intent.get("custodian_id") != token.custodian_id or
                    intent.get("launch_spec_digest") != token.launch_spec_digest or
                    intent.get("launch_spec_digest") != launch_spec_digest or
                    intent.get("session_id") != consumed_capability_receipt.session_id or
                    intent.get("fence_epoch") != consumed_capability_receipt.fence_epoch or
                    intent.get("supervisor_generation") != token.supervisor_generation or
                    intent.get("authorization_digest") !=
                    consumed_capability_receipt.authorization_digest):
                raise CustodyError("durable spawn intent does not bind complete token identity")
            # The successor invariant is enforced here, at the authoritative
            # mutation boundary: a store-backed slot capability reserved for exactly
            # this effect (slot, attempt, boot, campaign, predecessor, generation,
            # token, launch spec, custodian) must exist.  A label is never enough.
            try:
                self._store.creation_slot_grant(consumed_capability_receipt, token)
            except Exception as exc:
                raise CustodyError("reserved store slot capability required") from exc
            status = self._store.effect_status(consumed_capability_receipt)
            if status == "KNOWN_RESULT":
                envelope = self._store.effect_result(
                    consumed_capability_receipt.effect_id)
                existing = self._registry.get(token.token_id)
                if (existing is None or existing.token != token or
                        existing.receipt != envelope.receipt):
                    raise CustodyError("known result lacks exact custodian registry evidence")
                return existing.receipt
            if status in ("UNRESOLVED", "ACCEPTANCE_PENDING"):
                raise CustodyError("unresolved effect cannot create")
            if not self._store.creation_grant_active(consumed_capability_receipt):
                raise CustodyError("active first-dispatch creation grant required")
            if launch_spec_digest != token.launch_spec_digest:
                raise CustodyError("launch specification mismatch")
            with self._lock:
                existing = self._registry.get(token.token_id)
                if existing is not None:
                    raise CustodyError("unregistered existing effect is ambiguous")
                try:
                    accepted = self._store.accept_effect(consumed_capability_receipt)
                except Exception as exc:
                    raise CustodyError("capability was not accepted by authoritative store") from exc
                if accepted != intent:
                    raise CustodyError("accepted effect intent changed")
                if fault == "crash_after_acceptance":
                    self._store.mark_effect_unresolved(consumed_capability_receipt)
                    raise CustodyError("accepted effect result is unresolved")
                self._create_counts[token.token_id] = 1
                if self.first_create_observed_store_revision is None:
                    self.first_create_observed_store_revision = self.current_store_revision
                ordinal = len(self._registry) + 1
                pid = 10_000 + ordinal
                process = ProcessIdentity(
                    host_id="offline-host", boot_id=token.boot_id, host_pid=pid,
                    pid_namespace="offline-pidns", namespace_pid=1,
                    process_start_ticks=50_000 + ordinal,
                    executable_path="/offline/blocked-worker", executable_device=1,
                    executable_inode=100 + ordinal,
                    executable_digest=_digest("offline-worker"),
                    cgroup_path="/offline/workers/" + token.token_id,
                    cgroup_device=1, cgroup_inode=200 + ordinal,
                    cgroup_members=(pid,), custodian_id=self.identity,
                    spawn_token=token.token_id,
                    gpu_uuid="GPU-beba5a2f-9130-d279-5639-9ffda0d4e464", alive=True,
                )
                status = "UNKNOWN" if fault == "ambiguous_after_create" else "BLOCKED"
                receipt = CustodianReceipt(
                    receipt_id="create-" + token.token_id, custodian_id=self.identity,
                    spawn_token=token.token_id, launch_spec_digest=launch_spec_digest,
                    status=status, process_identity=process, possibly_live=True,
                )
                self._registry[token.token_id] = _Worker(token, process, status=status,
                                                          receipt=receipt)
                try:
                    self._store.record_effect_result(consumed_capability_receipt,
                                                     receipt)
                except Exception:
                    self._store.mark_effect_unresolved(consumed_capability_receipt)
                    raise
                return receipt

    def inspect_spawn(self, spawn_token):
        if type(spawn_token) is not str:
            raise CustodyError("spawn token")
        worker = self._registry.get(spawn_token)
        if worker is None:
            return CustodianReceipt("inspect-absent-" + spawn_token, self.identity,
                                    spawn_token, _digest("absent"), "FAILED_NO_CHILD",
                                    None, False)
        return CustodianReceipt(
            "inspect-" + spawn_token, self.identity, spawn_token,
            worker.token.launch_spec_digest, worker.status, worker.identity,
            worker.possibly_live,
        )

    def contain_spawn(self, spawn_token, recovery_capability, artifact_binding):
        self._ensure_live()
        if type(recovery_capability) is not str or not recovery_capability:
            raise CustodyError("recovery capability")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("containment artifact binding")
        with self._lock:
            worker = self._registry.get(spawn_token)
            if worker is None:
                raise ContainmentUnavailable("token-owned survivor unavailable")
            worker.contained = True
            worker.status = "EXITED"
            worker.possibly_live = False
            worker.identity = replace(worker.identity, alive=False)
            worker.receipt = CustodianReceipt(
                "contained-" + spawn_token, self.identity, spawn_token,
                worker.token.launch_spec_digest, "EXITED", worker.identity, False,
            )
            return ContainmentEvidence(
                "contain-" + spawn_token, self.identity, spawn_token, "CONTAIN",
                worker.identity.host_pid, worker.identity.process_start_ticks, False,
            )

    def watchdog_supervisor_lost(self, spawn_token, artifact_binding):
        return self.contain_spawn(spawn_token, "watchdog-containment", artifact_binding)

    def wait_reap(self, spawn_token):
        self._ensure_live()
        with self._lock:
            worker = self._registry.get(spawn_token)
            if worker is None or worker.status != "EXITED":
                raise CustodyError("actual exited child required before wait")
            if worker.reap_receipt is None:
                worker.reaped = True
                worker.status = "REAPED"
                worker.reap_receipt = ReapReceipt(
                    "reap-" + spawn_token, self.identity, spawn_token,
                    worker.identity.host_pid, worker.identity.process_start_ticks,
                    1, True,
                )
            return worker.reap_receipt

    def get_reap_receipt(self, spawn_token):
        worker = self._registry.get(spawn_token)
        return None if worker is None else worker.reap_receipt

    def validate_reap_receipt(self, receipt):
        if not isinstance(receipt, ReapReceipt):
            raise CustodyError("reap receipt type")
        worker = self._registry.get(receipt.spawn_token)
        if (worker is None or worker.reap_receipt != receipt or
                receipt.custodian_id != self.identity or not worker.reaped):
            raise CustodyError("reap receipt does not match custodian registry")
        return True

    def export_survivor_ownership(self, spawn_token, survivor,
                                  recovery_capability="contain-capability"):
        self._ensure_live()
        worker = self._registry.get(spawn_token)
        if worker is None:
            raise ContainmentUnavailable("worker absent")
        if not isinstance(survivor, OfflineSurvivor) or not survivor.alive:
            raise ContainmentUnavailable("separate survivor unavailable")
        authority = _digest(survivor.authority)
        if self._store is None or type(recovery_capability) is not str or not recovery_capability:
            raise ContainmentUnavailable("authoritative survivor transfer unavailable")
        sessions = [session for session in self._store._sessions.values()
                    if session.execution_live and
                    session.fence_epoch == self._store.witness.current_fence]
        if len(sessions) != 1:
            raise ContainmentUnavailable("unique current execution session required")
        session = sessions[0]
        transfer = SurvivorTransfer(
            "transfer-" + spawn_token, self.identity, survivor.identity, spawn_token,
            worker.identity, authority, self._store.witness.current_fence,
            session.session_id, survivor.artifact_binding,
            _digest(recovery_capability),
        )
        artifact_digest = _digest(repr(transfer.artifact_binding))
        self._store.append_nonauthorizing(
            transfer.fence_epoch,
            "survivor-transfer-%s-%d" % (spawn_token, self._store.revision + 1),
            {"record_type": "SURVIVOR_TRANSFER", "transfer_id": transfer.transfer_id,
             "source_custodian": transfer.source_custodian,
             "survivor_identity": transfer.survivor_identity,
             "spawn_token": transfer.spawn_token,
             "host_pid": transfer.process_identity.host_pid,
             "process_start_ticks": transfer.process_identity.process_start_ticks,
             "authority_digest": transfer.authority_digest,
             "artifact_digest": artifact_digest,
             "recovery_capability_digest": transfer.recovery_capability_digest,
             "fence_epoch": transfer.fence_epoch, "session_id": transfer.session_id},
        )
        survivor.register_transfer(transfer, self._store)
        return transfer

    def die(self):
        if not self.alive:
            return
        self.alive = False
        if self._loss_callback is not None:
            self._loss_callback("custodian-death")

    def underlying_create_count(self, spawn_token):
        return self._create_counts.get(spawn_token, 0)

    def underlying_create_count_for_all(self):
        return sum(self._create_counts.values())


class OfflineSurvivor:
    """Separate fake actor; possession and authority are explicit."""

    def __init__(self, identity, authority, artifact_binding):
        if type(identity) is not str or type(authority) is not str:
            raise CustodyError("survivor identity/authority")
        if not isinstance(artifact_binding, ArtifactBinding):
            raise CustodyError("survivor artifact binding")
        self.identity = identity
        self.authority = authority
        self.artifact_binding = artifact_binding
        self.alive = True
        self._acted = set()
        self._transfers = {}
        self._store = None

    def register_transfer(self, transfer, store):
        if not isinstance(transfer, SurvivorTransfer) or store is None:
            raise ContainmentUnavailable("authoritative transfer registration")
        self._store = store
        self._transfers[transfer.transfer_id] = transfer

    def contain_transferred(self, transfer, recovery_capability):
        if not self.alive or not isinstance(transfer, SurvivorTransfer):
            raise ContainmentUnavailable("survivor unavailable")
        if transfer.survivor_identity != self.identity:
            raise ContainmentUnavailable("survivor has no ownership rights")
        if transfer.authority_digest != _digest(self.authority):
            raise ContainmentUnavailable("survivor authority does not match transfer")
        if type(recovery_capability) is not str or not recovery_capability:
            raise CustodyError("survivor recovery capability")
        if (self._store is None or self._transfers.get(transfer.transfer_id) != transfer or
                transfer.artifact_binding != self.artifact_binding or
                transfer.fence_epoch != self._store.witness.current_fence or
                transfer.session_id not in self._store._sessions or
                transfer.recovery_capability_digest != _digest(recovery_capability) or
                transfer.process_identity.spawn_token != transfer.spawn_token):
            raise ContainmentUnavailable("forged, stale, or unauthorized survivor transfer")
        authoritative = [event for event in self._store.events
                         if event.get("record_type") == "SURVIVOR_TRANSFER" and
                         event.get("transfer_id") == transfer.transfer_id]
        if (len(authoritative) != 1 or
                authoritative[0].get("source_custodian") != transfer.source_custodian or
                authoritative[0].get("survivor_identity") != transfer.survivor_identity or
                authoritative[0].get("spawn_token") != transfer.spawn_token or
                authoritative[0].get("host_pid") != transfer.process_identity.host_pid or
                authoritative[0].get("process_start_ticks") !=
                transfer.process_identity.process_start_ticks or
                authoritative[0].get("authority_digest") != transfer.authority_digest or
                authoritative[0].get("artifact_digest") !=
                _digest(repr(transfer.artifact_binding)) or
                authoritative[0].get("recovery_capability_digest") !=
                transfer.recovery_capability_digest):
            raise ContainmentUnavailable("survivor transfer does not match durable ownership record")
        if transfer.spawn_token in self._acted:
            raise CustodyError("survivor action already performed")
        self._acted.add(transfer.spawn_token)
        return ContainmentEvidence(
            "survivor-contain-" + transfer.spawn_token, self.identity,
            transfer.spawn_token, "CONTAIN", transfer.process_identity.host_pid,
            transfer.process_identity.process_start_ticks, True,
        )
