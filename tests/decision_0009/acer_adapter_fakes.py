"""Deterministic offline fixtures for the Decision 0009 Acer adapter."""

from dataclasses import replace
import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path

from tools.decision_0009.acer_adapter.contracts import (
    ArtifactBinding,
    Authorization,
    BootActivation,
    EffectCapability,
    FenceSession,
    LocalAttemptEvidence,
    ProcessIdentity,
    ReapEvidence,
    ResidualEvidence,
    SlotSpec,
    SpawnToken,
)


CORE_COMMIT = "de04b26c14f7e7d60173f463e9d79f9b7134a700"
GPU_UUID = "GPU-beba5a2f-9130-d279-5639-9ffda0d4e464"


def digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class MutableArtifacts:
    def __init__(self):
        self.values = {
            "core": {"commit": CORE_COMMIT,
                     "files": {"core/policy.py": b"accepted core bytes\n"}},
            "adapter": {"files": {"adapter/supervisor.py": b"adapter bytes\n"}},
            "policy": b"policy identity bytes\n",
            "schema": b"schema identity bytes\n",
        }

    def read(self):
        return copy.deepcopy(self.values)

    def manifests(self):
        def manifest(kind, files, commit=None):
            record = {"kind": kind,
                      "files": [[path, hashlib.sha256(value).hexdigest()]
                                for path, value in sorted(files.items())]}
            if commit is not None:
                record["commit"] = commit
            encoded = (json.dumps(record, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()
        return {
            "core": manifest("core", self.values["core"]["files"],
                             self.values["core"]["commit"]),
            "adapter": manifest("adapter", self.values["adapter"]["files"]),
            "policy": hashlib.sha256(self.values["policy"]).hexdigest(),
            "schema": hashlib.sha256(self.values["schema"]).hexdigest(),
        }

    def substitute(self, name="adapter"):
        if name in ("core", "adapter"):
            path = next(iter(self.values[name]["files"]))
            self.values[name]["files"][path] = (name + " substituted\n").encode("utf-8")
        else:
            self.values[name] = (name + " substituted\n").encode("utf-8")


def matrix():
    orders = (("BL", "LB", "BL"), ("LB", "BL", "LB"),
              ("BL", "BL", "LB"), ("LB", "LB", "BL"))
    return tuple(
        SlotSpec("slot-%d-%d" % (boot, worker), "attempt-%d-%d" % (boot, worker),
                 boot, worker, "boot-cold" if worker == 1 else "same-boot-warm", order)
        for boot, row in enumerate(orders, 1)
        for worker, order in enumerate(row, 1)
    )


def authorization(artifacts=None):
    artifacts = artifacts or MutableArtifacts()
    values = artifacts.manifests()
    return Authorization(
        schema_version="decision-0009-acer-authorization/v1",
        authorization_id="auth-1",
        campaign_id="campaign-1",
        nonce="nonce-1",
        authorization_digest=digest("authorization"),
        core_commit=CORE_COMMIT,
        core_manifest_digest=values["core"],
        adapter_manifest_digest=values["adapter"],
        policy_digest=values["policy"],
        schema_digest=values["schema"],
        chair_identity="chair-1",
        trust_domain="offline-test",
        authenticated=True,
        offline_only=True,
        retry_authorized=False,
        reboot_authorized=False,
        expansion_authorized=False,
        tranche_b_authorized=False,
        slots=matrix(),
    )


def u04_authorization(artifacts=None):
    """Independent runtime carrier; enrollment is a separate setup operation."""
    from tools.decision_0009.acer_adapter.contracts import (
        AUTHORIZATION_V2_SCHEMA, authorization_digest,
    )
    payload = replace(authorization(artifacts), schema_version=AUTHORIZATION_V2_SCHEMA,
        evidence_operations=("WRITE_EXACT", "ESTABLISH_DURABILITY", "VERIFY_EXACT",
                             "PUBLISH_RECOVERY_SUPPLEMENT"),
        exact_byte_recovery_authorized=True, evidence_source_ids=("normalizer-1",),
        recovery_publisher_ids=("recovery-reader-1",), destination_rules=(),
        object_rules=(), supplement_rules=())
    return replace(payload, authorization_digest=authorization_digest(payload))


def offline_chair_service(payload, store_identity="store-1"):
    """Trusted test setup only, performed before creating any runtime object."""
    from tools.decision_0009.acer_adapter.contracts import (
        OfflineChairApproval, OfflineChairTrustRoot, canonical_authorization_bytes,
    )
    from tools.decision_0009.acer_adapter.authorization import OfflineChairAuthorizationVerifier
    approval = OfflineChairApproval(payload.chair_identity, payload.trust_domain,
        store_identity, payload.campaign_id, payload.authorization_id,
        payload.schema_version, canonical_authorization_bytes(payload),
        payload.authorization_digest)
    return OfflineChairAuthorizationVerifier(OfflineChairTrustRoot(
        "offline-root-1", 1, "offline-test", ("chair-1",), (approval,)))


def offline_activation_service(payload, store_identity='store-1'):
    from tools.decision_0009.acer_adapter.authorization import (
        OfflineBootActivationApproval, OfflineBootActivationVerifier)
    return OfflineBootActivationVerifier('offline-activation-root-1', tuple(
        OfflineBootActivationApproval(store_identity, payload.authorization_digest,
            payload.chair_identity, pattern % boot, boot, 'boot-%d' % boot)
        for boot in (1, 2, 3, 4)
        for pattern in ('activation-%d', 'fresh-activation-%d',
                        'campaign-activation-%d', 'consolidated-activation-%d')))


def activation(boot=1, boot_id="boot-1", predecessor=None, activation_id=None):
    return BootActivation(
        activation_id=activation_id or "activation-%d" % boot,
        authorization_digest=u04_authorization().authorization_digest,
        boot_ordinal=boot,
        observed_boot_id=boot_id,
        predecessor_closure_digest=predecessor,
        chair_identity="chair-1",
        authenticated=True,
    )


def session(epoch=1, boot=1):
    return FenceSession(epoch, "session-%d" % epoch, "supervisor-1", boot, True)


def identity(pid=123, start=456, namespace="pidns-1", gpu=GPU_UUID, alive=True):
    return ProcessIdentity(
        host_id="acer-1", boot_id="boot-1", host_pid=pid,
        pid_namespace=namespace, namespace_pid=1, process_start_ticks=start,
        executable_path="/usr/bin/python3", executable_device=1,
        executable_inode=2, executable_digest=digest("python"),
        cgroup_path="/workers/token-1", cgroup_device=3, cgroup_inode=4,
        cgroup_members=(pid,), custodian_id="custodian-1",
        spawn_token="spawn-1", gpu_uuid=gpu, alive=alive,
    )


def spawn_token():
    return SpawnToken("spawn-1", "campaign-1", "boot-1", "slot-1-1",
                      "attempt-1-1", digest("launch"), "custodian-1", 1)


def artifact_binding(artifacts=None, sequence=1):
    artifacts = artifacts or MutableArtifacts()
    values = artifacts.manifests()
    return ArtifactBinding(
        verification_id="verify-%d" % sequence,
        verifier_identity="offline-root",
        authorization_digest=digest("authorization"),
        transition="SPAWN_INTENT_PERSISTED",
        fence_epoch=1,
        session_id="session-1",
        core_digest=values["core"], adapter_digest=values["adapter"],
        policy_digest=values["policy"], schema_digest=values["schema"],
        immutable=True,
    )


def consumed_create_capability(binding=None):
    binding = binding or artifact_binding()
    return EffectCapability(
        capability_id="capability-create-1",
        transition_event_id="event-spawn-intent",
        transition_revision=1,
        transition_event_digest=digest("spawn-intent-event"),
        artifact_binding=binding,
        authorization_digest=binding.authorization_digest,
        fence_epoch=binding.fence_epoch,
        session_id=binding.session_id,
        target="custodian-1",
        operation="blocked-create",
        effect_id="spawn-effect-1",
        supervisor_generation=1,
        consumed=True,
    )


def local_attempt_evidence(attempt_id="attempt-1-1", missing=None):
    values = {
        "core_bytes_digest": digest("core-attempt"),
        "raw_evidence_digests": (digest("raw-attempt"),),
        "reap": ReapEvidence(digest("reap"), True),
        "residual": ResidualEvidence(
            digest("residual"),
            (digest("clear-1"), digest("clear-2"), digest("clear-3")),
            2_000_000_000, True, True, True,
        ),
        "immutable_storage_digest": digest("stored-attempt"),
        "readback_digest": digest("stored-attempt"),
        "completion_digest": digest("adapter-completion"),
        "disposition": "valid", "witnessed": True, "durable": True,
        "no_unresolved_worker": True,
    }
    if missing == "core_bytes":
        values["core_bytes_digest"] = None
    elif missing == "raw_evidence":
        values["raw_evidence_digests"] = ()
    elif missing == "reap":
        values["reap"] = ReapEvidence(None, False)
    elif missing == "residual":
        values["residual"] = ResidualEvidence(None, (), 0, False, False, False)
    elif missing == "immutable_storage":
        values["immutable_storage_digest"] = None
    elif missing == "readback":
        values["readback_digest"] = None
    elif missing == "valid_completion":
        values["disposition"] = "failed"
    elif missing == "witnessed":
        values["witnessed"] = False
    elif missing == "durable":
        values["durable"] = False
    elif missing == "no_unresolved_worker":
        values["no_unresolved_worker"] = False
    elif missing is not None:
        raise AssertionError("unknown prerequisite: " + missing)
    return LocalAttemptEvidence(attempt_id=attempt_id, **values)


def _schema_fixture(node, schema):
    """Build a small record that satisfies the accepted core's closed schema."""
    from tools.decision_0009.startup_characterization import policy as core_policy
    if "$ref" in node:
        return _schema_fixture(schema["$defs"][node["$ref"].split("/")[-1]], schema)
    if "const" in node:
        return copy.deepcopy(node["const"])
    if "enum" in node:
        return node["enum"][0]
    if "oneOf" in node:
        return _schema_fixture(node["oneOf"][0], schema)
    kind = node["type"]
    if kind == "object":
        properties = node.get("properties", {})
        additional = node.get("additionalProperties")
        return {key: _schema_fixture(properties.get(key, additional), schema)
                for key in node.get("required", ())}
    if kind == "array":
        return [_schema_fixture(node["items"], schema)
                for _ in range(node.get("minItems", 0))]
    if kind == "integer":
        return max(1, node.get("minimum", 0))
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    if node.get("pattern", "").startswith("^[0-9a-f]{64}"):
        return "a" * 64
    if node.get("pattern") == core_policy.TOKEN_PATTERN:
        return "example"
    return "/example" if "pattern" in node else "example"


@lru_cache(maxsize=2)
def _base_core_attempt(handle_order):
    import test_startup_characterization_protocol as core
    case = core.ControllerTests()
    case.setUp()
    if handle_order != "BL":
        case.controller.order = handle_order
        case.controller.expected = core.expected_worker_events(handle_order)
    case.controller.release()
    result = core.run(handle_order, core.Vendor(), case.controller.worker_event,
                      case.advance, clock=case.clock)
    if result["exit_code"] != 0:
        raise AssertionError(result)
    case.ports.exit_status = 0
    case.samples.values["worker_cgroup"].update(
        populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
    case.samples.values["worker_process"]["alive"] = False
    case.samples.values["gpu_process"].update(present=False, used_bytes=0)
    case.advance(2_200_000_000)
    trial = case.controller.complete_attempt()
    if trial["verdict"] != "valid":
        raise AssertionError(trial["reason_codes"])
    return trial


def _replace_core_identity(value, campaign_id, attempt_id, boot_id):
    if type(value) is dict:
        return {key: _replace_core_identity(item, campaign_id, attempt_id, boot_id)
                for key, item in value.items()}
    if type(value) is list:
        return [_replace_core_identity(item, campaign_id, attempt_id, boot_id)
                for item in value]
    if type(value) is str:
        return value.replace("run1", campaign_id).replace(
            "trial1", attempt_id).replace("boot-1", boot_id)
    return value


@lru_cache(maxsize=32)
def core_attempt_bytes(slot, campaign_id="campaign-1", boot_id=None):
    """Return semantically valid accepted-core attempt bytes for adapter tests."""
    boot_id = boot_id or "boot-%d" % slot.boot_ordinal
    trial = _replace_core_identity(
        copy.deepcopy(_base_core_attempt(slot.handle_order)), campaign_id,
        slot.attempt_id, boot_id)
    trial.update({
        "run_id": campaign_id, "trial_id": slot.attempt_id, "boot_id": boot_id,
        "boot": slot.boot_ordinal, "ordinal": slot.worker_ordinal,
        "state": slot.thermal_state, "handle_order": slot.handle_order,
    })
    trial["custody"].update({
        "boot": slot.boot_ordinal, "ordinal": slot.worker_ordinal,
        "state": slot.thermal_state, "boot_id": boot_id,
        "no_prior_experiment": slot.worker_ordinal == 1,
        "previous_trial_id": (None if slot.worker_ordinal == 1 else
                              "attempt-%d-%d" % (slot.boot_ordinal,
                                                  slot.worker_ordinal - 1)),
    })
    return (json.dumps(trial, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def residual_observations(*, allocated_bytes=0, populated=False, pids=(), descendants=(),
                          campaign_id="campaign-1", boot_id="boot-1",
                          slot_id="slot-1-1", attempt_id="attempt-1-1",
                          spawn_token_id="spawn-slot-1-1", observed_times=None):
    values = []
    for observed_ns in observed_times or (1, 1_000_000_001, 2_000_000_001):
        record = {
            "campaign_id": campaign_id,
            "boot_id": boot_id,
            "slot_id": slot_id,
            "attempt_id": attempt_id,
            "spawn_token": spawn_token_id,
            "observed_ns": observed_ns,
            "allocated_bytes": allocated_bytes,
            "cgroup_populated": populated,
            "cgroup_pids": list(pids),
            "owned_descendants": list(descendants),
            "gpu_process_present": False,
            "gpu_used_bytes": 0,
        }
        values.append((json.dumps(record, sort_keys=True, separators=(",", ":")) +
                       "\n").encode("utf-8"))
    return tuple(values)


def independent_fault_world(seed):
    """Seed a separate offline test world; never simulate reset by cloning.

    Each case has independent D/W/C state and fresh locks. Immutable trusted
    bootstrap services are shared. Crash/reconciliation within a case resets
    that case's actual store object and discards its volatile authority.
    """
    import threading
    from tools.decision_0009.acer_adapter.supervisor import _AuthorizationLock
    store = seed.store
    memo = {
        id(store._lock): threading.RLock(),
        id(store._authorization_lock): _AuthorizationLock(),
        id(store.witness._lock): threading.Lock(),
        id(seed.custodian._lock): threading.Lock(),
        id(store._authentication_service): store._authentication_service,
        id(store._activation_authentication_service): store._activation_authentication_service,
    }
    # Fault worlds are harness bootstrap, never reconstruction of a capability.
    # A seed with any B reservation must be exercised in its actual C world.
    from tools.decision_0009.acer_adapter.custody import _CustodyExclusion
    factory = seed.custodian._containment_factory
    if factory is not None:
        if factory._entries or factory._tokens:
            raise RuntimeError('cannot clone reserved or exposed survivor authority')
        memo[id(factory.lock)] = _CustodyExclusion()
        memo[id(factory._lifecycle_port._lock)] = threading.RLock()
        for domain in factory._domains.values():
            memo[id(domain.lock)] = threading.RLock()
    world = copy.deepcopy(seed, memo)
    if factory is not None:
        import uuid
        fresh = world.custodian._containment_factory
        fresh.epoch = uuid.uuid4().hex
        B_LIFETIME_WORLDS[fresh] = fresh._lifecycle_port
        B_READER_WORLDS[fresh] = fresh._reader_endpoint
    return world


class RecordingDispatch:
    def __init__(self, replacement=None, result="accepted"):
        self.replacement = replacement
        self.result = result
        self.calls = []

    def interlock(self):
        if self.replacement:
            self.replacement()

    def __call__(self, capability, binding):
        self.calls.append((capability, binding))
        return self.result


def inject_untrusted_record(store, fence_epoch, event_id, event):
    """Test-only retained-byte corruption; never invokes an authority writer.

    Model a planted legacy frame without a matching authenticated checkpoint.
    The witness deliberately remains unchanged, so construction must deny or
    quarantine and preserve these exact forensic bytes.
    """
    from tools.decision_0009.acer_adapter.supervisor import AppendReceipt, _canonical, _sha
    raw = _canonical(event)
    receipt = AppendReceipt(store.identity, store.revision + 1, event_id, _sha(raw),
        _sha(bytes.fromhex(store.chain_digest) + raw), fence_epoch, 'untrusted-fixture', False)
    store._durable.append({'event_id': event_id, 'event': copy.deepcopy(event),
                          'bytes': raw, 'receipt': receipt})
    return receipt


def make_supervisor(*, authorize_destination=False, publication_setup=None, chair_service_factory=None):
    from tools.decision_0009.acer_adapter.custody import OfflineCustodian
    from tools.decision_0009.acer_adapter.supervisor import (
        ArtifactVerificationPrimitive, OfflineDurableStore, OfflineWitness,
        PersistentSupervisor,
    )
    artifacts = MutableArtifacts()
    auth = u04_authorization(artifacts)
    if authorize_destination:
        from tools.decision_0009.acer_adapter.contracts import DestinationRule, authorization_digest
        auth = replace(auth, destination_rules=(DestinationRule('destination-rule-1',
            'offline-destination', 'offline-destination-port', 'evidence',
            'OBJECT_AND_NAMESPACE', 'ALL_LOWER_WRITERS'),))
        auth = replace(auth, authorization_digest=authorization_digest(auth))
    destinations = ()
    if publication_setup is not None:
        auth, destinations = publication_setup(auth)
    witness = OfflineWitness("witness-1")
    store = OfflineDurableStore("store-1", witness,
                                chair_verifier=(chair_service_factory or offline_chair_service)(auth),
                                activation_verifier=offline_activation_service(auth),
                                publication_destinations=destinations)
    fence = 1
    verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
    from tools.decision_0009.acer_adapter.custody import OfflineContainmentFactory
    lifetimes = BIndependentLifetimes()
    reader=object()
    factory = OfflineContainmentFactory('offline-custody-factory', verifier, lifetimes, reader_endpoint=reader)
    B_READER_WORLDS[factory]=reader
    custodian = OfflineCustodian("custodian-1", containment_factory=factory)
    B_LIFETIME_WORLDS[factory] = lifetimes
    supervisor = PersistentSupervisor(store, verifier, custodian, auth, session(fence))
    supervisor.admit_campaign(replace(activation(), authorization_digest=auth.authorization_digest))
    supervisor.establish_boot_custody("custody-proof", observer_isolated=True,
                                      watchdog_ready=True)
    supervisor.complete_boot_custody()
    return supervisor, artifacts, custodian


def complete_boot(supervisor):
    import json
    from tools.decision_0009.acer_adapter.evidence import (
        ImmutablePublication, canonical_core_bytes,
    )
    record_all_local_attempts(supervisor)
    candidate = supervisor.finalize_boot_closure_candidate(
        {"boot_id": supervisor.current_boot_id, "objects": ["attempts", "custody"]})
    publisher = ImmutablePublication(supervisor)
    receipts = []
    values = [candidate.bytes]
    values.extend(canonical_core_bytes(value)
                  for value in json.loads(candidate.bytes)["payload"]["objects"])
    for index, value in enumerate(values):
        intent = publisher.intent(
            "offline-destination",
            "boot-%d-object-%d" % (supervisor.current_boot_ordinal, index), value)
        publisher.exclusive_create(intent)
        publisher.write_durable(intent, value)
        receipts.append(publisher.verify(intent))
    return supervisor.complete_boot(candidate, tuple(receipts))


def record_all_local_attempts(supervisor):
    for slot in supervisor.authorization.slots:
        if (slot.boot_ordinal == supervisor.current_boot_ordinal and
                slot.slot_id not in supervisor._completed_attempts):
            supervisor.make_slot_eligible(slot.slot_id)
            receipt = supervisor.spawn_worker(slot.slot_id, digest("launch-" + slot.slot_id))
            supervisor.complete_worker_lifecycle(slot.slot_id)
            supervisor.persist_local_attempt_evidence(
                slot.slot_id, core_attempt_bytes(
                    slot, supervisor.authorization.campaign_id,
                    supervisor.current_boot_id), residual_observations(
                        campaign_id=supervisor.authorization.campaign_id,
                        boot_id=supervisor.current_boot_id,
                        slot_id=slot.slot_id,
                        attempt_id=slot.attempt_id,
                        spawn_token_id=supervisor._slot_tokens[slot.slot_id].token_id))


# Harness-only lifecycle source. Runtime actors receive no terminal hooks.
# Factories retain authenticated read-only subscriptions to these exact domains.
class BIndependentLifetimes:
    def __init__(self):
        import threading
        self._lock = threading.RLock()
        self._bindings = {}
        self._events = {}
        self._subscriptions = {}
        self._sequence = 0
        self._authority_exclusion = None
        self.available = True

    def bind_authority_exclusion(self,exclusion):
        if self._authority_exclusion is not None:raise RuntimeError('lifetime exclusion already pinned')
        self._authority_exclusion=exclusion

    def bind_lifetime(self, subject):
        with self._lock:
            if subject not in self._bindings:
                self._sequence += 1
                self._bindings[subject] = ('lifetime-%d' % self._sequence, object())
            return self._bindings[subject]

    def subscribe(self, subject, binding, observer, callback):
        with self._lock:
            if self._bindings.get(subject) != binding or type(observer) is not object:
                raise RuntimeError('actual prebound lifetime observation required')
            key=(subject,observer)
            self._subscriptions[key]=self._subscriptions.get(key,())+((binding,callback),)

    def read_event(self, subject, binding):
        with self._lock:
            if not self.available or self._bindings.get(subject) != binding:
                raise RuntimeError('lifetime provenance unavailable')
            return copy.deepcopy(self._events.get(subject))

    def terminate(self,subject):
        with self._authority_exclusion:
            callbacks=self._terminal_transition(subject)
        for callback in callbacks:callback()

    def _terminal_transition(self, subject):
        with self._lock:
            if subject not in self._bindings:
                raise RuntimeError('unregistered lifetime cannot emit terminal notification')
            if subject not in self._events:
                self._sequence += 1
                self._events[subject] = {'lifetime_binding_id':self._bindings[subject][0],
                    'lifetime_event_sequence':self._sequence,'terminal_state':'TERMINATED'}
            callbacks=[callback for (target,_),registrations in self._subscriptions.items() if target is subject
                for _,callback in registrations]
        return callbacks

    def invalidate_ownership(self,source,token_id):
        with self._authority_exclusion:
            callbacks=self._ownership_transition(source,token_id)
        for callback in callbacks:callback()

    def _ownership_transition(self,source,token_id):
        subject=(source,token_id)
        with self._lock:
            if subject not in self._bindings:
                raise RuntimeError('unregistered required ownership cannot be invalidated')
            if subject not in self._events:
                self._sequence+=1
                self._events[subject]={'ownership_binding_id':self._bindings[subject][0],
                    'ownership_event_sequence':self._sequence,'binding_state':'IRREVERSIBLY_INVALIDATED'}
            callbacks=[callback for (target,_),registrations in self._subscriptions.items() if target==subject
                for _,callback in registrations]
        return callbacks


B_LIFETIME_WORLDS = {}


def b_lifetimes(custodian):
    return B_LIFETIME_WORLDS[custodian._containment_factory]


B_READER_WORLDS = {}


def b_reader(factory):
    return B_READER_WORLDS[factory]
