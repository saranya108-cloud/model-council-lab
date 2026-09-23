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


def activation(boot=1, boot_id="boot-1", predecessor=None, activation_id=None):
    return BootActivation(
        activation_id=activation_id or "activation-%d" % boot,
        authorization_digest=digest("authorization"),
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


def make_supervisor():
    from tools.decision_0009.acer_adapter.custody import OfflineCustodian
    from tools.decision_0009.acer_adapter.supervisor import (
        ArtifactVerificationPrimitive, OfflineDurableStore, OfflineWitness,
        PersistentSupervisor,
    )
    artifacts = MutableArtifacts()
    auth = authorization(artifacts)
    witness = OfflineWitness("witness-1")
    store = OfflineDurableStore("store-1", witness)
    fence = store.acquire_fence("supervisor-1")
    verifier = ArtifactVerificationPrimitive("offline-root", auth, artifacts.read)
    custodian = OfflineCustodian("custodian-1")
    supervisor = PersistentSupervisor(store, verifier, custodian, auth, session(fence))
    supervisor.admit_campaign(activation())
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
