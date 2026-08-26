"""Tranche 1: provider_treatment_config is explicit, frozen, bounded treatment authority."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from datetime import datetime
from pathlib import Path
from types import MappingProxyType

from helpers import (
    FAKE_IDENTITY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
    transient_failure_options,
)
from model_council import (
    AdapterIdentity,
    ArtifactStore,
    Condition,
    GovernanceViolation,
    IntegrityViolation,
    RunSpec,
    SubprocessAdapter,
)
from model_council.artifacts import RUN_AUTHORITY, RUN_AUTHORITY_SCHEMA
from model_council.invocation import (
    KIND_INVOCATION_METADATA,
    serialize_invocation_record,
    treatment_digest_for_attempt,
)
from model_council.live_contract import LIVE_CONTRACT_VERSION
from model_council.protocol import EXECUTION_PROFILE_PRE_LIVE_LEGACY, HARNESS_PROTOCOL_VERSION
from model_council.roles import ALLOWED_INPUT_KEYS, ROLE_INSTRUCTIONS, STAGE_OUTPUT_KEYS
from model_council.security import (
    MAX_PROVIDER_TREATMENT_CONFIG_BYTES,
    MAX_PROVIDER_TREATMENT_CONFIG_DEPTH,
    MAX_PROVIDER_TREATMENT_CONFIG_ITEMS,
    MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES,
    canonical_json,
    digest_json,
    normalize_provider_treatment_config,
    sha256_bytes,
    sha256_text,
)
from model_council.types import Condition, ResourceLimits, TaskSpec


# Two structurally different hypothetical configs. Neutral code must persist
# both without interpreting key names as provider semantics.
REASONING_SHAPED = {
    "reasoning": {"effort": "high", "summary": "concise"},
    "text": {"verbosity": "low"},
}
RUNTIME_SHAPED = {
    "runtime": {
        "num_ctx": 8192,
        "think": True,
        "keep_alive": "5m",
        "stop": ["</s>", "USER:"],
    }
}


def _sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _replace_frozen(path: Path, payload: dict) -> None:
    path.chmod(0o644)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    path.chmod(0o444)


def _persisted_binding(run_dir: Path) -> dict:
    return json.loads((run_dir / "execution_binding.json").read_text())


def _persisted_declaration(run_dir: Path) -> dict:
    return json.loads((run_dir / "treatment_declaration.json").read_text())


def _invocation_path(run_dir: Path, role: str, attempt: int) -> Path:
    return run_dir / "invocations" / role / f"attempt-{attempt:04d}" / "invocation.json"


def _load_invocation(run_dir: Path, role: str, attempt: int) -> dict:
    return json.loads(_invocation_path(run_dir, role, attempt).read_text())


def _task_text_from_record(task_record: dict) -> str:
    return TaskSpec(
        task_id=task_record["task_id"],
        bug_report=task_record["bug_report"],
        workspace_id=task_record["workspace_id"],
        allowed_files=tuple(task_record["allowed_files"]),
        visible_test_command=task_record.get("visible_test_command"),
        snapshot_hash=task_record.get("snapshot_hash"),
    ).agent_visible_text()


def _stage_inputs_from_trusted_records(run_dir: Path, condition: str, role: str) -> dict[str, str]:
    task_record = json.loads((run_dir / "task.json").read_text())
    allowed = ALLOWED_INPUT_KEYS[(Condition(condition), role)]
    inputs = {}
    if "task" in allowed:
        inputs["task"] = _task_text_from_record(task_record)
    sources = {
        context_key: (producer, artifact_name)
        for producer, mapping in STAGE_OUTPUT_KEYS.items()
        for artifact_name, context_key in mapping.items()
    }
    for key in sorted(allowed):
        if key == "task":
            continue
        producer, artifact_name = sources[key]
        inputs[key] = (run_dir / producer / f"{artifact_name}.md").read_text(encoding="utf-8")
    return inputs


def _expected_attempt_digest_from_trusted_authority(run_dir: Path, role: str) -> str:
    """Recompute an attempt digest from run-defining records, not other invocations."""
    canonical = json.loads(json.loads((run_dir / "run_spec.json").read_text())["canonical"])
    binding = _persisted_binding(run_dir)
    return treatment_digest_for_attempt(
        condition=canonical["condition"],
        role=role,
        role_instruction=ROLE_INSTRUCTIONS[role],
        stage_inputs=_stage_inputs_from_trusted_records(
            run_dir, canonical["condition"], role
        ),
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        seed=canonical["seed"],
        resource_limits=ResourceLimits(**canonical["resource_limits"]),
        execution_profile=binding["execution_profile"],
        adapter_kind=binding["adapter_kind"],
        adapter_config_digest=binding["adapter_config_digest"],
        live_contract_version=binding["live_contract_version"],
        harness_protocol_version=binding["harness_protocol_version"],
        provider_treatment_config=binding["provider_treatment_config"],
    )[1]


def _rewrite_invocation_field(
    run_dir: Path, role: str, attempt: int, field: str, value
) -> None:
    """Rewrite one invocation field and the local manifest/seal consistency metadata."""
    path = _invocation_path(run_dir, role, attempt)
    record = json.loads(path.read_text())
    record[field] = value
    serialized = serialize_invocation_record(record)
    encoded = serialized.encode("utf-8")
    path.write_text(serialized)
    ref = f"invocations/{role}/attempt-{attempt:04d}/invocation.json"
    digest = sha256_bytes(encoded)
    size = len(encoded)
    lines = []
    for line in (run_dir / "manifest.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry.get("kind") == KIND_INVOCATION_METADATA and entry.get("ref") == ref:
            entry["sha256"] = digest
            entry["bytes"] = size
        lines.append(json.dumps(entry, sort_keys=True))
    (run_dir / "manifest.jsonl").write_text("\n".join(lines) + "\n")
    seal_path = run_dir / "seals" / f"{role}.json"
    if not seal_path.exists():
        return
    seal = json.loads(seal_path.read_text())
    for entry in seal.get("invocations") or []:
        if entry.get("kind") == KIND_INVOCATION_METADATA and entry.get("ref") == ref:
            entry["sha256"] = digest
            entry["bytes"] = size
    body = {
        "artifacts": seal["artifacts"],
        "invocations": seal.get("invocations") or [],
        "expected_attempts": seal.get("expected_attempts", 0),
    }
    seal["stage_digest"] = sha256_text(json.dumps(body, sort_keys=True))
    seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True))


def _rewrite_invocation_treatment_digest(
    run_dir: Path, role: str, attempt: int, new_digest: str
) -> None:
    _rewrite_invocation_field(run_dir, role, attempt, "treatment_digest", new_digest)


def _attempt_digest(provider_treatment_config):
    return treatment_digest_for_attempt(
        condition="A",
        role="solver",
        role_instruction=ROLE_INSTRUCTIONS["solver"],
        stage_inputs={"task": "example defect"},
        requested_identity=FAKE_IDENTITY,
        configured_identity=FAKE_IDENTITY,
        seed=7,
        resource_limits=ResourceLimits(),
        execution_profile=EXECUTION_PROFILE_PRE_LIVE_LEGACY,
        adapter_kind="fake",
        adapter_config_digest=digest_json({}),
        provider_treatment_config=provider_treatment_config,
    )[1]


class TestProviderTreatmentConfigPersistence(unittest.TestCase):
    def test_exact_configuration_round_trip(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-round", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-round"
            binding = _persisted_binding(run_dir)
            declaration = _persisted_declaration(run_dir)["declaration"]
            self.assertEqual(binding["provider_treatment_config"], REASONING_SHAPED)
            self.assertEqual(declaration["provider_treatment_config"], REASONING_SHAPED)
            self.assertIsInstance(binding["provider_treatment_config"], dict)

    def test_nested_structures_are_persisted_exactly(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=RUNTIME_SHAPED
            )
            result = runner.execute(make_spec("ptc-nested", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            stored = _persisted_binding(runs_root / "ptc-nested")["provider_treatment_config"]
            self.assertEqual(stored, RUNTIME_SHAPED)
            self.assertEqual(stored["runtime"]["stop"], ["</s>", "USER:"])
            self.assertIs(stored["runtime"]["think"], True)

    def test_canonical_ordering_is_stable(self):
        unordered = {"z": 1, "a": {"y": 2, "x": 1}}
        reordered = {"a": {"x": 1, "y": 2}, "z": 1}
        first = normalize_provider_treatment_config(unordered)
        second = normalize_provider_treatment_config(reordered)
        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertEqual(digest_json(first), digest_json(second))
        with TempRoot() as root:
            runner_a, runs_a = make_runner(root, provider_treatment_config=unordered)
            runner_b, runs_b = make_runner(root, provider_treatment_config=reordered)
            self.assertEqual(
                runner_a._treatment_hash(make_spec("ptc-ord-a", "A"), make_task()),
                runner_b._treatment_hash(make_spec("ptc-ord-b", "A"), make_task()),
            )
            runner_a.execute(make_spec("ptc-ord-a", "A"), make_task())
            persisted = json.dumps(
                _persisted_binding(runs_a / "ptc-ord-a")["provider_treatment_config"],
                sort_keys=True,
                separators=(",", ":"),
            )
            self.assertEqual(persisted, canonical_json(first))
            del runs_b

    def test_empty_default_is_compatible(self):
        with TempRoot() as root:
            omitted, runs_root = make_runner(root)
            explicit, _ = make_runner(root, provider_treatment_config={})
            spec = make_spec("ptc-empty", "A")
            task = make_task()
            self.assertEqual(omitted._treatment_hash(spec, task), explicit._treatment_hash(spec, task))
            result = omitted.execute(spec, task)
            self.assertEqual(result.status, "succeeded")
            binding = _persisted_binding(runs_root / "ptc-empty")
            declaration = _persisted_declaration(runs_root / "ptc-empty")["declaration"]
            self.assertEqual(binding["provider_treatment_config"], {})
            self.assertEqual(declaration["provider_treatment_config"], {})

    def test_is_not_inferred_from_adapter_options(self):
        options = {"seconds": 1, "runtime": {"think": True}}
        with TempRoot() as root:
            runner, runs_root = make_runner(root, options=options)
            result = runner.execute(make_spec("ptc-no-infer", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            binding = _persisted_binding(runs_root / "ptc-no-infer")
            self.assertEqual(binding["provider_treatment_config"], {})
            self.assertNotEqual(binding["adapter_config_digest"], digest_json({}))
            self.assertEqual(
                binding["adapter_config_digest"],
                digest_json(options),
            )


class TestProviderTreatmentConfigImmutability(unittest.TestCase):
    def _adapter(self, config):
        return SubprocessAdapter(FAKE_IDENTITY, provider_treatment_config=config)

    def test_caller_dict_mutation_does_not_change_authority(self):
        original = {"reasoning": {"effort": "high"}}
        adapter = self._adapter(original)
        original["reasoning"]["effort"] = "low"
        original["injected"] = True
        self.assertEqual(
            json.loads(canonical_json(adapter.provider_treatment_config)),
            {"reasoning": {"effort": "high"}},
        )
        with TempRoot() as root:
            runner, _ = make_runner(root, provider_treatment_config={"reasoning": {"effort": "high"}})
            expected = runner._treatment_hash(make_spec("ptc-mut-a", "A"), make_task())
            mutated_runner, _ = make_runner(root)
            mutated_runner.adapter = adapter
            self.assertEqual(
                mutated_runner._treatment_hash(make_spec("ptc-mut-b", "A"), make_task()),
                expected,
            )

    def test_nested_dict_mutation_does_not_change_authority(self):
        nested = {"runtime": {"keep_alive": "5m"}}
        inner = nested["runtime"]
        adapter = self._adapter(nested)
        inner["keep_alive"] = "1h"
        inner["num_ctx"] = 99
        self.assertEqual(
            json.loads(canonical_json(adapter.provider_treatment_config)),
            {"runtime": {"keep_alive": "5m"}},
        )

    def test_nested_list_mutation_does_not_change_authority(self):
        items = ["</s>"]
        config = {"runtime": {"stop": items}}
        adapter = self._adapter(config)
        items.append("USER:")
        items[0] = "tampered"
        frozen = json.loads(canonical_json(adapter.provider_treatment_config))
        self.assertEqual(frozen["runtime"]["stop"], ["</s>"])
        self.assertIsInstance(adapter.provider_treatment_config, MappingProxyType)
        with self.assertRaises(TypeError):
            adapter.provider_treatment_config["runtime"] = {}


class TestProviderTreatmentConfigSafety(unittest.TestCase):
    def test_secret_like_keys_are_rejected(self):
        cases = (
            {"api_key": "sk-test"},
            {"openai_api_key": "sk-test"},
            {"Authorization": "Bearer abc"},
            {"access_token": "tok"},
            {"client_secret": "shh"},
            {"x-api-key": "sk-test"},
            {"auth_token": "tok"},
            {"api-token": "tok"},
            {"api.token": "tok"},
            {"api token": "tok"},
            {"oauth_token": "tok"},
            {"id_token": "tok"},
            {"session_token": "tok"},
            {"request_headers": {}},
            {"default_headers": {}},
            {"http_headers": {}},
            {"api.key": "sk-test"},
            {"api key": "sk-test"},
        )
        for config in cases:
            with self.subTest(config=config):
                with self.assertRaises(GovernanceViolation):
                    SubprocessAdapter(FAKE_IDENTITY, provider_treatment_config=config)
                with self.assertRaises(GovernanceViolation):
                    normalize_provider_treatment_config(config)

    def test_nested_secret_like_keys_are_rejected(self):
        nested_cases = (
            {"runtime": {"credentials": {"user": "lab"}}},
            {"runtime": {"nested": [{"password": "x"}]}},
            {"provider": {"session_token": "tok"}},
            {"transport": {"request_headers": {"accept": "json"}}},
            {"nested": {"api-token": "tok"}},
            {"nested": {"api.token": "tok"}},
        )
        for nested in nested_cases:
            with self.subTest(config=nested):
                with self.assertRaises(GovernanceViolation):
                    SubprocessAdapter(FAKE_IDENTITY, provider_treatment_config=nested)
                with self.assertRaises(GovernanceViolation):
                    normalize_provider_treatment_config(nested)

    def test_legitimate_non_secret_keys_are_accepted(self):
        allowed = {
            "max_tokens": 128,
            "eos_token": "</s>",
            "reasoning": {"effort": "high"},
            "think": True,
            "num_ctx": 2048,
        }
        normalized = normalize_provider_treatment_config(allowed)
        self.assertEqual(normalized["max_tokens"], 128)
        self.assertEqual(normalized["eos_token"], "</s>")
        SubprocessAdapter(FAKE_IDENTITY, provider_treatment_config=allowed)

    def test_unsupported_non_json_values_are_rejected(self):
        cases = (
            {"blob": b"bytes"},
            {"when": datetime(2026, 1, 1)},
            {"path": Path("/tmp")},
            {"values": {1, 2}},
            {"items": (1, 2)},
            {"fn": object()},
            {"n": float("nan")},
            {"n": float("inf")},
        )
        for config in cases:
            with self.subTest(config=repr(config)):
                with self.assertRaises(GovernanceViolation):
                    normalize_provider_treatment_config(config)

    def test_top_level_must_be_an_object(self):
        for value in ("high", [1, 2], 3, True):
            with self.subTest(value=value):
                with self.assertRaises(GovernanceViolation):
                    normalize_provider_treatment_config(value)

    def test_bounded_size_and_depth_are_rejected(self):
        too_deep = {}
        cursor = too_deep
        for index in range(MAX_PROVIDER_TREATMENT_CONFIG_DEPTH + 1):
            nxt = {}
            cursor["k"] = nxt
            cursor = nxt
        with self.assertRaises(GovernanceViolation):
            normalize_provider_treatment_config(too_deep)

        too_many = {f"k{i}": i for i in range(MAX_PROVIDER_TREATMENT_CONFIG_ITEMS + 1)}
        with self.assertRaises(GovernanceViolation):
            normalize_provider_treatment_config(too_many)

        too_long = {"blob": "x" * (MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES + 1)}
        with self.assertRaises(GovernanceViolation):
            normalize_provider_treatment_config(too_long)

        oversized = {"blob": "x" * MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES}
        # A single max-length string plus object overhead may still fit; force
        # the encoded envelope over the byte ceiling with many keys if needed.
        if len(canonical_json(oversized).encode("utf-8")) <= MAX_PROVIDER_TREATMENT_CONFIG_BYTES:
            filler = "y" * MAX_PROVIDER_TREATMENT_CONFIG_STRING_BYTES
            oversized = {f"k{i}": filler for i in range(8)}
        self.assertGreater(
            len(canonical_json(oversized).encode("utf-8")),
            MAX_PROVIDER_TREATMENT_CONFIG_BYTES,
        )
        with self.assertRaises(GovernanceViolation):
            normalize_provider_treatment_config(oversized)


class TestProviderTreatmentConfigAuthority(unittest.TestCase):
    def test_exact_persistence_in_run_defining_records(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-auth-persist", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-auth-persist"
            binding = _persisted_binding(run_dir)
            declaration = _persisted_declaration(run_dir)
            self.assertEqual(binding["provider_treatment_config"], REASONING_SHAPED)
            self.assertEqual(
                declaration["declaration"]["provider_treatment_config"], REASONING_SHAPED
            )
            self.assertEqual(
                declaration["treatment_hash"],
                digest_json(declaration["declaration"]),
            )
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            self.assertEqual(
                authority["execution_binding_sha256"],
                _sha256_path(run_dir / "execution_binding.json"),
            )
            self.assertEqual(
                authority["treatment_declaration_sha256"],
                _sha256_path(run_dir / "treatment_declaration.json"),
            )

    def test_treatment_digest_changes_when_provider_treatment_changes(self):
        with TempRoot() as root:
            runner_a, _ = make_runner(root, provider_treatment_config=REASONING_SHAPED)
            runner_b, _ = make_runner(root, provider_treatment_config=RUNTIME_SHAPED)
            spec = make_spec("ptc-digest", "A")
            task = make_task()
            hash_a = runner_a._treatment_hash(spec, task)
            hash_b = runner_b._treatment_hash(spec, task)
            self.assertNotEqual(hash_a, hash_b)
            self.assertNotEqual(_attempt_digest(REASONING_SHAPED), _attempt_digest(RUNTIME_SHAPED))
            self.assertEqual(_attempt_digest({}), _attempt_digest(None))

    def test_treatment_reconstruction_succeeds_when_unchanged(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=RUNTIME_SHAPED
            )
            result = runner.execute(make_spec("ptc-recon-ok", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            report = ArtifactStore.verify_terminal_run(runs_root, "ptc-recon-ok")
            self.assertTrue(report["terminal_verified"])

    def test_tampered_persisted_config_fails_reconstruction(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-recon-bind", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-recon-bind"
            binding = _persisted_binding(run_dir)
            binding["provider_treatment_config"] = RUNTIME_SHAPED
            _replace_frozen(run_dir / "execution_binding.json", binding)
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            authority["execution_binding_sha256"] = _sha256_path(
                run_dir / "execution_binding.json"
            )
            _replace_frozen(run_dir / RUN_AUTHORITY, authority)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-recon-bind")

    def test_tampered_treatment_declaration_config_fails_reconstruction(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-recon-decl", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-recon-decl"
            stored = _persisted_declaration(run_dir)
            stored["declaration"]["provider_treatment_config"] = RUNTIME_SHAPED
            stored["treatment_hash"] = digest_json(stored["declaration"])
            _replace_frozen(run_dir / "treatment_declaration.json", stored)
            result_path = run_dir / "run_result.json"
            terminal = json.loads(result_path.read_text())
            terminal["treatment_hash"] = stored["treatment_hash"]
            result_path.write_text(json.dumps(terminal, indent=2, sort_keys=True))
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            authority["treatment_declaration_sha256"] = _sha256_path(
                run_dir / "treatment_declaration.json"
            )
            _replace_frozen(run_dir / RUN_AUTHORITY, authority)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-recon-decl")

    def test_run_authority_binds_execution_binding_including_config(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-auth-bind", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-auth-bind"
            binding = _persisted_binding(run_dir)
            binding["provider_treatment_config"] = RUNTIME_SHAPED
            _replace_frozen(run_dir / "execution_binding.json", binding)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-auth-bind")

    def test_coordinated_invocation_treatment_digest_rewrite_fails_terminal_verify(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-inv-rewrite", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-inv-rewrite"
            original = _load_invocation(run_dir, "solver", 1)["treatment_digest"]
            forged = "0" * 64
            self.assertNotEqual(original, forged)
            _rewrite_invocation_treatment_digest(run_dir, "solver", 1, forged)
            self.assertEqual(
                json.loads((run_dir / RUN_AUTHORITY).read_text())["execution_binding_sha256"],
                _sha256_path(run_dir / "execution_binding.json"),
            )
            self.assertEqual(
                _persisted_binding(run_dir)["provider_treatment_config"],
                REASONING_SHAPED,
            )
            completed = ArtifactStore.verify_completed(runs_root, "ptc-inv-rewrite")
            self.assertTrue(completed["integrity_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-inv-rewrite")

    def test_retry_attempt_treatment_digest_is_independently_expected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root,
                options=transient_failure_options(root),
                provider_treatment_config=RUNTIME_SHAPED,
            )
            result = runner.execute(
                make_spec("ptc-retry-digest", "A", max_stage_retries=1),
                make_task(),
            )
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-retry-digest"
            expected = _expected_attempt_digest_from_trusted_authority(run_dir, "solver")
            first = _load_invocation(run_dir, "solver", 1)
            second = _load_invocation(run_dir, "solver", 2)
            self.assertEqual(first["attempt"], 1)
            self.assertEqual(second["attempt"], 2)
            self.assertEqual(first["treatment_digest"], expected)
            self.assertEqual(second["treatment_digest"], expected)
            forged = "a" * 64
            self.assertNotEqual(expected, forged)
            _rewrite_invocation_treatment_digest(run_dir, "solver", 1, forged)
            self.assertEqual(_load_invocation(run_dir, "solver", 2)["treatment_digest"], expected)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-retry-digest")

    def test_coordinated_invocation_input_digest_rewrite_fails_terminal_verify(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-input-rewrite", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-input-rewrite"
            original = _load_invocation(run_dir, "solver", 1)
            forged = "f" * 64
            self.assertNotEqual(original["input_content_digest"], forged)
            self.assertNotEqual(original["treatment_digest"], forged)
            _rewrite_invocation_field(run_dir, "solver", 1, "input_content_digest", forged)
            rewritten = _load_invocation(run_dir, "solver", 1)
            self.assertEqual(rewritten["treatment_digest"], original["treatment_digest"])
            self.assertEqual(
                json.loads((run_dir / RUN_AUTHORITY).read_text())["execution_binding_sha256"],
                _sha256_path(run_dir / "execution_binding.json"),
            )
            completed = ArtifactStore.verify_completed(runs_root, "ptc-input-rewrite")
            self.assertTrue(completed["integrity_verified"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-input-rewrite")


class TestProviderTreatmentConfigVerification(unittest.TestCase):
    def test_terminal_verification_accepts_untampered_run_and_completed_topology_still_verifies(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-term", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            report = ArtifactStore.verify_terminal_run(runs_root, "ptc-term")
            self.assertEqual(report["verification_scope"], "terminal_run")
            self.assertTrue(report["terminal_verified"])
            completed = ArtifactStore.verify_completed(runs_root, "ptc-term")
            self.assertTrue(completed["integrity_verified"])
            self.assertNotEqual(completed.get("verification_scope"), "terminal_run")

    def test_partial_evidence_does_not_require_treatment_reconstruction(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=RUNTIME_SHAPED
            )
            result = runner.execute(make_spec("ptc-partial", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            (runs_root / "ptc-partial" / "run_result.json").unlink()
            report = ArtifactStore.verify_run_integrity(runs_root, "ptc-partial")
            self.assertEqual(report["verification_scope"], "partial_evidence")
            self.assertFalse(report["terminal_verified"])


class TestProviderTreatmentConfigNeutrality(unittest.TestCase):
    def test_structurally_different_configs_are_preserved_without_interpretation(self):
        with TempRoot() as root:
            for run_id, config in (
                ("ptc-neutral-reason", REASONING_SHAPED),
                ("ptc-neutral-runtime", RUNTIME_SHAPED),
            ):
                with self.subTest(run_id=run_id):
                    runner, runs_root = make_runner(
                        root, provider_treatment_config=config
                    )
                    result = runner.execute(make_spec(run_id, "A"), make_task())
                    self.assertEqual(result.status, "succeeded")
                    binding = _persisted_binding(runs_root / run_id)
                    declaration = _persisted_declaration(runs_root / run_id)["declaration"]
                    self.assertEqual(binding["provider_treatment_config"], config)
                    self.assertEqual(declaration["provider_treatment_config"], config)
                    ArtifactStore.verify_terminal_run(runs_root, run_id)


class TestProviderTreatmentProtocolV12(unittest.TestCase):
    def test_new_artifacts_identify_harness_protocol_v12(self):
        self.assertEqual(HARNESS_PROTOCOL_VERSION, "m1-dev-harness-v12")
        self.assertEqual(LIVE_CONTRACT_VERSION, "m1-live-contract-v3")
        self.assertEqual(RUN_AUTHORITY_SCHEMA, "m1-run-authority-v1")
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-v12", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-v12"
            binding = _persisted_binding(run_dir)
            declaration = _persisted_declaration(run_dir)["declaration"]
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            terminal = json.loads((run_dir / "run_result.json").read_text())
            invocation = _load_invocation(run_dir, "solver", 1)
            self.assertEqual(binding["harness_protocol_version"], "m1-dev-harness-v12")
            self.assertEqual(declaration["harness_protocol_version"], "m1-dev-harness-v12")
            self.assertEqual(authority["harness_protocol_version"], "m1-dev-harness-v12")
            self.assertEqual(terminal["harness_protocol_version"], "m1-dev-harness-v12")
            expected = _expected_attempt_digest_from_trusted_authority(run_dir, "solver")
            self.assertEqual(invocation["treatment_digest"], expected)
            v11 = treatment_digest_for_attempt(
                condition="A",
                role="solver",
                role_instruction=ROLE_INSTRUCTIONS["solver"],
                stage_inputs=_stage_inputs_from_trusted_records(run_dir, "A", "solver"),
                requested_identity=FAKE_IDENTITY,
                configured_identity=FAKE_IDENTITY,
                seed=7,
                resource_limits=ResourceLimits(),
                execution_profile=binding["execution_profile"],
                adapter_kind=binding["adapter_kind"],
                adapter_config_digest=binding["adapter_config_digest"],
                harness_protocol_version="m1-dev-harness-v11",
                provider_treatment_config=REASONING_SHAPED,
            )[1]
            self.assertNotEqual(expected, v11)

    def test_v11_protocol_stamp_is_not_accepted_as_v12(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-v11-reject", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-v11-reject"
            binding = _persisted_binding(run_dir)
            binding["harness_protocol_version"] = "m1-dev-harness-v11"
            _replace_frozen(run_dir / "execution_binding.json", binding)
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            authority["execution_binding_sha256"] = _sha256_path(
                run_dir / "execution_binding.json"
            )
            _replace_frozen(run_dir / RUN_AUTHORITY, authority)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-v11-reject")

    def test_frozen_historical_tags_remain_unchanged(self):
        root = Path(__file__).resolve().parents[1]
        harness = subprocess.run(
            ["git", "rev-parse", "m1-neutral-live-harness^{}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        baseline = subprocess.run(
            ["git", "rev-parse", "m1-dev-baseline^{}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(
            harness.stdout.strip(),
            "0a1feb021c9d81f156fb5fe29600eda22d9b414f",
        )
        self.assertEqual(
            baseline.stdout.strip(),
            "9eacf2ffdb4ac89ad756f656ec8b4a4da37feb65",
        )


class TestStructuredAdapterIdentity(unittest.TestCase):
    def _colon_identity(self):
        return AdapterIdentity(
            provider="fake-provider",
            model_id="glm-5.3:latest",
            model_version="v1",
            adapter_name="fake",
            adapter_version="v0",
        )

    def test_colon_containing_identity_component_survives_terminal_verification(self):
        identity = self._colon_identity()
        self.assertIn(":", identity.model_id)
        self.assertEqual(identity.key().count(":"), 5)
        with TempRoot() as root:
            runner, runs_root = make_runner(root, identity=identity)
            spec = RunSpec(
                run_id="ptc-colon-id",
                task_id="dev-001",
                condition=Condition.A,
                model_identifier=identity.key(),
                prompt_version="prompts-dev-v0",
                resource_limits=ResourceLimits(),
                seed=7,
            )
            result = runner.execute(spec, make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "ptc-colon-id"
            binding = _persisted_binding(run_dir)
            self.assertIn("adapter_identity", binding)
            stored = binding["adapter_identity"]
            self.assertEqual(stored["model_id"], "glm-5.3:latest")
            self.assertEqual(stored["provider"], identity.provider)
            self.assertEqual(stored["model_version"], identity.model_version)
            self.assertEqual(stored["adapter_name"], identity.adapter_name)
            self.assertEqual(stored["adapter_version"], identity.adapter_version)
            reconstructed = AdapterIdentity(
                provider=stored["provider"],
                model_id=stored["model_id"],
                model_version=stored["model_version"],
                adapter_name=stored["adapter_name"],
                adapter_version=stored["adapter_version"],
            )
            canonical = json.loads(json.loads((run_dir / "run_spec.json").read_text())["canonical"])
            self.assertEqual(reconstructed.key(), canonical["model_identifier"])
            self.assertEqual(reconstructed.key(), identity.key())
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            self.assertEqual(
                authority["execution_binding_sha256"],
                _sha256_path(run_dir / "execution_binding.json"),
            )
            report = ArtifactStore.verify_terminal_run(runs_root, "ptc-colon-id")
            self.assertTrue(report["terminal_verified"])

    def test_structured_identity_tamper_with_rebound_authority_is_detected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, provider_treatment_config=REASONING_SHAPED
            )
            result = runner.execute(make_spec("ptc-id-tamper", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            ArtifactStore.verify_terminal_run(runs_root, "ptc-id-tamper")
            run_dir = runs_root / "ptc-id-tamper"
            binding = _persisted_binding(run_dir)
            tampered = AdapterIdentity(
                provider="fake-provider",
                model_id="tampered-model",
                model_version="v1",
                adapter_name="fake",
                adapter_version="v0",
            )
            binding["adapter_identity"] = tampered.to_dict()
            _replace_frozen(run_dir / "execution_binding.json", binding)
            authority = json.loads((run_dir / RUN_AUTHORITY).read_text())
            authority["execution_binding_sha256"] = _sha256_path(
                run_dir / "execution_binding.json"
            )
            _replace_frozen(run_dir / RUN_AUTHORITY, authority)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs_root, "ptc-id-tamper")

    def test_invocation_identity_component_contradicts_trusted_identity(self):
        for field in ("requested_identity", "configured_identity"):
            with self.subTest(field=field):
                with TempRoot() as root:
                    runner, runs_root = make_runner(
                        root, provider_treatment_config=REASONING_SHAPED
                    )
                    run_id = f"ptc-inv-id-{field}"
                    result = runner.execute(make_spec(run_id, "A"), make_task())
                    self.assertEqual(result.status, "succeeded")
                    run_dir = runs_root / run_id
                    trusted = _persisted_binding(run_dir)["adapter_identity"]
                    original = _load_invocation(run_dir, "solver", 1)[field]
                    forged = dict(original)
                    forged["model_id"] = "contradictory-model"
                    self.assertEqual(forged["identity_key"], trusted["identity_key"])
                    self.assertNotEqual(forged["model_id"], trusted["model_id"])
                    _rewrite_invocation_field(run_dir, "solver", 1, field, forged)
                    self.assertEqual(
                        json.loads((run_dir / RUN_AUTHORITY).read_text())[
                            "execution_binding_sha256"
                        ],
                        _sha256_path(run_dir / "execution_binding.json"),
                    )
                    self.assertEqual(
                        _persisted_binding(run_dir)["adapter_identity"],
                        trusted,
                    )
                    completed = ArtifactStore.verify_completed(runs_root, run_id)
                    self.assertTrue(completed["integrity_verified"])
                    with self.assertRaises(IntegrityViolation):
                        ArtifactStore.verify_terminal_run(runs_root, run_id)

    def test_invocation_identity_key_incoherence_is_rejected(self):
        for field in ("requested_identity", "configured_identity"):
            with self.subTest(field=field):
                with TempRoot() as root:
                    runner, runs_root = make_runner(root)
                    run_id = f"ptc-inv-key-{field}"
                    result = runner.execute(make_spec(run_id, "A"), make_task())
                    self.assertEqual(result.status, "succeeded")
                    run_dir = runs_root / run_id
                    original = _load_invocation(run_dir, "solver", 1)[field]
                    forged = dict(original)
                    forged["identity_key"] = "forged:identity:key:does:not-match"
                    self.assertEqual(forged["model_id"], original["model_id"])
                    self.assertNotEqual(forged["identity_key"], original["identity_key"])
                    _rewrite_invocation_field(run_dir, "solver", 1, field, forged)
                    completed = ArtifactStore.verify_completed(runs_root, run_id)
                    self.assertTrue(completed["integrity_verified"])
                    with self.assertRaises(IntegrityViolation):
                        ArtifactStore.verify_terminal_run(runs_root, run_id)


if __name__ == "__main__":
    unittest.main()
