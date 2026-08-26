"""Artifact preservation: scoping, write-once sealing, durable hash integrity.

Enforcement model:
  - run_id must satisfy the safe-identifier policy and the resolved run
    directory is proven to stay inside runs_root (Finding 1);
  - each role may write only its own allowed artifacts into its own stage dir;
  - every write appends a SHA-256 entry to manifest.jsonl (Finding 9);
  - seal_stage persists per-stage hashes; sealed stages are immutable via the
    supported interface, and their hashes are re-verified before downstream
    transitions and before final evaluation;
  - event filenames are internal constants only.

Trust boundary (Decision 0004): the project-controlled harness and this
local ArtifactStore are trusted. Model/provider output is untrusted.
Verification detects corruption and inconsistency beneath the local run
authority record (run_authority.json). M1 does not attempt to defend
against a same-user attacker who arbitrarily rewrites the entire trusted
ArtifactStore, including that trust-anchor file. File hashes are not
signatures or external attestations.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .invocation import (
    INVOCATION_FILENAME,
    INVOCATION_ROOT,
    KIND_INVOCATION_METADATA,
    KIND_MODEL_ARTIFACT,
    KIND_UNTRUSTED_RAW_OUTPUT,
    MANIFEST_KINDS,
    MAX_RAW_EVIDENCE_BYTES,
    RAW_OUTPUT_FILENAME,
    attempt_dirname,
    bound_raw_evidence,
    invocation_ref,
    serialize_invocation_record,
    treatment_digest_for_attempt,
    verify_raw_evidence_truncation,
)
from .live_contract import LIVE_CONTRACT_VERSION
from .protocol import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    execution_profile_for_kind,
)
from .roles import (
    ALLOWED_INPUT_KEYS,
    CONDITION_STAGES,
    CONTEXT_POLICY_VERSION,
    EXPECTED_ARTIFACTS,
    EXTRA_ARTIFACTS,
    PRIMARY_ARTIFACT,
    ROLE_INSTRUCTIONS,
    STAGE_OUTPUT_KEYS,
)
from .security import contained_path, digest_json, normalize_provider_treatment_config, safe_identifier, sha256_bytes, sha256_text
from .types import (
    AdapterIdentity,
    Condition,
    GovernanceViolation,
    IntegrityViolation,
    ResourceLimits,
    RunSpec,
    STATUS_FAILED_BUDGET,
    STATUS_FAILED_CONTRACT,
    STATUS_FAILED_EVALUATION,
    STATUS_FAILED_GOVERNANCE,
    STATUS_INFRASTRUCTURE_FAILURE,
    STATUS_RETRY_EXHAUSTED,
    STATUS_SUCCEEDED,
    TaskSpec,
)

_TERMINAL_STATUSES = frozenset(
    {
        STATUS_SUCCEEDED,
        STATUS_FAILED_BUDGET,
        STATUS_FAILED_CONTRACT,
        STATUS_FAILED_EVALUATION,
        STATUS_FAILED_GOVERNANCE,
        STATUS_INFRASTRUCTURE_FAILURE,
        STATUS_RETRY_EXHAUSTED,
    }
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


EVENT_EVALUATION = "evaluation.json"
EVENT_RUN_RESULT = "run_result.json"
EVENT_GOVERNANCE_VIOLATION = "governance_violation.json"
EVENT_INTEGRITY = "integrity_check.json"
MANIFEST = "manifest.jsonl"
TREATMENT_DECLARATION = "treatment_declaration.json"
TASK_RECORD = "task.json"
EXECUTION_BINDING = "execution_binding.json"
EVALUATOR_BINDING = "evaluator_binding.json"
SOURCE_PROVENANCE = "source_provenance.json"
RUN_AUTHORITY = "run_authority.json"
RUN_AUTHORITY_SCHEMA = "m1-run-authority-v1"
STAGING_ROOT = ".uncommitted"
ALLOWED_EVENTS = frozenset({EVENT_EVALUATION, EVENT_RUN_RESULT, EVENT_GOVERNANCE_VIOLATION, EVENT_INTEGRITY})


class ArtifactStore:
    def __init__(
        self,
        runs_root: Path,
        run_spec: RunSpec,
        *,
        max_raw_evidence_bytes: int = MAX_RAW_EVIDENCE_BYTES,
    ) -> None:
        self.runs_root = Path(runs_root).resolve()
        self.run_spec = run_spec
        safe_identifier(run_spec.run_id, "run_id")
        self.run_dir = contained_path(self.runs_root, self.runs_root / run_spec.run_id)
        if self.run_dir.exists():
            raise GovernanceViolation(f"run directory already exists: {self.run_dir}")
        self._allowed_roles: tuple[str, ...] = CONDITION_STAGES[run_spec.condition]
        self._sealed: set[str] = set()
        # Authoritative in-parent hash record. Filesystem seals are persisted
        # evidence; THIS map is what an active run trusts. Altering both the
        # artifact and its seal file cannot fool the active run.
        self._authoritative: dict[tuple[str, str], str] = {}
        self._authoritative_invocations: dict[tuple[str, int, str], str] = {}
        self.max_raw_evidence_bytes = int(max_raw_evidence_bytes)
        self.run_dir.mkdir(parents=True)
        for role in self._allowed_roles:
            (self.run_dir / role).mkdir()
        spec_path = self.run_dir / "run_spec.json"
        spec_path.write_text(
            json.dumps(
                {"canonical": run_spec.canonical_json(), "spec_hash": run_spec.spec_hash},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        spec_path.chmod(0o444)
        self._spec_path = spec_path

    @property
    def spec_path(self) -> Path:
        return self._spec_path

    def artifact_path(self, role: str, name: str) -> Path:
        return self.run_dir / role / f"{name}.md"

    def artifact_ref(self, role: str, name: str) -> str:
        return str(self.artifact_path(role, name).relative_to(self.run_dir))

    def resolve_ref(self, ref: str) -> Path:
        """Resolve a stored reference with strict containment inside run_dir."""
        if not isinstance(ref, str) or not ref:
            raise GovernanceViolation("artifact reference must be a non-empty string")
        candidate = contained_path(self.run_dir, self.run_dir / ref)
        return candidate

    def read(self, ref: str) -> str:
        path = self.resolve_ref(ref)
        if not path.is_file():
            raise GovernanceViolation(f"artifact reference does not exist: {ref!r}")
        return path.read_text(encoding="utf-8")

    def _append_manifest(self, entry: dict) -> None:
        path = self.run_dir / MANIFEST
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def write(self, role: str, name: str, content: str) -> str:
        data = self._validated_artifact_bytes(role, name, content)
        path = self.artifact_path(role, name)
        if path.exists():
            raise GovernanceViolation(
                f"artifact already exists for stage {role!r}: {name!r} is write-once"
            )
        path.write_bytes(data)
        self._record_committed_artifact(role, name, data)
        return self.artifact_ref(role, name)

    def write_staged(self, role: str, name: str, content: str) -> str:
        """Persist a candidate artifact outside the committed role namespace."""
        data = self._validated_artifact_bytes(role, name, content)
        staging = self._staging_role_dir(role)
        staging.mkdir(parents=True, exist_ok=True)
        path = contained_path(self.run_dir, staging / f"{name}.md")
        if path.exists():
            raise GovernanceViolation(
                f"staged artifact already exists for stage {role!r}: {name!r} is write-once"
            )
        path.write_bytes(data)
        return str(path.relative_to(self.run_dir))

    def commit_staged_artifacts(self, role: str) -> dict[str, str]:
        """Promote staged artifacts into the committed role namespace as one transaction."""
        if role not in self._allowed_roles:
            raise GovernanceViolation(
                f"role {role!r} is not part of condition {self.run_spec.condition.value}; write rejected"
            )
        if role in self._sealed:
            raise GovernanceViolation(f"stage {role!r} is sealed; previous-stage artifacts are immutable")
        staging = self._staging_role_dir(role)
        if not staging.is_dir():
            raise GovernanceViolation(f"no staged artifacts to commit for stage {role!r}")
        staged_files = sorted(path for path in staging.glob("*.md") if path.is_file())
        if not staged_files:
            raise GovernanceViolation(f"no staged artifacts to commit for stage {role!r}")
        promoted: dict[str, str] = {}
        for staged in staged_files:
            name = staged.stem
            dest = self.artifact_path(role, name)
            if dest.exists():
                raise GovernanceViolation(
                    f"artifact already exists for stage {role!r}: {name!r} is write-once"
                )
            data = staged.read_bytes()
            dest.write_bytes(data)
            self._record_committed_artifact(role, name, data)
            promoted[name] = self.artifact_ref(role, name)
        shutil.rmtree(staging)
        self._remove_empty_staging_root()
        return promoted

    def abort_uncommitted_stage(self, role: str) -> None:
        """Roll back promoted files/seals for a stage that never successfully committed.

        Invocation evidence is retained as untrusted attempt evidence. Model
        artifacts and success seals for this role are removed so a deadline
        failure cannot leave a successful topology.
        """
        staging = self.run_dir / STAGING_ROOT / role
        if staging.exists():
            shutil.rmtree(staging)
        self._remove_empty_staging_root()
        seal_path = self.run_dir / "seals" / f"{role}.json"
        if seal_path.exists():
            seal_path.unlink()
        self._sealed.discard(role)
        expected_names = {PRIMARY_ARTIFACT.get(role), *EXTRA_ARTIFACTS.get(role, ())} - {None}
        for name in expected_names:
            path = self.artifact_path(role, name)
            if path.exists():
                path.unlink()
            self._authoritative.pop((role, name), None)
        self._rewrite_manifest_without_role_model_artifacts(role)

    def invocation_attempt_exists(self, role: str, attempt: int) -> bool:
        path = self.run_dir / INVOCATION_ROOT / role / attempt_dirname(attempt) / INVOCATION_FILENAME
        return path.is_file()

    def write_treatment_declaration(self, declaration: dict, treatment_hash: str) -> None:
        if type(declaration) is not dict:
            raise GovernanceViolation("treatment declaration must be an object")
        computed = digest_json(declaration)
        if computed != treatment_hash:
            raise GovernanceViolation("treatment declaration hash does not match payload")
        path = self.run_dir / TREATMENT_DECLARATION
        if path.exists():
            raise GovernanceViolation("treatment declaration already exists")
        path.write_text(
            json.dumps(
                {"declaration": declaration, "treatment_hash": treatment_hash},
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        path.chmod(0o444)

    def write_task_record(self, payload: dict) -> None:
        self._write_frozen_json(TASK_RECORD, payload)

    def write_execution_binding(self, payload: dict) -> None:
        self._write_frozen_json(EXECUTION_BINDING, payload)

    def write_evaluator_binding(self, payload: dict) -> None:
        self._write_frozen_json(EVALUATOR_BINDING, payload)

    def write_source_provenance(self, payload: dict) -> None:
        self._write_frozen_json(SOURCE_PROVENANCE, payload)

    def freeze_run_authority(self) -> None:
        """Freeze hashes of run-defining records as the local trust anchor.

        This is a harness-owned consistency root, not a signature. An attacker
        who can rewrite this file together with every bound input is outside
        the M1 ArtifactStore threat model (Decision 0004).
        """
        payload = {
            "schema": RUN_AUTHORITY_SCHEMA,
            "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
            "context_policy_version": CONTEXT_POLICY_VERSION,
            "live_contract_version": LIVE_CONTRACT_VERSION,
            "run_id": self.run_spec.run_id,
            "run_spec_sha256": _sha256_file(self.run_dir / "run_spec.json"),
            "task_sha256": _sha256_file(self.run_dir / TASK_RECORD),
            "execution_binding_sha256": _sha256_file(self.run_dir / EXECUTION_BINDING),
            "evaluator_binding_sha256": _sha256_file(self.run_dir / EVALUATOR_BINDING),
            "source_provenance_sha256": _sha256_file(self.run_dir / SOURCE_PROVENANCE),
            "treatment_declaration_sha256": _sha256_file(self.run_dir / TREATMENT_DECLARATION),
        }
        self._write_frozen_json(RUN_AUTHORITY, payload)

    def _write_frozen_json(self, filename: str, payload: dict) -> None:
        if type(payload) is not dict:
            raise GovernanceViolation(f"{filename} payload must be an object")
        path = contained_path(self.run_dir, self.run_dir / filename)
        if path.exists():
            raise GovernanceViolation(f"{filename} already exists")
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        path.chmod(0o444)

    def _validated_artifact_bytes(self, role: str, name: str, content: str) -> bytes:
        if type(content) is not str:
            raise GovernanceViolation(
                f"artifact {name!r} content must be a string, got {type(content).__name__}"
            )
        if role not in self._allowed_roles:
            raise GovernanceViolation(
                f"role {role!r} is not part of condition {self.run_spec.condition.value}; write rejected"
            )
        if role in self._sealed:
            raise GovernanceViolation(f"stage {role!r} is sealed; previous-stage artifacts are immutable")
        expected_names = {PRIMARY_ARTIFACT.get(role), *EXTRA_ARTIFACTS.get(role, ())} - {None}
        if name not in expected_names:
            raise GovernanceViolation(
                f"role {role!r} may only write artifacts {sorted(expected_names)}; got {name!r}"
            )
        safe_identifier(name, "artifact name")
        return content.encode("utf-8")

    def _record_committed_artifact(self, role: str, name: str, data: bytes) -> None:
        digest = sha256_bytes(data)
        self._authoritative[(role, name)] = digest
        self._append_manifest(
            {
                "kind": KIND_MODEL_ARTIFACT,
                "role": role,
                "name": name,
                "sha256": digest,
                "bytes": len(data),
                "written_at": _utcnow(),
            }
        )

    def _staging_role_dir(self, role: str) -> Path:
        safe_identifier(role, "role")
        return contained_path(self.run_dir, self.run_dir / STAGING_ROOT / role)

    def _remove_empty_staging_root(self) -> None:
        root = self.run_dir / STAGING_ROOT
        if root.is_dir() and not any(root.iterdir()):
            root.rmdir()

    def _rewrite_manifest_without_role_model_artifacts(self, role: str) -> None:
        entries = self._manifest_entries()
        kept = [
            entry
            for entry in entries
            if not (_entry_kind(entry) == KIND_MODEL_ARTIFACT and entry.get("role") == role)
        ]
        path = self.run_dir / MANIFEST
        tmp = path.with_name(f"{path.name}.tmp")
        if not kept:
            tmp.write_text("", encoding="utf-8")
        else:
            tmp.write_text(
                "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in kept),
                encoding="utf-8",
            )
        tmp.replace(path)

    def seal_stage(
        self,
        role: str,
        *,
        expected_attempts: int | None = None,
        before_persist=None,
    ) -> dict:
        if role not in self._allowed_roles:
            raise GovernanceViolation(f"cannot seal unknown role {role!r}")
        model_entries = [
            {
                "role": e["role"],
                "name": e["name"],
                "sha256": e["sha256"],
                "bytes": e["bytes"],
            }
            for e in self._manifest_entries()
            if _entry_kind(e) == KIND_MODEL_ARTIFACT and e.get("role") == role
        ]
        expected_names = EXPECTED_ARTIFACTS[role]
        names = [entry["name"] for entry in model_entries]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise GovernanceViolation(
                f"cannot seal stage {role!r}; expected exactly {sorted(expected_names)}, "
                f"found {sorted(names)}"
            )
        invocation_entries = [
            _invocation_seal_entry(e)
            for e in self._manifest_entries()
            if _entry_kind(e) in {KIND_INVOCATION_METADATA, KIND_UNTRUSTED_RAW_OUTPUT}
            and e.get("role") == role
        ]
        meta_attempts = sorted(
            e["attempt"]
            for e in invocation_entries
            if e.get("kind") == KIND_INVOCATION_METADATA
        )
        if expected_attempts is None:
            bound_attempts = meta_attempts[-1] if meta_attempts else 0
        else:
            if type(expected_attempts) is not int or isinstance(expected_attempts, bool) or expected_attempts < 0:
                raise GovernanceViolation(
                    f"expected_attempts must be a non-negative integer, got {expected_attempts!r}"
                )
            bound_attempts = expected_attempts
        expected_attempt_list = list(range(1, bound_attempts + 1))
        if meta_attempts != expected_attempt_list:
            raise GovernanceViolation(
                f"cannot seal stage {role!r}; expected invocation attempts "
                f"{expected_attempt_list}, found {meta_attempts}"
            )
        seal_body = {
            "artifacts": model_entries,
            "invocations": invocation_entries,
            "expected_attempts": bound_attempts,
        }
        seal = {
            "role": role,
            "sealed_at": _utcnow(),
            "artifacts": model_entries,
            "invocations": invocation_entries,
            "expected_attempts": bound_attempts,
            "stage_digest": sha256_text(json.dumps(seal_body, sort_keys=True)),
        }
        if before_persist is not None:
            before_persist()
        seal_path = self.run_dir / "seals" / f"{role}.json"
        seal_path.parent.mkdir(exist_ok=True)
        seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")
        self._sealed.add(role)
        return seal

    def _manifest_entries(self) -> list[dict]:
        path = self.run_dir / MANIFEST
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def verify_sealed_stage(self, role: str) -> None:
        """Cross-check a sealed stage against BOTH persisted seals and the
        authoritative parent-side record. Altering artifact + seal together
        still fails against the authoritative hashes while the run is active;
        after completion, the append-only manifest plays that role (see
        verify_completed)."""
        if role not in self._allowed_roles:
            raise IntegrityViolation(f"stage {role!r} is not part of this run")
        seal_path = self.run_dir / "seals" / f"{role}.json"
        if not seal_path.exists():
            raise IntegrityViolation(f"no seal record for stage {role!r}")
        try:
            seal = json.loads(seal_path.read_text())
            entries = seal["artifacts"]
            seal_role = seal["role"]
            stage_digest = seal["stage_digest"]
        except (OSError, TypeError, ValueError, KeyError) as exc:
            raise IntegrityViolation(f"malformed seal record for stage {role!r}") from exc
        if type(seal) is not dict or type(entries) is not list or seal_role != role:
            raise IntegrityViolation(f"malformed seal record for stage {role!r}")

        expected_keys = {(role, name) for name in EXPECTED_ARTIFACTS[role]}
        seal_index = _index_entries(entries, f"seal for stage {role!r}")
        if set(seal_index) != expected_keys:
            raise IntegrityViolation(
                f"seal for stage {role!r} does not contain the exact expected artifact set"
            )
        expected_digest = sha256_text(json.dumps(_seal_digest_body(seal, entries), sort_keys=True))
        if stage_digest != expected_digest:
            raise IntegrityViolation(f"stage digest mismatch for stage {role!r}")

        model_manifest = [
            e for e in self._manifest_entries() if _entry_kind(e) == KIND_MODEL_ARTIFACT
        ]
        manifest_index = _index_entries(model_manifest, "artifact manifest")
        allowed_keys = {
            (stage, name)
            for stage in self._allowed_roles
            for name in EXPECTED_ARTIFACTS[stage]
        }
        if not set(manifest_index).issubset(allowed_keys):
            raise IntegrityViolation("artifact manifest contains an unexpected artifact")
        stage_manifest = {key: value for key, value in manifest_index.items() if key[0] == role}
        if set(stage_manifest) != expected_keys:
            raise IntegrityViolation(
                f"manifest for stage {role!r} does not contain the exact expected artifact set"
            )

        for key in expected_keys:
            entry = seal_index[key]
            record = stage_manifest[key]
            _verify_manifest_match(entry, record, key)
            file_path = self.artifact_path(*key)
            if not file_path.is_file():
                raise IntegrityViolation(f"sealed artifact missing: {key[0]}/{key[1]}")
            data = file_path.read_bytes()
            actual = sha256_bytes(data)
            if actual != record["sha256"] or len(data) != record["bytes"]:
                raise IntegrityViolation(f"tampering detected: {key[0]}/{key[1]}")
            if key in self._authoritative and actual != self._authoritative[key]:
                raise IntegrityViolation(f"authoritative hash mismatch: {key[0]}/{key[1]}")
        self._verify_role_invocations(
            role,
            seal.get("invocations") or [],
            require_seal_match=True,
        )
        _verify_seal_invocation_bind(role, seal, self._manifest_entries())

    def record_invocation(self, role: str, attempt: int, record: dict, raw_text: str | None) -> dict:
        """Persist write-once untrusted invocation evidence. Not a stage artifact."""
        if role not in self._allowed_roles:
            raise GovernanceViolation(
                f"role {role!r} is not part of condition {self.run_spec.condition.value}"
            )
        safe_identifier(role, "role")
        dirname = attempt_dirname(attempt)
        safe_identifier(dirname, "attempt directory")
        inv_dir = contained_path(
            self.run_dir, self.run_dir / INVOCATION_ROOT / role / dirname
        )
        if inv_dir.exists():
            raise GovernanceViolation(
                f"invocation attempt namespace already exists for {role!r} attempt {attempt}"
            )
        inv_dir.mkdir(parents=True)
        bounded = bound_raw_evidence(raw_text, limit=self.max_raw_evidence_bytes)
        raw_meta = dict(bounded)
        raw_ref = None
        if bounded["present"]:
            raw_path = contained_path(inv_dir, inv_dir / RAW_OUTPUT_FILENAME)
            raw_bytes = bounded["stored_text"].encode("utf-8")
            raw_path.write_bytes(raw_bytes)
            raw_digest = sha256_bytes(raw_bytes)
            raw_meta["sha256_stored"] = raw_digest
            raw_ref = invocation_ref(role, attempt, RAW_OUTPUT_FILENAME)
            self._authoritative_invocations[(role, attempt, KIND_UNTRUSTED_RAW_OUTPUT)] = raw_digest
            self._append_manifest(
                {
                    "kind": KIND_UNTRUSTED_RAW_OUTPUT,
                    "role": role,
                    "attempt": attempt,
                    "ref": raw_ref,
                    "sha256": raw_digest,
                    "bytes": len(raw_bytes),
                    "truncated": bounded["truncated"],
                    "stored_bytes": bounded["stored_bytes"],
                    "observed_bytes": bounded["observed_bytes"],
                    "written_at": _utcnow(),
                }
            )
        if record.get("run_id") != self.run_spec.run_id:
            raise GovernanceViolation("invocation record run_id does not match the store")
        if record.get("role") != role or record.get("attempt") != attempt:
            raise GovernanceViolation("invocation record role/attempt does not match the path")
        record = dict(record)
        record["raw_output"] = {
            "present": bounded["present"],
            "truncated": bounded["truncated"],
            "ref": raw_ref,
            "stored_bytes": bounded["stored_bytes"],
            "observed_bytes": bounded["observed_bytes"],
            "sha256_stored": raw_meta.get("sha256_stored"),
            "sha256_complete": bounded["sha256_complete"],
            "truncation_label": bounded["label"],
        }
        serialized = serialize_invocation_record(record)
        meta_path = contained_path(inv_dir, inv_dir / INVOCATION_FILENAME)
        meta_bytes = serialized.encode("utf-8")
        meta_path.write_bytes(meta_bytes)
        meta_digest = sha256_bytes(meta_bytes)
        meta_ref = invocation_ref(role, attempt, INVOCATION_FILENAME)
        self._authoritative_invocations[(role, attempt, KIND_INVOCATION_METADATA)] = meta_digest
        self._append_manifest(
            {
                "kind": KIND_INVOCATION_METADATA,
                "role": role,
                "attempt": attempt,
                "ref": meta_ref,
                "sha256": meta_digest,
                "bytes": len(meta_bytes),
                "written_at": _utcnow(),
            }
        )
        return {"invocation_ref": meta_ref, "raw_ref": raw_ref, "record": record}

    def _verify_role_invocations(self, role: str, seal_invocations, *, require_seal_match: bool) -> None:
        manifest_inv = [
            e
            for e in self._manifest_entries()
            if _entry_kind(e) in {KIND_INVOCATION_METADATA, KIND_UNTRUSTED_RAW_OUTPUT}
            and e.get("role") == role
        ]
        if require_seal_match:
            seal_index = {(e.get("kind"), e.get("attempt"), e.get("ref")): e for e in seal_invocations}
            man_index = {(e.get("kind"), e.get("attempt"), e.get("ref")): e for e in manifest_inv}
            if set(seal_index) != set(man_index):
                raise IntegrityViolation(
                    f"seal invocations for stage {role!r} do not match the manifest"
                )
        _verify_invocation_files(
            self.run_dir,
            manifest_inv,
            run_id=self.run_spec.run_id,
            allowed_roles=self._allowed_roles,
            authoritative=self._authoritative_invocations,
        )

    def verify_invocation_evidence(self) -> dict:
        """Verify invocation evidence without claiming any stage succeeded."""
        _verify_all_invocation_evidence(
            self.run_dir,
            self._manifest_entries(),
            self._allowed_roles,
            run_id=self.run_spec.run_id,
            authoritative=self._authoritative_invocations,
        )
        return {"invocation_evidence_verified": True, "verified_at": _utcnow()}

    def verify_completed_run(self) -> dict:
        if set(self._sealed) != set(self._allowed_roles):
            raise IntegrityViolation("completed run is missing one or more stage seals")
        results = {}
        for role in self._allowed_roles:
            self.verify_sealed_stage(role)
            results[role] = "verified"
        invocation = self.verify_invocation_evidence()
        return {
            "integrity_verified": True,
            "stages": results,
            "invocation_evidence_verified": invocation["invocation_evidence_verified"],
            "verified_at": _utcnow(),
        }

    @classmethod
    def verify_completed(cls, runs_root: Path | str, run_id: str) -> dict:
        """Public read-only verifier for completed runs.

        Cross-checks manifest.jsonl, seals/*.json, artifact file hashes, and
        the terminal result's final-candidate reference. This detects
        accidental or targeted filesystem mutation of artifacts and/or seals,
        because the append-only manifest retains the original write-time
        hashes. Known limitation: a same-user attacker who rewrites ALL local
        evidence (artifacts + seals + manifest) post-completion defeats an
        unauthenticated local record; M1 does not provide external notarization.
        """
        runs = Path(runs_root).resolve()
        safe_identifier(run_id, "run_id")
        run_dir = contained_path(runs, runs / run_id)
        spec_path = run_dir / "run_spec.json"
        manifest_path = run_dir / MANIFEST
        result_path = run_dir / EVENT_RUN_RESULT
        if not spec_path.exists() or not manifest_path.exists() or not result_path.exists():
            raise IntegrityViolation(f"completed run evidence is incomplete for {run_id!r}")
        try:
            spec_payload = json.loads(spec_path.read_text())
            canonical = json.loads(spec_payload["canonical"])
            condition = Condition(canonical["condition"])
            expected_roles = CONDITION_STAGES[condition]
            expected_keys = {
                (role, name)
                for role in expected_roles
                for name in EXPECTED_ARTIFACTS[role]
            }
            if spec_payload["spec_hash"] != sha256_text(spec_payload["canonical"]):
                raise IntegrityViolation("run specification hash mismatch")
        except IntegrityViolation:
            raise
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed run specification for {run_id!r}") from exc

        try:
            manifest_entries = [
                json.loads(line)
                for line in manifest_path.read_text().splitlines()
                if line.strip()
            ]
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed artifact manifest for {run_id!r}") from exc
        model_entries = [e for e in manifest_entries if _entry_kind(e) == KIND_MODEL_ARTIFACT]
        records = _index_entries(model_entries, "artifact manifest")
        if set(records) != expected_keys:
            raise IntegrityViolation("artifact manifest does not match expected run topology")
        _verify_all_invocation_evidence(
            run_dir,
            manifest_entries,
            expected_roles,
            run_id=run_id,
            stages=None,
        )

        seals_dir = run_dir / "seals"
        sealed_roles = (
            [p.stem for p in sorted(seals_dir.glob("*.json"))] if seals_dir.exists() else []
        )
        if set(sealed_roles) != set(expected_roles):
            raise IntegrityViolation("stage seals do not match expected run topology")
        verified_stages = []
        for role in expected_roles:
            try:
                seal = json.loads((seals_dir / f"{role}.json").read_text())
                entries = seal["artifacts"]
                if type(seal) is not dict or type(entries) is not list or seal["role"] != role:
                    raise IntegrityViolation(f"malformed seal record for stage {role!r}")
                role_keys = {(role, name) for name in EXPECTED_ARTIFACTS[role]}
                seal_index = _index_entries(entries, f"seal for stage {role!r}")
                if set(seal_index) != role_keys:
                    raise IntegrityViolation(f"seal for stage {role!r} is incomplete")
                if seal["stage_digest"] != sha256_text(
                    json.dumps(_seal_digest_body(seal, entries), sort_keys=True)
                ):
                    raise IntegrityViolation(f"stage digest mismatch for stage {role!r}")
                _verify_seal_invocation_bind(role, seal, manifest_entries)
                for key in role_keys:
                    entry = seal_index[key]
                    record = records[key]
                    _verify_manifest_match(entry, record, key)
                    file_path = contained_path(run_dir, run_dir / key[0] / f"{key[1]}.md")
                    if not file_path.is_file():
                        raise IntegrityViolation(f"artifact missing: {key[0]}/{key[1]}")
                    data = file_path.read_bytes()
                    if sha256_bytes(data) != record["sha256"] or len(data) != record["bytes"]:
                        raise IntegrityViolation(f"artifact tampering detected for {key}")
            except IntegrityViolation:
                raise
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                raise IntegrityViolation(f"malformed seal record for stage {role!r}") from exc
            verified_stages.append(role)

        try:
            payload = json.loads(result_path.read_text())
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed terminal record for {run_id!r}") from exc
        if payload.get("status") != STATUS_SUCCEEDED:
            raise IntegrityViolation("completed-run verification requires a succeeded terminal record")
        final_ref = payload.get("final_candidate_ref")
        final_role = expected_roles[-1]
        final_name = PRIMARY_ARTIFACT[final_role]
        expected_final_ref = f"{final_role}/{final_name}.md"
        if final_ref != expected_final_ref:
            raise IntegrityViolation("terminal record final candidate reference is invalid")
        candidate = contained_path(run_dir, run_dir / final_ref)
        if not candidate.is_file():
            raise IntegrityViolation(f"terminal record references missing final candidate {final_ref!r}")
        final_record = records[(final_role, final_name)]
        if sha256_bytes(candidate.read_bytes()) != final_record["sha256"]:
            raise IntegrityViolation("final candidate hash does not match the manifest")
        _assert_invocation_attempt_topology(expected_roles, payload.get("stages") or [], manifest_entries)

        return {
            "run_id": run_id,
            "integrity_verified": True,
            "sealed_stages": verified_stages,
            "artifact_count": len(records),
            "final_candidate_ref": final_ref,
            "verified_at": _utcnow(),
        }

    @classmethod
    def verify_run_integrity(cls, runs_root: Path | str, run_id: str) -> dict:
        """Verify invocation evidence and any existing success seals.

        Does not claim failed or unsealed stages succeeded. Detects tampering
        with failed-attempt evidence while leaving terminal status untouched.
        """
        runs = Path(runs_root).resolve()
        safe_identifier(run_id, "run_id")
        run_dir = contained_path(runs, runs / run_id)
        spec_path = run_dir / "run_spec.json"
        manifest_path = run_dir / MANIFEST
        result_path = run_dir / EVENT_RUN_RESULT
        if not spec_path.exists() or not manifest_path.exists():
            raise IntegrityViolation(f"run evidence is incomplete for {run_id!r}")
        try:
            spec_payload = json.loads(spec_path.read_text())
            canonical = json.loads(spec_payload["canonical"])
            condition = Condition(canonical["condition"])
            expected_roles = CONDITION_STAGES[condition]
            if spec_payload["spec_hash"] != sha256_text(spec_payload["canonical"]):
                raise IntegrityViolation("run specification hash mismatch")
        except IntegrityViolation:
            raise
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed run specification for {run_id!r}") from exc
        try:
            manifest_entries = [
                json.loads(line)
                for line in manifest_path.read_text().splitlines()
                if line.strip()
            ]
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed artifact manifest for {run_id!r}") from exc
        _verify_all_invocation_evidence(
            run_dir,
            manifest_entries,
            expected_roles,
            run_id=run_id,
        )
        stages = []
        terminal_status = None
        if result_path.exists():
            try:
                payload = json.loads(result_path.read_text())
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise IntegrityViolation(f"malformed terminal record for {run_id!r}") from exc
            terminal_status = payload.get("status")
            stages = payload.get("stages") or []
            _assert_invocation_attempt_topology(expected_roles, stages, manifest_entries)

        seals_dir = run_dir / "seals"
        sealed_roles = (
            [p.stem for p in sorted(seals_dir.glob("*.json"))] if seals_dir.exists() else []
        )
        unexpected_seals = set(sealed_roles) - set(expected_roles)
        if unexpected_seals:
            raise IntegrityViolation(f"unexpected stage seals present: {sorted(unexpected_seals)}")
        failed_roles = {
            stage["role"]
            for stage in stages
            if stage.get("status") not in {None, "succeeded"}
        }
        sealed_failures = failed_roles.intersection(sealed_roles)
        if sealed_failures:
            raise IntegrityViolation(
                f"failed stage(s) must not have a success seal: {sorted(sealed_failures)}"
            )
        for role in sealed_roles:
            _verify_persisted_seal(run_dir, role, manifest_entries)
        return {
            "run_id": run_id,
            "verification_scope": "partial_evidence",
            "terminal_verified": False,
            "terminal_status": terminal_status,
            "invocation_evidence_verified": True,
            "completed_topology_verified": terminal_status == STATUS_SUCCEEDED
            and set(sealed_roles) == set(expected_roles),
            "sealed_stages": list(sealed_roles),
            "verified_at": _utcnow(),
        }

    @classmethod
    def verify_terminal_run(cls, runs_root: Path | str, run_id: str) -> dict:
        """Verify a finished run, including its terminal record.

        Distinct from verify_run_integrity, which may succeed on partial
        evidence without a terminal record. Callers must not treat a partial
        evidence result as a verified terminal failure.
        """
        runs = Path(runs_root).resolve()
        safe_identifier(run_id, "run_id")
        run_dir = contained_path(runs, runs / run_id)
        spec_path = run_dir / "run_spec.json"
        manifest_path = run_dir / MANIFEST
        result_path = run_dir / EVENT_RUN_RESULT
        if not spec_path.exists() or not manifest_path.exists():
            raise IntegrityViolation(f"run evidence is incomplete for {run_id!r}")
        if not result_path.exists():
            raise IntegrityViolation(f"terminal record is missing for {run_id!r}")
        _assert_run_authority(run_dir, run_id)
        try:
            spec_payload = json.loads(spec_path.read_text())
            canonical = json.loads(spec_payload["canonical"])
            condition = Condition(canonical["condition"])
            expected_roles = CONDITION_STAGES[condition]
            if spec_payload["spec_hash"] != sha256_text(spec_payload["canonical"]):
                raise IntegrityViolation("run specification hash mismatch")
        except IntegrityViolation:
            raise
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed run specification for {run_id!r}") from exc
        try:
            payload = json.loads(result_path.read_text())
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed terminal record for {run_id!r}") from exc
        status = payload.get("status")
        if status not in _TERMINAL_STATUSES:
            raise IntegrityViolation(f"terminal record has unrecognized status {status!r}")
        if payload.get("harness_protocol_version") != HARNESS_PROTOCOL_VERSION:
            raise IntegrityViolation("terminal record harness protocol version mismatch")
        if payload.get("spec_hash") != spec_payload["spec_hash"]:
            raise IntegrityViolation("terminal record spec_hash does not match run_spec.json")
        _assert_terminal_record_coherence(
            run_id=run_id,
            run_dir=run_dir,
            canonical=canonical,
            payload=payload,
        )
        try:
            manifest_entries = [
                json.loads(line)
                for line in manifest_path.read_text().splitlines()
                if line.strip()
            ]
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityViolation(f"malformed artifact manifest for {run_id!r}") from exc
        _verify_all_invocation_evidence(
            run_dir,
            manifest_entries,
            expected_roles,
            run_id=run_id,
            stages=payload.get("stages") or [],
        )
        execution_binding = _read_frozen_object(run_dir, EXECUTION_BINDING, "execution binding")
        _assert_invocation_profile_binding(run_dir, execution_binding, canonical, manifest_entries)
        _assert_invocation_treatment_digests(
            run_dir=run_dir,
            canonical=canonical,
            execution_binding=execution_binding,
            manifest_entries=manifest_entries,
        )
        _assert_terminal_status_topology(
            run_dir=run_dir,
            expected_roles=expected_roles,
            payload=payload,
            manifest_entries=manifest_entries,
        )
        if status == STATUS_SUCCEEDED:
            completed = cls.verify_completed(runs_root, run_id)
            completed["verification_scope"] = "terminal_run"
            completed["terminal_verified"] = True
            completed["terminal_status"] = status
            return completed
        seals_dir = run_dir / "seals"
        sealed_roles = (
            [p.stem for p in sorted(seals_dir.glob("*.json"))] if seals_dir.exists() else []
        )
        unexpected_seals = set(sealed_roles) - set(expected_roles)
        if unexpected_seals:
            raise IntegrityViolation(f"unexpected stage seals present: {sorted(unexpected_seals)}")
        for role in sealed_roles:
            _verify_persisted_seal(run_dir, role, manifest_entries)
        return {
            "run_id": run_id,
            "verification_scope": "terminal_run",
            "terminal_verified": True,
            "terminal_status": status,
            "invocation_evidence_verified": True,
            "completed_topology_verified": False,
            "sealed_stages": list(sealed_roles),
            "verified_at": _utcnow(),
        }

    def record_event(self, filename: str, payload: dict) -> str:
        if filename not in ALLOWED_EVENTS:
            raise GovernanceViolation(
                f"event filename {filename!r} is not an internal constant; allowed={sorted(ALLOWED_EVENTS)}"
            )
        path = self.run_dir / filename
        contained_path(self.run_dir, path)
        if path.exists():
            raise GovernanceViolation(f"event file already exists: {filename}")
        payload = dict(payload)
        payload["recorded_at"] = _utcnow()
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return str(path.relative_to(self.run_dir))


def _sha256_file(path: Path) -> str:
    if not path.is_file():
        raise IntegrityViolation(f"run-defining record is missing: {path.name}")
    return sha256_bytes(path.read_bytes())


_RUN_AUTHORITY_BINDINGS = (
    ("run_spec_sha256", "run_spec.json"),
    ("task_sha256", TASK_RECORD),
    ("execution_binding_sha256", EXECUTION_BINDING),
    ("evaluator_binding_sha256", EVALUATOR_BINDING),
    ("source_provenance_sha256", SOURCE_PROVENANCE),
    ("treatment_declaration_sha256", TREATMENT_DECLARATION),
)


def _assert_run_authority(run_dir: Path, run_id: str) -> dict:
    """Load the local trust anchor and require bound files to match it.

    Detects partial mutation among frozen run-defining records. Does not
    authenticate the ArtifactStore against an attacker who rewrites this
    file together with every bound input.
    """
    authority = _read_frozen_object(run_dir, RUN_AUTHORITY, "run authority")
    if authority.get("schema") != RUN_AUTHORITY_SCHEMA:
        raise IntegrityViolation("run authority schema is not recognized")
    if authority.get("harness_protocol_version") != HARNESS_PROTOCOL_VERSION:
        raise IntegrityViolation("run authority harness protocol version mismatch")
    if authority.get("context_policy_version") != CONTEXT_POLICY_VERSION:
        raise IntegrityViolation("run authority context-policy version mismatch")
    if authority.get("live_contract_version") != LIVE_CONTRACT_VERSION:
        raise IntegrityViolation("run authority live-contract version mismatch")
    if authority.get("run_id") != run_id:
        raise IntegrityViolation("run authority run_id does not match the run directory")
    for key, filename in _RUN_AUTHORITY_BINDINGS:
        actual = _sha256_file(run_dir / filename)
        if authority.get(key) != actual:
            raise IntegrityViolation(f"run authority hash mismatch for {filename}")
    return authority


def _assert_terminal_record_coherence(
    *,
    run_id: str,
    run_dir: Path,
    canonical: dict,
    payload: dict,
) -> None:
    if payload.get("run_id") != run_id:
        raise IntegrityViolation("terminal record run_id does not match the run directory")
    if canonical.get("run_id") != run_id:
        raise IntegrityViolation("run_spec.json run_id does not match the run directory")
    if payload.get("condition") != canonical.get("condition"):
        raise IntegrityViolation("terminal record condition does not match run_spec.json")
    if payload.get("model_identifier") != canonical.get("model_identifier"):
        raise IntegrityViolation("terminal record model identity does not match run_spec.json")
    task_record = _read_frozen_object(run_dir, TASK_RECORD, "task record")
    execution_binding = _read_frozen_object(run_dir, EXECUTION_BINDING, "execution binding")
    evaluator_binding = _read_frozen_object(run_dir, EVALUATOR_BINDING, "evaluator binding")
    reconstructed = _reconstruct_treatment(
        canonical=canonical,
        task_record=task_record,
        execution_binding=execution_binding,
        evaluator_binding=evaluator_binding,
    )
    declaration_path = run_dir / TREATMENT_DECLARATION
    if not declaration_path.is_file():
        raise IntegrityViolation("treatment declaration is missing")
    try:
        stored = json.loads(declaration_path.read_text())
        declaration = stored["declaration"]
        stored_hash = stored["treatment_hash"]
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise IntegrityViolation("malformed treatment declaration") from exc
    if type(declaration) is not dict or type(stored_hash) is not str:
        raise IntegrityViolation("malformed treatment declaration")
    if declaration != reconstructed:
        raise IntegrityViolation(
            "treatment declaration does not match independently authenticated inputs"
        )
    authoritative_hash = digest_json(reconstructed)
    if stored_hash != authoritative_hash:
        raise IntegrityViolation("treatment declaration hash does not match reconstructed treatment")
    if payload.get("treatment_hash") != authoritative_hash:
        raise IntegrityViolation("terminal treatment hash does not match the reconstructed treatment")
    _assert_source_provenance_coherence(run_dir, payload)


def _read_frozen_object(run_dir: Path, filename: str, label: str) -> dict:
    path = run_dir / filename
    if not path.is_file():
        raise IntegrityViolation(f"{label} is missing")
    try:
        payload = json.loads(path.read_text())
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IntegrityViolation(f"malformed {label}") from exc
    if type(payload) is not dict:
        raise IntegrityViolation(f"{label} must be an object")
    return payload


def _reconstruct_treatment(
    *,
    canonical: dict,
    task_record: dict,
    execution_binding: dict,
    evaluator_binding: dict,
) -> dict:
    required_task = (
        "task_id",
        "bug_report",
        "workspace_id",
        "allowed_files",
        "visible_test_command",
        "snapshot_hash",
        "task_content_hash",
    )
    missing_task = [key for key in required_task if key not in task_record]
    if missing_task:
        raise IntegrityViolation(f"task record missing fields: {missing_task}")
    recomputed_task_hash = digest_json(
        {
            "task_id": task_record["task_id"],
            "bug_report": task_record["bug_report"],
            "workspace_id": task_record["workspace_id"],
            "allowed_files": task_record["allowed_files"],
            "visible_test_command": task_record["visible_test_command"],
            "snapshot_hash": task_record["snapshot_hash"],
        }
    )
    if recomputed_task_hash != task_record["task_content_hash"]:
        raise IntegrityViolation("task record content hash does not match persisted task fields")
    if task_record["task_id"] != canonical.get("task_id"):
        raise IntegrityViolation("task record task_id does not match run_spec.json")
    required_exec = (
        "adapter_kind",
        "adapter_config_digest",
        "adapter_identity",
        "provider_treatment_config",
        "execution_profile",
        "live_contract_version",
        "harness_protocol_version",
        "context_policy_version",
    )
    missing_exec = [key for key in required_exec if key not in execution_binding]
    if missing_exec:
        raise IntegrityViolation(f"execution binding missing fields: {missing_exec}")
    if execution_binding["harness_protocol_version"] != HARNESS_PROTOCOL_VERSION:
        raise IntegrityViolation("execution binding harness protocol version mismatch")
    if execution_binding["context_policy_version"] != CONTEXT_POLICY_VERSION:
        raise IntegrityViolation("execution binding context-policy version mismatch")
    if execution_binding["live_contract_version"] != LIVE_CONTRACT_VERSION:
        raise IntegrityViolation("execution binding live-contract version mismatch")
    try:
        provider_treatment_config = normalize_provider_treatment_config(
            execution_binding["provider_treatment_config"]
        )
    except GovernanceViolation as exc:
        raise IntegrityViolation(
            "execution binding provider_treatment_config is not valid treatment authority"
        ) from exc
    try:
        registry_profile = execution_profile_for_kind(execution_binding["adapter_kind"])
    except Exception as exc:  # noqa: BLE001 - unknown kinds fail closed
        raise IntegrityViolation("execution binding adapter kind is not a registered profile") from exc
    if execution_binding["execution_profile"] != registry_profile:
        raise IntegrityViolation("execution binding profile does not match the trusted kind registry")
    adapter_identity = _adapter_identity_from_execution_binding(execution_binding)
    if adapter_identity.key() != canonical.get("model_identifier"):
        raise IntegrityViolation(
            "execution binding adapter identity does not match run_spec.json model_identifier"
        )
    if evaluator_binding.get("evaluator_version") in {None, ""}:
        raise IntegrityViolation("evaluator binding is missing evaluator_version")
    if evaluator_binding.get("evaluator_config_digest") in {None, ""}:
        raise IntegrityViolation("evaluator binding is missing evaluator_config_digest")
    return {
        "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
        "condition": canonical.get("condition"),
        "prompt_version": canonical.get("prompt_version"),
        "context_policy_version": CONTEXT_POLICY_VERSION,
        "resource_limits": canonical.get("resource_limits"),
        "seed": canonical.get("seed"),
        "model_identifier": canonical.get("model_identifier"),
        "adapter_kind": execution_binding["adapter_kind"],
        "adapter_config_digest": execution_binding["adapter_config_digest"],
        "provider_treatment_config": provider_treatment_config,
        "evaluator_version": evaluator_binding["evaluator_version"],
        "evaluator_config_digest": evaluator_binding["evaluator_config_digest"],
        "task_id": canonical.get("task_id"),
        "task_content_hash": recomputed_task_hash,
        "execution_profile": execution_binding["execution_profile"],
        "live_contract_version": execution_binding["live_contract_version"],
    }


def _assert_source_provenance_coherence(run_dir: Path, payload: dict) -> None:
    stored = _read_frozen_object(run_dir, SOURCE_PROVENANCE, "source provenance")
    if payload.get("source_provenance") != stored:
        raise IntegrityViolation("terminal source provenance does not match the frozen capture")


def _assert_evaluation_coherence(run_dir: Path, payload: dict, evaluator_binding: dict) -> None:
    status = payload.get("status")
    eval_path = run_dir / EVENT_EVALUATION
    terminal_eval = payload.get("evaluation")
    terminal_error = payload.get("evaluation_error")
    if status == STATUS_SUCCEEDED:
        if not eval_path.is_file():
            raise IntegrityViolation("succeeded run is missing evaluation.json")
        body = _load_json_object(eval_path, "evaluation record")
        outcome = body.get("outcome")
        if type(outcome) is not dict:
            raise IntegrityViolation("succeeded run evaluation is not a success outcome")
        if terminal_eval != outcome:
            raise IntegrityViolation("terminal evaluation does not match evaluation.json")
        if outcome.get("evaluator_version") != evaluator_binding.get("evaluator_version"):
            raise IntegrityViolation("evaluation.json evaluator version does not match the binding")
        if outcome.get("config_digest") != evaluator_binding.get("evaluator_config_digest"):
            raise IntegrityViolation("evaluation.json config digest does not match the binding")
        return
    if status == STATUS_FAILED_EVALUATION:
        if not eval_path.is_file():
            raise IntegrityViolation("failed_evaluation is missing evaluation.json")
        body = _load_json_object(eval_path, "evaluation record")
        if body.get("status") != STATUS_FAILED_EVALUATION:
            raise IntegrityViolation("evaluation.json does not record failed_evaluation")
        if terminal_eval is not None:
            raise IntegrityViolation("failed_evaluation must not carry a success evaluation")
        if terminal_error != body.get("error"):
            raise IntegrityViolation("terminal evaluation_error does not match evaluation.json")
        return
    if terminal_eval is not None:
        if not eval_path.is_file():
            raise IntegrityViolation("terminal evaluation is present without evaluation.json")
        body = _load_json_object(eval_path, "evaluation record")
        if terminal_eval != body.get("outcome"):
            raise IntegrityViolation("terminal evaluation does not match evaluation.json")


def _load_json_object(path: Path, label: str) -> dict:
    try:
        payload = json.loads(path.read_text())
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IntegrityViolation(f"malformed {label}") from exc
    if type(payload) is not dict:
        raise IntegrityViolation(f"{label} must be an object")
    return payload


def _assert_invocation_profile_binding(
    run_dir: Path, execution_binding: dict, canonical: dict, manifest_entries: list[dict]
) -> None:
    expected_profile = execution_binding.get("execution_profile")
    expected_condition = canonical.get("condition")
    expected_model = canonical.get("model_identifier")
    if expected_profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
        expected_compat = "live_contract"
    elif expected_profile == EXECUTION_PROFILE_PRE_LIVE_LEGACY:
        expected_compat = "pre_live_fake_adapter"
    else:
        raise IntegrityViolation("execution binding has an unsupported execution profile")
    trusted_identity = _adapter_identity_from_execution_binding(execution_binding)
    if trusted_identity.key() != expected_model:
        raise IntegrityViolation(
            "execution binding adapter identity does not match run_spec.json model_identifier"
        )
    for entry in manifest_entries:
        if _entry_kind(entry) != KIND_INVOCATION_METADATA:
            continue
        ref = entry.get("ref")
        path = contained_path(run_dir, run_dir / ref)
        record = _load_json_object(path, f"invocation record {ref}")
        compat = (record.get("adapter_evidence") or {}).get("compatibility")
        if compat != expected_compat:
            raise IntegrityViolation(
                f"invocation {ref} adapter compatibility does not match the execution binding"
            )
        if record.get("condition") != expected_condition:
            raise IntegrityViolation(f"invocation {ref} condition does not match run_spec.json")
        for field in ("requested_identity", "configured_identity"):
            observed = _adapter_identity_from_structured(
                record.get(field), f"invocation {ref} {field}"
            )
            if observed != trusted_identity:
                raise IntegrityViolation(
                    f"invocation {ref} {field} does not match trusted execution-binding identity"
                )


def _assert_invocation_treatment_digests(
    *,
    run_dir: Path,
    canonical: dict,
    execution_binding: dict,
    manifest_entries: list[dict],
) -> None:
    """Recompute each attempt digest from trusted run-defining treatment authority."""
    try:
        identity = _adapter_identity_from_execution_binding(execution_binding)
        resource_limits = ResourceLimits(**canonical["resource_limits"])
        condition = Condition(canonical["condition"])
    except (TypeError, ValueError, KeyError) as exc:
        raise IntegrityViolation("run_spec cannot reconstruct attempt treatment authority") from exc
    if identity.key() != canonical.get("model_identifier"):
        raise IntegrityViolation(
            "execution binding adapter identity does not match run_spec.json model_identifier"
        )
    task_record = _read_frozen_object(run_dir, TASK_RECORD, "task record")
    try:
        provider_treatment_config = normalize_provider_treatment_config(
            execution_binding["provider_treatment_config"]
        )
    except GovernanceViolation as exc:
        raise IntegrityViolation(
            "execution binding provider_treatment_config is not valid treatment authority"
        ) from exc
    for entry in manifest_entries:
        if _entry_kind(entry) != KIND_INVOCATION_METADATA:
            continue
        ref = entry.get("ref")
        role = entry.get("role")
        path = contained_path(run_dir, run_dir / ref)
        record = _load_json_object(path, f"invocation record {ref}")
        if role not in ROLE_INSTRUCTIONS:
            raise IntegrityViolation(f"invocation {ref} role is not a trusted condition role")
        try:
            stage_inputs = _stage_inputs_from_trusted_authority(
                run_dir, condition, role, task_record
            )
            expected_input, expected_digest = treatment_digest_for_attempt(
                condition=condition.value,
                role=role,
                role_instruction=ROLE_INSTRUCTIONS[role],
                stage_inputs=stage_inputs,
                requested_identity=identity,
                configured_identity=identity,
                seed=canonical["seed"],
                resource_limits=resource_limits,
                execution_profile=execution_binding["execution_profile"],
                adapter_kind=execution_binding["adapter_kind"],
                adapter_config_digest=execution_binding["adapter_config_digest"],
                live_contract_version=execution_binding["live_contract_version"],
                harness_protocol_version=execution_binding["harness_protocol_version"],
                provider_treatment_config=provider_treatment_config,
            )
        except (GovernanceViolation, IntegrityViolation, TypeError, ValueError, KeyError, OSError) as exc:
            raise IntegrityViolation(
                f"invocation {ref} treatment digest could not be independently reconstructed"
            ) from exc
        if record.get("input_content_digest") != expected_input:
            raise IntegrityViolation(
                f"invocation {ref} input_content_digest does not match reconstructed model-visible input"
            )
        if record.get("treatment_digest") != expected_digest:
            raise IntegrityViolation(
                f"invocation {ref} treatment digest does not match reconstructed treatment authority"
            )


def _adapter_identity_from_execution_binding(execution_binding: dict) -> AdapterIdentity:
    return _adapter_identity_from_structured(
        execution_binding.get("adapter_identity"),
        "execution binding adapter_identity",
    )


def _adapter_identity_from_structured(raw: object, label: str) -> AdapterIdentity:
    if type(raw) is not dict:
        raise IntegrityViolation(f"{label} must be an object")
    required = ("provider", "model_id", "model_version", "adapter_name", "adapter_version")
    missing = [key for key in required if key not in raw]
    if missing:
        raise IntegrityViolation(f"{label} missing fields: {missing}")
    extra = set(raw) - set(required) - {"identity_key"}
    if extra:
        raise IntegrityViolation(f"{label} has unexpected fields: {sorted(extra)}")
    for key in required:
        value = raw[key]
        if type(value) is not str or not value:
            raise IntegrityViolation(f"{label}.{key} must be a non-empty string")
    identity = AdapterIdentity(
        provider=raw["provider"],
        model_id=raw["model_id"],
        model_version=raw["model_version"],
        adapter_name=raw["adapter_name"],
        adapter_version=raw["adapter_version"],
    )
    stored_key = raw.get("identity_key")
    if stored_key is not None and stored_key != identity.key():
        raise IntegrityViolation(f"{label}.identity_key does not match identity fields")
    return identity


def _task_text_from_record(task_record: dict) -> str:
    try:
        return TaskSpec(
            task_id=task_record["task_id"],
            bug_report=task_record["bug_report"],
            workspace_id=task_record["workspace_id"],
            allowed_files=tuple(task_record["allowed_files"]),
            visible_test_command=task_record.get("visible_test_command"),
            snapshot_hash=task_record.get("snapshot_hash"),
        ).agent_visible_text()
    except (TypeError, ValueError, KeyError) as exc:
        raise IntegrityViolation("task record cannot reconstruct agent-visible task text") from exc


def _stage_inputs_from_trusted_authority(
    run_dir: Path, condition: Condition, role: str, task_record: dict
) -> dict[str, str]:
    allowed = ALLOWED_INPUT_KEYS.get((condition, role))
    if allowed is None:
        raise IntegrityViolation(
            f"no trusted context policy for condition {condition.value} role {role!r}"
        )
    sources = {
        context_key: (producer, artifact_name)
        for producer, mapping in STAGE_OUTPUT_KEYS.items()
        for artifact_name, context_key in mapping.items()
    }
    inputs: dict[str, str] = {}
    for key in sorted(allowed):
        if key == "task":
            inputs["task"] = _task_text_from_record(task_record)
            continue
        source = sources.get(key)
        if source is None:
            raise IntegrityViolation(f"trusted context key {key!r} has no producing stage")
        producer, artifact_name = source
        path = contained_path(run_dir, run_dir / producer / f"{artifact_name}.md")
        if not path.is_file():
            raise IntegrityViolation(
                f"cannot reconstruct {role!r} stage inputs; missing {producer}/{artifact_name}.md"
            )
        try:
            inputs[key] = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise IntegrityViolation(
                f"cannot reconstruct {role!r} stage inputs from {producer}/{artifact_name}.md"
            ) from exc
    return inputs


def _complete_successful_sealed_topology(
    run_dir: Path, expected_roles, manifest_entries: list[dict]
) -> bool:
    seals_dir = run_dir / "seals"
    sealed = {path.stem for path in seals_dir.glob("*.json")} if seals_dir.exists() else set()
    if sealed != set(expected_roles):
        return False
    model_entries = [entry for entry in manifest_entries if _entry_kind(entry) == KIND_MODEL_ARTIFACT]
    try:
        records = _index_entries(model_entries, "artifact manifest")
        expected_keys = {
            (role, name) for role in expected_roles for name in EXPECTED_ARTIFACTS[role]
        }
        if set(records) != expected_keys:
            return False
        for role in expected_roles:
            _verify_persisted_seal(run_dir, role, manifest_entries)
    except IntegrityViolation:
        return False
    return True


def _assert_terminal_status_topology(
    *,
    run_dir: Path,
    expected_roles,
    payload: dict,
    manifest_entries: list[dict],
) -> None:
    status = payload.get("status")
    complete = _complete_successful_sealed_topology(run_dir, expected_roles, manifest_entries)
    _assert_terminal_stage_status_coherence(
        run_dir=run_dir,
        expected_roles=expected_roles,
        payload=payload,
        manifest_entries=manifest_entries,
    )
    evaluator_binding = _read_frozen_object(run_dir, EVALUATOR_BINDING, "evaluator binding")
    _assert_evaluation_coherence(run_dir, payload, evaluator_binding)
    if status == STATUS_SUCCEEDED:
        if not complete:
            raise IntegrityViolation(
                "succeeded terminal record lacks a complete successful sealed topology"
            )
        if payload.get("final_candidate_ref") in {None, ""}:
            raise IntegrityViolation("succeeded terminal record is missing a final candidate")
        return
    if status == STATUS_FAILED_EVALUATION:
        if not complete:
            raise IntegrityViolation(
                "failed_evaluation requires a complete successful sealed topology"
            )
        return
    if complete:
        raise IntegrityViolation(
            f"terminal status {status!r} is incoherent with a complete successful sealed topology"
        )


def _assert_terminal_stage_status_coherence(
    *,
    run_dir: Path,
    expected_roles,
    payload: dict,
    manifest_entries: list[dict],
) -> None:
    stages = payload.get("stages") or []
    if type(stages) is not list:
        raise IntegrityViolation("terminal stage list must be an array")
    seals_dir = run_dir / "seals"
    sealed = {path.stem for path in seals_dir.glob("*.json")} if seals_dir.exists() else set()
    recorded_roles: list[str] = []
    for index, stage in enumerate(stages):
        if type(stage) is not dict:
            raise IntegrityViolation("terminal stage entry must be an object")
        role = stage.get("role")
        status = stage.get("status")
        if role not in expected_roles:
            raise IntegrityViolation(f"terminal stage {role!r} is not part of the condition topology")
        if index >= len(expected_roles) or expected_roles[index] != role:
            raise IntegrityViolation("terminal stages are not the expected condition prefix")
        recorded_roles.append(role)
        if status == "succeeded":
            if role not in sealed:
                raise IntegrityViolation(
                    f"terminal stage {role!r} is succeeded but has no success seal"
                )
            expected_refs = {f"{role}/{name}.md" for name in EXPECTED_ARTIFACTS[role]}
            output_refs = stage.get("output_refs") or []
            if type(output_refs) is not list or set(output_refs) != expected_refs:
                raise IntegrityViolation(
                    f"terminal stage {role!r} output refs do not match persisted artifacts"
                )
            for name in EXPECTED_ARTIFACTS[role]:
                if not (run_dir / role / f"{name}.md").is_file():
                    raise IntegrityViolation(f"succeeded stage {role!r} is missing artifact {name!r}")
        else:
            if role in sealed:
                raise IntegrityViolation(
                    f"terminal stage {role!r} is {status!r} but has a success seal"
                )
    for role in sealed:
        match = next((stage for stage in stages if stage.get("role") == role), None)
        if match is None or match.get("status") != "succeeded":
            raise IntegrityViolation(
                f"persisted success seal for {role!r} is missing from terminal succeeded stages"
            )


def _index_entries(entries: list[dict], label: str) -> dict[tuple[str, str], dict]:
    if type(entries) is not list:
        raise IntegrityViolation(f"{label} must be an array")
    indexed: dict[tuple[str, str], dict] = {}
    for entry in entries:
        if type(entry) is not dict:
            raise IntegrityViolation(f"{label} contains a non-object entry")
        role = entry.get("role")
        name = entry.get("name")
        if type(role) is not str or type(name) is not str:
            raise IntegrityViolation(f"{label} contains an invalid artifact reference")
        key = (role, name)
        if key in indexed:
            raise IntegrityViolation(f"{label} contains duplicate artifact {key}")
        indexed[key] = entry
    return indexed


def _verify_manifest_match(entry: dict, record: dict, key: tuple[str, str]) -> None:
    if type(record) is not dict:
        raise IntegrityViolation(f"manifest record for {key} is not an object")
    if (entry.get("role"), entry.get("name")) != key:
        raise IntegrityViolation(f"seal entry has incorrect ownership for {key}")
    if (record.get("role"), record.get("name")) != key:
        raise IntegrityViolation(f"manifest entry has incorrect ownership for {key}")
    for field in ("sha256", "bytes"):
        if field not in entry or field not in record or entry[field] != record[field]:
            raise IntegrityViolation(f"seal/manifest mismatch for {key}: {field}")
    if type(record["sha256"]) is not str or type(record["bytes"]) is not int:
        raise IntegrityViolation(f"manifest record for {key} has invalid hash metadata")
    if record["bytes"] < 0:
        raise IntegrityViolation(f"manifest record for {key} has negative byte count")


def _entry_kind(entry: dict) -> str:
    if type(entry) is not dict:
        raise IntegrityViolation("manifest contains a non-object entry")
    kind = entry.get("kind")
    if kind not in MANIFEST_KINDS:
        raise IntegrityViolation(f"manifest contains unknown record kind {kind!r}")
    return kind


def _seal_digest_body(seal: dict, artifacts: list) -> dict:
    return {
        "artifacts": artifacts,
        "invocations": seal.get("invocations") or [],
        "expected_attempts": seal.get("expected_attempts", 0),
    }


def _invocation_seal_entry(entry: dict) -> dict:
    bound = {
        "role": entry["role"],
        "attempt": entry["attempt"],
        "kind": entry["kind"],
        "ref": entry["ref"],
        "sha256": entry["sha256"],
        "bytes": entry["bytes"],
    }
    if entry.get("kind") == KIND_UNTRUSTED_RAW_OUTPUT:
        bound["truncated"] = bool(entry.get("truncated"))
        if "stored_bytes" in entry:
            bound["stored_bytes"] = entry["stored_bytes"]
        if "observed_bytes" in entry:
            bound["observed_bytes"] = entry["observed_bytes"]
    return bound


def _verify_seal_invocation_bind(role: str, seal: dict, manifest_entries: list[dict]) -> None:
    seal_inv = seal.get("invocations") or []
    if type(seal_inv) is not list:
        raise IntegrityViolation(f"seal invocations for stage {role!r} must be an array")
    man_inv = [
        e
        for e in manifest_entries
        if _entry_kind(e) in {KIND_INVOCATION_METADATA, KIND_UNTRUSTED_RAW_OUTPUT}
        and e.get("role") == role
    ]
    seal_index = {(e.get("kind"), e.get("attempt"), e.get("ref")): e for e in seal_inv}
    man_index = {(e.get("kind"), e.get("attempt"), e.get("ref")): e for e in man_inv}
    if set(seal_index) != set(man_index):
        raise IntegrityViolation(f"seal invocations for stage {role!r} do not match the manifest")
    for key, seal_entry in seal_index.items():
        if type(seal_entry) is not dict:
            raise IntegrityViolation(f"seal invocation entry for {key} is not an object")
        record = man_index[key]
        expected = _invocation_seal_entry(record)
        extra = set(seal_entry) - set(expected)
        missing = set(expected) - set(seal_entry)
        if extra or missing:
            raise IntegrityViolation(
                f"seal invocation entry for {key} has unexpected or missing fields"
            )
        for field in expected:
            if expected.get(field) != seal_entry.get(field):
                raise IntegrityViolation(
                    f"seal/manifest invocation mismatch for {key}: {field}"
                )
    meta_attempts = sorted(
        e.get("attempt") for e in man_inv if e.get("kind") == KIND_INVOCATION_METADATA
    )
    expected_attempts = seal.get("expected_attempts", 0)
    if meta_attempts != list(range(1, int(expected_attempts) + 1)):
        raise IntegrityViolation(
            f"sealed invocation attempts for stage {role!r} are not the consecutive "
            f"1..{expected_attempts} topology"
        )


def _verify_all_invocation_evidence(
    run_dir: Path,
    manifest_entries: list[dict],
    allowed_roles: tuple[str, ...] | list[str],
    *,
    run_id: str,
    authoritative: dict | None = None,
    stages=None,
) -> None:
    for entry in manifest_entries:
        _entry_kind(entry)
    inv_entries = [
        e
        for e in manifest_entries
        if _entry_kind(e) in {KIND_INVOCATION_METADATA, KIND_UNTRUSTED_RAW_OUTPUT}
    ]
    seen_refs: set[str] = set()
    for entry in inv_entries:
        ref = entry.get("ref")
        if type(ref) is not str or not ref:
            raise IntegrityViolation("invocation manifest entry is missing a harness-owned ref")
        if ref in seen_refs:
            raise IntegrityViolation(f"duplicate invocation evidence ref {ref!r}")
        seen_refs.add(ref)
        if entry.get("role") not in allowed_roles:
            raise IntegrityViolation(
                f"invocation evidence role {entry.get('role')!r} is not part of this run"
            )
    _verify_invocation_files(
        run_dir,
        inv_entries,
        run_id=run_id,
        allowed_roles=allowed_roles,
        authoritative=authoritative,
    )
    disk_refs = _invocation_files_on_disk(run_dir)
    if disk_refs != seen_refs:
        raise IntegrityViolation("invocation evidence on disk does not match the manifest")
    if stages is not None:
        _assert_invocation_attempt_topology(allowed_roles, stages, manifest_entries)


def _invocation_files_on_disk(run_dir: Path) -> set[str]:
    root = run_dir / INVOCATION_ROOT
    if not root.exists():
        return set()
    refs: set[str] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(run_dir).as_posix()
        refs.add(rel)
    return refs


def _verify_invocation_files(
    run_dir: Path,
    entries: list[dict],
    *,
    run_id: str,
    allowed_roles,
    authoritative: dict | None = None,
) -> None:
    for entry in entries:
        kind = _entry_kind(entry)
        role = entry.get("role")
        attempt = entry.get("attempt")
        ref = entry.get("ref")
        if type(role) is not str or type(attempt) is not int or isinstance(attempt, bool):
            raise IntegrityViolation("invocation manifest entry has invalid role/attempt")
        if role not in allowed_roles:
            raise IntegrityViolation(f"invocation evidence role {role!r} is not part of this run")
        expected_ref = invocation_ref(
            role,
            attempt,
            INVOCATION_FILENAME if kind == KIND_INVOCATION_METADATA else RAW_OUTPUT_FILENAME,
        )
        if ref != expected_ref:
            raise IntegrityViolation(
                f"invocation ref {ref!r} is not the harness-owned path {expected_ref!r}"
            )
        file_path = contained_path(run_dir, run_dir / ref)
        if not file_path.is_file():
            raise IntegrityViolation(f"invocation evidence missing: {ref}")
        data = file_path.read_bytes()
        actual = sha256_bytes(data)
        if actual != entry.get("sha256") or len(data) != entry.get("bytes"):
            raise IntegrityViolation(f"invocation evidence tampering detected for {ref}")
        auth_key = (role, attempt, kind)
        if authoritative and auth_key in authoritative and actual != authoritative[auth_key]:
            raise IntegrityViolation(f"authoritative invocation hash mismatch: {ref}")
        if kind == KIND_INVOCATION_METADATA:
            try:
                record = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise IntegrityViolation(f"malformed invocation record at {ref}") from exc
            if record.get("run_id") != run_id:
                raise IntegrityViolation(
                    f"invocation record {ref} belongs to a different run"
                )
            if record.get("role") != role or record.get("attempt") != attempt:
                raise IntegrityViolation(
                    f"invocation record {ref} does not match its harness path"
                )
        elif kind == KIND_UNTRUSTED_RAW_OUTPUT:
            if "truncated" not in entry:
                raise IntegrityViolation(f"raw evidence {ref} is missing truncation metadata")
            verify_raw_evidence_truncation(
                data,
                truncated=entry.get("truncated"),
                stored_bytes=entry.get("stored_bytes"),
                observed_bytes=entry.get("observed_bytes"),
            )
            if entry.get("bytes") != len(data):
                raise IntegrityViolation(f"raw evidence byte count does not match {ref}")
            if entry.get("stored_bytes") != len(data):
                raise IntegrityViolation(f"raw evidence stored_bytes does not match {ref}")


def _role_may_have_invocations(expected_roles, stages: list, role: str) -> bool:
    if any(stage.get("role") == role for stage in stages):
        return True
    if not stages:
        return role == expected_roles[0]
    last = stages[-1]
    if last.get("status") != "succeeded":
        return False
    try:
        idx = list(expected_roles).index(last["role"])
    except (ValueError, KeyError):
        return False
    return idx + 1 < len(expected_roles) and expected_roles[idx + 1] == role


def _assert_invocation_attempt_topology(expected_roles, stages: list, manifest_entries: list[dict]) -> None:
    if type(stages) is not list:
        raise IntegrityViolation("terminal stage list must be an array")
    recorded = {stage.get("role"): stage for stage in stages if type(stage) is dict}
    metas = [
        e
        for e in manifest_entries
        if _entry_kind(e) == KIND_INVOCATION_METADATA
    ]
    by_role: dict[str, list[int]] = {role: [] for role in expected_roles}
    for entry in metas:
        role = entry.get("role")
        if role not in by_role:
            raise IntegrityViolation(f"invocation metadata for unexpected role {role!r}")
        by_role[role].append(entry.get("attempt"))
    for role in expected_roles:
        attempts = sorted(by_role[role])
        if role in recorded:
            last_attempt = recorded[role].get("attempt")
            if type(last_attempt) is not int or isinstance(last_attempt, bool) or last_attempt < 1:
                raise IntegrityViolation(f"terminal stage {role!r} has an invalid attempt")
            expected = list(range(1, last_attempt + 1))
            if attempts != expected:
                raise IntegrityViolation(
                    f"invocation attempts for stage {role!r} must be {expected}, found {attempts}"
                )
        elif _role_may_have_invocations(expected_roles, stages, role):
            if attempts and attempts != list(range(1, attempts[-1] + 1)):
                raise IntegrityViolation(
                    f"invocation attempts for unrecorded stage {role!r} are not consecutive: {attempts}"
                )
        elif attempts:
            raise IntegrityViolation(
                f"unexpected invocation evidence for stage {role!r} which never started"
            )


def _verify_persisted_seal(run_dir: Path, role: str, manifest_entries: list[dict]) -> None:
    seal_path = contained_path(run_dir, run_dir / "seals" / f"{role}.json")
    try:
        seal = json.loads(seal_path.read_text())
        entries = seal["artifacts"]
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise IntegrityViolation(f"malformed seal record for stage {role!r}") from exc
    if type(seal) is not dict or type(entries) is not list or seal.get("role") != role:
        raise IntegrityViolation(f"malformed seal record for stage {role!r}")
    expected_keys = {(role, name) for name in EXPECTED_ARTIFACTS[role]}
    seal_index = _index_entries(entries, f"seal for stage {role!r}")
    if set(seal_index) != expected_keys:
        raise IntegrityViolation(f"seal for stage {role!r} is incomplete")
    if seal.get("stage_digest") != sha256_text(json.dumps(_seal_digest_body(seal, entries), sort_keys=True)):
        raise IntegrityViolation(f"stage digest mismatch for stage {role!r}")
    _verify_seal_invocation_bind(role, seal, manifest_entries)
    model_entries = [e for e in manifest_entries if _entry_kind(e) == KIND_MODEL_ARTIFACT]
    records = _index_entries(model_entries, "artifact manifest")
    for key in expected_keys:
        entry = seal_index[key]
        record = records[key]
        _verify_manifest_match(entry, record, key)
        file_path = contained_path(run_dir, run_dir / key[0] / f"{key[1]}.md")
        if not file_path.is_file():
            raise IntegrityViolation(f"artifact missing: {key[0]}/{key[1]}")
        data = file_path.read_bytes()
        if sha256_bytes(data) != record["sha256"] or len(data) != record["bytes"]:
            raise IntegrityViolation(f"artifact tampering detected for {key}")


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))
