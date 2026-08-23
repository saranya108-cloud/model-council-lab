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
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .roles import (
    CONDITION_STAGES,
    EXPECTED_ARTIFACTS,
    EXTRA_ARTIFACTS,
    PRIMARY_ARTIFACT,
)
from .security import contained_path, safe_identifier, sha256_bytes, sha256_text
from .types import (
    Condition,
    GovernanceViolation,
    IntegrityViolation,
    RunSpec,
    STATUS_SUCCEEDED,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


EVENT_EVALUATION = "evaluation.json"
EVENT_RUN_RESULT = "run_result.json"
EVENT_GOVERNANCE_VIOLATION = "governance_violation.json"
EVENT_INTEGRITY = "integrity_check.json"
MANIFEST = "manifest.jsonl"
ALLOWED_EVENTS = frozenset({EVENT_EVALUATION, EVENT_RUN_RESULT, EVENT_GOVERNANCE_VIOLATION, EVENT_INTEGRITY})


class ArtifactStore:
    def __init__(self, runs_root: Path, run_spec: RunSpec) -> None:
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
        path = self.artifact_path(role, name)
        data = content.encode("utf-8")
        if path.exists():
            raise GovernanceViolation(
                f"artifact already exists for stage {role!r}: {name!r} is write-once"
            )
        path.write_bytes(data)
        digest = sha256_bytes(data)
        self._authoritative[(role, name)] = digest
        self._append_manifest(
            {
                "role": role,
                "name": name,
                "sha256": digest,
                "bytes": len(data),
                "written_at": _utcnow(),
            }
        )
        return self.artifact_ref(role, name)

    def seal_stage(self, role: str) -> dict:
        if role not in self._allowed_roles:
            raise GovernanceViolation(f"cannot seal unknown role {role!r}")
        entries = [
            {"role": e["role"], "name": e["name"], "sha256": e["sha256"], "bytes": e["bytes"]}
            for e in self._manifest_entries()
            if e["role"] == role
        ]
        expected_names = EXPECTED_ARTIFACTS[role]
        names = [entry["name"] for entry in entries]
        if len(names) != len(set(names)) or set(names) != expected_names:
            raise GovernanceViolation(
                f"cannot seal stage {role!r}; expected exactly {sorted(expected_names)}, "
                f"found {sorted(names)}"
            )
        seal = {
            "role": role,
            "sealed_at": _utcnow(),
            "artifacts": entries,
            "stage_digest": sha256_text(json.dumps(entries, sort_keys=True)),
        }
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
        if stage_digest != sha256_text(json.dumps(entries, sort_keys=True)):
            raise IntegrityViolation(f"stage digest mismatch for stage {role!r}")

        manifest_index = _index_entries(self._manifest_entries(), "artifact manifest")
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

    def verify_completed_run(self) -> dict:
        if set(self._sealed) != set(self._allowed_roles):
            raise IntegrityViolation("completed run is missing one or more stage seals")
        results = {}
        for role in self._allowed_roles:
            self.verify_sealed_stage(role)
            results[role] = "verified"
        return {"integrity_verified": True, "stages": results, "verified_at": _utcnow()}

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
        records = _index_entries(manifest_entries, "artifact manifest")
        if set(records) != expected_keys:
            raise IntegrityViolation("artifact manifest does not match expected run topology")

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
                if seal["stage_digest"] != sha256_text(json.dumps(entries, sort_keys=True)):
                    raise IntegrityViolation(f"stage digest mismatch for stage {role!r}")
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

        return {
            "run_id": run_id,
            "integrity_verified": True,
            "sealed_stages": verified_stages,
            "artifact_count": len(records),
            "final_candidate_ref": final_ref,
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


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))
