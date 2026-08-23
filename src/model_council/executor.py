"""Parent-side adapter process boundary.

Trust model (Human Chair decision): adapter implementations are trusted,
project-controlled harness code; model OUTPUT is untrusted. The child process
exists for timeout/process isolation and a clean invocation protocol — it is
NOT an OS sandbox against hostile project-controlled Python.

The parent serializes a request, spawns the child with a minimal environment
and a per-invocation neutral scratch directory (never the runs namespace), and
enforces the stage timeout by terminating the direct child. Only serialized
JSON crosses the boundary.

Failure taxonomy:
  - ModelFailure: structured failure returned by the adapter/provider layer;
    qualifies for the preregistered model retry policy.
  - ProtocolError: malformed worker stdout/protocol or invalid usage metrics;
    infrastructure failure, never consumes model retry budget.
  - InfrastructureError: worker crash / spawn failure; never retried as model.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .types import (
    AdapterIdentity,
    InfrastructureError,
    ModelFailure,
    ProtocolError,
    ResourceLimits,
    StageTimeout,
)

_SRC_ROOT = Path(__file__).resolve().parents[1]


class SubprocessAdapter:
    def __init__(
        self,
        identity: AdapterIdentity,
        kind: str = "fake",
        options: dict | None = None,
        python_executable: str | None = None,
    ) -> None:
        self.identity = identity
        self.kind = kind
        # Deep-frozen so post-construction caller mutation cannot change what
        # the child executes or the recorded adapter configuration digest.
        from .security import deep_freeze

        self.options = deep_freeze(dict(options or {}))
        self.python_executable = python_executable or sys.executable
        self.last_scratch_dir: str | None = None

    @property
    def scratch_dir(self) -> str | None:
        return self.last_scratch_dir

    def _child_options(self) -> dict:
        # Reuse the harness canonicalizer so heterogeneous frozen sets use
        # the same type-stable ordering as treatment/provenance hashing.
        from .security import canonical_json

        plain_options = json.loads(canonical_json(self.options))
        return {
            **plain_options,
            "model_id": self.identity.model_id,
            "identity": self.identity.to_dict(),
        }

    def invoke(
        self,
        *,
        role_instruction: str,
        stage_inputs: dict[str, str],
        budget: ResourceLimits,
        seed: int,
    ) -> dict:
        request = {
            "adapter": {"kind": self.kind, "options": self._child_options()},
            "role_instruction": role_instruction,
            "stage_inputs": stage_inputs,
            "budget": budget.to_dict(),
            "seed": seed,
        }
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(_SRC_ROOT),
        }
        spawn_kwargs = {}
        if os.name == "posix":
            # New session/process group: guarantees we can terminate the direct
            # child cleanly. Descendant containment is NOT claimed; trusted
            # adapters must not intentionally spawn unmanaged descendants.
            spawn_kwargs["start_new_session"] = True
        try:
            with tempfile.TemporaryDirectory(prefix="mcl-scratch-") as scratch:
                self.last_scratch_dir = scratch
                completed = subprocess.run(
                    [self.python_executable, "-B", "-m", "model_council.worker"],
                    input=json.dumps(request),
                    capture_output=True,
                    text=True,
                    timeout=budget.stage_timeout_seconds,
                    cwd=scratch,
                    env=env,
                    **spawn_kwargs,
                )
        except subprocess.TimeoutExpired as exc:
            raise StageTimeout(
                f"adapter process exceeded {budget.stage_timeout_seconds}s and was terminated"
            ) from exc
        except OSError as exc:
            raise InfrastructureError(f"failed to spawn adapter process: {exc}") from exc
        # Note: scratch directory lifecycle is owned by the TemporaryDirectory
        # context above; on every exit path (success, model failure, timeout,
        # crash, malformed output) the scratch content is removed. The last
        # used path is retained for verification/testing purposes only.

        if completed.returncode != 0:
            # Worker crash is a process/infrastructure failure. It must NOT
            # masquerade as a model failure and consume model retry budget.
            raise InfrastructureError(
                f"worker exited unexpectedly (exit {completed.returncode}): "
                f"{completed.stderr.strip()[-500:]}"
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"worker stdout was not valid JSON: {exc}") from exc
        if not isinstance(payload, dict) or "ok" not in payload:
            raise ProtocolError("worker response missing required 'ok' field")
        if not payload["ok"]:
            error_class = payload.get("error_class")
            if error_class == "ModelFailure":
                message = payload.get("message")
                if not isinstance(message, str):
                    raise ProtocolError("ModelFailure payload missing string 'message'")
                raise ModelFailure(message)
            raise InfrastructureError(
                f"worker reported {error_class}: {payload.get('message')}"
            )
        response = payload.get("response")
        if not isinstance(response, dict):
            raise ProtocolError("worker response missing structured 'response' object")
        self._validate_usage_fields(response)
        self._validate_identity_used(response)
        return response

    @staticmethod
    def _validate_usage_fields(response: dict) -> None:
        for field in ("tokens_in", "tokens_out", "tool_uses"):
            value = response.get(field)
            if value is None:
                raise ProtocolError(f"usage field '{field}' missing from worker response")
            if isinstance(value, bool) or not isinstance(value, int):
                raise ProtocolError(
                    f"usage field '{field}' must be an integer, got {type(value).__name__}"
                )
            if value < 0:
                raise ProtocolError(f"usage field '{field}' must be non-negative")

    def _validate_identity_used(self, response: dict) -> None:
        used = response.get("identity_used")
        if not isinstance(used, dict):
            raise ProtocolError("worker response missing 'identity_used'")
        expected = self.identity.to_dict()
        for key in ("provider", "model_id", "model_version", "adapter_name", "adapter_version"):
            if not isinstance(used.get(key), str) or not used[key]:
                raise ProtocolError(f"identity_used['{key}'] must be a non-empty string")
        # The child reports what it actually resolved; equality with the
        # configured identity is enforced by the Runner against RunSpec.
        del expected
