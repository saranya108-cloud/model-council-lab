"""Remediation A: trusted execution profiles and live-protocol handshake."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    EXECUTION_PROFILE_LIVE_CONTRACT_V1,
    EXECUTION_PROFILE_PRE_LIVE_LEGACY,
    HARNESS_PROTOCOL_VERSION,
    LIVE_CONTRACT_VERSION,
    execution_profile_for_kind,
)
from model_council.adapters import LIVE_REGISTRY, REGISTRY
from model_council.invocation import build_invocation_record
from model_council.live_contract import (
    LIVE_CONTRACT_VERSION as CONTRACT_VERSION,
)
from model_council.protocol import ADAPTER_KIND_PROFILES
from model_council.roles import ROLE_INSTRUCTIONS
from model_council.types import ProtocolError
from model_council.worker import main as worker_main
from helpers import (
    FAKE_IDENTITY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
)
from test_invocation_evidence import _load_record
from test_live_contract import make_outcome, make_request


def _run_worker(payload):
    stdin = io.StringIO(json.dumps(payload))
    stdout = io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", stdout):
        code = worker_main()
    raw = stdout.getvalue()
    parsed = json.loads(raw) if raw.startswith("{") else raw
    return code, parsed


def _live_envelope(kind="live_stub", options=None, request=None, **overrides):
    live_request = request or make_request()
    payload = {
        "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
        "execution_profile": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
        "adapter": {
            "kind": kind,
            "options": {
                "model_id": FAKE_IDENTITY.model_id,
                "identity": FAKE_IDENTITY.to_dict(),
                **(options or {}),
            },
        },
        "live_invocation_request": live_request.to_dict(),
    }
    payload.update(overrides)
    return payload


class TestTrustedExecutionProfile(unittest.TestCase):
    def test_kind_registry_is_the_sole_profile_source(self):
        self.assertEqual(execution_profile_for_kind("fake"), EXECUTION_PROFILE_PRE_LIVE_LEGACY)
        self.assertEqual(execution_profile_for_kind("live_stub"), EXECUTION_PROFILE_LIVE_CONTRACT_V1)
        self.assertNotIn("live_stub", REGISTRY)
        self.assertNotIn("fake", LIVE_REGISTRY)
        with self.assertRaises(ProtocolError):
            execution_profile_for_kind("not-a-registered-kind")
        for kind, profile in ADAPTER_KIND_PROFILES.items():
            if profile == EXECUTION_PROFILE_LIVE_CONTRACT_V1:
                self.assertIn(kind, LIVE_REGISTRY)
            elif kind != "raw_garbage":
                self.assertIn(kind, REGISTRY)

    def test_legacy_fake_kind_still_accepts_legacy_response(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            result = runner.execute(make_spec("prof-legacy", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertEqual(runner.adapter.last_request["execution_profile"], EXECUTION_PROFILE_PRE_LIVE_LEGACY)
            self.assertEqual(
                runner.adapter.last_request["harness_protocol_version"], HARNESS_PROTOCOL_VERSION
            )
            self.assertIn("role_instruction", runner.adapter.last_request)
            self.assertNotIn("live_invocation_request", runner.adapter.last_request)

    def test_live_kind_returning_legacy_response_is_rejected(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root, kind="live_stub", options={"return_legacy_response": True}
            )
            result = runner.execute(make_spec("prof-legacy-shape", "A"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertIn("legacy", (result.metadata.get("error") or "").lower())

    def test_live_kind_cannot_use_legacy_invoke(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="live_stub")
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(ProtocolError):
                    runner.adapter.invoke(
                        role_instruction=ROLE_INSTRUCTIONS["solver"],
                        stage_inputs={"task": "t"},
                        budget=make_spec("x").resource_limits,
                        seed=0,
                    )
            mocked.assert_not_called()

    def test_legacy_kind_cannot_use_invoke_live(self):
        with TempRoot() as root:
            runner, _ = make_runner(root, kind="fake")
            with patch("model_council.executor.subprocess.run") as mocked:
                with self.assertRaises(ProtocolError):
                    runner.adapter.invoke_live(make_request())
            mocked.assert_not_called()

    def test_live_adapter_cannot_choose_pre_live_compatibility_label(self):
        live_record = build_invocation_record(
            run_id="prof-label",
            condition="A",
            role="solver",
            attempt=1,
            requested_identity=FAKE_IDENTITY,
            configured_identity=FAKE_IDENTITY,
            stage_timeout_seconds=60.0,
            attempt_timeout_seconds=12.0,
            input_content_digest="a" * 64,
            treatment_digest="b" * 64,
            tokens_in=1,
            tokens_out=1,
            cumulative_tokens_in=1,
            retry_decision="promote",
            retry_rationale="stage_succeeded",
            contract_verdict="passed",
            identity_verdict="passed",
            failure_class=None,
            execution_profile=EXECUTION_PROFILE_LIVE_CONTRACT_V1,
            provider_outcome=make_outcome(),
        )
        self.assertEqual(live_record["adapter_evidence"]["compatibility"], "live_contract")
        with self.assertRaises(Exception):
            build_invocation_record(
                run_id="prof-label-bad",
                condition="A",
                role="solver",
                attempt=1,
                requested_identity=FAKE_IDENTITY,
                configured_identity=FAKE_IDENTITY,
                stage_timeout_seconds=60.0,
                attempt_timeout_seconds=12.0,
                input_content_digest="a" * 64,
                treatment_digest="b" * 64,
                tokens_in=1,
                tokens_out=1,
                cumulative_tokens_in=1,
                retry_decision="promote",
                retry_rationale="stage_succeeded",
                contract_verdict="passed",
                identity_verdict="passed",
                failure_class=None,
                execution_profile=EXECUTION_PROFILE_LIVE_CONTRACT_V1,
                identity_used={"provider": "x"},
            )
        with self.assertRaises(Exception):
            build_invocation_record(
                run_id="prof-label-legacy-outcome",
                condition="A",
                role="solver",
                attempt=1,
                requested_identity=FAKE_IDENTITY,
                configured_identity=FAKE_IDENTITY,
                stage_timeout_seconds=60.0,
                attempt_timeout_seconds=12.0,
                input_content_digest="a" * 64,
                treatment_digest="b" * 64,
                tokens_in=1,
                tokens_out=1,
                cumulative_tokens_in=1,
                retry_decision="promote",
                retry_rationale="stage_succeeded",
                contract_verdict="passed",
                identity_verdict="passed",
                failure_class=None,
                execution_profile=EXECUTION_PROFILE_PRE_LIVE_LEGACY,
                provider_outcome=make_outcome(),
            )


class TestProtocolHandshake(unittest.TestCase):
    def test_missing_or_wrong_harness_version_prevents_adapter_call(self):
        with TempRoot() as root:
            counter = Path(root) / "counter"
            request = make_request()
            base = _live_envelope(
                options={"invocation_counter_path": str(counter)}, request=request
            )
            for payload in (
                {k: v for k, v in base.items() if k != "harness_protocol_version"},
                {**base, "harness_protocol_version": "m1-dev-harness-v0"},
                {**base, "harness_protocol_version": 7},
                {**base, "harness_protocol_version": ""},
            ):
                with self.subTest(version=payload.get("harness_protocol_version")):
                    if counter.exists():
                        counter.unlink()
                    code, parsed = _run_worker(payload)
                    self.assertEqual(code, 0)
                    self.assertFalse(parsed["ok"])
                    self.assertEqual(parsed["error_class"], "ProtocolError")
                    self.assertFalse(counter.exists())

    def test_wrong_live_contract_version_prevents_adapter_call(self):
        with TempRoot() as root:
            counter = Path(root) / "counter"
            live = make_request().to_dict()
            live["contract_version"] = "m1-live-contract-v0"
            payload = _live_envelope(
                options={"invocation_counter_path": str(counter)},
            )
            payload["live_invocation_request"] = live
            code, parsed = _run_worker(payload)
            self.assertEqual(code, 0)
            self.assertFalse(parsed["ok"])
            self.assertEqual(parsed["error_class"], "ProtocolError")
            self.assertFalse(counter.exists())
            self.assertEqual(CONTRACT_VERSION, LIVE_CONTRACT_VERSION)

    def test_profile_mismatch_between_runner_and_worker_rejected(self):
        with TempRoot() as root:
            counter = Path(root) / "legacy-counter"
            payload = {
                "harness_protocol_version": HARNESS_PROTOCOL_VERSION,
                "execution_profile": EXECUTION_PROFILE_LIVE_CONTRACT_V1,
                "adapter": {
                    "kind": "fake",
                    "options": {
                        "model_id": FAKE_IDENTITY.model_id,
                        "identity": FAKE_IDENTITY.to_dict(),
                        "invocation_counter_path": str(counter),
                    },
                },
                "role_instruction": ROLE_INSTRUCTIONS["solver"],
                "stage_inputs": {"task": "t"},
                "budget": make_spec("x").resource_limits.to_dict(),
                "seed": 0,
            }
            code, parsed = _run_worker(payload)
            self.assertEqual(code, 0)
            self.assertFalse(parsed["ok"])
            self.assertEqual(parsed["error_class"], "ProtocolError")
            self.assertIn("profile mismatch", parsed["message"])
            self.assertFalse(counter.exists())

    def test_unknown_kind_profile_rejected(self):
        payload = _live_envelope(kind="totally-unknown")
        payload["adapter"]["kind"] = "totally-unknown"
        code, parsed = _run_worker(payload)
        self.assertFalse(parsed["ok"])
        self.assertEqual(parsed["error_class"], "ProtocolError")

    def test_live_model_failure_is_protocol_failure_not_legacy_retry(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root, kind="live_stub", options={"raise_model_failure": True}
            )
            result = runner.execute(make_spec("prof-mf", "A", max_stage_retries=3), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertEqual(result.retries_used, 0)
            self.assertIn("ModelFailure", result.metadata.get("error") or "")


class TestLiveOutcomeMapping(unittest.TestCase):
    def test_live_success_maps_to_existing_artifact_topology(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="live_stub")
            result = runner.execute(make_spec("prof-live-a", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            run_dir = runs_root / "prof-live-a"
            self.assertTrue((run_dir / "solver" / "candidate.md").is_file())
            self.assertTrue((run_dir / "solver" / "evidence.md").is_file())
            self.assertFalse((run_dir / "solver" / "rogue.md").exists())
            record = _load_record(run_dir, "solver", 1)
            self.assertEqual(record["adapter_evidence"]["compatibility"], "live_contract")
            self.assertIsNotNone(record["adapter_evidence"]["provider_call_outcome"])
            self.assertEqual(
                runner.adapter.last_request["execution_profile"], EXECUTION_PROFILE_LIVE_CONTRACT_V1
            )
            self.assertIn("live_invocation_request", runner.adapter.last_request)
            self.assertNotIn("role_instruction", runner.adapter.last_request)

    def test_live_condition_c_retains_disposition_requirements(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="live_stub")
            result = runner.execute(make_spec("prof-live-c", "C"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertTrue((runs_root / "prof-live-c" / "reviser" / "final_candidate.md").is_file())

    def test_live_extra_artifact_name_is_not_promoted(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(
                root, kind="live_stub", options={"extra_artifact": "rogue"}
            )
            result = runner.execute(make_spec("prof-extra-art", "A"), make_task())
            self.assertEqual(result.status, "failed_contract")
            self.assertFalse((runs_root / "prof-extra-art" / "solver" / "rogue.md").exists())
            self.assertFalse((runs_root / "prof-extra-art" / "seals" / "solver.json").exists())

    def test_live_extra_nested_structured_key_fails(self):
        with TempRoot() as root:
            runner, _ = make_runner(
                root, kind="live_stub", options={"extra_nested_key": True}
            )
            result = runner.execute(make_spec("prof-nested", "C"), make_task())
            self.assertEqual(result.status, "failed_contract")

    def test_legacy_evidence_label_stays_legacy_for_fake_kind(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root, kind="fake")
            runner.execute(make_spec("prof-ev-legacy", "A"), make_task())
            record = _load_record(runs_root / "prof-ev-legacy", "solver", 1)
            self.assertEqual(record["adapter_evidence"]["compatibility"], "pre_live_fake_adapter")
            self.assertIsNone(record["adapter_evidence"]["provider_call_outcome"])


if __name__ == "__main__":
    unittest.main()
