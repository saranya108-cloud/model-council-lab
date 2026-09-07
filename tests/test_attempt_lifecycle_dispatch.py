"""Real journal fixtures and offline dispatch boundary tests. No provider I/O."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import os
import unittest
from unittest.mock import patch

from model_council.attempt_lifecycle import AttemptJournal, request_digest
from model_council.live_contract import build_exact_provider_identity_policy, parse_provider_call_outcome, NeutralProviderFailure
from model_council.openai_adapter import build_openai_responses_request
from model_council.security import digest_json
from model_council.types import ResourceLimits, ProtocolError


@contextmanager
def synthetic_journal(request, adapter=None):
    """Reserve a real journal in scratch; never bypass production validation."""
    with TemporaryDirectory() as root:
        identity = request.configured_identity
        policy = build_exact_provider_identity_policy(identity, identity)
        journal = AttemptJournal.create(Path(root), {
            "run_id": "offline", "role": request.role, "attempt": 1,
            "execution_instance_id": "f" * 32, "harness_protocol_version": "m1-dev-harness-v15",
            "predecessor_attempt_id": None, "treatment_digest": "a" * 64,
            "authority_digest": "a" * 64, "request_digest": request_digest(request),
            "input_content_digest": request.input_content_digest,
            "request_parameter_digest": request.request_parameter_digest,
            "configured_identity": identity.to_dict(), "wire_model": policy["wire_model"],
            "identity_policy_digest": digest_json(policy), "resource_limits": ResourceLimits(max_stage_retries=0).to_dict(),
            "attempt_timeout_seconds": request.attempt_timeout_seconds,
        })
        previous = adapter.attempt_journal if adapter is not None else None
        if adapter is not None:
            adapter.attempt_journal = journal
        try:
            yield journal
        finally:
            if adapter is not None:
                adapter.attempt_journal = previous


@contextmanager
def synthetic_writer(request):
    with synthetic_journal(request) as journal:
        journal.permit(request.attempt_timeout_seconds)
        writer = journal.open_writer()
        try:
            yield writer
        finally:
            os.close(writer.fd)


def invoke_with_journal(adapter, request):
    """Direct executor fixtures reserve the authorization normally owned by runner."""
    if adapter.kind != "openai_responses":
        return adapter.invoke_live(request)
    with synthetic_journal(request, adapter):
        return adapter.invoke_live(request)


def observed_transport_success(fixture):
    def transport(translated, secret, timeout, *, lifecycle):
        from model_council.openai_adapter import _OpenAITransportSuccess
        lifecycle.append("sdk_call_boundary", {"wire_request_digest": digest_json(translated)})
        lifecycle.append("sdk_return_observed")
        return _OpenAITransportSuccess(response=fixture)
    return transport


def offline_dispatch(adapter, request, operation):
    """A synthetic worker performs the same journal transitions as a real one."""
    journal = adapter.attempt_journal
    if not journal.permission_granted:
        journal.permit(request.attempt_timeout_seconds)
    writer = journal.open_writer()
    writer.append("sdk_call_boundary", {"wire_request_digest": digest_json(build_openai_responses_request(request, adapter.provider_treatment_config))})
    try:
        try:
            result = operation()
        except BaseException as exc:
            writer.append("sdk_exception_observed")
            if isinstance(exc, NeutralProviderFailure) and exc.outcome is not None:
                writer.outcome(exc.outcome)
            journal.close("interrupted" if isinstance(exc, KeyboardInterrupt) else "infrastructure", worker_reaped=True)
            raise
        writer.append("sdk_return_observed")
        try:
            outcome = parse_provider_call_outcome(result["outcome"]) if isinstance(result, dict) else result
            writer.outcome(outcome)
        except (ValueError, TypeError, KeyError, AttributeError):
            pass  # Deliberately malformed protocol fixture: no normalized observation.
        journal.close("returned", worker_reaped=True)
        return result
    finally:
        os.close(writer.fd)


class TestDispatchAuthorization(unittest.TestCase):
    def test_missing_attempt_fails_before_worker_launch(self):
        from helpers import FAKE_IDENTITY
        from model_council.executor import SubprocessAdapter
        from test_live_contract import make_request
        adapter = SubprocessAdapter(FAKE_IDENTITY, kind="openai_responses")
        with patch.object(adapter, "_spawn_worker", side_effect=AssertionError("launched")):
            with self.assertRaises(ProtocolError):
                adapter.invoke_live(make_request())

    def test_sdk_return_survives_normalization_failure(self):
        from test_openai_adapter_transport import _invoke
        result, seen = _invoke(response=object())
        self.assertEqual(len(seen["factory_calls"]), 1)
        self.assertEqual([e["event"] for e in seen["lifecycle_events"]], [
            "attempt_prepared", "dispatch_permitted", "sdk_call_boundary", "sdk_return_observed",
        ])


_FAULT_HOOK = r'''
import time
import model_council.attempt_lifecycle as lifecycle
_original_append = lifecycle.JournalWriter.append
_fault = _CONFIG.get("lifecycle_fault", "")
def _fault_append(self, event, data=None):
    if _fault == "before_sdk" and event == "sdk_call_boundary":
        os._exit(73)
    if _fault == "torn_return" and event == "sdk_return_observed":
        os.write(self.fd, b'{"torn":')
        os.fsync(self.fd)
        os._exit(74)
    _original_append(self, event, data)
    if _fault == "after_" + event:
        os._exit(75)
    if _fault == "timeout_" + event:
        time.sleep(60)
lifecycle.JournalWriter.append = _fault_append
'''


def run_fault_worker(root, mode="", *, timeout=3.0):
    """Real executor/worker/adapter with an offline SDK and exact crash points."""
    from helpers import make_task
    from model_council import ExperimentRunner, SubprocessAdapter, ExternalEvaluator, EvaluationConfig
    from test_openai_adapter_skeleton import _install_offline_openai_python, _isolated_environ, _read_offline_calls
    from test_openai_adapter_transport import _offline_success_config, _offline_error_config
    from test_openai_adapter_translation import _completed_fixture, _solver_envelope
    from test_provider_identity_policy import OPENAI_IDENTITY, _spec
    config = _offline_success_config()
    config["response"] = _completed_fixture(_solver_envelope(artifacts={
        "candidate": "PROPOSED_FIX: preserve leap-day dates", "evidence": "offline proposal",
    }))
    config["response"]["model"] = "wrong-model" if mode == "identity_mismatch" else OPENAI_IDENTITY.model_id
    if mode == "transport_loss":
        config = _offline_error_config("APIConnectionError")
    elif mode == "malformed":
        config["response"] = {}
    config["lifecycle_fault"] = mode
    executable, calls = _install_offline_openai_python(root, config)
    path = Path(executable)
    source = path.read_text()
    path.write_text(source.replace("from model_council.worker import main", _FAULT_HOOK + "\nfrom model_council.worker import main"))
    runs = Path(root) / "runs"
    adapter = SubprocessAdapter(OPENAI_IDENTITY, kind="openai_responses", python_executable=executable)
    runner = ExperimentRunner(adapter, ExternalEvaluator(EvaluationConfig()), runs_root=runs)
    with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"):
        result = runner.execute(_spec("fault", stage_timeout_seconds=timeout), make_task())
    journal = AttemptJournal(runs / "fault/attempt-lifecycle/solver/attempt-0001/journal.jsonl")
    return result, journal, _read_offline_calls(calls), runs


class TestDurableDispatchFaults(unittest.TestCase):
    def test_crashes_preserve_exact_prefix_and_never_redispatch(self):
        cases = (
            ("before_sdk", 2, 0, "indeterminate"),
            ("after_sdk_call_boundary", 3, 0, "indeterminate"),
            ("after_sdk_return_observed", 4, 1, "indeterminate"),
            ("after_outcome_observed", 5, 1, "unsafe_response_observed"),
        )
        from model_council import ArtifactStore
        with TemporaryDirectory() as base:
            for mode, event_count, calls, safety in cases:
                with self.subTest(mode=mode):
                    root = Path(base) / mode
                    root.mkdir()
                    result, journal, observed, runs = run_fault_worker(root, mode)
                    self.assertEqual(result.status, "infrastructure_failure")
                    self.assertEqual(len(observed), calls)
                    snapshot = journal.inspect(require_closed=True)
                    self.assertEqual(len(snapshot["events"]), event_count)
                    self.assertEqual(snapshot["retry_safety"], safety)
                    report = ArtifactStore.verify_terminal_run(runs, "fault")
                    self.assertTrue(report["attempt_lifecycle_verified"])
                    self.assertEqual(report["attempt_retry_safety"], {"solver": safety})

    def test_timeouts_retain_worker_observations(self):
        from model_council import ArtifactStore
        for marker, events, calls in (("sdk_call_boundary", 3, 0), ("sdk_return_observed", 4, 1), ("outcome_observed", 5, 1)):
            with self.subTest(marker=marker), TemporaryDirectory() as root:
                result, journal, observed, runs = run_fault_worker(root, "timeout_" + marker, timeout=1.0)
                self.assertEqual(result.status, "retry_exhausted")
                self.assertEqual(len(observed), calls)
                snapshot = journal.inspect(require_closed=True)
                self.assertEqual(len(snapshot["events"]), events)
                self.assertNotEqual(snapshot["retry_safety"], "safe_not_dispatched")
                self.assertFalse((runs / "fault/seals/solver.json").exists())
                self.assertTrue(ArtifactStore.verify_terminal_run(runs, "fault")["attempt_lifecycle_verified"])

    def test_malformed_and_transport_loss_keep_conservative_facts(self):
        from model_council import ArtifactStore
        for mode, marker in (("malformed", "sdk_return_observed"), ("transport_loss", "sdk_exception_observed")):
            with self.subTest(mode=mode), TemporaryDirectory() as root:
                result, journal, calls, runs = run_fault_worker(root, mode)
                self.assertNotEqual(result.status, "succeeded")
                self.assertEqual(len(calls), 1)
                snapshot = journal.inspect(require_closed=True)
                self.assertEqual(snapshot["events"][3]["event"], marker)
                self.assertEqual(snapshot["retry_safety"], "indeterminate")
                self.assertTrue(ArtifactStore.verify_terminal_run(runs, "fault")["attempt_lifecycle_verified"])

    def test_success_and_identity_rejection_both_preserve_response(self):
        from model_council import ArtifactStore
        for mode, status in (("", "succeeded"), ("identity_mismatch", "failed_governance")):
            with self.subTest(mode=mode), TemporaryDirectory() as root:
                result, journal, calls, runs = run_fault_worker(root, mode)
                self.assertEqual(result.status, status)
                self.assertEqual(len(calls), 1)
                self.assertEqual(journal.inspect(require_closed=True)["retry_safety"], "unsafe_response_observed")
                report = ArtifactStore.verify_terminal_run(runs, "fault")
                self.assertTrue(report["provider_identity_policy_verified"])
                self.assertTrue(report["attempt_lifecycle_verified"])

    def test_torn_response_persistence_rejects_full_verification(self):
        from model_council import ArtifactStore
        from model_council.types import IntegrityViolation
        with TemporaryDirectory() as root:
            result, journal, calls, runs = run_fault_worker(root, "torn_return")
            self.assertNotEqual(result.status, "succeeded")
            self.assertEqual(len(calls), 1)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "fault")
