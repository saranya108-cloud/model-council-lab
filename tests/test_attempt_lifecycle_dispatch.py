"""Real journal fixtures and offline dispatch boundary tests. No provider I/O."""
from contextlib import contextmanager, ExitStack
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
_early_out = os.dup(1) if _fault.startswith("diagnostic_") else None
_early_err = os.dup(2) if _fault.startswith("diagnostic_") else None
def _emit(fd, size):
    body = (b"PRIVATE_DIAGNOSTIC_SENTINEL" * (size // len(b"PRIVATE_DIAGNOSTIC_SENTINEL") + 1))[:size]
    while body:
        body = body[os.write(fd, body):]
def _fault_append(self, event, data=None):
    if _fault.startswith("diagnostic_") and event == "sdk_call_boundary":
        if _fault == "diagnostic_stdout":
            _emit(_early_out, 65537)
        elif _fault == "diagnostic_stderr":
            _emit(_early_err, 65537)
        else:
            _emit(_early_out, 49152)
            _emit(_early_err, 49153)
        os._exit(76)
    if _fault == "before_sdk" and event == "sdk_call_boundary":
        os._exit(73)
    if _fault == "torn_return" and event == "sdk_return_observed":
        os.write(self.fd, b'{"torn":')
        os.fsync(self.fd)
        os._exit(74)
    _original_append(self, event, data)
    if event == "outcome_observed" and _fault in ("protocol_overflow", "protocol_malformed"):
        import model_council.worker as worker
        fd = worker._protocol_out.fileno()
        if _fault == "protocol_overflow":
            _emit(fd, 8000001)
        else:
            os.write(fd, b'{malformed')
        os._exit(0)
    if _fault == "after_" + event:
        os._exit(75)
    if _fault == "timeout_" + event:
        if _CONFIG.get("lifecycle_ready_path"):
            # Signal only after the lifecycle append and its fsync completed.
            with open(_CONFIG["lifecycle_ready_path"], "xb"):
                pass
        time.sleep(60)
lifecycle.JournalWriter.append = _fault_append
'''


def run_fault_worker(root, mode="", *, timeout=3.0, timeout_at_marker=False):
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
    ready = Path(root) / "lifecycle-ready"
    if timeout_at_marker:
        config["lifecycle_ready_path"] = str(ready)
    executable, calls = _install_offline_openai_python(root, config)
    path = Path(executable)
    source = path.read_text()
    path.write_text(source.replace("from model_council.worker import main", _FAULT_HOOK + "\nfrom model_council.worker import main"))
    runs = Path(root) / "runs"
    adapter = SubprocessAdapter(OPENAI_IDENTITY, kind="openai_responses", python_executable=executable)
    runner = ExperimentRunner(adapter, ExternalEvaluator(EvaluationConfig()), runs_root=runs)
    with ExitStack() as stack:
        stack.enter_context(_isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"))
        if timeout_at_marker:
            import time
            from model_council import executor
            real_collect = executor._collect_openai_worker
            def collect(process, **kwargs):
                started = time.monotonic()
                deadline = kwargs["deadline"]
                expired_at = None
                def clock():
                    nonlocal expired_at
                    now = time.monotonic()
                    # This prefix test controls when the communication clock
                    # expires; a real-time watchdog still bounds fixture failure.
                    if expired_at is None and (ready.exists() or now - started >= 10):
                        expired_at = now
                    return deadline - 1 if expired_at is None else deadline + now - expired_at
                return real_collect(process, monotonic=clock, **kwargs)
            stack.enter_context(patch.object(executor, "_collect_openai_worker", collect))
        result = runner.execute(_spec("fault", stage_timeout_seconds=timeout), make_task())
    if timeout_at_marker and not ready.exists():
        raise AssertionError("offline worker did not reach the requested durable marker")
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
                result, journal, observed, runs = run_fault_worker(root, "timeout_" + marker, timeout=1.0, timeout_at_marker=True)
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


class TestActivatedCommunicationEvidence(unittest.TestCase):
    def test_durable_outcome_survives_failed_protocol_delivery(self):
        import json
        from model_council import ArtifactStore
        for mode, reason in (("protocol_overflow", "infrastructure"), ("protocol_malformed", "returned")):
            with self.subTest(mode=mode), TemporaryDirectory() as root:
                result, journal, calls, runs = run_fault_worker(root, mode)
                self.assertEqual(result.status, "infrastructure_failure")
                self.assertEqual(len(calls), 1)
                snapshot = journal.inspect(require_closed=True)
                self.assertEqual(snapshot['closure']['reason'], reason)
                self.assertEqual(snapshot['outcome']['kind'], 'success')
                record = json.loads((runs / 'fault/invocations/solver/attempt-0001/invocation.json').read_text())
                self.assertEqual(record['lifecycle_observed_outcome'], snapshot['outcome'])
                self.assertIsNone(record['adapter_evidence']['provider_call_outcome'])
                self.assertEqual(record['retry_decision'], 'stop')
                self.assertEqual(record['promoted_artifact_refs'], [])
                self.assertFalse((runs / 'fault/seals/solver.json').exists())
                self.assertFalse((runs / 'fault/attempt-lifecycle/verifier').exists())
                report = ArtifactStore.verify_terminal_run(runs, 'fault')
                self.assertEqual(report['attempt_retry_safety'], {'solver': 'unsafe_response_observed'})

    def test_diagnostic_overflow_before_sdk_has_no_observations_or_leaks(self):
        import json
        from model_council import ArtifactStore
        for mode in ('stdout', 'stderr', 'aggregate'):
            with self.subTest(mode=mode), TemporaryDirectory() as root:
                result, journal, calls, runs = run_fault_worker(root, 'diagnostic_' + mode)
                self.assertEqual(result.status, 'infrastructure_failure')
                self.assertEqual(calls, [])
                snapshot = journal.inspect(require_closed=True)
                self.assertEqual([e['event'] for e in snapshot['events']], ['attempt_prepared', 'dispatch_permitted'])
                self.assertEqual(snapshot['closure']['reason'], 'infrastructure')
                self.assertFalse((runs / 'fault/seals/solver.json').exists())
                self.assertFalse((runs / 'fault/attempt-lifecycle/verifier').exists())
                record = json.loads((runs / 'fault/invocations/solver/attempt-0001/invocation.json').read_text())
                self.assertEqual(record['retry_decision'], 'stop')
                self.assertIsNone(record['lifecycle_observed_outcome'])
                for path in (runs / 'fault').rglob('*'):
                    if path.is_file():
                        # Boolean assertion deliberately cannot print the body.
                        self.assertFalse(b'PRIVATE_DIAGNOSTIC_SENTINEL' in path.read_bytes(), 'diagnostic content persisted')
                self.assertTrue(ArtifactStore.verify_terminal_run(runs, 'fault')['attempt_lifecycle_verified'])
