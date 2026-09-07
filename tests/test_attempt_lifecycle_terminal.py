"""F5 reconstruction and tamper probes using disposable, entirely offline runs."""
import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import make_runner, make_task
from model_council import ArtifactStore
from model_council.attempt_lifecycle import AttemptJournal
from model_council.invocation import KIND_INVOCATION_METADATA
from model_council.security import canonical_json, digest_json
from model_council.types import IntegrityViolation
from test_attempt_lifecycle_dispatch import offline_dispatch, run_fault_worker
from test_provider_identity_policy import OPENAI_IDENTITY, _spec, _outcome, _run_with_observations


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


_INTENDED_INVOCATION_REF = "invocations/solver/attempt-0001/invocation.json"


def rewrite_record(run, **fields):
    """Repair local hashes so semantic checks, not stale hashes, reject a forgery."""
    path = run / _INTENDED_INVOCATION_REF
    record = json.loads(path.read_text())
    record.update(fields)
    path.write_text(canonical_json(record))
    rehash_inventory(run, _INTENDED_INVOCATION_REF)


def rehash_inventory(run, ref):
    """Rehash only the intended invocation-metadata/seal entry."""
    matched = 0
    manifest = []
    for line in (run / "manifest.jsonl").read_text().splitlines():
        entry = json.loads(line)
        if entry.get("kind") == KIND_INVOCATION_METADATA and entry.get("ref") == ref:
            path = run / entry["ref"]
            entry.update(sha256=_sha(path), bytes=path.stat().st_size)
            matched += 1
        manifest.append(entry)
    if matched != 1:
        raise AssertionError(f"expected exactly one invocation-metadata match for {ref!r}, found {matched}")
    (run / "manifest.jsonl").write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in manifest))
    seal_matched = 0
    for path in (run / "seals").glob("*.json"):
        seal = json.loads(path.read_text())
        changed = False
        for entry in seal.get("invocations", []):
            if entry.get("ref") != ref:
                continue
            target = run / entry["ref"]
            entry.update(sha256=_sha(target), bytes=target.stat().st_size)
            changed = True
            seal_matched += 1
        if not changed:
            continue
        body = {key: seal[key] for key in ("artifacts", "invocations", "expected_attempts")}
        if "attempt_lifecycle" in seal:
            body.update(attempt_lifecycle=seal["attempt_lifecycle"], lifecycle_binding_version=seal["lifecycle_binding_version"])
        seal["stage_digest"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        path.write_text(json.dumps(seal, sort_keys=True))
    if seal_matched != 1:
        raise AssertionError(f"expected exactly one seal invocation match for {ref!r}, found {seal_matched}")


class TestLifecycleTerminal(unittest.TestCase):
    def test_rehash_preserves_model_artifact_entries_without_ref(self):
        with TemporaryDirectory() as root:
            runs, run = self.success(root)
            before = [json.loads(line) for line in (run / "manifest.jsonl").read_text().splitlines()]
            without_ref = [entry for entry in before if "ref" not in entry]
            self.assertTrue(without_ref)
            self.assertTrue(all(entry["kind"] == "model_artifact" for entry in without_ref))
            rehash_inventory(run, _INTENDED_INVOCATION_REF)
            after = [json.loads(line) for line in (run / "manifest.jsonl").read_text().splitlines()]
            self.assertEqual(before, after)
            self.assertTrue(ArtifactStore.verify_terminal_run(runs, "terminal")["terminal_verified"])

    def success(self, root):
        result, runs, _, _ = _run_with_observations(root, "terminal", "A", {"solver": OPENAI_IDENTITY.model_id})
        self.assertEqual(result.status, "succeeded")
        self.assertTrue(ArtifactStore.verify_terminal_run(runs, "terminal")["attempt_lifecycle_verified"])
        return runs, runs / "terminal"

    def test_pre_dispatch_budget_failure_is_closed_not_started(self):
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with patch.object(runner.adapter, "invoke_live", side_effect=AssertionError("dispatch forbidden")) as invoke:
                result = runner.execute(_spec("budget", max_input_tokens_per_stage=1), make_task())
            invoke.assert_not_called()
            self.assertNotEqual(result.status, "succeeded")
            report = ArtifactStore.verify_terminal_run(runs, "budget")
            self.assertEqual(report["attempt_retry_safety"], {"solver": "safe_not_dispatched"})
            journal = AttemptJournal(runs / "budget/attempt-lifecycle/solver/attempt-0001/journal.jsonl")
            self.assertEqual(len(journal.inspect()["events"]), 1)
            self.assertEqual(journal.inspect()["closure"]["event"], "closed_not_started")

    def test_interrupted_preparation_is_never_retry_safe(self):
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            create = AttemptJournal.create
            def interrupted(*args, **kwargs):
                create(*args, **kwargs)
                raise KeyboardInterrupt()
            with patch.object(AttemptJournal, "create", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(_spec("prepared"), make_task())
            journal = AttemptJournal(runs / "prepared/attempt-lifecycle/solver/attempt-0001/journal.jsonl")
            self.assertEqual(journal.inspect()["retry_safety"], "indeterminate")
            self.assertEqual(len(journal.inspect()["events"]), 1)
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "prepared")

    def test_interrupted_adapter_entry_with_zero_invocations_has_durable_attempt(self):
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            entries = []
            def interrupted(request):
                entries.append(request)
                journal = runner.adapter.attempt_journal
                journal.permit(request.attempt_timeout_seconds)
                journal.close("interrupted", worker_reaped=True)
                raise KeyboardInterrupt()
            with patch.object(runner.adapter, "invoke_live", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    runner.execute(_spec("interrupted"), make_task())
            self.assertEqual(len(entries), 1)
            self.assertEqual(list((runs / "interrupted").glob("invocations/*/*/invocation.json")), [])
            report = ArtifactStore.verify_terminal_run(runs, "interrupted")
            self.assertEqual(report["terminal_status"], "infrastructure_failure")
            self.assertEqual(report["attempt_retry_safety"], {"solver": "indeterminate"})

    def test_worker_exit_uncertainty_prevents_closure(self):
        from model_council.executor import _WorkerExitUncertain
        from test_openai_adapter_skeleton import _isolated_environ
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            def fake_run(*args, **kwargs):
                reaping = kwargs.get("reaping")
                if reaping is not None:
                    reaping.mark_uncertain()
                raise _WorkerExitUncertain("unconfirmed")
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor._run_openai_worker", side_effect=fake_run,
            ):
                result = runner.execute(_spec("uncertain"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            journal = AttemptJournal(runs / "uncertain/attempt-lifecycle/solver/attempt-0001/journal.jsonl")
            self.assertFalse(journal.inspect()["closed"])
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "uncertain")

    def test_cleanup_failure_does_not_erase_worker_reaping_uncertainty(self):
        from test_openai_adapter_skeleton import _isolated_environ

        class _FailingStream:
            def close(self):
                raise OSError("cleanup failed")

        class _UncertainWorker:
            def __init__(self):
                self.stdin = _FailingStream()
                self.stdout = _FailingStream()
                self.stderr = _FailingStream()

            def communicate(self, input, timeout=None):
                raise RuntimeError("worker interrupted before exit")

            def kill(self):
                raise OSError("kill unconfirmed")

            def wait(self, timeout=None):
                raise OSError("wait unconfirmed")

        import subprocess

        real_popen = subprocess.Popen

        def fake_popen(*args, **kwargs):
            command = args[0] if args else kwargs.get("args", ())
            if "model_council.worker" in command:
                return _UncertainWorker()
            return real_popen(*args, **kwargs)

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen", side_effect=fake_popen,
            ):
                result = runner.execute(_spec("uncertain-cleanup"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            journal = AttemptJournal(
                runs / "uncertain-cleanup/attempt-lifecycle/solver/attempt-0001/journal.jsonl"
            )
            snapshot = journal.inspect()
            self.assertFalse(snapshot["closed"])
            self.assertIsNone(snapshot["closure"])
            self.assertFalse(journal.path.with_name("closed.json").exists())
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_terminal_run(runs, "uncertain-cleanup")

    def _uncertain_worker_popen(self, close_exc=None, *, saw_close=None):
        class _Stream:
            def close(self):
                if saw_close is not None:
                    saw_close.append(close_exc)
                if close_exc is not None:
                    raise close_exc()

        class _UncertainWorker:
            def __init__(self):
                self.stdin = _Stream()
                self.stdout = _Stream()
                self.stderr = _Stream()

            def communicate(self, input, timeout=None):
                raise RuntimeError("worker interrupted before exit")

            def kill(self):
                raise OSError("kill unconfirmed")

            def wait(self, timeout=None):
                raise OSError("wait unconfirmed")

        import subprocess

        real_popen = subprocess.Popen

        def fake_popen(*args, **kwargs):
            command = args[0] if args else kwargs.get("args", ())
            if "model_council.worker" in command:
                return _UncertainWorker()
            return real_popen(*args, **kwargs)

        return fake_popen

    def _assert_reaping_uncertain(self, runs, run_id, *, saw):
        self.assertTrue(saw)
        journal = AttemptJournal(
            runs / f"{run_id}/attempt-lifecycle/solver/attempt-0001/journal.jsonl"
        )
        snapshot = journal.inspect()
        self.assertIn("dispatch_permitted", [event["event"] for event in snapshot["events"]])
        self.assertFalse(snapshot["closed"])
        self.assertIsNone(snapshot["closure"])
        self.assertFalse(journal.path.with_name("closed.json").exists())
        with self.assertRaisesRegex(IntegrityViolation, "incomplete or unrecognized lifecycle namespace"):
            ArtifactStore.verify_terminal_run(runs, run_id)

    def test_stream_cleanup_keyboardinterrupt_does_not_attest_reaping(self):
        from test_openai_adapter_skeleton import _isolated_environ

        saw_close = []
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._uncertain_worker_popen(KeyboardInterrupt, saw_close=saw_close),
            ):
                result = runner.execute(_spec("uncertain-ki-cleanup"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "uncertain-ki-cleanup", saw=saw_close)

    def test_stream_cleanup_systemexit_does_not_attest_reaping(self):
        from test_openai_adapter_skeleton import _isolated_environ

        saw_close = []
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._uncertain_worker_popen(SystemExit, saw_close=saw_close),
            ):
                result = runner.execute(_spec("uncertain-systemexit-cleanup"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "uncertain-systemexit-cleanup", saw=saw_close)

    def test_scratch_cleanup_oserror_does_not_attest_reaping(self):
        from test_openai_adapter_skeleton import _isolated_environ
        import tempfile

        saw_scratch = []
        real_cleanup = tempfile.TemporaryDirectory.cleanup

        def fake_cleanup(self):
            name = getattr(self, "name", "") or ""
            if "mcl-scratch-" in os.path.basename(name):
                saw_scratch.append(name)
                try:
                    real_cleanup(self)
                finally:
                    raise OSError("scratch cleanup failed")
            return real_cleanup(self)

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._uncertain_worker_popen(),
            ), patch(
                "model_council.executor.tempfile.TemporaryDirectory.cleanup",
                fake_cleanup,
            ):
                result = runner.execute(_spec("uncertain-scratch-cleanup"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "uncertain-scratch-cleanup", saw=saw_scratch)

    def test_scratch_cleanup_oserror_preserves_returned_closure(self):
        import tempfile

        real_cleanup = tempfile.TemporaryDirectory.cleanup
        real_close = AttemptJournal.close
        close_reasons = []
        persisted = []

        def observe_close(journal, reason, **kwargs):
            close_reasons.append(reason)
            return real_close(journal, reason, **kwargs)

        with TemporaryDirectory() as root:
            closure_path = Path(root) / "runs/fault/attempt-lifecycle/solver/attempt-0001/closed.json"

            def fail_scratch_cleanup(directory):
                if "mcl-scratch-" in os.path.basename(directory.name):
                    persisted.append(closure_path.read_bytes())
                    try:
                        real_cleanup(directory)
                    finally:
                        raise OSError("scratch cleanup failed after returned closure")
                return real_cleanup(directory)

            with patch.object(AttemptJournal, "close", observe_close), patch(
                "model_council.executor.tempfile.TemporaryDirectory.cleanup",
                fail_scratch_cleanup,
            ):
                result, journal, calls, runs = run_fault_worker(root)
            self.assertEqual(close_reasons, ["returned"])
            self.assertEqual(len(calls), 1)
            self.assertEqual(persisted, [closure_path.read_bytes()])
            snapshot = AttemptJournal(journal.path).inspect(require_closed=True)
            self.assertEqual(snapshot["closure"]["reason"], "returned")
            self.assertIs(snapshot["closure"]["worker_reaped"], True)
            self.assertEqual(result.status, "infrastructure_failure")
            terminal = json.loads((runs / "fault/run_result.json").read_text())
            self.assertIn("scratch cleanup failed after returned closure", terminal["error"])
            self.assertNotIn("FileExistsError", terminal["error"])
            self.assertTrue(ArtifactStore.verify_terminal_run(runs, "fault")["attempt_lifecycle_verified"])

    def _worker_only_popen(self, worker_factory):
        import subprocess

        real_popen = subprocess.Popen

        def fake_popen(*args, **kwargs):
            command = args[0] if args else kwargs.get("args", ())
            if "model_council.worker" in command:
                return worker_factory()
            return real_popen(*args, **kwargs)

        return fake_popen

    def test_partial_spawn_failure_does_not_attest_reaping(self):
        from test_openai_adapter_skeleton import _isolated_environ

        saw_popen = []

        def worker_factory():
            saw_popen.append(True)
            raise OSError("popen failed after possible child creation")

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._worker_only_popen(worker_factory),
            ):
                result = runner.execute(_spec("partial-spawn"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "partial-spawn", saw=saw_popen)

    def test_post_popen_transition_cannot_remain_attestable(self):
        from model_council.executor import _WorkerReaping
        from test_openai_adapter_skeleton import _isolated_environ

        created = []
        real_mark = _WorkerReaping.mark_uncertain

        def fake_mark(self):
            if created and self.may_attest():
                raise KeyboardInterrupt()
            return real_mark(self)

        class _LiveUnreaped:
            def __init__(self):
                self.stdin = None
                self.stdout = None
                self.stderr = None

            def communicate(self, input, timeout=None):
                raise KeyboardInterrupt()

            def kill(self):
                raise OSError("kill unconfirmed")

            def wait(self, timeout=None):
                raise OSError("wait unconfirmed")

        def worker_factory():
            proc = _LiveUnreaped()
            created.append(proc)
            return proc

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._worker_only_popen(worker_factory),
            ), patch.object(_WorkerReaping, "mark_uncertain", fake_mark):
                result = runner.execute(_spec("post-return-interrupt"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "post-return-interrupt", saw=created)

    def test_normal_return_closure_requires_explicit_reaping_state(self):
        from model_council.executor import _WorkerReaping
        from test_openai_adapter_skeleton import _isolated_environ

        class _QuietStream:
            def close(self):
                return None

        class _ReturnedWorker:
            def __init__(self):
                self.returncode = 0
                self.stdin = _QuietStream()
                self.stdout = _QuietStream()
                self.stderr = _QuietStream()

            def communicate(self, input, timeout=None):
                return ("{}", "")

        def fake_mark_reaped(self):
            return None

        saw_return = []
        def worker_factory():
            saw_return.append(True)
            return _ReturnedWorker()

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._worker_only_popen(worker_factory),
            ), patch.object(_WorkerReaping, "mark_reaped", fake_mark_reaped):
                result = runner.execute(_spec("return-without-reaped"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self._assert_reaping_uncertain(runs, "return-without-reaped", saw=saw_return)

    def test_unknown_reaping_state_does_not_attest_closure(self):
        from model_council.executor import _WorkerReaping
        from test_openai_adapter_skeleton import _isolated_environ

        class _QuietStream:
            def close(self):
                return None

        class _ReturnedWorker:
            def __init__(self):
                self.returncode = 0
                self.stdin = _QuietStream()
                self.stdout = _QuietStream()
                self.stderr = _QuietStream()

            def communicate(self, input, timeout=None):
                return ("{}", "")

        def fake_mark_reaped(self):
            self.status = "not-a-recognized-state"

        saw_return = []
        def worker_factory():
            saw_return.append(True)
            return _ReturnedWorker()

        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with _isolated_environ(OPENAI_API_KEY="offline-f5-not-a-real-key"), patch(
                "model_council.executor.subprocess.Popen",
                side_effect=self._worker_only_popen(worker_factory),
            ), patch.object(_WorkerReaping, "mark_reaped", fake_mark_reaped):
                result = runner.execute(_spec("unknown-reaping-state"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            unknown = _WorkerReaping()
            unknown.status = "not-a-recognized-state"
            self.assertFalse(unknown.may_attest())
            self._assert_reaping_uncertain(runs, "unknown-reaping-state", saw=saw_return)

    def test_crash_after_durable_closure_reconstructs_from_disk(self):
        close = AttemptJournal.close
        def crash_after_close(journal, *args, **kwargs):
            close(journal, *args, **kwargs)
            raise KeyboardInterrupt()
        with TemporaryDirectory() as root, patch.object(AttemptJournal, "close", crash_after_close):
            with self.assertRaises(KeyboardInterrupt):
                run_fault_worker(root)
            report = ArtifactStore.verify_terminal_run(Path(root) / "runs", "fault")
            self.assertEqual(report["terminal_status"], "infrastructure_failure")
            self.assertEqual(report["attempt_retry_safety"], {"solver": "unsafe_response_observed"})

    def test_stored_retry_classification_cannot_override_evidence(self):
        with TemporaryDirectory() as root:
            runs, run = self.success(root)
            record = json.loads((run / "invocations/solver/attempt-0001/invocation.json").read_text())
            forged = {**record["attempt_lifecycle"], "retry_safety": "safe_not_dispatched"}
            rewrite_record(run, attempt_lifecycle=forged)
            with self.assertRaisesRegex(IntegrityViolation, "invocation lifecycle binding"):
                ArtifactStore.verify_terminal_run(runs, "terminal")

    def test_extra_retry_safe_boolean_is_rejected_by_strict_v3_schema(self):
        with TemporaryDirectory() as root:
            runs, run = self.success(root)
            rewrite_record(run, retry_safe=True)
            with self.assertRaisesRegex(IntegrityViolation, "invocation schema"):
                ArtifactStore.verify_terminal_run(runs, "terminal")

    def test_invocation_normalized_outcome_must_equal_durable_observation(self):
        with TemporaryDirectory() as root:
            runs, run = self.success(root)
            rewrite_record(run, lifecycle_observed_outcome=None)
            with self.assertRaisesRegex(IntegrityViolation, "differs from durable observation"):
                ArtifactStore.verify_terminal_run(runs, "terminal")

    def test_moved_missing_and_extra_namespaces_are_rejected(self):
        for mutation in ("moved", "missing", "extra", "open"):
            with self.subTest(mutation=mutation), TemporaryDirectory() as root:
                runs, run = self.success(root)
                base = run / "attempt-lifecycle/solver/attempt-0001"
                if mutation == "moved":
                    base.rename(base.with_name("attempt-0002"))
                elif mutation == "missing":
                    (run / "attempt-lifecycle").rename(Path(root) / "withheld-evidence")
                elif mutation == "extra":
                    (run / "attempt-lifecycle/unused").mkdir()
                else:
                    (base / "closed.json").rename(Path(root) / "withheld-closure.json")
                with self.assertRaises(IntegrityViolation):
                    ArtifactStore.verify_terminal_run(runs, "terminal")

    def test_event_after_closure_and_rehashed_wrong_binding_are_rejected(self):
        cases = {
            "after_closure": "closure binding mismatch",
            "wrong_binding": "lifecycle authority binding mismatch",
        }
        for mutation, reason in cases.items():
            with self.subTest(mutation=mutation), TemporaryDirectory() as root:
                runs, run = self.success(root)
                path = run / "attempt-lifecycle/solver/attempt-0001/journal.jsonl"
                closure_path = path.with_name("closed.json")
                events = [json.loads(line) for line in path.read_text().splitlines()]
                if mutation == "after_closure":
                    closure = json.loads(closure_path.read_text())
                    closure["event_count"] = len(events) - 1
                    closure["head_digest"] = events[-2]["digest"]
                    closure_path.write_text(canonical_json(closure))
                else:
                    events[0]["data"]["authority_digest"] = "0" * 64
                    previous = None
                    for event in events:
                        event["previous_digest"] = previous
                        event["digest"] = digest_json({k: v for k, v in event.items() if k != "digest"})
                        previous = event["digest"]
                    path.write_text("".join(canonical_json(e) + "\n" for e in events))
                    closure = json.loads(closure_path.read_text())
                    closure["head_digest"] = events[-1]["digest"]
                    closure_path.write_text(canonical_json(closure))
                with self.assertRaisesRegex(IntegrityViolation, reason):
                    ArtifactStore.verify_terminal_run(runs, "terminal")

    def test_runner_blocks_outcome_without_matching_lifecycle_before_promotion(self):
        with TemporaryDirectory() as root:
            runner, runs = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            def conflicting(request):
                offline_dispatch(runner.adapter, request, lambda: _outcome(request))
                outcome = _outcome(request).to_dict()
                outcome["stage_output"]["artifacts"]["candidate"] = "PROPOSED_FIX: altered"
                from model_council.live_contract import parse_provider_call_outcome
                return parse_provider_call_outcome(outcome)
            with patch.object(runner.adapter, "invoke_live", side_effect=conflicting):
                result = runner.execute(_spec("conflict"), make_task())
            self.assertEqual(result.status, "infrastructure_failure")
            self.assertFalse((runs / "conflict/seals/solver.json").exists())
            self.assertFalse((runs / "conflict/evaluation.json").exists())

    def test_restart_refuses_existing_run_without_rewriting_evidence(self):
        from model_council.types import GovernanceViolation
        with TemporaryDirectory() as root:
            _, run = self.success(root)
            before = {str(p.relative_to(run)): p.read_bytes() for p in run.rglob("*") if p.is_file()}
            runner, _ = make_runner(root, kind="openai_responses", identity=OPENAI_IDENTITY)
            with self.assertRaises(GovernanceViolation):
                runner.execute(_spec("terminal"), make_task())
            after = {str(p.relative_to(run)): p.read_bytes() for p in run.rglob("*") if p.is_file()}
            self.assertEqual(before, after)

    def test_historical_v14_openai_reconstructs_f2_without_f5(self):
        """Build a v14 artifact fixture; no historical dispatch mode is enabled."""
        from model_council.invocation import treatment_digest_for_attempt
        from model_council.roles import ROLE_INSTRUCTIONS
        from model_council.types import ResourceLimits
        from test_provider_treatment_config import _stage_inputs_from_trusted_records
        with TemporaryDirectory() as root:
            _, source = self.success(root)
            run = Path(root) / "historical/terminal"
            for path in source.rglob("*"):
                relative = path.relative_to(source)
                if path.is_file() and relative.parts[0] != "attempt-lifecycle":
                    target = run / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(path.read_bytes())
            version = "m1-dev-harness-v14"
            binding_path = run / "execution_binding.json"
            binding = json.loads(binding_path.read_text())
            binding["harness_protocol_version"] = version
            binding.pop("attempt_lifecycle_schema")
            binding.pop("execution_instance_id")
            binding_path.write_text(canonical_json(binding))
            declaration_path = run / "treatment_declaration.json"
            declaration = json.loads(declaration_path.read_text())
            declaration["declaration"]["harness_protocol_version"] = version
            declaration["treatment_hash"] = digest_json(declaration["declaration"])
            declaration_path.write_text(canonical_json(declaration))
            spec = json.loads(json.loads((run / "run_spec.json").read_text())["canonical"])
            record_path = run / "invocations/solver/attempt-0001/invocation.json"
            record = json.loads(record_path.read_text())
            record["schema"] = "m1-invocation-record-v2"
            record.pop("attempt_lifecycle")
            record.pop("lifecycle_observed_outcome")
            record["treatment_digest"] = treatment_digest_for_attempt(
                condition="A", role="solver", role_instruction=ROLE_INSTRUCTIONS["solver"],
                stage_inputs=_stage_inputs_from_trusted_records(run, "A", "solver"),
                requested_identity=OPENAI_IDENTITY, configured_identity=OPENAI_IDENTITY,
                seed=spec["seed"], resource_limits=ResourceLimits(**spec["resource_limits"]),
                execution_profile=binding["execution_profile"], adapter_kind="openai_responses",
                adapter_config_digest=binding["adapter_config_digest"],
                provider_treatment_config=binding["provider_treatment_config"],
                provider_identity_policy=binding["provider_identity_policy"],
                harness_protocol_version=version,
            )[1]
            record_path.write_text(canonical_json(record))
            seal_path = run / "seals/solver.json"
            seal = json.loads(seal_path.read_text())
            seal.pop("attempt_lifecycle")
            seal.pop("lifecycle_binding_version")
            seal_path.write_text(canonical_json(seal))
            rehash_inventory(run, _INTENDED_INVOCATION_REF)
            terminal_path = run / "run_result.json"
            terminal = json.loads(terminal_path.read_text())
            terminal["harness_protocol_version"] = version
            terminal["treatment_hash"] = declaration["treatment_hash"]
            terminal.pop("attempt_lifecycle")
            terminal_path.write_text(canonical_json(terminal))
            authority_path = run / "run_authority.json"
            authority = json.loads(authority_path.read_text())
            authority["harness_protocol_version"] = version
            authority["execution_binding_sha256"] = _sha(binding_path)
            authority["treatment_declaration_sha256"] = _sha(declaration_path)
            authority_path.write_text(canonical_json(authority))
            report = ArtifactStore.verify_terminal_run(run.parent, "terminal")
            self.assertTrue(report["terminal_verified"])
            self.assertTrue(report["provider_identity_policy_verified"])
            self.assertFalse(report["attempt_lifecycle_verified"])
            self.assertIsNone(report["attempt_lifecycle_schema"])
            self.assertNotIn("attempt_retry_safety", report)
