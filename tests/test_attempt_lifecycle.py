"""Offline F5 journal durability and transition requirements."""
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from helpers import TempRoot


class TestAttemptLifecycle(unittest.TestCase):
    def test_duplicate_attempt_id_is_rejected_before_permission(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        from types import SimpleNamespace
        with TempRoot() as root, patch("model_council.attempt_lifecycle.uuid.uuid4", return_value=SimpleNamespace(hex="a" * 32)):
            first = AttemptJournal.create(Path(root), binding())
            first.close("not_started", worker_reaped=True)
            with self.assertRaisesRegex(IntegrityViolation, "duplicate attempt ID"):
                AttemptJournal.create(Path(root), {**binding(), "role": "verifier"})
            self.assertFalse((Path(root) / "attempt-lifecycle/verifier").exists())

    def test_bounds_schema_and_contradictory_observations_fail_closed(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            writer = journal.open_writer()
            try:
                for event, payload in (("closed_not_started", {}), ("provider_accepted", {}), ("sdk_return_observed", {}), ("sdk_call_boundary", {"wire_request_digest": "bad"})):
                    with self.subTest(event=event), self.assertRaises(IntegrityViolation):
                        writer.append(event, payload)
                with patch("model_council.attempt_lifecycle.MAX_FRAME_BYTES", 16):
                    with self.assertRaises(IntegrityViolation):
                        writer.events()
                self.assertEqual(len(writer.events()), 2)
            finally:
                os.close(writer.fd)

    def test_prepared_binding_cannot_change_during_active_execution(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.security import canonical_json, digest_json
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            event = json.loads(journal.path.read_text())
            event["data"]["authority_digest"] = "0" * 64
            event["digest"] = digest_json({k: v for k, v in event.items() if k != "digest"})
            journal.path.write_text(canonical_json(event) + "\n")
            with self.assertRaisesRegex(IntegrityViolation, "prepared authority changed"):
                journal.permit()

    def test_unconfirmed_worker_exit_cannot_close(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            with self.assertRaises(IntegrityViolation):
                journal.close("interrupted", worker_reaped=False)
            self.assertFalse(journal.inspect()["closed"])

    def test_closure_resynchronizes_journal_before_publishing_closure(self):
        from model_council.attempt_lifecycle import AttemptJournal
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            observed = []
            sync = os.fsync
            def observe(fd):
                observed.append(os.fstat(fd).st_ino)
                sync(fd)
            with patch("model_council.attempt_lifecycle.os.fsync", side_effect=observe):
                journal.close("interrupted", worker_reaped=True)
            self.assertEqual(observed, [journal.path.stat().st_ino,
                                       journal.path.with_name("closed.json").stat().st_ino,
                                       journal.path.parent.stat().st_ino])

    def test_failed_journal_sync_during_closure_does_not_publish_closed_json(self):
        from model_council.attempt_lifecycle import AttemptJournal
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            info = journal.path.stat()
            journal_identity = (info.st_dev, info.st_ino)
            sync = os.fsync
            observed = []

            def fail_journal_sync(fd):
                info = os.fstat(fd)
                identity = (info.st_dev, info.st_ino)
                observed.append(identity)
                if identity == journal_identity:
                    raise OSError("journal sync failed")
                sync(fd)

            with patch("model_council.attempt_lifecycle.os.fsync", side_effect=fail_journal_sync):
                with self.assertRaisesRegex(OSError, "journal sync failed"):
                    journal.close("interrupted", worker_reaped=True)
            self.assertEqual(observed, [journal_identity])
            self.assertTrue(journal.persistence_failed)
            self.assertFalse(journal.path.with_name("closed.json").exists())
            snapshot = AttemptJournal(journal.path).inspect()
            self.assertFalse(snapshot["closed"])
            self.assertEqual(snapshot["retry_safety"], "indeterminate")

    def test_reconstructed_namespace_is_inspection_only(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            original = AttemptJournal.create(Path(root), binding())
            reconstructed = AttemptJournal(original.path)
            self.assertFalse(reconstructed.inspect()["closed"])
            with self.assertRaises(IntegrityViolation):
                reconstructed.permit()

    def test_reconstruction_rejects_closure_head_mismatch(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.security import canonical_json
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            journal.close("interrupted", worker_reaped=True)
            self.assertTrue(AttemptJournal(journal.path).inspect(require_closed=True)["closed"])
            closure_path = journal.path.with_name("closed.json")
            closure = json.loads(closure_path.read_text())
            head = closure["head_digest"]
            closure["head_digest"] = ("0" if head[0] != "0" else "1") + head[1:]
            closure_path.write_text(canonical_json(closure))
            reconstructed = AttemptJournal(journal.path)
            with self.assertRaisesRegex(IntegrityViolation, "closure binding mismatch"):
                reconstructed.inspect(require_closed=True)

    def test_writer_requires_append_descriptor(self):
        from model_council.attempt_lifecycle import AttemptJournal, JournalWriter
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            fd = os.open(journal.path, os.O_RDWR)
            try:
                with self.assertRaises(IntegrityViolation):
                    JournalWriter(fd, journal.inspect()["attempt_id"])
            finally:
                os.close(fd)

    def test_failed_permission_sync_never_becomes_safe(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            with patch("model_council.attempt_lifecycle.os.fsync", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    journal.permit()
            with self.assertRaises(IntegrityViolation):
                journal.close("not_started", worker_reaped=True)

    def test_second_call_boundary_and_postclosure_events_rejected(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            writer = journal.open_writer()
            try:
                writer.append("sdk_call_boundary", {"wire_request_digest": "f" * 64})
                with self.assertRaises(IntegrityViolation):
                    writer.append("sdk_call_boundary", {"wire_request_digest": "f" * 64})
            finally:
                os.close(writer.fd)
            journal.close("interrupted", worker_reaped=True)
            with self.assertRaises(IntegrityViolation):
                journal.open_writer()

    def test_lifecycle_api_exists(self):
        from model_council import attempt_lifecycle as lifecycle
        self.assertEqual(lifecycle.LIFECYCLE_SCHEMA, "m1-attempt-lifecycle-v1")

    def test_permission_cannot_be_reclassified_not_started(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            journal.permit()
            with self.assertRaises(IntegrityViolation):
                journal.close("not_started", worker_reaped=True)
            self.assertEqual(journal.inspect()["retry_safety"], "indeterminate")

    def test_only_closed_not_started_is_safe(self):
        from model_council.attempt_lifecycle import AttemptJournal
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            self.assertEqual(journal.inspect()["retry_safety"], "indeterminate")
            journal.close("not_started", worker_reaped=True)
            self.assertEqual(journal.inspect()["retry_safety"], "safe_not_dispatched")

    def test_failed_sync_does_not_grant_permission(self):
        from model_council.attempt_lifecycle import AttemptJournal
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            with patch("model_council.attempt_lifecycle.os.fsync", side_effect=OSError("disk")):
                with self.assertRaises(OSError):
                    journal.permit()
            self.assertFalse(journal.permission_granted)

    def test_namespace_reuse_is_rejected(self):
        from model_council.attempt_lifecycle import AttemptJournal
        with TempRoot() as root:
            AttemptJournal.create(Path(root), binding())
            with self.assertRaises(FileExistsError):
                AttemptJournal.create(Path(root), binding())

    def test_torn_journal_never_establishes_safety(self):
        from model_council.attempt_lifecycle import AttemptJournal
        from model_council.types import IntegrityViolation
        with TempRoot() as root:
            journal = AttemptJournal.create(Path(root), binding())
            with journal.path.open("ab") as stream:
                stream.write(b'{"partial":')
            with self.assertRaises(IntegrityViolation):
                journal.inspect()


def binding():
    from helpers import FAKE_IDENTITY
    from model_council.types import ResourceLimits
    return {
        "run_id": "unit", "role": "solver", "attempt": 1,
        "execution_instance_id": "f" * 32, "harness_protocol_version": "m1-dev-harness-v15",
        "predecessor_attempt_id": None, "treatment_digest": "a" * 64,
        "authority_digest": "a" * 64, "request_digest": "b" * 64,
        "input_content_digest": "c" * 64, "request_parameter_digest": "d" * 64,
        "configured_identity": FAKE_IDENTITY.to_dict(), "wire_model": FAKE_IDENTITY.model_id,
        "identity_policy_digest": "e" * 64, "resource_limits": ResourceLimits(max_stage_retries=0).to_dict(),
        "attempt_timeout_seconds": 1.0,
    }
