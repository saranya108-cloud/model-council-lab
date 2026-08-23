"""Provenance, deep-freeze, and durable artifact-integrity tests (Findings 7-9)."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from model_council import (
    EvaluationConfig,
    ExperimentRunner,
    ExternalEvaluator,
    InfrastructureError,
    ResourceLimits,
    RunSpec,
    Condition,
    GovernanceViolation,
    IntegrityViolation,
)
from model_council.artifacts import ArtifactStore
from model_council.runner import HARNESS_PROTOCOL_VERSION
from helpers import (
    FAKE_IDENTITY,
    IDENTITY_KEY,
    TempRoot,
    make_runner,
    make_spec,
    make_task,
)


class TestProvenance(unittest.TestCase):
    def test_metadata_mutation_after_creation_does_not_change_hash(self):
        mutable = {"experimenter_note": "v1"}
        spec = RunSpec(
            run_id="prov-1",
            task_id="dev-001",
            condition=Condition.A,
            model_identifier=IDENTITY_KEY,
            prompt_version="p1",
            resource_limits=ResourceLimits(),
            metadata=mutable,
        )
        before = spec.spec_hash
        mutable["experimenter_note"] = "TAMPERED"
        mutable["extra"] = True
        self.assertEqual(spec.spec_hash, before)
        self.assertNotIn("TAMPERED", spec.canonical_json())

    def test_task_content_hash_binds_snapshot_description(self):
        task_a = make_task("dev-x", bug_report="defect A")
        task_b = make_task("dev-x", bug_report="defect B")
        self.assertNotEqual(task_a.content_hash, task_b.content_hash)

    def test_treatment_hash_changes_with_meaningful_config(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            spec = make_spec("prov-2", "A")
            task = make_task()
            hash_a = runner._treatment_hash(spec, task)
            spec_other_prompt = RunSpec(
                run_id=spec.run_id,
                task_id=spec.task_id,
                condition=spec.condition,
                model_identifier=IDENTITY_KEY,
                prompt_version="p2-changed",
                resource_limits=spec.resource_limits,
                seed=spec.seed,
            )
            hash_b = runner._treatment_hash(spec_other_prompt, task)
            self.assertNotEqual(hash_a, hash_b)
            evaluator_other = ExternalEvaluator(
                EvaluationConfig(required_markers=("OTHER_MARKER",))
            )
            original = runner.evaluator
            runner.evaluator = evaluator_other
            try:
                hash_c = runner._treatment_hash(spec, task)
            finally:
                runner.evaluator = original
            self.assertNotEqual(hash_a, hash_c)

    def test_runspec_seed_drives_fake_adapter_output(self):
        with TempRoot() as root:
            outputs = {}
            for seed in (7, 8):
                runner, runs_root = make_runner(root)
                result = runner.execute(make_spec(f"seed-{seed}", "A", seed=seed), make_task())
                outputs[seed] = (runs_root / f"seed-{seed}" / result.final_candidate_ref).read_text()
            self.assertNotEqual(outputs[7], outputs[8])
        # Same seed reproduces byte-identical output across fresh processes.
        with TempRoot() as root:
            texts = []
            for i in range(2):
                runner, runs_root = make_runner(root)
                result = runner.execute(make_spec(f"same-{i}", "A", seed=99), make_task())
                texts.append((runs_root / f"same-{i}" / result.final_candidate_ref).read_text())
            self.assertEqual(texts[0], texts[1])

    def test_terminal_payload_records_protocol_version_and_source_revision(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            result = runner.execute(make_spec("prov-3", "A"), make_task())
            payload = json.loads((Path(root) / "runs" / "prov-3" / "run_result.json").read_text())
            self.assertEqual(payload["harness_protocol_version"], HARNESS_PROTOCOL_VERSION)
            self.assertIn("harness_protocol_version", payload)
            self.assertTrue(payload["treatment_hash"])
            self.assertTrue(payload["verified_identity"])
            sp = payload["source_provenance"]
            self.assertIn("source_revision", sp)
            self.assertIn("working_tree_dirty", sp)
            self.assertIsInstance(sp["working_tree_dirty"], bool)
            self.assertIn(
                "not a cryptographic hash of the source tree",
                payload["treatment_hash_scope"],
            )

    def test_source_provenance_is_captured_before_run_output(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)

            def capture_before_store():
                self.assertFalse(runs_root.exists())
                return {
                    "source_revision": "clean-test-revision",
                    "working_tree_dirty": False,
                    "git_available": True,
                    "uncommitted_implementation": False,
                }

            with patch("model_council.runner.source_revision", side_effect=capture_before_store):
                result = runner.execute(make_spec("prov-order", "A"), make_task())
            self.assertEqual(result.status, "succeeded")
            self.assertFalse(result.metadata["source_provenance"]["working_tree_dirty"])


class TestArtifactIntegrity(unittest.TestCase):
    def test_seal_records_hashes_and_stage_digest(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("integ-1", "A"))
            store.write("solver", "candidate", "stable content")
            store.write("solver", "evidence", "supporting content")
            seal = store.seal_stage("solver")
            self.assertEqual(
                {entry["name"] for entry in seal["artifacts"]}, {"candidate", "evidence"}
            )
            self.assertTrue((Path(root) / "runs" / "integ-1" / "seals" / "solver.json").exists())

    def test_direct_tampering_detected_by_verification(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("integ-2", "A"))
            ref = store.write("solver", "candidate", "original bytes")
            store.write("solver", "evidence", "supporting bytes")
            store.seal_stage("solver")
            target = Path(root) / "runs" / "integ-2" / ref
            target.write_text("tampered bytes")
            with self.assertRaises(IntegrityViolation):
                store.verify_sealed_stage("solver")

    def test_deletion_of_sealed_artifact_detected(self):
        with TempRoot() as root:
            store = ArtifactStore(Path(root) / "runs", make_spec("integ-3", "A"))
            ref = store.write("solver", "candidate", "data")
            store.write("solver", "evidence", "supporting data")
            store.seal_stage("solver")
            (Path(root) / "runs" / "integ-3" / ref).unlink()
            with self.assertRaises(IntegrityViolation):
                store.verify_sealed_stage("solver")

    def test_completed_run_verification_detects_post_hoc_tampering(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("integ-4", "C"), make_task())
            self.assertTrue(result.metadata["integrity"]["integrity_verified"])
            # Supported public API verification of the untouched run passes.
            report = ArtifactStore.verify_completed(runs_root, "integ-4")
            self.assertTrue(report["integrity_verified"])
            self.assertEqual(sorted(report["sealed_stages"]), ["reviser", "solver", "verifier"])
            # Post-completion tampering is detected by the same public API.
            victim = runs_root / "integ-4" / "verifier" / "findings.md"
            victim.write_text(victim.read_text() + "\nAPPENDED FORGERY\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "integ-4")

    def test_joint_artifact_and_seal_tampering_detected(self):
        """SOL attack: rewriting artifact AND seal must not pass, because the
        append-only manifest retains original write-time hashes."""
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("integ-6", "A"), make_task())
            run_dir = runs_root / "integ-6"
            candidate = run_dir / "solver" / "candidate.md"
            new_bytes = b"fully forged content"
            candidate.write_bytes(new_bytes)
            seal_path = run_dir / "seals" / "solver.json"
            seal = json.loads(seal_path.read_text())
            import hashlib

            for entry in seal["artifacts"]:
                if entry["name"] == "candidate":
                    entry["sha256"] = hashlib.sha256(new_bytes).hexdigest()
                    entry["bytes"] = len(new_bytes)
            seal_path.write_text(json.dumps(seal, indent=2, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "integ-6")

    def test_completed_verification_rejects_empty_stage_seal(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            runner.execute(make_spec("integ-empty-seal", "A"), make_task())
            seal_path = runs_root / "integ-empty-seal" / "seals" / "solver.json"
            seal = json.loads(seal_path.read_text())
            seal["artifacts"] = []
            seal_path.write_text(json.dumps(seal, sort_keys=True))
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, "integ-empty-seal")

    def test_completed_verification_requires_all_expected_stage_seals(self):
        for condition, roles in (
            ("A", ("solver",)),
            ("B", ("draft", "self_review", "reviser")),
            ("C", ("solver", "verifier", "reviser")),
        ):
            for omitted_role in roles:
                with self.subTest(condition=condition, omitted_role=omitted_role):
                    with TempRoot() as root:
                        runner, runs_root = make_runner(root)
                        run_id = f"integ-seals-{condition}-{omitted_role}"
                        runner.execute(make_spec(run_id, condition), make_task())
                        (runs_root / run_id / "seals" / f"{omitted_role}.json").unlink()
                        with self.assertRaises(IntegrityViolation):
                            ArtifactStore.verify_completed(runs_root, run_id)

    def test_missing_final_seal_and_altered_candidate_are_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            run_id = "integ-final-missing"
            result = runner.execute(make_spec(run_id, "C"), make_task())
            final_path = runs_root / run_id / result.final_candidate_ref
            final_path.write_text("altered final candidate")
            (runs_root / run_id / "seals" / "reviser.json").unlink()
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, run_id)

    def test_missing_manifest_record_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            run_id = "integ-missing-manifest"
            runner.execute(make_spec(run_id, "A"), make_task())
            manifest = runs_root / run_id / "manifest.jsonl"
            lines = manifest.read_text().splitlines()
            manifest.write_text("\n".join(lines[:1]) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, run_id)

    def test_extra_manifest_record_is_rejected(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            run_id = "integ-extra-manifest"
            runner.execute(make_spec(run_id, "A"), make_task())
            manifest = runs_root / run_id / "manifest.jsonl"
            first = json.loads(manifest.read_text().splitlines()[0])
            first["name"] = "unexpected"
            manifest.write_text(manifest.read_text() + json.dumps(first) + "\n")
            with self.assertRaises(IntegrityViolation):
                ArtifactStore.verify_completed(runs_root, run_id)

    def test_intact_completed_a_b_c_runs_verify(self):
        with TempRoot() as root:
            for condition in ("A", "B", "C"):
                runner, runs_root = make_runner(root)
                run_id = f"integ-intact-{condition}"
                result = runner.execute(make_spec(run_id, condition), make_task())
                self.assertEqual(result.status, "succeeded")
                self.assertTrue(
                    ArtifactStore.verify_completed(runs_root, run_id)["integrity_verified"]
                )

    def test_solver_artifact_byte_identical_through_full_council(self):
        with TempRoot() as root:
            runner, runs_root = make_runner(root)
            result = runner.execute(make_spec("integ-5", "C"), make_task())
            run_dir = runs_root / "integ-5"
            manifest = [
                json.loads(line)
                for line in (run_dir / "manifest.jsonl").read_text().splitlines()
                if line.strip()
            ]
            candidate_entries = [e for e in manifest if e["role"] == "solver" and e["name"] == "candidate"]
            self.assertEqual(len(candidate_entries), 1)
            on_disk = (run_dir / "solver" / "candidate.md").read_bytes()
            import hashlib

            self.assertEqual(hashlib.sha256(on_disk).hexdigest(), candidate_entries[0]["sha256"])
            # Downstream stages ran after the solver was sealed.
            roles_order = [s.role for s in result.stage_results]
            self.assertEqual(roles_order, ["solver", "verifier", "reviser"])

    def test_evaluator_configuration_is_single_source_of_truth(self):
        """execute() takes no evaluation config; the injected evaluator governs."""
        import inspect

        sig = inspect.signature(ExperimentRunner.execute)
        self.assertEqual(list(sig.parameters), ["self", "run_spec", "task_spec"])
        with TempRoot() as root:
            strict = ExternalEvaluator(EvaluationConfig(required_markers=("NEVER_PRESENT",)))
            runner, _ = make_runner(root)
            runner.evaluator = strict
            result = runner.execute(make_spec("prov-eval", "A"), make_task())
            self.assertFalse(result.evaluation.passed)


if __name__ == "__main__":
    unittest.main()


class TestDeepFreeze(unittest.TestCase):
    def test_nested_tuple_dict_list_dict_frozen(self):
        nested = {"meta": ({"inner": [1, 2, {"deep": "value"}]},)}
        spec = RunSpec(
            run_id="frz-1",
            task_id="dev-001",
            condition=Condition.A,
            model_identifier=IDENTITY_KEY,
            prompt_version="p",
            resource_limits=ResourceLimits(),
            metadata=nested,
        )
        before = spec.spec_hash
        # Mutate the caller-owned structure at every level.
        nested["meta"][0]["inner"][2]["deep"] = "MUTATED"
        nested["meta"][0]["inner"].append("extra")
        self.assertEqual(spec.spec_hash, before)
        self.assertNotIn("MUTATED", spec.canonical_json())
        self.assertNotIn("extra", spec.canonical_json())

    def test_set_canonicalization_is_type_stable_and_order_independent(self):
        def build(metadata):
            return RunSpec(
                run_id="frz-set",
                task_id="dev-001",
                condition=Condition.A,
                model_identifier=IDENTITY_KEY,
                prompt_version="p1",
                resource_limits=ResourceLimits(),
                metadata=metadata,
            )

        string_set = build({"values": {"one", "two"}})
        number_set = build({"values": {1, 2}})
        mixed_set = build({"nested": ({"values": {1, "one"}},)})
        self.assertEqual(string_set.spec_hash, build({"values": {"two", "one"}}).spec_hash)
        self.assertEqual(number_set.spec_hash, build({"values": {2, 1}}).spec_hash)
        self.assertTrue(mixed_set.spec_hash)

    def test_mutable_evaluator_inputs_do_not_change_digest(self):
        required = ["MARKER_A"]
        prohibited = ["BAD_MARKER"]
        config = EvaluationConfig(required_markers=required, prohibited_markers=prohibited)
        digest_before = config.config_digest
        required.append("MARKER_B")
        prohibited.clear()
        self.assertEqual(config.config_digest, digest_before)
        evaluator = ExternalEvaluator(config)
        outcome = evaluator.evaluate("has MARKER_A")
        self.assertTrue(outcome.passed)
        self.assertNotIn("MARKER_B", str(outcome.to_dict()))

    def test_adapter_option_mutation_after_runner_construction_ignored(self):
        with TempRoot() as root:
            options = {"verifier_extra_finding": False}
            runner, _ = make_runner(root, options=options)
            hash_a = runner._treatment_hash(make_spec("opt-1", "A"), make_task())
            options["verifier_extra_finding"] = True  # caller mutates after ctor
            hash_b = runner._treatment_hash(make_spec("opt-1", "A"), make_task())
            self.assertEqual(hash_a, hash_b)


class TestScratchCleanup(unittest.TestCase):
    def test_scratch_removed_after_success(self):
        with TempRoot() as root:
            runner, _ = make_runner(root)
            runner.adapter.invoke(
                role_instruction="role:solver x", stage_inputs={"task": "t"},
                budget=ResourceLimits(), seed=0,
            )
            scratch = Path(runner.adapter.last_scratch_dir)
            self.assertFalse(scratch.exists())

    def test_scratch_removed_after_worker_crash_and_timeout(self):
        from model_council.types import ModelFailure as MF, StageTimeout as ST

        with TempRoot() as root:
            crash, _ = make_runner(root, kind="crash_worker")
            with self.assertRaises((InfrastructureError, MF)):
                crash.adapter.invoke(
                    role_instruction="role:solver x", stage_inputs={"task": "t"},
                    budget=ResourceLimits(), seed=0,
                )
            self.assertFalse(Path(crash.adapter.last_scratch_dir).exists())

        with TempRoot() as root:
            slow, _ = make_runner(root, kind="sleep", options={"seconds": 20})
            with self.assertRaises(ST):
                slow.adapter.invoke(
                    role_instruction="role:solver x", stage_inputs={"task": "t"},
                    budget=ResourceLimits(stage_timeout_seconds=0.5), seed=0,
                )
            self.assertFalse(Path(slow.adapter.last_scratch_dir).exists())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
