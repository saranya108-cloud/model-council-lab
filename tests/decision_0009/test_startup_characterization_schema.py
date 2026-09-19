"""In-memory contract tests; no evidence files or snapshots are written."""

import copy
import hashlib
import json
from pathlib import Path
import unittest

from tools.decision_0009.startup_characterization import policy as p
from tools.decision_0009.startup_characterization.controller import (
    ProtocolError, Campaign, Controller, evidence_bundle, validate_record, render_report, validate_attempt, reconstruct,
)
from test_startup_characterization_protocol import Clock, Samples, Ports, Vendor, libraries, identity, run
import test_startup_characterization_protocol as protocol
from tools.decision_0009.startup_characterization.observer import Sampler
from dataclasses import replace
from types import SimpleNamespace


SCHEMA = json.loads((Path(__file__).parents[2] / "tools/decision_0009/startup_characterization/schema-v1.json").read_text())


def shift_attempt(trial, offset):
    """Translate one boot-local time interval without changing its measurements."""
    ev = trial["evidence"]
    ev["sampler_started_ns"] -= offset
    trial["custody"]["observed_ns"] -= offset
    if "admitted_ns" in trial:
        trial["admitted_ns"] -= offset
    ev["proof"]["library_stat_ns"] -= offset
    for event in ev["events"]:
        event["monotonic_raw_ns"] -= offset
    for sample in ev["samples"]:
        for key in ("sample_start_monotonic_raw_ns", "sample_end_monotonic_raw_ns"):
            sample[key] -= offset
    for journal in ("worker_raw", "observation_raw", "identity_raw"):
        for record in ev.get(journal, []):
            record["received_ns"] -= offset
            if type(record["raw"]) is dict:
                for key in ("monotonic_raw_ns", "sample_start_monotonic_raw_ns", "sample_end_monotonic_raw_ns", "observed_ns"):
                    if key in record["raw"]:
                        record["raw"][key] -= offset
    for journal in ("identity_records", "mapping_records"):
        for record in ev[journal]:
            record["observed_ns"] -= offset
            if "received_ns" in record:
                record["received_ns"] -= offset
    for frame in ev["baseline_frames"]:
        frame[0] -= offset
    trial.update(reconstruct(trial))


def fixture(node):
    """Populate the schema vocabulary, then independently mutate contract fields."""
    if "$ref" in node:
        return fixture(SCHEMA["$defs"][node["$ref"].split("/")[-1]])
    if "const" in node:
        return copy.deepcopy(node["const"])
    if "enum" in node:
        return node["enum"][0]
    if "oneOf" in node:
        return fixture(node["oneOf"][0])
    kind = node["type"]
    if kind == "object":
        value = {key: fixture(node.get("properties", {}).get(key, node.get("additionalProperties")))
                 for key in node.get("required", ())}
        if "matrix" in value:
            value["matrix"] = list(p.trial_matrix())
        return value
    if kind == "array":
        return [fixture(node["items"]) for _ in range(node.get("minItems", 0))]
    if kind == "integer":
        return max(1, node.get("minimum", 0))
    if kind == "boolean":
        return True
    if kind == "null":
        return None
    if node.get("pattern", "").startswith("^[0-9a-f]{64}"):
        return "a" * 64
    if node.get("pattern") == p.TOKEN_PATTERN:
        return "example"
    return "/example" if "pattern" in node else "example"


class SchemaTests(unittest.TestCase):
    def test_safe_identifiers_and_integer_ordinals(self):
        for kind, field in (("trial", "trial_id"), ("event", "run_id"), ("sample", "boot_id")):
            for value in ("../outside", "a/b", "a\\b", "x\n", "x\r", "x\t", "*x", "x y", ".", "x\x00"):
                record = fixture(SCHEMA["$defs"][kind])
                record[field] = value
                with self.subTest(kind=kind, value=repr(value)), self.assertRaises(ProtocolError):
                    validate_record(kind, record)
        trial = fixture(SCHEMA["$defs"]["trial"])
        trial["ordinal"] = True
        with self.assertRaises(ProtocolError):
            validate_record("trial", trial)
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["matrix"][0]["boot"] = True
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest)

    def test_missing_host_and_summary_fields(self):
        for field in ("memory_peak_bytes", "memory_max_bytes", "swap_max_bytes"):
            sample = fixture(SCHEMA["$defs"]["sample"])
            del sample["metrics"][field]
            with self.assertRaises(ProtocolError):
                validate_record("sample", sample)
        for field in ("preconditions", "baseline_metrics", "peak_metrics", "delta_metrics", "phase_durations_ns", "tripwire_results"):
            trial = fixture(SCHEMA["$defs"]["trial"])
            trial[field] = {}
            with self.assertRaises(ProtocolError):
                validate_record("trial", trial)

    def test_manifest_rejects_extra_library_and_missing_sources(self):
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["library_manifest"]["extra"] = copy.deepcopy(manifest["library_manifest"]["libcuda"])
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest)
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["source_artifact_hashes"] = {}
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest)
    def test_all_four_valid_shapes_and_required_fields(self):
        for kind in ("manifest", "event", "sample", "trial"):
            value = fixture(SCHEMA["$defs"][kind])
            validate_record(kind, value, SCHEMA)
            for field in value:
                malformed = copy.deepcopy(value)
                del malformed[field]
                with self.subTest(kind=kind, missing=field), self.assertRaises(ProtocolError):
                    validate_record(kind, malformed, SCHEMA)

    def test_integer_bytes_and_timestamps(self):
        event = fixture(SCHEMA["$defs"]["event"])
        for value in (1.5, "1", True, -1):
            event["monotonic_raw_ns"] = value
            with self.assertRaises(ProtocolError):
                validate_record("event", event, SCHEMA)
        sample = fixture(SCHEMA["$defs"]["sample"])
        sample["metrics"]["memory_current_bytes"] = 1.5
        with self.assertRaises(ProtocolError):
            validate_record("sample", sample, SCHEMA)

    def test_explicit_unavailable_observation(self):
        sample = fixture(SCHEMA["$defs"]["sample"])
        sample.update(available=False, unavailable_reason="QUERY_FAILED", metrics=None)
        validate_record("sample", sample, SCHEMA)
        sample["unavailable_reason"] = None
        with self.assertRaises(ProtocolError):
            validate_record("sample", sample, SCHEMA)

    def test_nested_missing_fields_and_wrong_library_hash(self):
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        del manifest["host_identity"]["kernel"]
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest, SCHEMA)
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["library_manifest"]["libcuda"]["sha256"] = "label-not-a-hash"
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest, SCHEMA)

    def test_unauthorized_scope_and_policy_drift(self):
        for field, value in (("tranche_b_authorized", True), ("canonical_head", "0" * 40)):
            manifest = fixture(SCHEMA["$defs"]["manifest"])
            manifest[field] = value
            with self.assertRaises(ProtocolError):
                validate_record("manifest", manifest, SCHEMA)
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["thresholds"]["worker_memory_max_bytes"] += 1
        with self.assertRaises(ProtocolError):
            validate_record("manifest", manifest, SCHEMA)

    def test_unknown_fields_versions_calls_streams(self):
        for kind, field, value in (("event", "call_name", "cudaMemGetInfo"),
                                   ("event", "schema_version", "v2"),
                                   ("sample", "stream", "nvidia-smi"),
                                   ("trial", "extra", 0)):
            record = fixture(SCHEMA["$defs"][kind])
            record[field] = value
            with self.assertRaises(ProtocolError):
                validate_record(kind, record, SCHEMA)

    def test_seal_bytes_and_no_recursive_checksum(self):
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        event = fixture(SCHEMA["$defs"]["event"])
        event["event_type"] = "EVIDENCE_SEALED"
        sample = fixture(SCHEMA["$defs"]["sample"])
        trial = fixture(SCHEMA["$defs"]["trial"])
        trial["verdict"] = "invalid"
        for key in ("pid", "process_start_ticks", "cgroup_path", "cgroup_inode", "gpu_uuid", "boot_id"):
            event[key] = trial["identity_binding"][key]
        trial["boot_id"] = event["boot_id"]
        sample["boot_id"] = event["boot_id"]
        with self.assertRaises(ProtocolError):
            evidence_bundle(manifest, [event], [sample], [trial], "Tranche B remains CLOSED.\n")
        trial["trial_id"] = "../outside"
        with self.assertRaises(ProtocolError):
            evidence_bundle(manifest, [event], [sample], [trial], "report")

    def test_policy_schema_consistency(self):
        self.assertEqual(SCHEMA["$defs"]["thresholds"]["properties"]["max_sample_gap_ns"]["const"], p.MAX_SAMPLE_GAP_NS)
        self.assertEqual(SCHEMA["$defs"]["timeouts"]["properties"]["worker_ns"]["const"], p.TIMEOUTS.worker_ns)


class CampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.campaign = Campaign("run1")
        cls.trials = []
        previous = None
        now = 0
        for index, slot in enumerate(p.trial_matrix(), 1):
            clock = Clock(now)
            ident = replace(identity(), boot_id="boot-" + str(slot["boot"]), pid=200 + index,
                            process_start_ticks=500 + index, cgroup_path="/workers/trial" + str(index))
            trial_id = "trial" + str(index)
            source = Samples(clock, ident, "run1", trial_id)
            observer = replace(ident, pid=124, process_start_ticks=346, cgroup_path="/observers/run1")
            sampler = Sampler(source, ident, observer, "run1", trial_id, clock)
            frames = []
            for n in range(601):
                sampler.tick()
                frames.append((clock(), copy.deepcopy(source.values)))
                if n != 600:
                    clock.advance(p.SAMPLE_PERIOD_NS)
            ports = Ports(clock)
            ports.observed = ident
            controller = Controller("run1", trial_id, ident, slot["handle_order"], ports, sampler, clock)
            proof = dict.fromkeys(p.PRECONDITIONS, True)
            proof["library_stat_ns"] = clock()
            cls.campaign.admit(controller, {"boot": slot["boot"], "ordinal": slot["ordinal"], "state": slot["state"],
                "boot_id": ident.boot_id, "observed_ns": clock(), "no_prior_experiment": slot["ordinal"] == 1,
                "previous_trial_id": None if slot["ordinal"] == 1 else previous})
            controller.prepare(frames, proof, libraries())
            controller.release()
            def advance(ns):
                for _ in range(ns // p.SAMPLE_PERIOD_NS):
                    clock.advance(p.SAMPLE_PERIOD_NS)
                    controller.tick()
            result = run(slot["handle_order"], Vendor(), controller.worker_event, advance, clock=clock)
            if result["exit_code"] != 0:
                raise AssertionError(result)
            ports.exit_status = 0
            source.values["worker_cgroup"].update(populated=False, pids=[], cgroup_events={"populated": 0, "frozen": 0})
            source.values["worker_process"]["alive"] = False
            source.values["gpu_process"].update(present=False, used_bytes=0)
            advance(2_200_000_000)
            cls.trials.append(controller.complete_attempt())
            now, previous = clock(), trial_id
        cls.manifest = fixture(SCHEMA["$defs"]["manifest"])
        cls.manifest.update(run_id="run1", library_manifest=libraries(), expansion_authorization_reference=None)

    def test_complete_campaign_seals_and_hashes_every_artifact(self):
        bundle = self.campaign.seal(self.manifest)
        self.assertEqual(len(bundle), 17)
        journal = [json.loads(line) for line in bundle["events.jsonl"].splitlines()]
        self.assertEqual(journal[-1]["event_type"], "EVIDENCE_SEALED")
        validate_record("campaign_seal", journal[-1])
        self.assertEqual(len(journal[-1]["trial_ids"]), 12)
        self.assertEqual(sum(e["event_type"] == "EVIDENCE_SEALED" for e in journal), 1)
        for line in bundle["sha256sums.txt"].decode().splitlines():
            digest, path = line.split("  ")
            self.assertEqual(hashlib.sha256(bundle[path]).hexdigest(), digest)
        self.assertNotIn("sha256sums.txt", bundle["sha256sums.txt"].decode())
        self.assertIn("production_admission_authorized", bundle["report.md"].decode())
        with self.assertRaises(ProtocolError):
            self.campaign.seal(self.manifest)

    def test_minimal_report_and_incomplete_matrix_rejected(self):
        events = [e for t in self.trials for e in t["evidence"]["events"]]
        samples = [s for t in self.trials for s in t["evidence"]["samples"]]
        with self.assertRaises(ProtocolError):
            evidence_bundle(self.manifest, events, samples, self.trials[:-1], "report")
        with self.assertRaises(ProtocolError):
            evidence_bundle(self.manifest, events, samples, self.trials, "report")

    def test_raw_gap_and_summary_tampering_rejected(self):
        for field in ("maximum_sample_gap_ns", "startup_duration_ns"):
            bad = copy.deepcopy(self.trials[0])
            bad[field]["value"] += 1
            with self.assertRaises(ProtocolError):
                validate_attempt(bad)
        bad = copy.deepcopy(self.trials[0])
        bad["evidence"]["observation_raw"][0]["eligible"] = False
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)

    def test_matrix_order_and_expansion_authority(self):
        with self.assertRaises(ProtocolError):
            Campaign("run1", expanded=True)
        campaign = Campaign("run1", expanded=True, expansion_authorization="chair-approved-expansion")
        self.assertEqual(len(campaign.matrix), 18)
        stopped = Campaign("run1")
        stopped.taint("IDENTITY")
        with self.assertRaises(ProtocolError):
            stopped.admit(None, {})

    def test_campaign_rejects_wrong_order_and_warm_custody(self):
        clock = Clock()
        controller = SimpleNamespace(state="NEW", campaign=None, run_id="run1", order="LB", identity=identity(), clock=clock)
        custody = dict(boot=1, ordinal=1, state="boot-cold", boot_id="boot-1", observed_ns=0,
                       no_prior_experiment=True, previous_trial_id=None)
        campaign = Campaign("run1")
        with self.assertRaises(ProtocolError):
            campaign.admit(controller, custody)
        controller.order = "BL"
        wrong = dict(custody, ordinal=2, state="same-boot-warm")
        with self.assertRaises(ProtocolError):
            campaign.admit(controller, wrong)
        campaign.admit(controller, custody)
        with self.assertRaises(ProtocolError):
            Campaign("run1").admit(controller, custody)

    def test_omitted_stream_and_changed_baseline_cannot_be_reconstructed_as_valid(self):
        bad = copy.deepcopy(self.trials[0])
        bad["evidence"]["samples"] = [s for s in bad["evidence"]["samples"] if s["stream"] != "gpu_process"]
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)
        bad = copy.deepcopy(self.trials[0])
        bad["evidence"]["baseline_frames"][0][1]["worker_cgroup"]["memory_current_bytes"] += 1
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)

    def bundle_for(self, trials):
        return evidence_bundle(self.manifest,
            [e for t in trials for e in t["evidence"]["events"]],
            [s for t in trials for s in t["evidence"]["samples"]],
            trials, render_report(self.manifest, trials))

    def test_successor_release_before_predecessor_completion_rejected(self):
        trials = copy.deepcopy(self.trials)
        shift_attempt(trials[1], trials[1]["evidence"]["sampler_started_ns"])
        validate_attempt(trials[1])  # Individually consistent; campaign custody is wrong.
        with self.assertRaises(ProtocolError):
            self.bundle_for(trials)

    def test_successor_admission_before_residual_clearance_rejected(self):
        trials = copy.deepcopy(self.trials)
        predecessor_end = trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
        release = next(e["monotonic_raw_ns"] for e in trials[1]["evidence"]["events"] if e["event_type"] == "RELEASE")
        shift_attempt(trials[1], release - predecessor_end)
        trials[1]["admitted_ns"] = predecessor_end - 1
        trials[1]["custody"]["observed_ns"] = predecessor_end - 1
        validate_attempt(trials[1])
        with self.assertRaises(ProtocolError):
            self.bundle_for(trials)

    def test_individually_valid_successor_baseline_overlaps_despite_late_release(self):
        trials = copy.deepcopy(self.trials)
        shift_attempt(trials[1], 1)
        validate_attempt(trials[1])
        completed = trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
        self.assertGreater(trials[1]["admitted_ns"], completed)
        self.assertLess(trials[1]["evidence"]["sampler_started_ns"], completed)
        with self.assertRaises(ProtocolError):
            self.bundle_for(trials)

    def test_successor_release_rechecks_lifecycle(self):
        end = self.trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
        campaign, controller, custody, frames = self.successor(end)
        campaign.admit(controller, custody)
        proof = dict.fromkeys(p.PRECONDITIONS, True)
        proof["library_stat_ns"] = controller.clock()
        controller.prepare(frames, proof, libraries())
        controller.sampler.started_ns = end - 1
        with self.assertRaises(ProtocolError):
            controller.release()
        self.assertNotIn("release", controller.ports.actions)
        self.assertTrue(campaign.stopped)

    def test_successor_lifecycle_overlap_rejected_by_sealing(self):
        from tools.decision_0009.startup_characterization.controller import check_campaign_order
        for field in ("sampler", "baseline", "receipt"):
            with self.subTest(field=field):
                trials = copy.deepcopy(self.trials)
                end = trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
                ev = trials[1]["evidence"]
                if field == "sampler":
                    ev["sampler_started_ns"] = end - 1
                elif field == "baseline":
                    ev["baseline_frames"][0][0] = end - 1
                else:
                    ev["observation_raw"][0]["received_ns"] = end - 1
                with self.assertRaises(ProtocolError):
                    check_campaign_order(self.manifest, trials)
                with self.assertRaises(ProtocolError):
                    self.bundle_for(trials)

    def successor(self, start):
        prior = self.trials[0]
        clock = Clock(start)
        ident = replace(identity(), pid=300, process_start_ticks=600, cgroup_path="/workers/successor")
        source = Samples(clock, ident, "run1", "successor")
        sampler = Sampler(source, ident, replace(ident, pid=124, process_start_ticks=346,
                          cgroup_path="/observers/run1"), "run1", "successor", clock)
        frames = []
        for n in range(601):
            sampler.tick()
            frames.append((clock(), copy.deepcopy(source.values)))
            if n != 600:
                clock.advance(p.SAMPLE_PERIOD_NS)
        ports = Ports(clock)
        ports.observed = ident
        controller = Controller("run1", "successor", ident, "LB", ports, sampler, clock)
        campaign = Campaign("run1")
        campaign.attempts = [copy.deepcopy(prior)]
        campaign.boot_ids = {1: "boot-1"}
        custody = dict(boot=1, ordinal=2, state="same-boot-warm", boot_id="boot-1", observed_ns=clock(),
                       no_prior_experiment=False, previous_trial_id=prior["trial_id"])
        return campaign, controller, custody, frames

    def test_successor_live_admission_rejects_early_sampler_or_receipt(self):
        end = self.trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
        for defect in ("sampler", "receipt"):
            with self.subTest(defect=defect):
                campaign, controller, custody, _ = self.successor(end - 1 if defect == "sampler" else end)
                if defect == "receipt":
                    controller.sampler.raw_records[0]["received_ns"] = end - 1
                with self.assertRaises(ProtocolError):
                    campaign.admit(controller, custody)
                self.assertNotIn("release", controller.ports.actions)

    def test_successor_live_preparation_rechecks_baseline_and_observations(self):
        end = self.trials[0]["evidence"]["events"][-1]["monotonic_raw_ns"]
        for defect in ("baseline", "receipt", "sampler", None):
            with self.subTest(defect=defect):
                campaign, controller, custody, frames = self.successor(end)
                campaign.admit(controller, custody)
                if defect == "baseline":
                    frames[0] = (end - 1, frames[0][1])
                elif defect == "receipt":
                    controller.sampler.raw_records[0]["received_ns"] = end - 1
                elif defect == "sampler":
                    controller.sampler.started_ns = end - 1
                proof = dict.fromkeys(p.PRECONDITIONS, True)
                proof["library_stat_ns"] = controller.clock()
                if defect:
                    with self.assertRaises(ProtocolError):
                        controller.prepare(frames, proof, libraries())
                    self.assertNotIn("release", controller.ports.actions)
                else:
                    controller.prepare(frames, proof, libraries())
                    controller.release()
                    self.assertEqual(controller.state, "RUNNING")

    def test_sequential_boot_local_epochs_and_complete_report(self):
        trials = copy.deepcopy(self.trials)
        offsets = {t["boot"]: t["evidence"]["sampler_started_ns"] for t in trials if t["ordinal"] == 1}
        for trial in trials:
            shift_attempt(trial, offsets[trial["boot"]])
        bundle = self.bundle_for(trials)
        report = json.loads(bundle["report.md"].decode().split("\n\n", 1)[1])
        self.assertEqual(report["acceptance"], {"matrix_complete": True, "all_attempts_valid": True, "raw_evidence_crosschecked": True})

    def test_failed_cleanup_comparison_without_startup_duration(self):
        case = protocol.ControllerTests()
        case.setUp()
        failed = case.finish_worker("cublasLtCreate")
        self.assertFalse(failed["startup_duration_ns"]["available"])
        report = json.loads(render_report(self.manifest, [failed, self.trials[1]]).split("\n\n", 1)[1])
        for comparison in report["review"].values():
            self.assertIn("ORDER_FAILURE_CLEANUP_DIFFERENCE", comparison["reasons"])
            self.assertTrue(comparison["missing_measurements"])
            self.assertFalse(comparison["expansion_authorized"])
        self.assertFalse(report["acceptance"]["matrix_complete"])
        self.assertFalse(report["acceptance"]["all_attempts_valid"])


class ReplayCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        case = protocol.ControllerTests()
        case.setUp()
        cls.trial = case.finish_worker()

    def test_absent_dwell_gpu_rejected_after_consistent_reconstruction(self):
        bad = copy.deepcopy(self.trial)
        for sample in bad["evidence"]["samples"]:
            if sample["stream"] == "gpu_process":
                sample["metrics"].update(present=False, used_bytes=0)
        for record in bad["evidence"]["observation_raw"]:
            if record["raw"]["stream"] == "gpu_process":
                record["raw"]["metrics"].update(present=False, used_bytes=0)
        for _, frame in bad["evidence"]["baseline_frames"]:
            frame["gpu_process"].update(present=False, used_bytes=0)
        bad.update(reconstruct(bad))
        with self.assertRaisesRegex(ProtocolError, "GPU.*dwell|dwell.*GPU"):
            validate_attempt(bad)

    def test_worker_receipt_timing_and_raw_order_rejected(self):
        for mutation in ("zero", "before", "stale", "future", "missing", "reordered", "extra"):
            bad = copy.deepcopy(self.trial)
            journal = bad["evidence"]["worker_raw"]
            record = journal[0]
            if mutation == "zero":
                for record in journal:
                    record["received_ns"] = 0
            elif mutation == "before":
                record["received_ns"] = record["raw"]["monotonic_raw_ns"] - 1
            elif mutation == "stale":
                record["received_ns"] = record["raw"]["monotonic_raw_ns"] + p.PRE_RELEASE_AGE_NS + 1
            elif mutation == "future":
                record["received_ns"] = bad["evidence"]["events"][-1]["monotonic_raw_ns"] + 1
            elif mutation == "missing":
                del record["received_ns"]
            elif mutation == "reordered":
                journal[0], journal[1] = journal[1], journal[0]
                for index, record in enumerate(journal, 1):
                    record["sequence"] = index
            else:
                journal.append(copy.deepcopy(journal[-1]))
                journal[-1]["sequence"] = len(journal)
            bad.update(reconstruct(bad))
            with self.subTest(mutation=mutation), self.assertRaises(ProtocolError):
                validate_attempt(bad)

    def test_observer_journal_correspondence_cannot_be_repaired_by_summaries(self):
        for mutation in ("raw_only", "ineligible", "future_receipt"):
            bad = copy.deepcopy(self.trial)
            record = bad["evidence"]["observation_raw"][-1]
            if mutation == "raw_only":
                record["raw"]["metrics"]["query_latency_ns"] += 1
            elif mutation == "ineligible":
                record["eligible"] = False
            else:
                record["received_ns"] = bad["evidence"]["events"][-1]["monotonic_raw_ns"] + 1
            bad.update(reconstruct(bad))
            with self.subTest(mutation=mutation), self.assertRaises(ProtocolError):
                validate_attempt(bad)

    def test_release_cannot_use_samples_received_after_release(self):
        bad = copy.deepcopy(self.trial)
        release = next(e["monotonic_raw_ns"] for e in bad["evidence"]["events"] if e["event_type"] == "RELEASE")
        for record in bad["evidence"]["observation_raw"]:
            if record["raw"]["sample_end_monotonic_raw_ns"] >= release - p.PRE_RELEASE_AGE_NS:
                record["received_ns"] = max(record["received_ns"], release + 1)
        bad.update(reconstruct(bad))
        with self.assertRaisesRegex(ProtocolError, "receipt|available.*release"):
            validate_attempt(bad)

    def test_identity_gate_cannot_use_snapshot_received_after_gate(self):
        bad = copy.deepcopy(self.trial)
        release = next(e["monotonic_raw_ns"] for e in bad["evidence"]["events"] if e["event_type"] == "RELEASE")
        for record in bad["evidence"]["identity_raw"]:
            record["received_ns"] = max(record["received_ns"], release + 1)
        for record in bad["evidence"]["identity_records"]:
            record["received_ns"] = max(record["received_ns"], release + 1)
        bad.update(reconstruct(bad))
        with self.assertRaisesRegex(ProtocolError, "identity.*checkpoint|identity.*receipt"):
            validate_attempt(bad)

    def test_proof_numeric_types_and_closed_fields(self):
        for value in (True, False, -1, 1.5, "1", None, {}, []):
            bad = copy.deepcopy(self.trial)
            bad["evidence"]["proof"]["library_stat_ns"] = value
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                validate_attempt(bad)
        bad = copy.deepcopy(self.trial)
        bad["evidence"]["proof"]["undeclared_authority"] = True
        with self.assertRaises(ProtocolError):
            validate_attempt(bad)

    def test_incomplete_report_flags_are_derived(self):
        manifest = fixture(SCHEMA["$defs"]["manifest"])
        manifest["run_id"] = "run1"
        manifest["library_manifest"] = libraries()
        report = json.loads(render_report(manifest, [self.trial]).split("\n\n", 1)[1])
        self.assertFalse(report["acceptance"]["matrix_complete"])
        self.assertTrue(report["acceptance"]["all_attempts_valid"])
        self.assertTrue(report["acceptance"]["raw_evidence_crosschecked"])
        bad = copy.deepcopy(self.trial)
        bad["evidence"]["worker_raw"][0]["received_ns"] = 0
        report = json.loads(render_report(manifest, [bad]).split("\n\n", 1)[1])
        self.assertFalse(report["acceptance"]["raw_evidence_crosschecked"])


if __name__ == "__main__":
    unittest.main()
