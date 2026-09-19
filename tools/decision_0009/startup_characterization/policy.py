"""Frozen Decision 0009 startup characterization policy; no execution authority."""

from dataclasses import dataclass
import time
import re
from fractions import Fraction
from statistics import median

SCHEMA_VERSION = "decision-0009-startup/v1"
CANONICAL_BRANCH = "m1-live-adapter-dev"
CANONICAL_HEAD = "724700217f8d7183757768fb2a856872b64a3cf3"
TRANCHE_A_DIGEST = "726cfbf2107f542465169e4ca8704aabc98a9588ef577744c45fff05e45e4c16"
GPU_UUID = "GPU-beba5a2f-9130-d279-5639-9ffda0d4e464"
GIB = 1 << 30
MIB = 1 << 20
SECOND_NS = 1_000_000_000
MILLISECOND_NS = 1_000_000
WORKER_MEMORY_MAX_BYTES = 2 * GIB
WORKER_SWAP_MAX_BYTES = 0
WORKER_DELTA_MAX_BYTES = GIB
GPU_PROCESS_MAX_BYTES = GIB
GPU_CAUTION_BYTES = 512 * MIB
OBSERVER_MAX_BYTES = 512 * MIB
UNATTRIBUTED_MAX_BYTES = 256 * MIB
BASELINE_GPU_DRIFT_BYTES = 256 * MIB
BASELINE_NS = 60 * SECOND_NS
SAMPLE_PERIOD_NS = 100 * MILLISECOND_NS
MAX_SAMPLE_GAP_NS = 250 * MILLISECOND_NS
PRE_RELEASE_AGE_NS = 150 * MILLISECOND_NS
IDENTITY_AGE_NS = 100 * MILLISECOND_NS
LIBRARY_STAT_AGE_NS = 60 * SECOND_NS
DWELL_NS = 2 * SECOND_NS
DWELL_TOLERANCE_NS = 100 * MILLISECOND_NS
DWELL_MAX_NS = 3 * SECOND_NS
MIN_DWELL_SAMPLES = 10
RESIDUAL_CLEAR_NS = 2 * SECOND_NS
RESIDUAL_CLEAR_SAMPLES = 3
MAPPING_ORDER = ("libcudart", "libcublasLt", "libcublas")
CALL_ALLOWLIST = frozenset(("cudaSetDevice", "cublasCreate_v2",
                          "cublasDestroy_v2", "cublasLtCreate", "cublasLtDestroy"))
CREATE_ORDER = {"BL": ("cublasCreate_v2", "cublasLtCreate"),
                "LB": ("cublasLtCreate", "cublasCreate_v2")}
DESTROY_FOR = {"cublasCreate_v2": "cublasDestroy_v2",
               "cublasLtCreate": "cublasLtDestroy"}
INITIAL_MATRIX = (("BL", "LB", "BL"), ("LB", "BL", "LB"),
                  ("BL", "BL", "LB"), ("LB", "LB", "BL"))
EXPANSION_MATRIX = (("BL", "LB", "LB"), ("LB", "BL", "BL"))
BARRIERS = ("BOOT_BASELINE_VALID", "OBSERVER_ARMED", "WORKER_READY", "RELEASE",
            "STARTUP_COMPLETE", "DWELL_COMPLETE", "CLEANUP_RELEASE",
            "CLEANUP_COMPLETE", "PROCESS_REAPED", "RESIDUAL_CLEAR", "EVIDENCE_SEALED")
STREAMS = ("worker_cgroup", "worker_process", "gpu_device", "gpu_process",
           "machine_reserve", "observer_cgroup")


@dataclass(frozen=True)
class Timeouts:
    mapping_ns: int = 5 * SECOND_NS
    mapping_total_ns: int = 10 * SECOND_NS
    device_ns: int = 10 * SECOND_NS
    create_ns: int = 10 * SECOND_NS
    destroy_ns: int = 5 * SECOND_NS
    worker_ns: int = 45 * SECOND_NS
    cooperative_ns: int = 5 * SECOND_NS
    term_ns: int = 5 * SECOND_NS
    kill_ns: int = 5 * SECOND_NS


TIMEOUTS = Timeouts()

TOKEN_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$(?![\s\S])"
LIBRARY_FAMILIES = (*MAPPING_ORDER, "libcuda")
LIBRARY_ATTRIBUTES = ("path", "device", "inode", "size_bytes", "mtime_ns",
                      "elf_build_id", "soname", "package_version", "sha256")
PRECONDITIONS = ("cold_or_warm_proven", "persistence_unchanged", "desktop_stable",
                 "no_unexpected_compute", "target_libraries_absent", "pidfd_or_start_guard",
                 "source_hashes_verified", "environment_clean", "library_stats_match")
PHASES = (*MAPPING_ORDER, "cudaSetDevice", *CREATE_ORDER["BL"],
          *DESTROY_FOR.values(), "dwell")
TRIPWIRES = ("WORKER_DELTA", "WORKER_LIMIT_OR_SWAP", "WORKER_MEMORY_EVENT",
            "GPU_PROCESS", "UNATTRIBUTED_DEVICE", "OBSERVER_MEMORY", "HOST_RESERVE",
            "DEVICE_RESERVE", "MACHINE_PRESSURE", "WORKER_LOST")


@dataclass(frozen=True)
class ExpansionPolicy:
    gpu_caution_bytes: int = GPU_CAUTION_BYTES
    spread_percent: int = 25
    median_difference_percent: int = 20
    duration_difference_ns: int = 25 * MILLISECOND_NS
    memory_difference_bytes: int = 32 * MIB
    baseline_difference_bytes: int = 512 * MIB
    baseline_difference_percent: int = 5
    ledger_disagreement_bytes: int = 256 * MIB


EXPANSION = ExpansionPolicy()


def token(value):
    if type(value) is not str or re.fullmatch(TOKEN_PATTERN, value) is None:
        raise ValueError("unsafe evidence identifier")
    return value


def evaluate_expansion(rows):
    """Exact rational comparisons; lower median is the relative denominator.

    rows contain boot, state, order, duration_ns, memory_bytes, baseline_bytes,
    gpu_bytes, ledger_disagreement_bytes, outcome and cleanup. No launch authority.
    A zero denominator triggers only for a strictly positive difference.
    """
    fields = {"boot", "state", "order", "duration_ns", "memory_bytes", "baseline_bytes",
              "gpu_bytes", "ledger_disagreement_bytes", "outcome", "cleanup"}
    numeric = fields - {"boot", "state", "order", "outcome", "cleanup"}
    for row in rows:
        if set(row) != fields or row["state"] not in ("boot-cold", "same-boot-warm") or row["order"] not in CREATE_ORDER:
            raise ValueError("comparison row")
        if type(row["boot"]) is not int or any(row[k] is not None and (type(row[k]) is not int or row[k] < 0) for k in numeric):
            raise ValueError("comparison integer")
        if row["boot"] < 1 or row["outcome"] not in ("valid", "invalid", "aborted") or row["cleanup"] not in ("PASS", "FAIL", "UNKNOWN"):
            raise ValueError("comparison outcome")
    reasons = set()
    caution = any(r["gpu_bytes"] is not None and r["gpu_bytes"] >= EXPANSION.gpu_caution_bytes for r in rows)
    if caution:
        reasons.add("GPU_CAUTION")
    med = lambda values: median([Fraction(v) for v in values])
    for field, absolute in (("duration_ns", EXPANSION.duration_difference_ns),
                            ("memory_bytes", EXPANSION.memory_difference_bytes)):
        for state in ("boot-cold", "same-boot-warm"):
            for order in CREATE_ORDER:
                values = [r[field] for r in rows if r["state"] == state and r["order"] == order and r[field] is not None]
                if values and 100 * (max(values) - min(values)) > EXPANSION.spread_percent * med(values):
                    reasons.add("WITHIN_STATE_ORDER_SPREAD")
        for key, label, groups in (("order", "BL_LB_DIFFERENCE", ("BL", "LB")),
                                    ("state", "COLD_WARM_DIFFERENCE", ("boot-cold", "same-boot-warm"))):
            values = [[r[field] for r in rows if r[key] == g and r[field] is not None] for g in groups]
            if all(values):
                a, b = map(med, values)
                if abs(a - b) > absolute and 100 * abs(a - b) > EXPANSION.median_difference_percent * min(a, b):
                    reasons.add(label)
    baselines = [med([r["baseline_bytes"] for r in rows if r["boot"] == b and r["baseline_bytes"] is not None])
                 for b in sorted({r["boot"] for r in rows if r["baseline_bytes"] is not None})]
    if len(baselines) > 1 and max(baselines) - min(baselines) > max(EXPANSION.baseline_difference_bytes, min(baselines) * Fraction(EXPANSION.baseline_difference_percent, 100)):
        reasons.add("CROSS_BOOT_BASELINE")
    if any(r["ledger_disagreement_bytes"] is not None and r["ledger_disagreement_bytes"] > EXPANSION.ledger_disagreement_bytes for r in rows):
        reasons.add("LEDGER_DISAGREEMENT")
    signatures = []
    for order in CREATE_ORDER:
        group = [(r["outcome"], r["cleanup"]) for r in rows if r["order"] == order]
        signatures.append({key: Fraction(group.count(key), len(group)) for key in set(group)})
    if all(signatures) and signatures[0] != signatures[1]:
        reasons.add("ORDER_FAILURE_CLEANUP_DIFFERENCE")
    return {"caution": caution, "expansion_recommended": bool(reasons),
            "reasons": sorted(reasons), "expansion_authorized": False,
            "comparison_evidence_present": bool(rows),
            "missing_measurements": [{"row": i, "fields": sorted(k for k in numeric if row[k] is None)}
                                     for i, row in enumerate(rows, 1) if any(row[k] is None for k in numeric)],
            "production_admission_authorized": False}


def raw_ns():
    """No wall-clock or alternate monotonic-clock fallback on unsupported hosts."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def host_reserve_bytes(total_bytes):
    return max(16 * GIB, (total_bytes + 7) // 8)


def device_reserve_bytes(total_bytes):
    return max(8 * GIB, (total_bytes + 15) // 16)


def trial_matrix(expanded=False):
    if type(expanded) is not bool:
        raise ValueError("expanded must be boolean")
    rows = INITIAL_MATRIX + (EXPANSION_MATRIX if expanded else ())
    return tuple({"boot": boot, "ordinal": ordinal, "handle_order": order,
                  "state": "boot-cold" if ordinal == 1 else "same-boot-warm"}
                 for boot, row in enumerate(rows, 1)
                 for ordinal, order in enumerate(row, 1))


def phase_timeout_ns(name):
    if name in MAPPING_ORDER:
        return TIMEOUTS.mapping_ns
    if name == "cudaSetDevice":
        return TIMEOUTS.device_ns
    if name in CREATE_ORDER["BL"]:
        return TIMEOUTS.create_ns
    if name in DESTROY_FOR.values():
        return TIMEOUTS.destroy_ns
    raise ValueError("unknown phase")
