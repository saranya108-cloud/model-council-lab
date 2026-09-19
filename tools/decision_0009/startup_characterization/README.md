# Decision 0009 startup characterization — F1–F4 correction for Claude Opus re-review

**NOT authorized for Acer execution. Tranche B remains CLOSED.**

This independent Python/ctypes harness characterizes the sub-envelope from the
first explicit CUDA-family library mapping through completion of the second
handle creation. Python startup, baseline collection, the two-second dwell,
destruction, process teardown and evidence sealing are recorded separately.
Nothing imports or changes accepted Tranche A code or evidence.

## Components and integration boundary

- `policy.py`: byte/nanosecond constants, timeouts, matrices, raw monotonic clock.
- `worker.py`: explicit loader and closed call state machine. Importing it has
  no CUDA effect. A future isolated process transport invokes `run` only after
  RELEASE. The real `CtypesBackend` loads libraries only when explicitly called.
- `observer.py`: persistent six-stream sampler, freshness and attribution
  checks, baseline validation, and independent reserve/tripwire evaluation.
- `controller.py`: release gates, worker protocol validation, external watchdog,
  cooperative/TERM/KILL states, reap/residual checks, attempt reconstruction,
  campaign custody/order/taint state, and deterministic campaign evidence bytes.
- `schema-v1.json`: Draft 2020-12 schema; select `$defs.manifest`, `.event`,
  `.sample`, `.trial`, or `.campaign_seal`. The stdlib validator rejects unknown
  schema vocabulary. The final campaign seal is a distinct cross-boot record.

Host operations are injected through `HostPorts` and `SampleBackend`. No Acer
launcher, signal/cgroup-writing adapter, NVML backend or live CLI is included.
These are explicit implementation-review integration obligations, not simulated
runtime proof. Port methods must be nonblocking. A future reviewed adapter must
contain stalled queries in independently supervised processes and transport
worker records through a bounded preallocated, prefaulted status/event buffer.
There is no in-process mechanism capable of interrupting a blocked ctypes call.

The controller must run separately from the worker, receive records in sequence,
and tick at least every 100 ms. Calling the worker synchronously in the controller
would defeat its watchdog and is prohibited for any future live integration.
The sampler and controller retain raw records before validation, including
unavailable samples, backend exception type/stream, and malformed worker records.
These journals are embedded in the completed attempt. Only eligible samples
enter freshness and summary calculations. A failed stream immediately loses its
eligible latest observation; its earlier raw records remain intact.
Identity queries also have a raw journal: receipt time, raw response (including
null or malformed JSON), eligibility and rejection reason. Query exceptions retain
their exception class; non-JSON responses retain an explicit UNSERIALIZABLE marker
and type name. Only independently validated snapshots enter `identity_records`.
Preparation and RELEASE use the post-query receipt as the upper endpoint for the
100 ms observation freshness check: observation <= receipt <= consuming gate.
Receipt-to-gate age is also bounded by 100 ms. RELEASE is timestamped after the
query returns, with sample, library-stat and custody freshness rechecked then.
Thus an identity failure can abort a trial without making its evidence impossible
to finalize. Identity mismatches and malformed preparation responses stop the
owning campaign permanently, even if a later response would match.

## Exact worker behavior

Both variants explicitly load absolute paths with `RTLD_NOW | RTLD_LOCAL`:

1. `libcudart`, resolving `cudaSetDevice`.
2. `libcublasLt`, resolving its create/destroy pair.
3. `libcublas`, resolving its create/destroy pair.

BL calls `cudaSetDevice(0)`, `cublasCreate_v2`, `cublasLtCreate`, dwells with both
handles live, then calls `cublasLtDestroy`, `cublasDestroy_v2`.
LB calls `cudaSetDevice(0)`, `cublasLtCreate`, `cublasCreate_v2`, dwells with both
handles live, then calls `cublasDestroy_v2`, `cublasLtDestroy`.

Those five symbols are the complete application-issued CUDA-family allowlist.
Only successful creates transfer handle ownership. Failed creates stop startup;
successful earlier handles are destroyed in reverse order. Destruction failures
are recorded and never retried; remaining owned handles are still attempted.
Numeric vendor statuses are retained without querying diagnostic strings.

cuBLAS depends on cuBLASLt. BL/LB describes **handle order**, never library order.
Library mapping and symbol resolution are timed together per library. Duplicate
or unadmitted NVIDIA/CUDA mapping identities invalidate the trial. Internal vendor
activity induced by allowed functions is within the measured envelope.

Forbidden: `ctypes.util.find_library`, basename search, `LD_LIBRARY_PATH` fallback,
lazy binding, alternate libraries, explicit `dlclose`, all other CUDA runtime or
driver calls, including `cudaMemGetInfo`, `cudaFree(0)`, `cudaDeviceReset`, version
queries, allocations, streams, events, graphs, modules, kernels, cuBLAS/cuBLASLt
configuration/workspace/heuristic/compute calls, NVIDIA queries in the worker,
GGUF/tokenizer/model access, model loading and inference.
The integration adapter must reject loader environment injection (including
`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`) and independently attest mapped
dependency identities. Absolute top-level paths alone do not pin dependencies.

## Identity, barriers and clocks

Bind boot ID, PID, `/proc/<pid>/stat` start ticks, PID namespace inode,
executable path/inode, dedicated cgroup path/inode/exact membership and GPU UUID
`GPU-beba5a2f-9130-d279-5639-9ffda0d4e464`. Use a pidfd where supported; otherwise
revalidate the complete process start identity before targeting any operation.
The observer and controller must be outside the worker cgroup. GPU ordinal zero
must be bound by `CUDA_VISIBLE_DEVICES` to the exact UUID; record any
`NVIDIA_VISIBLE_DEVICES` and require the same UUID, plus `CUDA_DEVICE_ORDER=PCI_BUS_ID`.

Bind all loaded CUDA/NVIDIA paths, SONAMEs, versions or explicit unavailability,
ELF build IDs, device/inode, size, mtime and SHA-256. Measure full hashes after
the final worker of each boot to avoid deliberately warming library file pages.
Before release, independently compare current stat identity to the manifest.
The manifest has exactly four families: libcudart, libcublasLt, libcublas,
and libcuda. Additional families are rejected; there is no implicit dependency
extension. Every mapping comparison includes path, device, inode, size, mtime,
ELF build ID, SONAME, package version (or explicit unavailability), and SHA-256.

`worker.run` requires injected `mapping_gate` and `terminal_gate` callbacks.
The first gate follows the final mapping CALL_END and precedes cudaSetDevice;
the terminal gate follows all destruction attempts and precedes CLEANUP_COMPLETE.
Both must return exactly True. They supply freshly timestamped observations to
`Controller.verify_mapping`; arbitrary early or duplicate proofs are rejected.
Each proof retains its observation and controller receipt timestamps. Observation
must be at or after the last mapping completion, or the last destruction attempt
at the terminal checkpoint; equality is allowed by the event model. Receipt must
follow observation within the existing 100 ms identity-freshness bound, and precede
the authorized first CUDA call or cleanup-completion event. These bounds are
checked at the live gate and independently during replay.
The future transport must hold the worker at these two checkpoints without
issuing any extra CUDA call. Complete library-byte observation and continuity
must be independently established by that transport. This patch implements no
hash acquisition on the Acer and does not permit hashing to warm cold pages.

Normal barriers are BOOT_BASELINE_VALID → OBSERVER_ARMED → WORKER_READY → RELEASE
→ STARTUP_COMPLETE → DWELL_COMPLETE → CLEANUP_RELEASE → CLEANUP_COMPLETE →
PROCESS_REAPED → RESIDUAL_CLEAR → ATTEMPT_COMPLETE. Only final campaign sealing
adds EVIDENCE_SEALED. Failure paths add ABORT and
ESCALATION; they must not fabricate successful startup/dwell barriers.
All authoritative timestamps use `CLOCK_MONOTONIC_RAW` integer nanoseconds.
Equal timestamps are permitted; decreasing timestamps, future records and
cross-identity records are rejected. Sequence numbers disambiguate equal times.
Worker emission-to-receipt latency uses the existing 150 ms pre-release freshness
bound. Receipt times must be ordered and within the live attempt. Replay checks
the ordered raw/canonical worker correspondence, observer sample correspondence,
and that samples were actually received before the gate that uses them. Successful
empty GPU-process queries remain eligible for baseline/residual observation, but
cannot establish exact-worker attribution during the required dwell observations.

After abort, an already issued call may return and transfer ownership; no new
startup call can begin. Only CLEANUP_RELEASE, the reverse destruction suffix for
owned handles, and CLEANUP_COMPLETE are then accepted. Raw rejected records
remain journaled. Successful cleanup never clears the aborted verdict.

## Observations and limits

The persistent observer collects worker-cgroup metrics, process identity/liveness,
GPU device and per-process metrics, machine reserve, and its own cgroup cost.
Sampling is nominally 100 ms, with a 250 ms maximum gap and 150 ms pre-release
freshness. Process/cgroup revalidation is at most 100 ms old and library stat
evidence at most 60 seconds old. Dwell is 2 seconds ±100 ms, with at least ten
samples per stream. A three-second dwell watchdog is an additional failure bound.
Raw worker-cgroup metrics require memory.current, memory.peak, memory.events,
memory.events.local, memory.swap.current, effective memory.max/memory.swap.max,
cgroup.events (populated/frozen), cgroup.procs (pids), and membership_exact.
The effective configuration readback is also retained independently in the
attempt. Missing fields and contradictory limits/membership invalidate evidence.
Controller identity snapshots retain timestamps and are rechecked during each
live tick as well as at release and both mapping checkpoints.

| Control | Frozen threshold |
|---|---:|
| Worker memory.max / memory.swap.max | 2 GiB / 0 bytes |
| Worker sampled increase | 1 GiB |
| GPU per-process memory | 1 GiB |
| GPU caution band | 512 MiB |
| Observer cgroup memory | 512 MiB |
| Unattributed device increase | 256 MiB |
| Baseline GPU drift over 60 s | 256 MiB |
| Host reserve | max(16 GiB, ceil(MemTotal/8)) |
| Device reserve | max(8 GiB, ceil(device total/16)) |

GiB=2^30 bytes; MiB=2^20 bytes. Thresholds are conservative experiment tripwires,
not measured startup budgets. Sampled GPU use is not preventative enforcement.
Host and GPU ledgers can overlap on GB10 and must not be added as unique physical
consumption. Swap/PSI-full/OOM counter increases veto or abort the trial.

Individual mappings have 5 s limits; combined mapping/resolution 10 s;
cudaSetDevice and each create 10 s; each destroy 5 s; RELEASE-to-exit 45 s.
On failure, request cooperative cleanup for 5 s, TERM for 5 s, then KILL for 5 s.
An unreaped process after this escalation taints the boot. Following an abort,
residual verification shares that same 15 s absolute deadline; reaping does not
restart the budget. Three distinct clear samples spanning two seconds must
establish empty cgroup, dead process and absent GPU PID. A successful normal exit
starts a bounded 15 s residual-observation window. Insufficient clearance evidence
at the deadline taints the boot even if the process has already exited.

## Cold/warm and matrix

Boot-cold requires a new boot ID and documented post-boot custody establishing
that no earlier experimental/application CUDA, cuBLAS, cuBLASLt or model work
ran. The first experimental worker follows a stable 60 s observed baseline.
Driver/display baseline and observer initialization remain recorded; this is
not a claim that observation has no effect on the machine.

Same-boot-warm requires a previously completed, residual-clear startup worker,
a new PID/start tuple and cgroup, and no reused handles or process context.
Driver state and page cache may remain warm. Failed/tainted boots cannot produce
successor trials. Cold/warm custody is an independently supplied precondition;
the controller cannot infer it from an empty GPU-process snapshot.

Do not change persistence mode or desktop configuration. Record them and require
unchanged persistence mode and a stable desktop/process baseline across included
boots. No intentional interactive desktop activity during observation.

| Boot | Cold worker | Warm worker 2 | Warm worker 3 |
|---|---|---|---|
| 1 | BL | LB | BL |
| 2 | LB | BL | LB |
| 3 | BL | BL | LB |
| 4 | LB | LB | BL |
| 5, contingent | BL | LB | LB |
| 6, contingent | LB | BL | BL |

The initial matrix is four boots/twelve workers. Expansion to six/eighteen is
reviewed and separately authorized if any caution-band observation, >25% within
state/order spread, >20% BL/LB or cold/warm median difference exceeding 25 ms or
32 MiB, cross-boot baseline difference exceeding max(512 MiB, 5%), unexplained
ledger disagreement >256 MiB, or order-dependent failure/cleanup difference occurs.
These are report/review criteria; the controller never automatically launches
replacement trials or expansion. Invalid attempts remain in evidence.

`ExpansionPolicy` freezes the complete thresholds in integer bytes, nanoseconds,
and percentages. `evaluate_expansion` uses exact rational medians. The relative
denominator for two medians is the lower median; spread means maximum minus
minimum within a state/order group. A zero denominator triggers only on positive
difference. Cross-boot baseline comparison uses per-boot medians and the larger
of 512 MiB and 5% of the lower baseline. These denominator/spread conventions
make previously implicit arithmetic explicit and require Sol re-review.
Caution is inclusive at 512 MiB; every stated “greater than” comparison is strict.
Outputs separate caution and expansion recommendation, and always deny expansion
and production admission authority. The 2 GiB effective host ceiling is a
preventative cgroup limit; sampled increases/GPU use are observation tripwires;
sampling gaps/freshness are evidence-validity rules, not memory budgets.
The report evaluates memory comparisons independently for worker current/peak,
GPU process/device used bytes, and observer memory; it never combines ledgers.
Order-dependent outcome/cleanup differences compare empirical outcome frequencies.

`Campaign.admit` binds each NEW controller to the next matrix slot **before
`Controller.prepare`**, with fresh boot custody and retained `admitted_ns`.
Unowned controllers cannot prepare. Preparation failures are sticky aborts and
taint the campaign; replacement controllers and successors cannot take its slot.
Cold slots require a unique boot and no prior experimental
work. Warm slots require the preceding valid, residual-clear attempt, a new PID
and cgroup, and the same boot. Any controller abort stops the campaign permanently.
Restoring an identity cannot permit release retry or a successor. An expanded
campaign requires its separate nonempty authorization reference, using the same
safe ASCII token grammar as evidence identifiers. Boolean, numeric, empty,
whitespace-only or structured references are rejected at construction. This
records **claimed authority only**: the future Acer adapter must bind the reference
to actual Human Chair authorization for the exact execution scope. A recommendation
alone cannot instantiate expanded authority.
Admission, preparation, RELEASE and final replay/sealing require a valid
predecessor with RESIDUAL_CLEAR and ATTEMPT_COMPLETE on the same boot. The
successor sampler start, first baseline frame and first observation receipt must
all be at or after predecessor ATTEMPT_COMPLETE; admission and RELEASE alone do
not establish separation. Preparation and RELEASE recheck the lifecycle evidence.
The future Acer adapter must additionally prove that the successor process was
spawned after predecessor reaping; the core has no process-spawn-time witness.
Boot ordinals remain ordered; monotonic epochs from different boots are never
compared.

## Evidence and review

Artifacts: `manifest.json`, `events.jsonl`, `samples.jsonl`, one
`trials/<trial-id>.json` per attempt, `report.md`, and `sha256sums.txt`.
`Controller.complete_attempt` produces an attempt with ATTEMPT_COMPLETE,
including all raw journals and explicit unavailable metrics. If final replay or
same-boot cross-check validation rejects it, completion retains the original
journals and a structured `replay_validation_error` (exception type and message),
sets verdict `invalid` with `REPLAY_VALIDATION_FAILURE`, permanently stops the
campaign and finishes its active slot. The invalid attempt remains serializable
and reportable, but cannot pass replay, enable a successor or be sealed. Successful
replay leaves `replay_validation_error` null. Validation failure is never promoted
to successful completion.
It does not emit EVIDENCE_SEALED. Invalid/aborted attempts are retained by the
campaign, which remains incomplete/tainted and cannot seal accepted evidence.
`Campaign.seal` and `evidence_bundle` require exactly the declared matrix in order,
valid attempts, unique custody/worker bindings, and a report derived from the
validated evidence. There is no replacement/retry path to erase a failed slot.

Every summary has closed required keys. Calls, phase durations, startup duration,
baseline/peak/delta/minimum metrics, gaps, preconditions, tripwires, cleanup and
residual results are reconstructed from retained events and samples. Baseline
frames are bound before live baseline validation and by the same check in replay.
For each stream and frame timestamp, the latest eligible accepted sample at or
before that timestamp must match exactly; equal sample timestamps use journal
order. Frame-to-sample age and observation-to-receipt latency are at most 150 ms,
and receipt must precede the preparation gate. Fabricated, future, stale,
unavailable or mismatched frames cannot authorize preparation. Replay checks observation identity,
sequencing, timestamps, mapping checkpoints, dwell and residual coverage.
Baseline metrics are the last observed pre-release baseline; peak/minimum metrics
cover RELEASE through PROCESS_REAPED, and deltas are peak minus baseline (signed).
No absent measurement is replaced by zero. Accepted host peaks retain the actual
memory.peak counter separately from the sampled memory.current peak.
The preparation proof is a closed object containing the declared boolean
preconditions and a nonnegative exact-integer `library_stat_ns`; booleans are never
accepted as numeric timestamps. An unavailable proof remains null in an aborted
attempt and cannot establish a valid attempt.

`render_report` generates the complete structured report, including scope,
source/host/software/library identities, authorization, matrix, all summaries,
custody, policy comparisons, criteria and observation limitations. An arbitrary
string cannot substitute for this report. Reports also support invalid, aborted and
incomplete campaigns: unavailable measurements remain explicit, numeric policy
comparisons use only available measurements, and outcome/cleanup comparisons do
not depend on successful timing. Each comparison lists missing measurements;
absence of a trigger with missing evidence is not a pass. Empty reports carry no
comparison evidence. Acceptance flags are derived from attempt validation and
campaign custody checks, and validation failures are reported explicitly.
Reporting never grants accepted sealing or execution authority. The seal binds
every attempt ID and its SHA-256; it has no cross-boot monotonic timestamp because
CLOCK_MONOTONIC_RAW epochs from distinct boots cannot be globally ordered.
All bytes are returned in memory without writing them. A later authorized
publisher must create exclusively, never overwrite, and independently read back
every artifact. Checksums cover every artifact except the checksum index itself.
No record may change after sealing. Schema validity is not semantic acceptance.
Identifiers allow only ASCII letters/digits followed by letters/digits/underscore/
hyphen (at most 96 characters). Integer checks exclude Python booleans.

The report must include scope/exclusions, canonical HEAD and source hashes,
authorization, complete host/software/boot/library identity, cold/warm custody,
persistence/desktop observations, all valid/invalid/aborted attempts, each phase
timing, independent ledger baselines/peaks/deltas, minimum reserves, largest gaps,
cleanup/residual results, BL/LB and cold/warm comparisons, every deviation and
missing datum, observer effects, sampling limitations and criterion-by-criterion
acceptance. Explicitly state that no GGUF was accessed and Tranche B stayed closed.

Completion requires the approved balanced matrix, all identity bindings, exact
call order, complete timely observations, no hard-tripwire/reserve/timeout/OOM/
swap failure, residual clearance and validated immutable evidence. Startup
characterization does not prove production admission or any model/compute bound.

## Authorization boundary and local validation

This patch authorizes no live operation. Acer copy/deployment, execution, NVML
queries, cgroup changes/removal, signals, boots, installation, persistence/desktop
changes, evidence publication and contingent expansion require specific Human
Chair authorization. Git mutation requires separate authorization. GGUF/model
work and Tranche B remain outside this procedure even after its acceptance.

Offline tests use in-memory fakes only. From the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest discover -s tests/decision_0009 -p 'test_startup_characterization_*.py' -v
```

This command installs nothing, launches no workers, writes no caches/evidence,
loads no CUDA/NVML library, sends no signals and performs no cgroup operation.
Stop for Claude Opus focused F1–F4 re-review. **Tranche B remains CLOSED.**
