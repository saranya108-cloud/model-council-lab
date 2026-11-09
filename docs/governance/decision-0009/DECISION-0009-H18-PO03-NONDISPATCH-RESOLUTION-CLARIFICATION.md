# Decision 0009 — H18 §3.2 / H18-PO-03 non-dispatch-resolution clarification

**Recorded:** November 9, 2026

**Human Chair:** Amy

**Scope:** Recording of architectural adoption only; three localized operative edits.

**Read-only repository checkpoint:** `m1-live-adapter-dev` at `f212dd18b40c15d759197f73104e80cbc77cd1fe`.

## Adoption and independent review

The Human Chair architecturally adopted the exact Astra / OpenAI-authored narrow correction to H18 Architecture Draft 4 §3.2 and H18 Proof-Obligation Register Draft 4 H18-PO-03, with no further revision. This record documents that adoption and the separately authorized one-file repository recording; it does not perform a new architectural review or revise the adopted correction.

The supplied Kimi K3.1 Pro / Moonshot AI review returned **FORMAL REVIEWER ELIGIBLE — ACCEPT**, with **no blocking findings**, **no non-blocking notes**, **all five required adversarial cases PASS**, and **no broader H18/Register correction required**. The five cases covered pending requests, definite dispatch, post-loss evidence, restored `Q` with unavailable E6/E7, and preservation of historical uncertainty. That disposition qualifies only the exact narrow correction against the two controlling base artifacts; it is not a full re-review of H18 or the Register and does not extend the historical Kimi or Argon acceptances to new language.

The review and Human Chair adoption are recorded in [Use Fable As Supervisor](chatgpt-conversation://6af231fe-1524-83e8-9c30-aa0be3c5b0c1). The Human Chair supplied the complete Astra correction candidate for this recording. Its sections C and D are reproduced verbatim below, including the three-edit instructions. The candidate's historical pre-review status does not replace the subsequent Kimi disposition and Human Chair adoption recorded here.

## Controlling base artifacts and preserved historical evidence

The two controlling base artifacts are:

| Artifact | Pinned repository path | SHA-256 |
|---|---|---|
| H18 Architecture Draft 4 | `provenance/h18-draft4-2026-11/Pasted text(20261107-223309).txt` | `528ac9212b207f439e236adc74518e075abe4fd2c39bbeff7457f0c31c114629` |
| H18 Proof-Obligation Register Draft 4 | `provenance/h18-draft4-2026-11/Pasted text(20261108-190715).txt` | `16c224d956a1b643d294b9fceb1cf73c7dddf2bdc469e2f14d378069d0db96ab` |

The associated pinned historical review artifacts are:

| Artifact | Pinned repository path | SHA-256 |
|---|---|---|
| Kimi qualifying H18 review | `provenance/h18-draft4-2026-11/Pasted text(20261107-225744).txt` | `0ba7c2d0cf28e27270358130ad74b39c249124a639770c7f1ce819e207c44f2a` |
| Argon qualifying Register review | `provenance/h18-draft4-2026-11/Pasted text(20261108-192107).txt` | `6ca921f5f088c9ac39ae48b1cf121c993b73f1cba67e59e3c08b905954728481` |

Paths above are relative to this record's directory. All four pinned historical Draft 4/review artifacts remain unchanged and historically authoritative as preserved evidence, subject to the qualifications in the [H18 Draft 4 provenance record](DECISION-0009-H18-DRAFT4-PROVENANCE-RECORD.md). This clarification controls only the identified H18 §3.2 / H18-PO-03 semantics going forward. The replacement instructions below define the adopted overlay; they do not authorize editing the pinned artifacts. No other H18 or Register provision is amended.

## Adopted H18 §3.2 correction — verbatim candidate section C

Replace only the paragraph beginning “A slot leaves the active in-flight state only when…” in §3.2 with:

A slot leaves the active in-flight state upon admissible evidence that its original operation has ended, or through the limited non-dispatch resolution below. Completion is normally established by the original terminal return under a backend contract showing that the return ends the relevant effect interval. An acknowledgement of asynchronous submission does not establish completion.

The non-dispatch resolution is available only to a slot whose entry into `IN_FLIGHT` rested solely on possible dispatch; it is unavailable to a definitely dispatched operation. Positive admissible evidence satisfying §7.1 must establish both absence of crossing throughout the relevant interval, beginning at first technical reachability, and exclusion of any subsequent crossing by that same operation. A request that has not crossed but remains capable of crossing, including through pending or delegated dispatch, does not satisfy this rule.

Resolution removes that slot’s execution-state obstruction to `Q`; `Q` must still satisfy §4.1 in full. `U(k)` remains false. Preserve the original dispatch-uncertain assessment and its potential-effect uncertainty in the evidence history alongside the resolution. Resolution permits no retry or redispatch, reverses no stop, and changes no frozen reporting disposition.

Any reliance on evidence acquired after a relevant loss remains subject to Level-2 Evidence Contract §6: the exact post-loss observation must belong to the original authorized sequence and have the applicable adopted method. Without those conditions, that evidence cannot discharge the execution-state obstruction. This resolution grants no additional observation, probe, cancellation, or recovery operation and does not relax the no-overlap rule.

The following component-loss and timeout paragraphs remain unchanged.

## Adopted H18-PO-03 correction — verbatim candidate section D

First, replace only the first sentence of PO-03’s paragraph beginning “Ending an active in-flight state…” with:

Except for the limited non-dispatch resolution specified below, ending an operation’s active in-flight state requires separate admissible evidence that its original operation ended under the applicable backend semantics.

Retain that paragraph’s existing terminal-return and asynchronous-acknowledgement sentences.

Then replace the paragraph beginning “For a slot that only possibly dispatched…” with:

For a slot whose `IN_FLIGHT` entry rested solely on possible dispatch, non-dispatch resolution requires positive admissible evidence under PO-09 covering the interval from earliest technical reachability through resolution, together with evidence excluding any later crossing by that same operation. Evidence that crossing has not occurred so far is insufficient while pending, delegated, or other dispatch remains possible. This route is unavailable to a definitely dispatched operation and remains subject to the post-loss requirements above. It removes only the resolved slot’s obstruction to `Q`; all other requirements of `Q` remain applicable. `U(k)` stays false. Retain the original uncertainty and potential-effect assessment in the evidence history alongside the resolution. No stop is reversed, no frozen disposition is reopened, and no retry or redispatch is permitted. E6/E7 remain subject to every existing eligibility predicate and bound.

## Adopted semantic scope and preserved constraints

A slot whose `IN_FLIGHT` state arose solely from possible dispatch may use the non-dispatch resolution path only when admissible evidence establishes both that the operation **did not cross** the governed dispatch boundary and **can no longer cross** that boundary.

This path:

- Does not apply to definite dispatch.
- May remove only that slot's obstruction to `Q`; it does not itself establish `Q`.
- Leaves `U(k)` false and permits no retry or redispatch.
- Reverses no stop and reopens no frozen disposition.
- Does not make E6/E7 eligible by itself; every existing eligibility predicate and bound remains applicable.
- Preserves the original dispatch-uncertain and potential-effect history.
- Preserves post-loss evidence controls, including original authorization for the exact post-loss observation and the applicable adopted method.
- Preserves no-overlap, late-return confinement, capacity accounting, backend neutrality, and reporting/execution-state separation.

Restoring `Q` does not guarantee an E6/E7 opportunity. Frozen or otherwise ineligible terminal slots remain unavailable. The correction adds no observation, probe, cancellation, recovery operation, evidence-production route, artifact allowance, reservation refund, or capacity transfer.

## Authority boundary

**Architectural adoption only.** This clarification grants no implementation, execution, backend selection, platform observation, B5/P0/Approval-B progression, F/Q/O authority, cleanup, custody transition, or successor authority. Separate authorization for this one-file documentary recording does not expand those boundaries.

B5 G1 remains **HOLD**; both P0 candidates remain **NOT QUALIFIED**; Approval B and V2-2B implementation/execution remain **UNAUTHORIZED**. The capacity envelope remains **NOT YET PROVEN SUFFICIENT**.

Staging, commit, and push are outside this recording authorization.
