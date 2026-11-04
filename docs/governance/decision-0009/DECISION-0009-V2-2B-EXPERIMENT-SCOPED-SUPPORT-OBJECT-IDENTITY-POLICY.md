# Decision 0009 — V2-2B Experiment-Scoped Support-Object Identity Policy

## Adoption and recording metadata

- **Architectural adoption date:** November 3, 2026.
- **Human Chair:** Amy.
- **Policy author:** Astra.
- **Independent reviewer:** Opus 5.5; Author ≠ Reviewer preserved.
- **Adopted text:** corrected Section H, H1–H20, exactly as independently reviewed.
- **Focused re-review disposition:** **ACCEPT WITH NON-BLOCKING NOTES**.
- **Accepted findings:** **B1–B3 CLOSED; C1–C6 CLOSED; 14/14 required adversarial scenarios PASS; no new blocking defect identified**. These are documentary review results, not newly executed tests or platform experiments.
- **Preserved boundaries:** separation from actual F/Q/O identity and operational/authorization boundaries.
- **Non-blocking notes:** N1–N6 retained for future design and authorization work; optional N1/N2 wording is not incorporated into the adopted text.

Amy's explicit adoption follows Astra's correction and Opus's focused independent re-review in the source record below. The proposal-stage statements within the transcription are preserved exactly as reviewed, including “Not effective unless explicitly adopted” and “if adopted.” They describe the text's proposal-stage provenance; Amy subsequently adopted that exact text on November 3. The surrounding correction analysis (Sections A–G) and recommendation (Section I) are not transcribed as governing policy.

This file records the adoption under Amy's later, specific two-file documentation-creation authorization. **Recording grants no implementation, experiment, operational, filesystem-effect, object-creation, host/candidate inspection, protected-read, P0, Approval B, privilege, service, Git, cleanup, release, or successor authority.** Architectural adoption itself did not authorize recording. No experiment or experimental capacity is authorized or allocated by this record. Actual-lifecycle support accounting and existing gate dispositions remain unchanged.

## Provenance and governing references

1. [Astra 2 Define V2-2B identity policy](codex://threads/01a1a390-e79c-7282-af44-4c21301e551b): corrected recommendation of November 3, 2026, Section H (H1–H20), correction turn `01a1a3e0-4c96-7810-911a-feca084cc982`, final response `msg_0b0fdf7f75c893b2016aea77411bac87d1a4831a2da03cc7ef`; Amy's explicit adoption in turn `01a1a3e9-22d3-7700-a634-339883512709`. This is the transcription and adoption source.
2. [Opus independent review](../../../Claude%20outputs/D0009-V2-2B-identity-policy-independent-review.md): initial **REJECT — CORRECTION REQUIRED**, findings B1–B3 and clarifications C1–C6; retained as review history, not the final disposition.
3. [Opus focused independent re-review](../../../Claude%20outputs/D0009-V2-2B-identity-policy-focused-re-review.md): final **ACCEPT WITH NON-BLOCKING NOTES**, §§B–C closure, §D N1–N6, §I 14/14 adversarial results, and §K adoption recommendation.
4. [Retention V2/M0 adoption record §8](DECISION-0009-RETENTION-FORMAT-V2-AND-M0-ADOPTION.md#8-reconciled-budgets-are-paper-bounds): unchanged actual-lifecycle support allowance and paper budgets. The new experimental ceilings do not consume, replenish, enlarge, or replace that allowance.
5. [Implementation plan §D1](DECISION-0009-RETENTION-V2-M0-IMPLEMENTATION-PLAN.md#d1-evidence-levels), [§E](DECISION-0009-RETENTION-V2-M0-IMPLEMENTATION-PLAN.md#e-corrected-tranche-sequence), and [§N](DECISION-0009-RETENTION-V2-M0-IMPLEMENTATION-PLAN.md#n-corrected-human-chair-gate-map): evidence levels, sequencing, and the separately authorized V2-2B scope. Disposable Level-2 evidence does not establish candidate or actual F/Q qualification.
6. [Lifecycle governance bindings, Part C §8](DECISION-0009-HUMAN-CHAIR-LIFECYCLE-GOVERNANCE-BINDINGS.md#8-platform-baseline-transition) and [Part C §10](DECISION-0009-HUMAN-CHAIR-LIFECYCLE-GOVERNANCE-BINDINGS.md#10-continuing-validity-rule): platform-baseline transition and continuing validity of material premises.
7. [Progress Summary](chatgpt-conversation://6aea4f12-a11c-83e8-9712-f4c7a1aec038): November 3 checkpoint, subsequent read-only recording-scope extraction, and separate two-file recording approval. See also the [dated handoff](../../reviews/decision-0009-progress-handoff-2026-11-03.md).

**Publication/provenance limitation:** At recording time, the Retention V2/M0 adoption record, implementation plan, and both Opus review artifacts are existing untracked, preserved local files. Their references do not imply that they are committed or remotely published and do not authorize staging, committing, or modifying them. The independent reviews explicitly reported that the full r2 and Amendment 1a texts, V2-2A non-blocking notes, and B5/P0 status materials were not independently available in the repository. This record does not claim independent verification of those unavailable materials.

## Exact transcription boundary

The following fenced block reproduces corrected Section H verbatim from the source response, including its original headings and proposal-stage wording. Adoption metadata and retained notes are outside the block.

````markdown
## H. Corrected complete policy

### Decision 0009 — V2-2B Experiment-Scoped Support-Object Identity Policy

**Proposed governing text. Not effective unless explicitly adopted by the Human Chair following independent re-review.**

### H1. Controlling text, scope, and authority

This section H is the complete proposed governing policy and replaces the earlier proposed §R. Surrounding correction analysis is explanatory and supplies no additional governing permission.

This policy applies solely to V2-2B disposable Level-2 experiments and their experimental support evidence. It does not amend actual Decision 0009 lifecycle support accounting.

The experimental ceilings, accounting interval, evidence designations, and cross-attempt controls below are new Human Chair architectural policy choices if adopted; they are not represented as preexisting r2 requirements for Level-2 experiments.

Adoption authorizes no code changes, implementation, tests, experiments, filesystem effects, object creation, protected reads, host/candidate inspection, P0, Approval B, privilege, services, cleanup, release, backend selection, Git mutation, or successor activity.

### H2. Distinct identity concepts

The following remain distinct:

- **Live experimental identity:** continuity of a particular object during one bounded experiment.
- **Evidence artifact identity:** the origin, version, integrity, and historical relationships of a retained record.
- **Reference identity:** what object a particular reference designates in a specified context and interval.
- **Accounting identity:** proven relationships permitting one support object to be counted once.
- **Later operational identity:** identity needed for actual F/Q/O and other operational gates.

Historical evidence may preserve claims about an object after its live domain ends. It does not preserve or recreate authority or capability to operate on that object.

### H3. Experiment boundary, termination, and cleanup

One identity domain comprises one specifically authorized bounded experiment attempt, including its predeclared cases and bounded terminal evidence production.

Before the first governed effect, its authorization must establish its designation, substantive propositions, cases, producers, operations, destinations, population bounds, allocation, evidence obligations, and completion/stop conditions. A designation is a reference, not proof of identity or authority.

The active phase ends at planned completion or a required stop. Only expressly preauthorized bounded terminal actions may follow. The domain closes with a complete or explicitly incomplete/unresolved closure record. Stopping must not depend on successful future evidence capture.

Any disposable cleanup specifically authorized within V2-2B belongs to the active or preauthorized terminal phase. Its evidence is governed experimental support. Cleanup shall not remove retained governed evidence without separate release authority and satisfaction of applicable preservation conditions.

A terminated attempt shall not resume. Later classification or review shall not revive its live domain.

### H4. Attempts, replication, and prohibited retries

A failure, uncertainty, conflict, or incomplete result grants no retry, repair, replay, replacement, or further-attempt authority.

Except for the predetermined replication exception below, a later attempt requires the earlier attempt to have stopped, its complete or incomplete closure record to be available to the Human Chair, explicit Chair disposition of that outcome, and new specific authority for the later attempt.

Advance authority conditioned on an earlier attempt failing, becoming uncertain, conflicting, or remaining incomplete is prohibited retry authority. New names or domains shall not evade this rule or any existing operation-level no-retry restriction.

Predetermined independent replication is permitted only where specific advance authority fixes its justification, finite repetitions, cases, domain boundaries, allocations, reporting, and stop conditions independently of individual outcomes. That authority may cover multiple individually specified experiments. It shall not select additional repetitions because earlier results were unfavorable, or omit attempted repetitions from reporting.

Each attempted repetition retains its original result. Completion of one repetition does not override a stop affecting the safety, provenance, or completeness of later repetitions. Replication does not authorize resumption of a terminated attempt.

### H5. Governed objects and classification

A governed experimental support object is one particular bounded support artifact with evidenced origin or admission and a traceable history of relevant uses.

Every object produced or admitted by the experiment shall be classified in its inventory as governed support, test subject, or contextual object, with its accounting treatment stated. An artifact relied upon as evidence or used as support is governed support regardless of labels such as temporary, diagnostic, or test output.

An unclassified produced object is provisionally treated as governed support for accounting and remains subject to the completeness stop in H9. Classification or charging alone does not prove admissibility.

Names, labels, wrappers, Python identity, addresses, paths, inodes, UUIDs, digests, content equality, and serialization identity shall not independently establish governed identity. This policy selects no concrete identifier. Such observations may contribute to a separately reviewed proof.

Synthetic objects and model outputs remain Level 1; they shall not be relabeled as empirical Level-2 evidence.

### H6. Sameness, distinctness, copies, and grouping

Multiple references may count once only when admissible evidence connects the object’s origin/admission, relevant references, observation intervals, and continuity through intervening operations, without unresolved substitution or contradiction.

Separate creation or recreation establishes distinct objects even when bytes or labels match. Copies, clones, exports, excerpts produced as separate artifacts, and reconstructed artifacts do not inherit source-object identity.

Records shall distinguish proven distinctness from conservative separate accounting.

One support object originally produced as a single artifact may contain multiple related observations, preserving their provenance and causality. Separately created governed objects shall not later be merged into one charge by packaging, compression, aggregation, or report generation. Any separately created governed container or derivative is also accounted for.

### H7. Aliases, state, replacement, and reopening

Each relied-upon alias relationship must have an evidenced origin, interval, and continuity basis. Stable identity does not prove unchanged contents or properties. Evidence remains bound to the object and state actually observed.

Replacement, rename-over, or recreation does not transfer predecessor identity. Earlier evidence remains about the predecessor and its interval. Known replacement support objects receive separate charges.

Parent replacement invalidates unsupported namespace continuity without automatically establishing leaf recreation. An independently proven retained leaf binding does not restore a replaced parent/path relationship.

Closing one alias need not end continuity where another proven live binding remains. Reopening a pathname does not automatically preserve identity. After all established live bindings are lost, reacquisition shall not be treated as continuation without a separately adopted bounded proof method and applicable authority.

Any necessary live cross-process transfer must preserve an evidenced relationship within the same domain. A separately adopted method is a prerequisite wherever an intended test requires reopening or post-writer-loss observation; its necessity shall not be dismissed as hypothetical.

An unexpected runner interruption or restart does not authorize resumption. An expressly designed subject-process termination test may proceed only within its original authorized sequence and established continuity method; it grants no retry.

Serialization, runner/evaluator handoff, and later review may preserve historical relationships without reconstructing live experimental identity.

### H8. Closed inventory and reservations

Before execution, the experiment must enumerate:

- support-artifact classes, test subjects, and contextual objects;
- roles, maximum instances, and size bounds;
- every authorized producer, including children, framework components, and reporting components;
- permitted production, acquisition, creation, transfer, and output operations;
- destinations and relevant reference relationships;
- retained evidence and terminal, failure, stopping, and authorized-cleanup outputs.

A caller-supplied list or authorization is not proof of actual completeness. The reviewed method must establish coverage of production routes and reconcile actual events with the declared inventory.

Dynamic instances may arise only within predeclared roles, operations, destinations, and reserved maxima. No silent population expansion is permitted.

Before the first governed effect, reserve sufficient capacity for the worst-case cumulative demand on every permitted path through terminal reporting and closure. Mutually exclusive branches may be treated as such only where their exclusion is established. Previously incurred charges shall not be refunded by branch selection.

An uncertain creation retains its full potential charge/reservation, is recorded as uncertain, and authorizes no replacement attempt.

### H9. Unexpected production and completeness failure

Unexpected or unreconciled production, acquisition, transfer, or output potentially within governed support scope breaks demonstrated inventory completeness.

No exemption is presumed for framework, harness, temporary, diagnostic, or teardown artifacts. An artifact may not be ignored merely because no positive criterion was intended to rely on it.

While completeness is unproven, positive qualification dependent on it is blocked and further governed experimental dispatch stops. Preserve and record the artifact and known facts within applicable authority; no additional inspection, capture, deletion, or cleanup permission is implied.

Conservative charging does not restore completeness. If possible population or size is unbounded or unknown, no demonstrated capacity bound may be claimed.

A later justified classification may establish exclusion from the governed population, but must also address whether the event reveals an undeclared production route within that population. Such classification cannot retrospectively authorize an effect, restart a terminated attempt, or replace missing observations.

### H10. New per-experiment experimental ceilings

By this policy, if adopted, each specifically authorized V2-2B experiment receives a separate experimental support allocation stated in its authorization, no greater than:

- **128 governed support objects;**
- **65,536 bytes per object;**
- **4,194,304 aggregate bytes.**

Each limit is enforced independently. An authorization may impose smaller bounds.

These are newly adopted experimental safety ceilings, not inherited operational allowance. Policy adoption alone allocates no capacity and authorizes no experiment.

There is no cumulative V2-2B allocation under this policy. A later experiment receives its own allocation only through specific authority satisfying H4. Unused capacity is nontransferable. Cases or repeated operations within one domain share that domain’s allocation.

Experiments shall not be subdivided or relabeled to evade a declared limit or conceal part of one experiment’s evidence production.

### H11. Experimental accounting interval and capacity failures

The allocation covers all governed support admitted or created for the experiment, including admitted inputs, from the experiment’s governed acquisition/production through bounded terminal reporting and closure.

Repeated proven references to one object count once; distinct objects count separately. Accounting must retain the maximum charge incurred for each object during the interval. Disappearance, deletion, cleanup, replacement, shrinking, phase change, and domain termination do not replenish the allocation.

Required evidence, the inventory record, final report, and failure branches must fit the declared reservations. Exceeding a reservation or ceiling is a capacity failure, not permission to enlarge the allocation, split a report, truncate required evidence, borrow capacity, or create a replacement representation.

Where closure cannot fit or complete, retain available evidence and record incomplete closure only through already authorized bounded means. Reporting failure does not delay the mandatory stop or convert the experiment to a pass.

### H12. Separation from actual lifecycle accounting

V2-2B experimental accounting neither consumes, credits, replenishes, enlarges, replaces, nor modifies the actual Decision 0009 lifecycle support allowance or its existing lifetime/account rules.

This separation does not exempt experimental material later admitted as actual lifecycle support. The later gate must determine and account for that admission under its own governing rules and authority.

No new operational support or phase capacity is created. Experimental ceilings shall not be presented as actual F/Q/O capacity or as a bound on total retained evidence across multiple experiments.

### H13. Unresolved identity, dependency, and conflict

Unresolved references receive no deduplication benefit. Where population and sizes are bounded, conservative separate charging may establish a provisional capacity upper bound only. It does not establish provenance, completeness, identity qualification, or authority to continue.

An issue is material if it can affect identity continuity, inventory completeness, accounting, evidence applicability, or a claimed result. An action or claim is dependent if its justification relies on a proposition affected by that issue.

If materiality or dependency cannot be affirmatively resolved, treat the issue as material/dependent for dispatch and positive-qualification purposes. Uncertainty shall not be classified as immaterial merely to continue.

Preserve original observations, competing claims, partial outcomes, known violations, and dispatch uncertainty. Do not silently merge, choose favorable evidence, overwrite earlier observations, or retry to obtain a cleaner record. Missing output does not prove non-dispatch.

An unresolved continuity conflict or completeness failure terminates active experimental dispatch and prevents overall positive qualification. Other unresolved issues block all affected claims and actions; uncertain impact receives the fail-closed treatment above.

### H14. Proposition identity and attempt lineage

The same material experimental proposition is the substantive Level-2 claim concerning a property or failure behavior, its operation/mechanism, relevant inputs and fault conditions, platform/configuration premises, and intended reliance.

Names, paths, labels, report titles, or incidental implementation changes do not establish a different proposition. Materially overlapping claims remain related. Changed premises and their significance must be disclosed; uncertain relevance requires inclusion in the lineage rather than favorable exclusion.

Each later attempt’s authorization and retained record shall identify applicable earlier attempts addressing that proposition, their original outcomes, dispositions, and accessible evidence references. The lineage shall be reconciled against the applicable authorization/disposition history; an unverified assertion that no earlier attempts exist is insufficient.

Earlier failed, uncertain, conflicting, or incomplete results remain available to proposition-level review. Later evidence shall not erase, overwrite, replace, silently supersede, or be selectively presented without applicable earlier evidence.

A proposition-level evaluation must address the combined record and explain any narrower conclusion or applicability distinction. Unresolved lineage completeness prevents a claim that the overall evidence record supports positive qualification.

### H15. Retained evidence and platform binding

Relied-upon observations, inventory/identity records, reports, and required provenance and closure material are governed experimental support.

The retained record shall preserve:

- experiment designation, external authorization, propositions, and attempt lineage;
- declared and actual scope, producers, operations, destinations, and bounds;
- object roles, classifications, origins/admissions, and relevant states;
- reference relationships and sameness/distinctness proof bases;
- sequence, relevant intervals, original outcomes, and dispatch uncertainty;
- replacements, disappearances, conflicts, missing evidence, and limitations;
- reservations, charges, reconciliation, termination, and closure disposition;
- exactly which Level-2 claims are supported, violated, uncertain, or unobserved;
- the platform and configuration premises necessary to interpret those claims.

Platform premises must identify the relevant release/build, execution context, and mechanism/configuration facts where material, together with their evidence source, acquisition interval, and applicability limitations. A name copied from a prompt or earlier report is not an established experimental baseline.

Every relied-upon observation must remain attributable to its particular subject, reference relationship, sequence/state, producer, operation, original outcome, and relevant platform premises.

The finite evidence reservation must include the record’s own production and terminal/failure branches without requiring an endless chain of reports about reports. The record does not authenticate itself. Digests may support integrity checks but independently prove neither authority, original acquisition, object identity, nor completeness.

### H16. Independent review and later artifacts

Retained evidence must permit independent reconstruction and evaluation without reopening original live experimental objects.

Author and independent acceptance reviewer shall differ, preferably by model family where practicable. Author correction checks are not acceptance.

Later review artifacts are outside the closed experiment’s allocation. They neither add charges to nor reopen that allocation; they are governed and accounted for under the authority permitting their production.

They must remain distinguishable from original experimental evidence. They cannot silently amend original outcomes, supply missing original observations, or move required terminal evidence outside the experiment to evade its cap.

Required adverse evidence shall remain available for applicable later proposition-level evaluation. Release or loss shall not be concealed; missing required evidence prevents unsupported positive reliance.

### H17. Cross-experiment citation, admission, and currentness

No live support-object identity carries into another experiment.

A prior report merely cited as a historical reference is not thereby admitted as a governed object of the citing experiment. The new record containing the citation remains accounted for.

A prior report actually relied upon as an evidentiary input must be admitted to and charged in the receiving experiment’s inventory. Repeated proven references to that admitted report count once. Separately created copies, excerpt artifacts, and derivatives receive their own charges; packaging does not merge them.

Calling substantive reliance a “citation” shall not evade admission or charging. Attempt-lineage references must still make applicable adverse evidence available; citation terminology shall not conceal it.

Historical reports retain their original platform/context and evidence-level limitations. Copying, admission, citation, matching platform labels, or a later date does not establish current platform behavior. Currentness and applicability require separately governed justification.

Cross-experiment reference or admission neither revives live identity nor transfers or refunds experimental capacity or actual lifecycle capacity.

### H18. Backend neutrality and evidence transfer

Direct bounded operations, an explicit effect backend, and a separate runner with a pure evaluator remain possible architectures. This policy selects none.

Each must produce admissible original observations, establish inventory coverage, preserve uncertainty, and support independent interpretation. A producer’s unsupported identity or completeness assertion is insufficient.

A runner/evaluator handoff requires a separately adopted evidence-transfer and provenance contract. Governed transport artifacts must be accounted for. Serialized labels preserve historical assertions only; they do not reconstruct live identity. A pure evaluator cannot establish omitted-producer absence by parsing a supplied list.

### H19. Operational boundary and prerequisites

This policy establishes no operational identity, qualification, custody, restoration, release, or service authority for actual F/Q/O, P/I/O, candidates, or parents. Disposable Level-2 evidence cannot substitute for required higher-level evidence.

Concrete acquisition/transfer/reporting contracts, continuity methods where necessary, inventories, reservations, backend choice, implementation scope, execution envelope, terminal behavior, and release arrangements remain separately governed and require applicable review and specific authority.

This policy changes no status or disposition of B5 G1/G2, the host-observation envelope, P0 candidates, B3/B4, or any other gate. It is not an independent status record for those matters.

### H20. Re-review, adoption, and stop

The corrected proposal requires independent follow-up review by someone other than its author before Human Chair adoption is recommended.

Neither delivery, author-assessed closure of findings, independent review, nor architectural adoption grants implementation, experiment, recording, cleanup, release, or successor authority.

No successor activity follows from this policy.

````

## Retained non-blocking notes N1–N6

These are future design/authorization notes from Opus's focused re-review §D, retained by Amy's adoption. They do not amend the transcription above, open a workstream, or grant authority. N1/N2 optional wording remains only in the review artifact; neither optional change has been inserted into H4 or H14.

| Note | Retained concern and future handling |
|---|---|
| N1 — Concurrent attempts | H14's “earlier attempts” wording leaves a literal concurrency edge. H13's prohibition on favorable selection and reconciliation against authorization history still apply. Future design/authorization work must retain applicable concurrent evidence; the review's optional wording change was not adopted into this transcription. |
| N2 — Stopping replication early on success | Read H4 with H14's combined-record requirement: predetermined replication must not become “stop at the first pass.” Preserve all attempted repetitions and the authorized safety/stop conditions. The optional additional sentence was not inserted. |
| N3 — Scope of “a later attempt” | Future authorizations should state their relationship to earlier attempts and the same material proposition, avoiding ambiguity about unrelated experiments. |
| N4 — Reclassification and unauthorized effects | Reclassification can resolve support-population completeness only; it does not cure production by an unenumerated producer or into an undeclared destination. Record the known violation for Chair disposition; no retroactive authority follows. |
| N5 — Acquiring platform premises | Establishing H15 release/build and configuration facts is itself a host observation. It must be covered by specific future V2-2B authority and respect the boundaries of the unopened host-observation envelope. |
| N6 — Aggregate visibility | Where specific authority covers multiple experiments or a replication series, state the combined maximum allocation. There is no cumulative V2-2B cap; finite specific Chair authorizations bound the total. |

## Recording disposition and stop

This is an architectural adoption record, not an implementation or execution package. Concrete acquisition/transfer/reporting contracts, necessary continuity methods, inventories and reservations, backend selection, implementation scope, execution envelope, terminal behavior, evidence preservation/release, and applicable gate prerequisites remain separately governed.

B5 G1 remains **HOLD** and the P0 and other gate dispositions are unchanged, as reported in the source-attributed November 3 handoff. This recording performs no new host observation or qualification.

The authorized mutation is limited to this new policy record and the dated handoff. Review the exact new-file diff and preservation evidence, then stop for Human Chair review. Staging, commit, and push remain separately unauthorized. No successor authority follows.

