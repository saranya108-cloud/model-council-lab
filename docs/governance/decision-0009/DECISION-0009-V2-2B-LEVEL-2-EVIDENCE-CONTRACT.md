# Decision 0009 — V2-2B Level-2 Evidence Contract

## H18 Draft 4 architectural adoption — November 7, 2026

Human Chair **Amy architecturally adopts “V2-2B Concrete H18 Evidence Acquisition, Transfer, and Provenance Architecture — Draft 4” (November 7, 2026)**. Fresh-family formal reviewer **Kimi K3.1 Pro / Moonshot AI** returned **ACCEPT WITH NON-BLOCKING NOTES** and found **no new blocking defect**.

The adoption retains Kimi’s two non-blocking cautions:

1. **Source-write cutoff clarity.** Implementation/conformance records must make explicit that the pre-seal source-write route is fenced before `L-S`/source-manifest final state is captured. A return arriving after that fence remains confined until the declared `X-L` route rather than making `L-S`/manifest stale.
2. **Do not broaden the E3 claim implicitly.** If E3 is later treated as an independent pass/fail qualification proposition, its own independent expected-outcome source and native-result mapping must also be bound before the first governed effect.

**Adoption is architecture-only.** It does not constitute backend selection or qualification, empirical H18 satisfaction, capacity sufficiency, implementation authority, execution authority, host/platform observation authority, P0 qualification, B5 progression, Approval B, F/Q/O creation or qualification, cleanup, custody transition, or successor authority. **CANDIDATE ENVELOPE NOT YET PROVEN SUFFICIENT** remains the capacity disposition.

**Unchanged gates:** B5 G1 **HOLD**; both P0 candidates **NOT QUALIFIED**; Approval B **unauthorized**; V2-2B implementation and execution **unauthorized**.

Current [Decision 0010](../../decisions/0010-mandatory-cross-family-review.md), amended November 7, 2026, applies **revision-scoped reviewer independence**: no qualifying self-review of an authored or materially co-authored current revision; historical family contribution alone is not permanent disqualification. Kimi’s fresh-family formal review is recorded for this Draft 4 adoption gate, not as a permanent-family exclusion rule.

**Recording provenance and scope:** [Sol 5.6 Analyze Progress Plan](chatgpt-conversation://6aef8068-27b0-83e8-92f8-9e914d10baf0) and Amy’s explicit November 7 repository-recording instruction supply the adoption and review disposition recorded here. This entry records that decision; it does not transcribe Draft 4 or claim a new independent review. The November 6 adoption record, verbatim Draft 2, and review appendix below remain historical records unchanged. Their statements that adoption of the general contract alone leaves the concrete H18 architecture separately unresolved are now read alongside this subsequent architecture-only adoption; they do not establish empirical H18 satisfaction or additional authority.

## Adoption and recording metadata

- **Human Chair:** Amy.
- **Architectural adoption date:** November 6, 2026.
- **Adopted candidate:** Decision 0009 — V2-2B Level-2 Evidence Contract, Draft 2, November 6, 2026, exactly as independently reviewed.
- **Disposition:** Architecturally adopted; recorded under a separate, specific one-file documentation-creation authorization.
- **Authority:** Architectural adoption and this bounded recording only; no implementation or execution authority.
- **Drafting role:** Astra. This recording preserves the authorship and contribution provenance in the adopted candidate and supplied review; it does not infer model identity from a role or harness label.
- **Qualifying independent review dispositions accepted by the Human Chair:** Muse Wonder / Meta Muse family — ACCEPT WITH NON-BLOCKING NOTES; Kimi K3.1 Pro / Moonshot AI Kimi family — ACCEPT WITH NON-BLOCKING NOTES.

The complete Draft 2 candidate is transcribed verbatim below, including its title, original proposal-stage wording, author-assessment language, source-verification material, review dispositions, and stopping language in §§1–18. Those statements describe the candidate at delivery. Amy subsequently adopted that exact candidate on November 6, 2026. This surrounding adoption record does not rewrite the candidate or convert its author assessments into independent-review findings.

The complete supplied Kimi review is preserved verbatim in a separate appendix. It is review evidence, not a replacement for the adopted candidate or the Human Chair's authority. Reported review passes are documentary adversarial-review results, not newly executed tests or platform experiments.

## Provenance and transcription identities

- **Source chat:** [Decision 0009 resume and adoption](codex://threads/01a1b28f-e900-71b2-90a2-e12bc2e757e6).
- **Preserved chat transcript:** `/Users/aclab/.codex/sessions/2026/11/06/rollout-2026-11-06T12-32-18-01a1b28f-e900-71b2-90a2-e12bc2e757e6.jsonl`.
- **Draft 2 source:** assistant message `msg_0d9acd85d1c2f4ef016aee4aff183887d1a50e21487a588eed`, record ordinal `306`, document writing block `96142`. The transcription is the complete content inside that block, excluding its writing-block delimiters and the commentary outside it.
- **Draft 2 transcription:** 44,000 UTF-8 bytes; SHA-256 `f7f17cc01ae41d712f074c70ef917a011f061839eea17f74acc15a9e2cbd8ee0`.
- **Human Chair adoption:** user message `msg_01a1b2f7-a9e7-7e73-a11c-a37e4994a8c8`, record ordinal `324`, in the source chat.
- **Separate one-file recording authorization:** user message `msg_01a1b2fb-e01f-7240-96e4-9d3b92cc05c0`, record ordinal `360`, in the source chat.
- **Kimi review source:** the complete supplied attachment `/Users/aclab/.codex/attachments/a2cec359-4c55-401d-9e21-1aed29c00688/Pasted text.txt`.
- **Kimi review:** 12,829 bytes; supplied and verified SHA-256 `8282deaf3a239fe585bacf024d1ca343db75839dd0228fcb7a9ebeeaf31aaf31`. The appendix preserves the attachment exactly, including its supplied footer.
- **Normative source access:** the adopted candidate's §§13–14 preserve the complete r2 and Final Amendment 1a retrieval locators, message selectors, hashes, and clause references. This recording creates no separate specification copy and does not alter either source.

The transcription delimiters and their separator newlines are recording structure, not part of either hashed source text.

## Independent-review provenance and dispositions

### Kimi K3.1 Pro

The complete supplied review identifies **Kimi K3.1 Pro**, model ID `moonshotai/kimi-k3.1-pro`, supplied through OpenRouter, with underlying **Moonshot AI Kimi** family. It records its Decision 0010 whole-document eligibility determination, runtime identity evidence, and lack of identified substantive contribution to the reviewed material. Amy accepted this as qualifying independent review.

Its disposition is **ACCEPT WITH NON-BLOCKING NOTES**. The review records independent retrieval and inspection of both complete normative source messages; verification of their message IDs and SHA-256 hashes; no material specification-fidelity discrepancy; independent closure of B1–B9; acceptance of N1–N11 dispositions subject to retained notes; **30/30 required adversarial scenarios PASS**; no new blocking finding; and readiness for architectural adoption with the stated authority exclusions. The complete review, rather than this summary alone, is preserved in Appendix A.

### Muse Wonder

Amy's adoption statement records **Muse Wonder / Meta Muse family — qualifying ACCEPT WITH NON-BLOCKING NOTES**. Muse's complete review was not supplied for this recording. No unavailable review text, exact runtime identifier, source-verification detail, finding-by-finding disposition, or adversarial result is invented or reconstructed. The recorded Muse disposition is attributed to the Human Chair's adoption statement.

### Correction and contribution lineage

Draft 1 received Opus's **REJECT — CORRECTION REQUIRED** findings. Draft 2 contains the bounded author corrections and the B1–B9 author-assessment and N1–N11 disposition tables. Kimi subsequently independently closed B1–B9 and accepted the dispositions subject to its retained notes. The concurrent-lineage and no-first-success refinements originated in earlier Opus review findings. Amy knowingly adopted those refinements after subsequent independent review. This provenance is preserved for Decision 0010; recording does not erase substantive contribution history or grant future reviewer eligibility.

## Human Chair concurrency disposition and retained conditions

Amy accepts determination **C — H1–H20 leave non-replication concurrent materially overlapping attempts genuinely ambiguous**. This does not block adoption of the general Level-2 Evidence Contract.

**No non-replication concurrent materially overlapping attempt is authorized or presumed permissible. A separate Human Chair policy decision is required before any such architecture may be authorized or dispatched.**

Predetermined replication remains governed by H4. This recording neither resolves the ambiguity nor adopts a universal replication-only concurrency rule.

The retained non-blocking conditions are:

1. The concurrency ambiguity remains unresolved pending a separate Human Chair policy decision.
2. The concurrent-lineage and no-first-success refinements have Opus/review origins and were knowingly adopted after subsequent independent review.
3. Adoption of this general contract does not satisfy the still-separate concrete H18 transfer/provenance contract, continuity methods, production inventories, platform-premise acquisition, case matrix, backend selection, or other concrete-design prerequisites. Those remain separately governed and unresolved.

## Authority boundary and unchanged gates

The Human Chair separately authorized creation and verification of this one governance file only. This recording grants no further recording, implementation, execution, backend-selection, filesystem-effect, host/platform-observation, P0, B5 progression, Approval B, F/Q/O creation/identity/custody/qualification, cleanup, release, Git, or successor authority.

As expressly reaffirmed by the Human Chair in the adoption and recording authorization:

- **B5 G1 remains HOLD.**
- **Both P0 candidates remain NOT QUALIFIED.**
- **V2-2B implementation and execution remain unauthorized.**

These are preserved Human Chair dispositions, not new host observations or qualification results. No existing repository file, README/index, progress note, Decision 0010, other governance record, preserved unrelated file, r2 text, or Amendment 1a text is authorized to change. Staging, committing, pushing, fetching, restoration, normalization, cleanup, tests, experiments, and successor activity remain outside this one-file recording authorization.

## Verbatim adopted candidate — Draft 2, §§1–18

<!-- BEGIN VERBATIM ADOPTED DRAFT 2 -->
````markdown
# Decision 0009 — Proposed V2-2B Level-2 Evidence Contract

**Revision:** Draft 2 — November 6, 2026  
**Human Chair:** Amy  
**Status:** Corrected candidate for Human Chair review  
**Authority:** Chat-only author correction  
**Independent acceptance:** PENDING / NOT QUALIFIED  
**Adoption, recording, implementation, and execution authority:** NONE

**1. Purpose, precedence, and authority**

This proposed contract defines evidence requirements for a future, separately authorized V2-2B disposable Level-2 experiment: acquisition, provenance, transfer, inventory completeness, continuity, accounting, reporting, and disposition.

The adopted H1–H20 policy controls experimental identity and accounting. Decision 0010 controls independent-review eligibility. Exact r2 and final Amendment 1a texts control technical requirements attributed to those specifications. Derived plans, summaries, and V2-2A models do not replace them.

This candidate contains proposed evidence requirements for review. It does not amend H1–H20, select a backend or identifier, establish a wire format, allocate capacity, or authorize effects. Adoption of this general contract would not itself satisfy a concrete design’s H18 transfer/provenance-contract requirement.

Actual F/Q/O objects, their actual parents, protected P/I/O objects, and P0 candidates shall not be disposable Level-2 subjects or destinations. No protected access or qualification follows from this prohibition.

**2. Propositions and experiment boundaries**

Before execution, each proposed claim shall identify:

- The property or failure behavior and its governing source.
- The operation/mechanism, relevant inputs and fault conditions.
- Material platform/configuration premises and observation intervals.
- Intended reliance, required observations, dependencies, and limits.
- Conditions producing a supported, violated, uncertain, or unobserved conclusion.

Proposition identity follows H14. Names, paths, labels, report titles, and **incidental** implementation changes do not establish a different proposition.

A material mechanism or premise change may establish a distinct proposition. Its materiality and significance must be disclosed. Distinct propositions are evaluated separately; a favorable result for one does not automatically support another.

Materially overlapping propositions remain related. Applicable earlier and concurrent attempts remain in lineage, including adverse results. Uncertain relevance requires inclusion with an explanation, not favorable exclusion.

Thus neither an implementation change alone nor a shared label permits unrelated evidence to be merged. Nor may a superficially new proposition erase applicable adverse history.

One specifically authorized bounded attempt forms one live experimental identity domain. Its cases share its allocation. Before the first governed effect, authority must fix the matters required by H3, including propositions, cases, producers, operations, destinations, population bounds, allocation, evidence obligations, and stop/completion conditions.

The active phase ends at planned completion or required stop. Only expressly preauthorized bounded terminal actions may follow. Domain closure is complete or explicitly incomplete/unresolved. A terminated attempt shall not resume.

**3. Claim-to-evidence requirements**

All rows require the provenance, continuity, inventory, accounting, and authority controls in this contract.

| Property | Required evidence and coverage | Limits on positive reliance |
|---|---|---|
| **Exclusive creation** | Original requests, outcomes, effects, and subject/reference relationships for successful creation and exercised negative cases relevant to the proposition. Coverage must include applicable pre-existing-target and final-component link cases, including symbolic, dangling-symbolic, and hard-link cases where applicable. Any claimed inapplicability needs an evidenced rationale and an explicitly narrowed proposition. | Success at an empty location proves only that creation succeeded in that case. Unexercised exclusion behavior cannot be reported as established exclusivity. Preserve original negative-case outcomes and any unexpected effect. |
| **Exact size and relevant object state** | Observed logical size, object type, applicable link count, relevant binding/parent relationship, and stability through the reliance interval. A regular-file proposition requires evidence of regular-file type. A proposition derived from Amendment 1a §3 must preserve its expected link count of one and same-object conditions. | Intended size, a supplied constant, or allocation success is insufficient. A point observation does not establish interval stability. Type/link predicates applicable to a regular subject must not erase contrary outcomes from negative link cases. |
| **Allocation** | Exact authorized allocation operation, original result, relevant before/after observations, and the allocation property actually demonstrated. | Logical size does not establish physical allocation. Preallocation does not prove future persistence, atomicity, or immunity from storage failure. |
| **Zero state** | Coverage of every range required by the proposition, tied to the relevant subject and pre-write state. | Sampling, unreadable ranges, absent output, or assumed initialization cannot establish complete required zero coverage. |
| **Synchronization/readback** | Original write extent/result, synchronization invocation and original result, causal ordering, current exact readback equality, required zero-suffix observations, and continuity within the observed interval. | These observations do not themselves demonstrate survival of an OS crash. Valid bytes, checksums, or later readback cannot supply missing historical synchronization evidence. |
| **Applicable resource-limit behavior** | Exact limit proposition and process context; observed soft/hard values; ordering relative to writable capability; exercised boundary cases; original statuses and partial effects. The concrete design must declare applicable signal/error behavior, including SIGXFSZ/EFBIG where relevant, signal disposition, child inheritance where relevant, partial-write behavior, and resulting termination or uncertainty. | These event types are proposed coverage obligations, not claims that r2 specifies their platform semantics. Expected behavior needs an applicable source basis. Link every short/error/uncertain result to §8 and every termination to §6. A process-local check cannot establish another process’s inherited state. |
| **Write-capability exclusion** | The relevant capability topology and intervals, covering writable descriptors, writable mappings, asynchronous or concurrent activity, one-writer requirements, unintended inheritance, fork/exec inheritance, descriptor/capability passing, and any relevant library, thread, or signal-handler path. | A clean descriptor table does not prove absence of all write capability. Unobserved processes, capabilities, or intervals remain unestablished. No system-wide scanning is implied. A prohibited writer topology cannot be qualified as compliant by exercising it. |
| **Short/error/uncertain outcomes** | Original operation, requested extent, original return or termination status, known partial effects, dispatch uncertainty, subsequent authorized trace, stop decision, and missing evidence. | No failure-branch, terminal, diagnostic, reporting, recovery, or similar action may repeat, complete, extend, repair, replace, replay, or otherwise substitute for the failed or uncertain governed operation, regardless of purpose. Such actions must not manufacture a substitute observation of the tested property. |

For a proposition targeting r2 §13’s F-writer constraint, the required limit is:

`RLIMIT_FSIZE soft = hard = 16,777,216`

It is established and read back before writable capability. It is a qualified operating constraint, not an arbitrary-root security boundary. This does not prescribe that setting for every experimental process or authorize changing any limit.

A case modeling Amendment 1a §6 must distinguish payload write → successful synchronization → receipt write → successful synchronization → exact payload/receipt readback and zero-suffix verification → required closure evidence. This does not create actual Q or adopt its format for experimental reporting.

The accepted durability contract and its empirical demonstration are distinct. Synchronization status and same-instance readback do not establish process- or OS-crash survival. A crash-survival proposition requires separately authorized fault execution, an originally specified post-crash observation, applicable platform premises, and an adopted continuity method consistent with §6. Without them, survival remains unestablished.

No atomicity or power-loss durability claim is added. Generic Level-2 evidence does not qualify the eventual candidate, actual writer closure, privileged custody transitions, parent suitability, or final sealing.

**4. Observation provenance**

Every relied-upon empirical observation shall remain attributable to:

1. Its governing external authorization and permitted scope.
2. The subject’s evidenced origin/admission, classification, relevant references, and identity proof basis.
3. The producer, relevant version/configuration, authorized role, and relationship to the operation.
4. The requested operation, relevant inputs/bounds, and established, disproven, or uncertain dispatch.
5. Relevant state, sequence, observation interval, and intervening operations.
6. Original result, status, partial effects, errors, conflicts, and uncertainty.
7. Material platform/configuration premises, their evidence sources, acquisition intervals, and applicability limits.
8. Acquisition, transfer, transformation, retention, integrity checks, and known omissions or loss.
9. The proposition and dependencies that the observation supports, contradicts, or leaves unresolved.

Names, hashes, serialization labels, and self-consistent records do not independently prove authority, original acquisition, identity, completeness, or currentness.

The acquisition design must explain how these relationships are established. Acquiring platform premises requires specific observation authority; copied platform labels remain attributed historical information.

**5. Closed inventory and production coverage**

The concrete design shall enumerate all relevant production and admission routes, including:

- Subjects, inputs, and experiment outputs.
- Runner, evaluator, child-process, framework, diagnostic, reporting, and teardown outputs.
- Transfer, serialization, normalization, reconciliation, accounting, and closure artifacts.
- Historical reports and other admitted evidence.
- Effects mediated by the OS, platform, framework, or execution environment.

The last category includes, where applicable, crash reports, core dumps, system-generated diagnostics, logs, snapshots, framework capture files, temporary files, and teardown artifacts.

For each relevant route, the design shall either declare its production and accounting treatment or establish an evidenced exclusion basis. It need not claim that every ambient platform object is governed; it must demonstrate the boundary rather than presume an exemption.

For each declared class, state producer, permitted operations, destination, classification, maximum instances, size bounds, reference relationships, retention obligations, and accounting treatment. Every produced/admitted object must receive a classification. Labels do not exempt material actually used as support.

Coverage must explain relevant production paths, including failure and platform-mediated paths. Reconcile actual events against those declarations. A caller-supplied inventory or the evaluated producer’s unsupported assertion cannot establish completeness.

Dynamic instances are limited to predeclared roles, operations, destinations, and reserved maxima. Uncertain creation retains its full potential charge/reservation and uncertainty; it grants no replacement.

Unexpected or unreconciled potentially governed production invokes H9: completeness is unproven, further governed dispatch stops, and dependent positive qualification is blocked. Preserve and report only within existing authority.

Apply retained policy note N4 separately: known unauthorized production, producers, or destinations remain violations for Chair disposition. Reclassification cannot retroactively authorize them, restore a terminated attempt, or supply missing observations.

No platform/framework artifact may support a positive claim unless it was declared or properly admitted under applicable authority and satisfies the remaining evidence requirements. A later admission does not cure the original violation or authorize resumed dispatch.

**6. Continuity-requirements matrix**

A required method must be concrete, separately reviewed/adopted, and covered by applicable authority. No method overrides H3/H4 termination or no-retry restrictions.

| Situation | Method requirement | Treatment |
|---|---|---|
| Successive observations through an uninterrupted established binding | No additional reopening method merely because observations repeat. | Demonstrate origin, binding continuity, relevant state changes, and interval coverage. |
| One alias closes while another proven binding remains | No additional reacquisition method solely for alias closure. | Establish the surviving binding and its interval; apply other triggering rows. |
| Pathname reopening, including while another binding survives | **Yes.** | Prove the reopened reference’s relationship to the subject and namespace history. Path equality is insufficient. |
| Loss of all established live bindings followed by intended reacquisition | **Yes, adopted before reliance.** | No continuity claim without the bounded proof and authority. A terminated domain cannot be revived. |
| Planned writer termination followed by observation | **Yes.** | The original authorized sequence must specify post-writer-loss observation and continuity. Planned termination does not silently cover an unplanned event. |
| Unexpected termination of any relevant subject, writer, child, framework component, evaluator, or runner; or OS crash/reboot | **Yes for any originally authorized post-loss reliance; otherwise none is available.** | Record the error/uncertainty, termination, and known partial effects. Stop dependent dispatch. Grant no resumption, retry, repair, or replacement. Later positive reliance is barred unless that exact post-loss observation was in the original authorized sequence and has the applicable adopted method. |
| Unexpected runner interruption/restart specifically | No method permits resumption of the terminated attempt. | Only independently authorized surviving or bounded terminal mechanisms may preserve originally authorized observations. Restarting the runner cannot reopen active dispatch or manufacture missing evidence. |
| Historical runner-to-evaluator handoff | No live-object continuity method merely for historical review; **a concrete H18 transfer/provenance contract is required**. | Preserve original acquisition, outcomes, ordering, accounting, and limitations. This general contract does not satisfy the concrete H18 requirement. |
| Live cross-process transfer within the domain | **Yes.** | Establish sender/receiver relationship, references/capabilities, intervals, and continuity. This grants no permission for writable F/Q transfer prohibited by exact sources. |
| Parent replacement with a retained leaf binding | **Yes for pathname-based observation after replacement**, under the reopening row. | A surviving leaf binding does not restore parent/path continuity. Parent replacement does not itself prove leaf recreation. Unresolved continuity conflict stops active dispatch. |
| Copy, export, excerpt, regenerated artifact, or newly serialized artifact | No method permits inheritance of the source’s live identity. | Preserve derivation and historical provenance; account separately where governed. |
| Cross-experiment use | No live identity crosses domains. | Apply historical admission/citation, lineage, currentness, and receiving-experiment accounting rules. |
| Review after domain closure | No reopening of original experimental subjects is implied. | Review retained evidence; missing original observations remain missing. |

The unexpected-termination row is not an exception to the runner rule, mandatory stop, or closed-domain prohibition. If the originally authorized post-loss observation cannot occur without prohibited resumption, substitution, or an unadopted method, it remains unavailable. The draft supplies no post-crash mechanism.

**7. Evidence transfer and producer integrity**

This contract selects no backend, runner, evaluator, transport, storage, or normalization architecture.

A concrete transfer/provenance contract shall demonstrate:

- Original acquisition, producer, authority, and observation interval.
- What was emitted, transferred, received, transformed, and retained.
- Whether artifacts are proven identical, distinct copies/derivatives, or unresolved.
- Detection and reporting of omissions, truncation, duplication, reordering, conflicting versions, regeneration/re-derivation, and selective emission.
- Preservation of original outcomes and their distinction from interpretation.
- Inventory/accounting coverage for every governed transfer and evaluator artifact.
- Independent reconstruction from retained evidence without reopening live subjects.

The production-completeness basis shall not rest solely on the producer being evaluated. A regenerated consistent record, successful parse, or matching digest cannot establish the history it purports to describe.

A legitimate, authorized derivative must be identified as a derivative and preserve its source relationships. It cannot replace original acquisition evidence or supply an observation never made.

Transfer failure grants no undeclared retransmission, replacement representation, spool, fallback store, repair, or additional capture authority.

Even if adopted, this general contract leaves the concrete H18 contract unresolved until the actual design, production coverage, transfer semantics, and provenance proof are separately reviewed and adopted.

**8. Acceptance, failure, stopping, and closure**

Reports shall distinguish:

- Admissibility of an observation.
- The claim actually established or contradicted.
- Inventory, continuity, accounting, and closure completeness.
- The combined historical conclusion.

These are semantic reporting obligations, not new F/Q fields or authority dispositions.

Positive reliance requires demonstrated applicable obligations. Preserve supported, violated, uncertain, and unobserved results distinctly. Known adverse results remain visible even when other evidence is incomplete.

Conflicts retain their sources and dependencies. They must not be averaged, silently merged, overwritten, regenerated away, or selectively omitted. Unresolved materiality/dependency is treated as material/dependent.

An unresolved continuity conflict or completeness failure terminates active dispatch and prevents overall positive qualification. Other unresolved issues block affected claims/actions. Uncertain impact receives the same conservative treatment.

The purpose-independent no-retry rule in §3 applies to every failure, terminal, diagnostic, reporting, and recovery path. Separately authorized preservation of already-acquired evidence may describe the original outcome; it may not repeat the failed operation or manufacture a substitute observation.

Stopping cannot depend on successful future capture. Only expressly preauthorized bounded terminal actions may follow. Failure grants no new inspection, capture, cleanup, or recovery authority.

Closure shall record declared/actual scope, original outcomes, partial effects, missing evidence, conflicts, inventory reconciliation, charges, stop reason, preservation state, and limitations. Complete reporting does not mean experimental success.

Physical validity, synchronization, closure, and custody are separate predicates. Later review cannot manufacture missing original evidence.

Where closure cannot fit or complete, preserve available evidence and record incomplete closure only through already authorized bounded means. Reporting failure neither delays stopping nor converts the outcome to a pass.

**9. Lineage, replication, and concurrent interference**

Lineage shall be reconciled against the applicable authorization/disposition history, with accessible evidence references and original outcomes.

Apply §2’s distinction between incidental changes, material changes, distinct propositions, and material overlap. A combined record is not permission to transfer a favorable result across incompatible mechanisms or premises. Explain every applicability distinction.

Include applicable earlier and concurrent attempts, including failed, uncertain, conflicting, and incomplete ones. Uncertain relevance requires inclusion with explanation. An assertion of no earlier attempts is insufficient without reconciliation.

Except for H4’s predetermined replication exception, later attempts require the earlier attempt to stop, closure to be available, Chair disposition, and new specific authority. Failure-conditioned advance authority, renaming, or concurrency cannot evade this rule.

Predetermined replication requires finite, advance-fixed justification, cases, domains, allocations, reporting, and stop conditions independent of individual outcomes. It cannot add repetitions because of unfavorable results or stop merely at the first success. Preserve every attempted repetition and applicable safety, provenance, completeness, capacity, and authority stops.

Any concurrent design must identify shared-host, namespace, process, resource, and evidence-production interference; establish its applicability and bounds; preserve cross-domain event attribution; and stop dependent dispatch where interference or provenance remains unresolved.

This contract grants no concurrent execution authority. A proposed schedule must demonstrate specific H4-compliant authority. Unresolved eligibility blocks dispatch.

H1–H20 does not expressly establish the reviewer’s proposed universal rule that every concurrent overlapping attempt must be replication. This draft does not add that blanket rule or infer permission for other concurrency. Any such policy resolution remains a separate Chair decision.

**10. Accounting, imported evidence, and later review**

Every specifically authorized experiment has a separately stated allocation, bounded independently by:

| Experimental support limit | Ceiling |
|---|---:|
| Object count | 128 |
| Bytes per object | 65,536 |
| Aggregate bytes | 4,194,304 |

This draft allocates nothing. Lower authorized bounds remain controlling.

Reserve worst-case cumulative demand across all permitted paths through closure, including uncertain creation, admitted inputs, platform/framework outputs, transfers, evaluator outputs, normalization, inventory reconciliation, accounting, reporting, and failure/terminal evidence. Mutually exclusive paths may share a maximum only where exclusion is established; incurred charges never disappear.

Repeated proven references may count once. Distinct creations, replacements, copies, derivatives, and governed containers count separately. Packaging does not merge charges. Each object retains its maximum incurred charge. Deletion, shrinking, phase change, domain termination, or branch selection provides no refund or transferable capacity.

Conservative separate accounting can establish only a provisional bound where population and sizes are known. It cannot establish identity, provenance, completeness, or permission to continue.

Exceeding a reservation or ceiling is an H11 capacity failure. It grants no permission to enlarge allocation, split a report to evade bounds, truncate required evidence, borrow capacity, or create a replacement representation. Where closure cannot complete, §8 applies.

A historical report actually relied upon must be admitted and charged. A citation alone does not admit its source, but citation terminology cannot hide substantive reliance or adverse lineage.

An oversized required historical input is a capacity failure. It may not be replaced by a selectively favorable excerpt, split, or substitute representation to evade the bound. Excerpts genuinely permitted by a separately justified narrower proposition remain distinct governed derivatives; they must not conceal relevant adverse content or replace required source access. If required evidence cannot be lawfully admitted and preserved within bounds, the dependent claim remains blocked.

**Later review artifacts** are produced **after the experiment domain closes**, under separate authority. Their own charges do not reopen the closed allocation.

All evidence required for the experiment’s acquisition, admissibility, transfer, normalization, reconciliation, accounting, reporting, or closure belongs in the experiment’s governed support reservation, regardless of producer or label. Deferring required production until after closure does not convert it into exempt later review; the experiment’s missing obligation remains unmet.

Retained H-policy notes N1–N6 remain applicable: concurrent lineage, no first-pass selection, explicit attempt relationships, no retroactive authority through classification, separately authorized platform-premise acquisition, and combined allocation visibility for multi-experiment authority. The proposed concurrent-lineage and no-first-success wording is a contract-level refinement for explicit Chair consideration, not an amendment already inserted into H1–H20.

Experimental accounting does not consume, replenish, enlarge, or replace actual lifecycle accounting. Later admission into actual lifecycle support requires that lifecycle’s own authority and accounting.

**11. Operational separation and attributed gate status**

Level-2 conclusions apply only to demonstrated disposable mechanisms, subjects, intervals, fault conditions, and platform premises.

They do not establish actual F/Q/O identity, qualification, custody, parent suitability, candidate correctness, restoration, release, service authority, or operational admissibility. Relabeling, copying, matching bytes, or citation cannot promote them.

This draft changes no gate disposition and is not an independent status record. The November 3 handoff, continued by the November 6 resume instructions, reports B5 G1 **HOLD**, G2 unopened, the B5 host-observation envelope undesigned, both P0 candidates **NOT QUALIFIED**, Approval B unauthorized, and V2-2B implementation/execution unauthorized. No contrary disposition is established here.

The subject/destination exclusions in §1 apply throughout. No operational inspection or actual-object qualification is performed by this drafting.

**12. Remaining prerequisites**

Before implementation or execution can be considered, separate work and authority remain necessary for:

1. Concrete case selection, exact source-to-case mapping, and independent expected outcomes.
2. Acquisition and interpretation methods, including negative-case coverage.
3. Every applicable continuity proof and any post-loss observation architecture.
4. Backend selection and the concrete H18 transfer/provenance contract.
5. Complete production-route analysis, including platform/framework effects and exclusions.
6. Finite inventories, reservations, imported-evidence fit, and closure bounds.
7. Platform-premise acquisition, any fault execution, and concurrent-interference controls.
8. Exact disposable paths, processes, capabilities, operations, stops, retention, and any cleanup/release arrangements.
9. Applicable P0 and Approval B prerequisites under the governing sequence.
10. Eligible independent review, Chair architectural adoption, and separate specific implementation/execution approvals.

No disputed source interpretation may be silently resolved by implementation. The blanket concurrency restriction identified in §9 remains a policy question, not a prerequisite this author has adopted.

**13. Independently retrievable normative sources**

The complete preserved source messages are in this existing local archive:

[Preserved source transcript](/Users/aclab/.codex/sessions/2026/10/25/rollout-2026-10-25T06-03-33-01a17328-c2be-7930-aa54-f5f668900d59.jsonl.zst)

Absolute locator:

`/Users/aclab/.codex/sessions/2026/10/25/rollout-2026-10-25T06-03-33-01a17328-c2be-7930-aa54-f5f668900d59.jsonl.zst`

| Source | Exact record/message selector | Governing portion |
|---|---|---|
| r2 | JSONL `ordinal: 303`; decompressed record line 304; message `msg_0e71e34095ccc4de016ade20d4c7488190a647e7411cef9cf4` | **Part II — Complete consolidated specification** |
| Final Amendment 1a | JSONL `ordinal: 611`; decompressed record line 612; message `msg_0e71e34095ccc4de016ade53b724d88190a94e4eb4d86951d1` | **H. Consolidated final amendment text**, followed by `mcl-d0009-m0-custody-amendment-1a` |

The enclosing chat is [the preserved source chat](codex://threads/01a17328-c2be-7930-aa54-f5f668900d59). The archive and exact selectors above are the verified retrieval route; a chat preview is not a substitute for the complete message.

Complete message SHA-256 values:

- r2: `b9a1ce67aa5c8050a95de324969a25046f13d2f6e4bf56f92832dea96fce6b05`
- Amendment 1a: `9869dd6ec374677a8150de725e05e705bc4ac8798ec5b7b20ed705e0a6f49144`

A reviewer with authorized access to the same preserved archive can use this read-only extraction in the existing Python 3.14 environment. It writes the selected complete source message to standard output and creates no file. Set `which` to either source name.

```python
import hashlib
import json
import sys
from compression import zstd

which = "r2"  # or "amendment1a"
archive = (
    "/Users/aclab/.codex/sessions/2026/10/25/"
    "rollout-2026-10-25T06-03-33-"
    "01a17328-c2be-7930-aa54-f5f668900d59.jsonl.zst"
)
sources = {
    "r2": (
        303,
        "msg_0e71e34095ccc4de016ade20d4c7488190a647e7411cef9cf4",
        "b9a1ce67aa5c8050a95de324969a25046f13d2f6e4bf56f92832dea96fce6b05",
    ),
    "amendment1a": (
        611,
        "msg_0e71e34095ccc4de016ade53b724d88190a94e4eb4d86951d1",
        "9869dd6ec374677a8150de725e05e705bc4ac8798ec5b7b20ed705e0a6f49144",
    ),
}
ordinal, message_id, expected = sources[which]
with zstd.open(archive, "rt") as stream:
    for line in stream:
        record = json.loads(line)
        if record.get("ordinal") != ordinal:
            continue
        payload = record["payload"]
        assert payload["id"] == message_id
        text = "".join(
            item["text"]
            for item in payload["content"]
            if item.get("type") == "output_text"
        )
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == expected
        sys.stdout.write(text)
        break
    else:
        raise RuntimeError("Required preserved source message not found")
```

The reviewer must retrieve and inspect the text, not accept a digest or this author’s verification table as substantive proof. If access fails, specification fidelity remains independently unverified; no installation, copying, upload, or alternative disclosure is authorized by this recipe.

**14. Refreshed source-verification and requirement map**

Both complete message digests were rechecked during this correction pass. The clauses below were independently reread by the author. Line numbers refer to the **extracted complete message text**, not the compressed file.

| Exact source and location | Relevant excerpt | Draft 2 use |
|---|---|---|
| r2 Part II §9, lines 612–701; “Supporting material,” 683–693 | “128 objects”; “65,536 bytes per object”; “4,194,304 bytes aggregate.” | §10 distinguishes actual-lifecycle limits from H10’s separately adopted experimental ceilings. |
| r2 §13, lines 878–902 | “RLIMIT_FSIZE soft = hard = 16,777,216”; “before acquiring writable capability”; “not an arbitrary-root security boundary.” | §3 resource-limit proposition and limits of the claim. |
| r2 §13, lines 890–902 | “Only the creation/allocation phase establishes size/allocation.” “Qualification uses separately authorized disposable objects, never F.” | §§1, 3, 11: allocation scope and actual-F exclusion. |
| r2 §14, lines 904–937 | “one identified writer process and one intended F writable descriptor”; “No duplicate/transfer, writable mapping, fork, exec, or subprocess.” | §3 full write-capability coverage; §6 transfer prohibition. |
| r2 §14, lines 908–926 | “bounded self-descriptor inspection”; “No secondary writer thread or reentrant signal-handler writer.” | §3 bounded inspection, lifecycle and concurrent-capability coverage. |
| r2 §15, lines 939–951 | “A short write, error, or uncertain result stops the affected ordinary log/terminal area. Do not fill a suffix or retry.” | §§3, 8 purpose-independent failure handling. |
| r2 §15, lines 945–949 | “Successful records require the accepted synchronization and exact readback”; neither valid bytes nor listed mechanisms prove atomicity, historical synchronization, or power-loss durability. | §3 synchronization/readback boundary. Crash-survival evidence is an additional proposed evidentiary obligation, not an assertion that these observations prove survival. |
| Amendment 1a §3, lines 174–227; especially 201–209 | “same regular file” with bound device, inode/FILEID, “expected link count of one, size, and parent relationship.” | §3 Q-derived type/link/stability requirements and §6 continuity. These are not claimed as a universal property of negative-test link subjects. |
| Amendment 1a §3, lines 219–227 | “Writable descriptor transfer, unintended inheritance, writable mappings, asynchronous writes, and concurrent writers are prohibited.” | §3 capability surface and §6 transfer limits. |
| Amendment 1a §6, lines 457–487; steps at 470–477 | “Require successful `fsync(Q)`” before and after receipt writing; then exact payload/receipt readback, zero suffix, and closure evidence. | §3 capture-order mapping. |
| Amendment 1a §6, lines 481–487 | “Valid bytes do not establish that either synchronization completed.” “Do not fill a missing suffix, rewrite a receipt, retry in another cell, replace Q, or replay the producing operation.” | §§3, 7, 8: evidence boundaries and no substitute execution. |
| Amendment 1a §7, lines 489–534 | “Uncertain dispatch is not proof of non-dispatch”; “physical validity and durability/closure status as distinct predicates.” | §§4, 8: missing output, physical validity, dispatch and closure. |
| Amendment 1a §8, lines 536–555 | “Do not depend on a new successful Q capture”; “Do not reconstruct missing observations afterward.” | §§6, 8: independent stopping and unavailable observations. |

Additional governing mappings:

| Contract requirement | Governing basis |
|---|---|
| Proposition identity and materially overlapping lineage | H14; H13; retained policy N1 |
| No-retry, termination and replication | H3–H4; H7; H13 |
| Identity and continuity | H2; H5–H7; H15–H18 |
| Production coverage, platform-mediated effects and reconciliation | H5; H8–H9; H13; retained policy N4 |
| Experimental accounting and closure obligations | H8; H10–H12; H16–H17 |
| Platform-premise authority/currentness | H15; H17; retained policy N5; Lifecycle Bindings Part C §§8, 10 |
| Review eligibility and renewed review | Decision 0010 rules 1–7 |
| Remaining gates and authority | H19–H20; accepted plan §§D, E, N |

The exact r2/Amendment texts do not specify SIGXFSZ/EFBIG expectations or the complete negative-case experiment matrix. Those are explicitly proposed coverage obligations arising from this correction, with concrete platform semantics and case applicability still requiring source-supported design and separate authority.

**15. B1–B9 author closure table**

“CLOSED” means the identified defect has been corrected in this candidate by author assessment. It is not an independent acceptance disposition.

| Finding | Corrected section | Exact correction | Source basis | Author assessment |
|---|---|---|---|---|
| B1 Proposition identity | §§2, 9 | Incidental changes distinguished from material changes; distinct claims evaluated separately; material overlap and changed premises remain visible. | H13–H14; retained policy N1 | **CLOSED** |
| B2 Purpose-limited no-retry | §§3, 7–8 | Purpose limitation removed; all failure/terminal/diagnostic/reporting/recovery substitutes barred. | H3–H4, H13; r2 §15; Amendment §§6, 8 | **CLOSED** |
| B3 Exclusivity unexercised | §3 | Requires relevant exercised pre-existing-target and final-link negative cases; otherwise narrows the claim. | H15, H18; proposed review-directed coverage; r2 §14 reference rules | **CLOSED** |
| B4 Crash-durability overclaim | §§3, 6 | Current ordering/status/readback separated from survival; fault, post-crash observation and continuity prerequisites explicit. | H7, H15, H19; r2 §15; Amendment §§6–7 | **CLOSED** |
| B5 Descriptor-only exclusion | §3 | Covers mappings, asynchronous/concurrent activity, writer count, inheritance, passing and intervals. | r2 §14; Amendment §3 | **CLOSED** |
| B6 Unexpected termination | §6 | Explicit all-relevant-process/OS-loss row; dependent stop, original-sequence requirement, no resumption/substitution. | H3–H4, H7, H13, H15 | **CLOSED** |
| B7 Later-review accounting | §10 | After-closure/separate-authority definition; all required experiment evidence charged regardless of producer or label. | H8, H11, H15–H16 | **CLOSED** |
| B8 Platform-mediated production | §§5, 10 | Declared routes or evidenced exclusions; H9 handling, N4 violations and admission limits. | H5, H8–H9, H13; retained policy N4 | **CLOSED** |
| B9 Source retrievability | §§13–14 | Existing archive path, exact record/message selectors, full-text extraction, digests, clause locations and excerpts. | Preserved complete normative messages; accepted-plan source identities | **CLOSED — local retrieval verified; next reviewer’s retrieval remains pending** |

**16. N1–N11 disposition table**

These numbers refer to the Draft 1 review notes, not the older policy’s retained N1–N6.

| Review note | Disposition | Result or reason |
|---|---|---|
| N1 Status attribution | **Incorporated** | §11 changes no status and attributes historical dispositions to the handoff; no independent status record claimed. |
| N2 Actual-object exclusions | **Incorporated** | §§1, 11 expressly exclude actual F/Q/O, actual parents, protected objects and P0 candidates as subjects/destinations. |
| N3 Type/link/stability | **Incorporated with source limits** | §3 includes relevant state and interval proof; Amendment §3’s regular-file/link-one condition is accurately scoped. |
| N4 Resource-limit effects | **Incorporated as coverage requirements** | §3 requires applicable signal/error, inheritance and partial-write treatment, linked to failure and termination rules. No unsupported platform outcome is asserted. |
| N5 Parent replacement/reopening | **Incorporated** | §6 explicitly says **Yes** for pathname-based observation after replacement and applies the reopening method requirement. |
| N6 Concurrency-only-as-replication; interference | **Partly incorporated** | §9 adds interference, attribution and H4-authority checks. The universal replication-only restriction is not explicitly established by H1–H20; it requires separate Chair policy consideration. No other concurrency is authorized or presumed permissible. |
| N7 Regeneration/selective emission | **Incorporated** | §7 names these threats; production completeness cannot rest solely on the evaluated producer. |
| N8 Concrete H18 contract | **Incorporated** | §§1, 6–7, 12 explicitly retain the concrete design’s separately adopted transfer/provenance contract prerequisite. |
| N9 Capacity consequences | **Incorporated** | §10 states H11’s no enlargement, splitting, truncation, borrowing or replacement consequences. |
| N10 Oversized/adverse historical evidence | **Incorporated** | §10 treats required oversized input as capacity failure and prohibits selective excerpts or substitutes used to evade limits or hide adverse evidence. |
| N11 Knowing adoption of contract refinements | **Incorporated as disclosure** | §10 identifies concurrent-lineage and no-first-success provisions as proposed contract-level refinements. They do not silently amend H1–H20; their review-origin contribution history must be disclosed. |

**17. Change log from Draft 1**

- Corrected proposition identity and related-lineage treatment.
- Removed the purpose test from no-retry and barred disguised substitute operations.
- Added required exclusivity negative-case coverage.
- Separated synchronization/current readback from crash-survival evidence.
- Expanded descriptors to the full relevant write-capability surface.
- Added unexpected process/OS termination and explicit parent-replacement reopening treatment.
- Closed evaluator/later-review accounting gaps.
- Added platform-mediated production, exclusion proofs and violation handling.
- Added regeneration/selective-emission controls and the unresolved concrete H18 prerequisite.
- Clarified historical-evidence capacity failures and gate-status attribution.
- Supplied retrievable complete normative sources, exact selectors, excerpts and refreshed verification.
- Flagged N6’s blanket concurrency restriction rather than silently adopting it.

No backend, experiment mechanism, implementation, or new operational workstream has been selected.

**18. Next eligible independent review and stopping point**

The next review must cover the exact Draft 2 candidate, source retrieval and specification fidelity, B1–B9 corrections, each N-note disposition, and the unresolved N6 policy point.

The reviewer should re-examine the prior adversarial scenarios, especially:

- Material mechanism changes that incorrectly merge evidence or evade lineage.
- Diagnostic/terminal operations that substitute for failed work.
- Exclusivity without exercised collision/link cases.
- Synchronization/readback promoted to crash survival.
- Surviving mappings or asynchronous capability after descriptor closure.
- Unexpected writer, evaluator, framework or OS loss.
- Undeclared platform outputs and selective producer emission.
- Evaluator evidence charged as later review.
- Oversized historical reports with adverse content omitted.
- Concurrency used to evade H4 or obscure interference.
- Source access failure presented as specification verification.

Decision 0010 eligibility must be established using actual author/reviewer model-family evidence and substantive contribution history. A Codex URL or role name alone is insufficient. The supplied Opus review’s eligibility conclusion is reported input, not independently ratified here.

Disclose the prior Opus findings and incorporated recommendations. If any reviewer substantively revises the candidate, apply Decision 0010’s contributor and renewed-review rules. Do not automatically assume that a prior reviewer remains eligible for every part of the revised artifact.

No reviewer has been contacted or invoked. Author closure does not establish independent approval. Human Chair consideration, architectural adoption, recording, implementation, execution and all later gates remain separate.

**Stop: Draft 2 is delivered for Human Chair review only.**
````
<!-- END VERBATIM ADOPTED DRAFT 2 -->

## Appendix A — Complete supplied Kimi K3.1 Pro qualifying review

The following source text is preserved verbatim. Its supplied SHA-256 is `8282deaf3a239fe585bacf024d1ca343db75839dd0228fcb7a9ebeeaf31aaf31`. Its eligibility and acceptance findings are the independent review's recorded determinations, accepted by the Human Chair; this recording is not a new independent review.

<!-- BEGIN VERBATIM KIMI REVIEW -->
````text
ACCEPT WITH NON-BLOCKING NOTES
A. Reviewer eligibility
- Exact model: Kimi K3.1 Pro, model ID moonshotai/kimi-k3.1-pro, supplied through OpenRouter.
- Underlying foundation-model family: Moonshot AI Kimi.
- Operating as a Kimi/Moonshot AI family model: Yes.
- Contribution history: Neither I nor the Kimi/Moonshot family is identified in the supplied lineage as a substantive contributor to Draft 1, Draft 2, adopted H1–H20, or the incorporated B1–B9/N1–N11 findings. Those contributions are attributed to Astra/OpenAI and Claude Opus/Anthropic. Muse Wonder/Meta’s subsequent review was not used as evidence of correctness. I have not revised Draft 2.
Decision 0010 conclusion: The runtime model-identity evidence and supplied substantive-contribution history establish family separation from every identified contributing family. I am eligible to perform this whole-document qualifying review. This satisfies the reviewer-side requirement; Human Chair authority remains separate.
B. Normative-source verification
Read-only retrieval from the supplied archive succeeded. Both complete messages were inspected, including all specifically requested sections.
Source	Retrieval and integrity result
r2	Ordinal 303, decompressed record line 304, message ID msg_0e71e34095ccc4de016ade20d4c7488190a647e7411cef9cf4; 1,190 lines inspected. SHA-256 independently computed as b9a1ce67aa5c8050a95de324969a25046f13d2f6e4bf56f92832dea96fce6b05 — matched.
Final Amendment 1a	Ordinal 611, decompressed record line 612, message ID msg_0e71e34095ccc4de016ade53b724d88190a94e4eb4d86951d1; 960 lines inspected. SHA-256 independently computed as 9869dd6ec374677a8150de725e05e705bc4ac8798ec5b7b20ed705e0a6f49144 — matched.
Also inspected the adopted H1–H20 transcription and retained N1–N6, Decision 0010, implementation-plan §§B, D1, E, M, N–R, and Lifecycle Bindings Part C §§8 and 10.
Material discrepancies: None found in Draft 2’s specification-dependent claims. In particular:
- The experimental ceilings are correctly attributed to H10, not inherited from r2’s operational support limits.
- The RLIMIT_FSIZE, writer-topology, no-retry, Q capture-order, link-count, and closure distinctions match the exact sources.
- Draft 2 correctly identifies SIGXFSZ/EFBIG expectations and the complete negative-case matrix as proposed coverage obligations, not semantics supplied by r2 or Amendment 1a.
- Its additional crash-survival evidence requirement is presented as an evidentiary requirement, not as a claim that fsync plus readback already proves survival.
- Historical gate-status statements match the November 3 handoff; this review did not independently requalify those statuses.
C. B1–B9 closure table
Finding	Disposition	Reason and affected sections
B1 — Proposition identity	CLOSED	§§2 and 9 distinguish incidental and material changes, separately evaluate distinct propositions, retain materially overlapping and concurrent lineage, and prevent favorable transfer or adverse-history escape.
B2 — No retry	CLOSED	§§3, 7, and 8 make the prohibition purpose-independent. Diagnostic, terminal, reporting, recovery, preservation, cleanup, troubleshooting, or similar labeling cannot authorize a repeated or substitute governed operation.
B3 — Exclusive creation	CLOSED	§3 requires relevant exercised pre-existing-target and applicable symbolic, dangling-symbolic, and hard-link cases, or an evidenced rationale with a narrowed proposition. Empty-location success is expressly insufficient.
B4 — Synchronization versus crash survival	CLOSED	§§3 and 6 separate synchronization/current readback from survival and require authorized fault execution, originally specified post-crash observation, platform premises, and an adopted continuity method. No post-crash mechanism is claimed.
B5 — Write capability	CLOSED	§3 covers descriptors, mappings, asynchronous/concurrent activity, writer count, library/thread/signal paths, inheritance, passing, and intervals. A clean descriptor table is explicitly insufficient.
B6 — Unexpected termination	CLOSED	§6 covers relevant subject/process/framework/evaluator/runner/OS loss, binding loss, reopening, and reacquisition. It bars resumption and post-loss positive reliance without original authorization and an applicable adopted method.
B7 — Later-review accounting	CLOSED	§10 charges all experiment-required evidence regardless of producer or label. Later review is limited to genuinely post-closure artifacts under separate authority.
B8 — Platform/framework production	CLOSED	§§5, 8, and 10 require declared/accounted routes or evidenced exclusions, including failure and platform-mediated paths. Unexpected potentially governed production invokes fail-closed H9 handling.
B9 — Normative-source fidelity	CLOSED	Independent complete-message retrieval, ID/hash verification, and clause inspection succeeded. Draft 2’s source references and qualifications are materially accurate.
D. N1–N11 assessment
Note	Assessment	Chair attention
N1	Status attribution is properly source-bound and non-authoritative.	None beyond ordinary review.
N2	Actual-object and P0 exclusions are explicit and preserved throughout.	None.
N3	Type/link/stability requirements are included with correct Amendment-1a scoping.	None.
N4	Resource-limit effects are required coverage, not unsupported assertions of platform semantics.	Concrete semantics remain a §12 design prerequisite.
N5	Parent replacement correctly triggers the pathname-reopening requirement.	None.
N6	Partly incorporated is the accurate disposition. Interference and lineage controls are present; the blanket replication-only rule is not established by the governing text.	Yes — see concurrency determination below.
N7	Regeneration, selective emission, and producer-integrity threats are adequately addressed.	None.
N8	The concrete H18 contract remains expressly unresolved and separately required.	Adoption must not be represented as satisfying it.
N9	Capacity-failure consequences are complete and consistent with H11.	None.
N10	Oversized/adverse historical evidence cannot be evaded through favorable excerpts or substitutes.	None.
N11	The refinements and their proposed/non-H1–H20 status are disclosed.	Yes — adoption should knowingly record the refinements and their review-origin contribution history.
E. Concurrency determination
C. H1–H20 leave the issue genuinely ambiguous, and a separate Human Chair policy decision is required before non-replication concurrent materially overlapping attempts may be authorized.
H4 expressly governs later attempts and predetermined replication. H14’s lineage wording concerns “earlier attempts,” while retained N1 expressly identifies the concurrent-attempt edge. Neither text affirmatively authorizes another concurrent architecture nor expressly states the reviewer’s proposed universal replication-only restriction.
Does this block adoption of the general Draft 2 contract? No. Section 9 grants no concurrency authority, requires H4-compliant specific authority and interference controls, blocks unresolved eligibility, and reserves the blanket-rule question for the Chair. Predetermined replication remains available only under H4.
F. Adversarial results
#	Scenario	Result and principal safeguard
1	Material change merges favorable evidence	PASS — §§2, 9: separate evaluation; no automatic transfer.
2	Material change escapes adverse lineage	PASS — §§2, 9: overlapping claims and adverse history retained.
3	Failed attempt renamed as new work	PASS — §§2, 9: labels and incidental changes do not change proposition identity.
4	Retry disguised as diagnostics	PASS — §§3, 8: purpose-independent prohibition.
5	Retry disguised as terminal reporting/recovery	PASS — §§3, 8: no substitute operation; terminal actions must be preauthorized and non-repeating.
6	Exclusivity without negative cases	PASS — §3: exercised coverage or narrowed proposition required.
7	fsync plus readback promoted to crash survival	PASS — §§3, 6: survival remains unestablished without separate prerequisites.
8	Writable mapping survives descriptor closure	PASS — §3: mappings and full capability intervals must be addressed.
9	Async/concurrent write survives apparent closure	PASS — §3: asynchronous/concurrent activity and writer topology required.
10	Inheritance or descriptor transfer preserves capability	PASS — §§3, 6: fork/exec, passing, inheritance, and live transfer covered.
11	Unexpected writer death followed by reacquisition	PASS — §6: no resumption or continuity claim without original authorization and adopted proof.
12	OS crash/reboot followed by pathname reopening	PASS — §§3, 6: reopening and post-loss rules apply; no mechanism is presumed.
13	Runner restart resumes terminated work	PASS — §6: expressly prohibited.
14	Evaluator/report evidence moved outside accounting	PASS — §10: required evidence remains charged regardless of label.
15	Platform/framework artifact omitted	PASS — §5: declaration/evidenced exclusion and H9 failure handling.
16	Producer regenerates or selectively emits favorable evidence	PASS — §§5, 7: independent completeness basis and derivative/source preservation required.
17	Transfer omits, truncates, or reorders adverse evidence	PASS — §§7, 8: detection, reporting, conflict preservation, and blocked reliance.
18	Matching digest or valid parse promoted to completeness	PASS — §§4, 7: neither establishes acquisition history or completeness.
19	Oversized history replaced by favorable excerpt	PASS — §10: capacity failure and anti-evasion controls.
20	Predetermined replication stops after first success	PASS — §9: outcome-independent stops and no first-success termination.
21	Unfavorable repetition omitted	PASS — §§8, 9: every attempted repetition and original outcome preserved.
22	Concurrency obscures attribution or becomes hidden retry	PASS — §§2, 9: concurrent lineage, attribution, H4 controls, and no execution authority.
23	Shared-host/namespace interference remains unresolved	PASS — §9: dependent dispatch stops.
24	Uncertain creation refunded or replaced	PASS — §§5, 10: full potential charge retained; no replacement.
25	Packaging/compression merges charges	PASS — §10: distinct objects and containers remain separately charged.
26	Reporting failure delays mandatory stop	PASS — §8: expressly prohibited.
27	Missing evidence reconstructed after closure	PASS — §§6, 8, 10: later review cannot supply original observations.
28	Actual F/Q/O or P0 candidate used disposably	PASS — §§1, 11: expressly prohibited.
29	General contract treated as concrete H18 satisfaction	PASS — §§1, 6, 7, 12: expressly rejected.
30	Draft 2 treated as implementation/execution authority	PASS — §§1, 11, 12, 18: no such authority follows.
No additional adversarial scenario was necessary beyond those specified.
Authority boundary
Draft 2 grants none of the prohibited authorities: repository/file mutation, Git mutation, backend selection, implementation, test/experiment execution, filesystem effects, host/platform observation, P0 inspection, B5 progression, Approval B, F/Q/O creation or qualification, custody transition, cleanup/release, or successor authority. Its conditional future requirements do not accidentally expand authority. This review likewise grants no implementation or execution authority.
G. New blocking findings
NONE.
H. Non-blocking notes
1. The Chair must separately resolve the N6 concurrency ambiguity before authorizing non-replication concurrent materially overlapping attempts.
2. The adoption record should expressly acknowledge the concurrent-lineage and no-first-success refinements and preserve their Opus/review-origin contribution history.
3. Architectural adoption must not be represented as satisfying the concrete H18 contract, continuity methods, production inventory, platform-premise acquisition, case matrix, or other §12 prerequisites.
I. Recommendation to Human Chair
Draft 2 is ready for Human Chair architectural adoption as written, subject to the non-blocking notes above. Adoption should be expressly architecture-only and should preserve every existing gate, operational exclusion, concrete-design prerequisite, and separate implementation/execution approval requirement.
Mutation confirmation: No mutation occurred during this review. I performed only read-only archive extraction and inspection of existing governance sources. I did not edit or create files, alter the archive, mutate Git, install software, run experiments or tests, create experimental objects, acquire new host/platform observations, inspect P0 candidates, reopen B5, perform cleanup, or assume successor authority.
Build · Kimi K3.1 Pro · 2m 22s · 155.4 tok/s
Build·Kimi K3.1 ProOpenRouter
~
````
<!-- END VERBATIM KIMI REVIEW -->

## Recording stopping point

This file records the adopted architecture and its review provenance under the separate one-file creation authorization. It grants no successor authority. Present the exact new-file boundary and preservation verification to the Human Chair, then stop. Staging, commit, push, implementation, experiments, operational actions, cleanup, and release remain separately unauthorized.
