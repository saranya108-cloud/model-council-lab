# Decision 0009: Candidate Pre-Gate V2-2B Requirements and Closure Architecture — Opus Successor

**For:** Amy, Human Chair · **Date:** November 12, 2026 (Human Chair local date)
**Author (architect):** Claude Opus 5.5, model ID `claude-opus-5-5`, Anthropic / Claude family. This identity is self-reported by the session; independent lineage evidence is outside this artifact.
**Supersedes, as a candidate only:** Fable 5.2, *Decision 0009: Candidate Pre-Gate V2-2B Requirements and Closure Architecture*, 49,516 bytes, SHA-256 `f1e733547de7c53d2efe0647cc659d850d41118f6a51936605445e0f6df984cc` (Astra disposition: **REVISE**).
**Controlling sequencing architecture:** Sequencing Architecture Revision 4, SHA-256 `fbd2790d9e58dad673ca996487ba63413233c82c7c07d0f80533a32062096c4c` (adopted; Option 1, bounded scope split).
**Status:** non-adopted Category 2 candidate, produced under the bounded Opus-takeover assignment. Chat-delivered and architecture-only, it returns for whole-artifact cross-family review. It is not self-certified.

---

## A. Executive conclusion

**1. The central proposition holds, on my own reading of the sources.** A useful, abstract, backend-neutral set of broader V2-2B requirements can be stated before P0 and Approval B. I reach this independently. The Level-2 Evidence Contract and H1–H20 apply to every V2-2B disposable Level-2 experiment by their own terms (Contract §1; H1), so a large body of obligations already governs any broader profile. The adopted narrow-profile architecture (H18 Draft 4, Register Draft 4 and the §3.2 / PO-03 clarification) supplies tested semantics that can be stated abstractly for an arbitrary finite schedule without protected facts. Revision 4 provides the category boundary, the reliance-and-effects test and the §F classification rule needed to keep such work abstract. Three qualifications apply:

- what can be fixed now are **statements**; nearly every **binding** (cases, schedule, mechanisms, routes, allocations, oracles) waits on a gate, a selection, concrete-design closure or evidence;
- statements derived from the narrow profile govern broader scope **only after their own review and your adoption**, and they never reinterpret the narrow profile;
- until you adopt closure arrangements for broader scope, no formal feasibility showing or selection for that scope can be completed, because there is no standard to meet.

**2. Three kinds of statement are separated.** They are faithful restatements of generally applicable adopted text (**A0**), faithful generalizations of adopted narrow-profile semantics (**A1-G**), and new Category 2 rules with no adopted analogue or a deliberately different strength (**A1-N**). Every A1-N rule is identified and justified. I label nothing A0 unless the controlling clause already reaches broader scope by its own terms.

**3. Lifecycle (B1) is rebuilt from the adopted text.** It is not a patch of Fable's wording. The successor catalogue keeps distinct the definite-dispatch and possible-dispatch-only entries into `IN_FLIGHT`; exit by original completion; the limited non-dispatch resolution, which requires both a historical non-crossing showing and a showing that the same operation can no longer cross; permanent attempt ineligibility; the attempt-wide obstruction to `Q`; frozen reporting dispositions; terminal-action eligibility; and three separate late-return mechanisms. Those mechanisms are capability-admission closure, original-return capture and frozen-disposition finality. Post-loss evidence restrictions apply throughout. The generalization is faithful, and no stricter or looser variant is introduced (§E group II; §O).

**4. Concurrency (B2) is split into three questions.** Policy dependency **P** attaches only to determination C, which covers non-replication concurrent attempts that materially overlap. Overlapping subject operations inside one attempt remain prohibited by the serial-dispatch requirement. Any broader proposition that needs such overlap is **blocked under the retained architecture**. It does not wait on policy. Predetermined replication remains under H4 and Contract §9 (§H).

**5. Historical evidence (B3) can cross domains as evidence, under the receiving domain's own rules.** Live identity, capacity, qualification status and acceptance never cross. Admitting historical evidence is not in itself a Category 3 act (§I).

**6. Category 3 and general-policy change (B4) are classified by effect.** Evaluating E3 independently is already provided for by PO-01 when its oracle package is bound before the first governed effect. A Category 3 trigger arises only where an E3 treatment would change an adopted narrow-profile rule, bound or constant. Changing H10's ceilings, the Contract or the categorical gate order is a general governance amendment, not a narrow-profile revision (§N).

**7. The closure model in §F is a candidate dependency model.** It is not a ladder. It separates exploratory comparison, which closes nothing, from formal closure, and the Approval B **read** from post-read **tailoring**. It keeps one conditional ordering: if a credible feasibility showing for some obligation cannot be made without a protected-interface fact, then that showing, and any selection that relies on it, must wait until the fact has been lawfully acquired. It does not generalize that ordering into a rule that all selection follows Approval B.

**8.** Checked against Revision 4, the candidate is **consistent with it**. It **triggers nothing in Category 3** and **proposes no general-policy amendment**.

---

## B. Source basis and limitations

### B.1 Repository baseline (read-only; no fetch)

| Observation | Result |
|---|---|
| Branch | `m1-live-adapter-dev` |
| Local HEAD and cached tracking ref | `42a8c597502a8e6d4c946ad583220ba036271f6b` (both) |
| `git status --porcelain` (default compact untracked-directory mode) | 17 entries |
| `git status --porcelain --untracked-files=all` | 24 entries |
| Staged changes | none |
| Live remote | not verified |

The two counts reflect the enumeration mode only, as the handoff records. This is not divergence. I did not modify, stage or reconcile anything.

### B.2 Controlling sources and how far I read them

In the table, `…/` abbreviates `docs/governance/decision-0009/`.

| Source | Location (repository-relative unless stated) | Identity | Read |
|---|---|---|---|
| Revision 4 | `docs/governance/decision-0009/provenance/sequencing-rev4-2026-11-12/FABLE-SEQUENCING-ARCHITECTURE-REV4.txt`; also the supplied attachment | `fbd2790d9e58dad673ca996487ba63413233c82c7c07d0f80533a32062096c4c`, 23,741 bytes; the attachment matches once the two leading bytes lost in upload are restored | In full |
| Revision 4 adoption record | `…/DECISION-0009-SEQUENCING-ARCHITECTURE-REV4-ADOPTION.md` | `dbd57cc08001740578aa7eff1531eb932a4d8edb42ac51644ea13847e4f8d86c` | In full |
| Level-2 Evidence Contract, with the Nov 6/7/8 adoption records | `…/DECISION-0009-V2-2B-LEVEL-2-EVIDENCE-CONTRACT.md` | `ddc72233c60166279dff4e4dca7ad009b85fef1d6a8cda108ee19a07a53804d0` | Adoption records and verbatim Draft 2 §§1–18 in full. Kimi appendix not used |
| H1–H20 and retained notes N1–N6 | `…/DECISION-0009-V2-2B-EXPERIMENT-SCOPED-SUPPORT-OBJECT-IDENTITY-POLICY.md` | `93a6df2354f303fc799c32f3606e4074f8359500c0ecb15bf5d0180c665b93ce` | Section H and the N1–N6 table in full. Metadata lines skimmed |
| H18 Architecture Draft 4 | `…/provenance/h18-draft4-2026-11/Pasted text(20261107-223309).txt` | `528ac9212b207f439e236adc74518e075abe4fd2c39bbeff7457f0c31c114629` | In full |
| Proof-Obligation Register Draft 4 | `…/provenance/h18-draft4-2026-11/Pasted text(20261108-190715).txt` | `16c224d956a1b643d294b9fceb1cf73c7dddf2bdc469e2f14d378069d0db96ab` | In full |
| H18 §3.2 / PO-03 non-dispatch clarification | `…/DECISION-0009-H18-PO03-NONDISPATCH-RESOLUTION-CLARIFICATION.md` | `77177132f0cf643f4b9a1466e5de672a17c74e970de9935d586f622b9d235a19` | In full |
| Implementation Plan (untracked working-copy file) | `…/DECISION-0009-RETENTION-V2-M0-IMPLEMENTATION-PLAN.md` | `f7bf6d738df25e3875ab452bf49918c69c330903d1cc039cb2048ee44d22b657`, 49,705 bytes, **untracked** | §§A, B, D, E, I, J, N, O, P, Q, R. Not §§C, F, G, H, K, L, M, S |
| Decision 0010 (adopted, amended) | `docs/decisions/0010-mandatory-cross-family-review.md` (tracked) | `3b1d7be562f07834b1809684eb502fc1363ad00257bd0df58a0098dc042eba93`, 14,185 bytes | Status and clauses 1–12, enforcement and relationship sections in full |
| Lifecycle governance bindings | `…/DECISION-0009-HUMAN-CHAIR-LIFECYCLE-GOVERNANCE-BINDINGS.md` | `cc2891242c1da1f8f7d15d607207cdc989735b1a228cb8e387dafa8f6a507bc8` | Part C §§8 and 10 only |
| Fable candidate (superseded) | supplied attachment | `f1e733547de7c53d2efe0647cc659d850d41118f6a51936605445e0f6df984cc` once the one leading byte lost in upload is restored | In full |
| Astra review of the Fable candidate | supplied attachment | 26,982 bytes, SHA-256 `506fd1acb674aea55fdc5c47869c34fab8bd23bf72fd8b62d3fdd2563297ebf6` as supplied; no recorded reference hash exists to compare | In full |

Every repository digest above was freshly computed and matches its provenance record where one exists.

### B.3 Limitations

- **The r2 and Final Amendment 1a normative texts were not retrieved.** They sit in an archive outside the connected folder. Where I rely on them, I rely only on the excerpts the Evidence Contract preserves (§14) and make no independent specification-fidelity claim.
- **Untracked sources.** The Implementation Plan and the Retention V2/M0 adoption record are untracked working-copy files. I cite the Plan by its observed SHA-256 above. I do not present it as committed content, and I did not open the adoption record. The untracked file `docs/decisions/0010-mandatory-cross-family-review-1.md` (`2f3f068d317a047cdfbb3dbcfb82065aa7a45bc4484442c560c64188dc19b94e`) is the pinned r2 *proposal* named in Decision 0010's adoption record. I did not treat it as the governing text.
- **Unread portions.** I did not read the Kimi and Argon review artifacts or Astra's Revision 4 review and qualification records beyond their headings and the adoption record's summary of them. No claim below depends on them.
- **No protected path, P0 candidate, platform object or B5-governed surface was inspected.**

---

## C. Scope and exclusions

**In scope.** These are abstract obligations for V2-2B propositions outside the adopted two-case profile, together with:

- the maturity of each obligation's statement and bindings;
- its dependencies, eventual evidence and earliest legitimate closure point;
- a non-governing candidate dependency model and an abstract capacity model;
- an abstract map of what Approval-B-visible information would bind;
- a classification of possible later changes as Category 3, general-policy amendment, or neither.

**Outside this candidate, and not attempted:**

- no P0 qualification, Approval B, protected read, or inference about protected content;
- no Approval B inspection-envelope design;
- no B5 host-observation envelope design;
- no platform-premise acquisition;
- no backend named, compared, ranked, selected or eliminated;
- no closure of CP1, CP2 or any candidate closure point;
- no concrete design, code, execution or cleanup;
- no change to H18 Draft 4, the Register, the clarification, the 64-object envelope, H1–H20, the Contract, Revision 4 or Decision 0010;
- no resolution of determination C;
- no repository mutation.

**Labels.** `R-nn`, `K`-points, `A0`/`A1-G`/`A1-N`, and the dependency letters are candidate reference labels. None of them is a Register obligation or closure point, and none confers authority.

---

## D. Corrected proposition-maturity taxonomy

I retain the statement/binding split and the A0/A1 distinction because each separates two questions that a single label would merge. I retain P only in the narrowed form below. I replace the single class I with two classes, so that a narrow-profile revision cannot be confused with a general-policy amendment. I add one marker, BLOCKED-R, for propositions the retained architecture cannot exercise.

### D.1 Statement versus binding

Every requirement carries two classifications:

- **Statement class:** whether the obligation, as worded, can govern broader scope now, and on what basis.
- **Binding dependencies:** what must happen before its values, cases, mechanisms or evidence can be fixed.

An obligation can be adoptable as a statement while every one of its bindings is still blocked.

### D.2 Statement classes

| Class | Test | Effect of adoption |
|---|---|---|
| **A0 — adopted restatement** | The cited adopted clause already applies to the broader scope by its own terms. That is true of H1–H20, which apply to every V2-2B disposable Level-2 experiment under H1. It is true of the Contract, which covers future V2-2B experiments under §1, of Decision 0010, of Revision 4, and of the categorical sequence that Register §5 and PO-22 state for all V2-2B implementation and execution. The restatement must be neither broader nor narrower than the clause. | Adds no obligation, only an index. Where my wording and the source differ, the source controls. |
| **A1-G — faithful generalization** | The obligation comes from adopted narrow-profile text (H18 Draft 4, Register Draft 4, the §3.2 / PO-03 clarification) and keeps every element of the narrow rule, **including its exceptions and limits**. Only profile-specific identities and constants become symbolic. Each A1-G entry names the exceptions it preserves. | Governs broader scope only after qualifying review and your adoption. It is never read back onto the narrow profile. |
| **A1-N — new Category 2 rule** | The obligation has no adopted analogue, or it is deliberately stricter or looser than its analogue. It must state what is new and why. | As for A1-G, with the justification itself open to review. |

### D.3 Binding-dependency classes

| Class | Dependency |
|---|---|
| **B** | May be explored now. Its suitability as a governing rule depends on facts not yet available, so it is not offered for adoption. |
| **C** | Needs a P0 qualification result or another P0-gated fact. Proposition-specific: it applies only where the reliance actually concerns such a fact. |
| **D** | Needs protected-interface information obtainable only through a lawfully authorized Approval B **document read**. Information the read cannot supply, such as actual deployment behavior, is class G, not D. |
| **E** | Needs your backend selection after applicable feasibility closure. |
| **F** | Would settle concrete design, or let later work treat a concrete answer as settled, under Revision 4 §F. Waits for applicable concrete-design closure. A bounded candidate may investigate such an answer before then, but may not adopt or rely on it. |
| **G** | Needs empirical, deployment or platform evidence acquired under specific authority. |
| **H** | Needs B5-governed characterization or exclusion of autonomous agents. B5 G1 is HOLD. |
| **P** | Needs your separate policy decision on **determination C** (non-replication concurrent materially overlapping attempts). It is used for nothing else. |
| **I₃ — Category 3** | The proposal would change adopted narrow-profile architecture, semantics or limits (Revision 4 §D). It requires architectural revision with full review and inherits no prior acceptance. |
| **I_G — general governance amendment** | The proposal would change generally applicable adopted policy: H1–H20 (including H10's ceilings), the Contract, Decision 0010, Revision 4's sequencing architecture, or the categorical gate order. It requires its own governance revision, which is not a Category 3 revision unless it also changes the narrow profile (§N). |
| **BLOCKED-R** | The proposition cannot be exercised under the retained architecture as stated. Exercising it would need a separately proposed and adopted architectural change, which nothing here proposes. |

### D.4 Labels create no authority

A class records a dependency; it does not satisfy it. Assigning A0 does not make an index entry governing beyond its source, and assigning F to an answer does not stop bounded investigation of that answer.

---

## E. Corrected broader requirements catalogue

### E.0 Conventions

- **Evidence classes.** I borrow the Register §3 letters as terms only: **S** for static assurance, **E** for empirical premise evidence and **X** for execution evidence. An entry stating what evidence will *eventually be required* never authorizes acquiring it (R-32).
- **Closure points** are the candidate, non-governing points defined in §F:
  - K0 statement adoption;
  - K1 exploratory documentary comparison;
  - K2 formal feasibility showing;
  - K3 backend selection;
  - K4R Approval B read;
  - K4T post-read tailoring;
  - K5 concrete-design closure;
  - K6 concrete-design adoption;
  - K7 implementation authorization;
  - K8 first governed effect;
  - K9 each dependent dispatch;
  - K10 sealing and finalization cutoffs;
  - K11 positive qualification;
  - PF, the event of an execution-observable premise failing.
- **"Statement: K0"** means the statement could be adopted as abstract architecture after qualifying review and your decision. It does not mean adopted.
- **Read-back.** No A1-G or A1-N statement reinterprets H18 Draft 4, the Register or the clarification. For the narrow profile the adopted narrow text controls.
- **"H18" naming.** "H18 §n" and "H18 Draft 4" mean the adopted H18 Architecture Draft 4. "H18 (policy)" means item H18 of the H1–H20 policy.
- **Status entries.** Each entry lists its controlling clauses, with the status that clause supports in brackets. Where an entry mixes A0 and A1-G elements, each element is attributed separately.

### Group I — Propositions, domains, lineage and concurrency

**R-01 — Proposition fixing.** No governed effect occurs until each broader proposition has recorded:
- its property or failure behavior and the governing source;
- the operation or mechanism, relevant inputs and fault conditions;
- material platform and configuration premises, and observation intervals;
- intended reliance, required observations, dependencies and limits;
- the conditions that will yield a supported, violated, uncertain or unobserved conclusion.

The attempt's authority fixes the H3 matters before that effect.

- *Source / status:* Contract §2; H3; H14 [A0].
- *Dependencies:* statement none. Bindings: D (which properties are material for the actual interface); F (case realization).
- *Abstract/concrete:* abstract. The actual case set is concrete.
- *Evidence eventually required:* S for the fixed record; X for outcomes.
- *Earliest legitimate closure:* statement K0; case set after K4T; fixed no later than K8.
- *If unmet:* no proposition is evaluable and no first governed effect may occur.
- *Narrow H18:* the narrow propositions are already fixed by H18 §2. No interaction.

**R-02 — Independent oracle and native-result mapping.** Each pass/fail proposition has two things bound before the first governed effect:
- an expected outcome drawn from an applicable authoritative source, independent of observation;
- a mapping from native results to conclusion classes.

An observed result cannot define either one retrospectively.

- *Source / status:*
  - [A0] Contract §12 item 1 (independent expected outcomes are a prerequisite); Contract §2 and H3 (conclusion conditions and propositions fixed before execution). Contract §3 states the source-basis requirement expressly only in its resource-limit row ("Expected behavior needs an applicable source basis"). Applying it to every pass/fail proposition is therefore [A1-G], drawn from PO-01 and H18 §2.
  - [A1-G] The explicit native-result mapping and its staged closure, from PO-01 and H18 §2. This preserves PO-01's separation of credible feasibility, design-level mapping, exact source and revision binding, and later result evaluation.
- *Dependencies:* D (interface-specific oracle sources and result domains); E; F (mapping); G (deployment-dependent result modes).
- *Abstract/concrete:* abstract. A chosen mapping is concrete.
- *Evidence eventually required:* S for oracle and semantics; E for deployed applicability; X for the original result.
- *Earliest legitimate closure:* statement K0; credible feasibility K2; mapping K5; exact source and revision binding K8; evaluation K11.
- *If unmet:* results are uninterpretable and positive reliance is barred.
- *Narrow H18:* generalizes PO-01. Inside the narrow profile, PO-01 already permits E3 to be an independent pass/fail proposition when its own oracle and mapping are bound before the first effect. That is not a Category 3 matter (§N.2).

**R-03 — Property-specific coverage and reliance limits.** Where a broader proposition concerns any property in the Contract §3 claim-to-evidence table, that row's evidence, coverage and limits on positive reliance apply as stated. Such properties include:
- exclusive creation;
- exact size and object state;
- allocation;
- zero state;
- synchronization and readback;
- resource-limit behavior;
- write-capability exclusion;
- short, error and uncertain outcomes.

Two §3 consequences carry over unchanged:
- A proposition targeting the r2 §13 F-writer constraint must establish and read back the stated `RLIMIT_FSIZE` values before writable capability.
- A case modeling Amendment 1a §6 must keep its capture-order distinctions.

A claim that a row is inapplicable needs an evidenced rationale and an explicitly narrowed proposition. Synchronization and readback never establish crash survival (R-29).

- *Source / status:* Contract §3, including the `RLIMIT_FSIZE` and Amendment 1a §6 paragraphs and the durability paragraph [A0]. The r2 and Amendment texts were not retrieved; I rely on the Contract's statements of them (§B.3).
- *Dependencies:* D (which rows are material); F; G (platform semantics such as signal and error behavior); C where reliance concerns a P0-gated fact.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; E; X for exercised cases, including negative cases.
- *Earliest legitimate closure:* statement K0; applicable rows after K4T; coverage design K5.
- *If unmet:* the property claim is unestablished, or narrowed with an explicit rationale.
- *Narrow H18:* the narrow profile excludes most rows by its §2 exclusions. No interaction.

**R-04 — Proposition identity, materiality and lineage.**
- Proposition identity follows H14. Names, labels, paths, report titles and incidental implementation changes do not create a distinct proposition. A material change of mechanism or premise may create one, and its significance must be disclosed.
- Materially overlapping propositions stay related. Applicable earlier and concurrent attempts, including adverse, failed, uncertain, conflicting and incomplete ones, stay in lineage.
- Where materiality, dependency or relevance is uncertain, the matter is treated as material, dependent and included.
- Lineage is reconciled against the authorization and disposition history. An assertion that no earlier attempts exist is insufficient.
- Proposition-level evaluation addresses the combined record.

- *Source / status:* H13; H14; Contract §§2 and 9; retained notes N1 and N2 [A0].
- *Dependencies:* statement none. Bindings need the authorization and disposition history (S).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for reconciliation; X for original outcomes.
- *Earliest legitimate closure:* statement K0; reconciled for each attempt before K8; combined-record evaluation at K11.
- *If unmet:* an overall positive qualification claim is blocked (H14).
- *Narrow H18:* applies to the narrow profile by its own terms. Nothing changes.

**R-05 — Domain separation.** Each specifically authorized bounded attempt is one live experimental identity domain with its own allocation, which its cases share. Nothing of the following crosses into another domain, whether between the narrow profile and a broader profile or between two broader profiles:
- live identity or capability;
- capacity or unused allocation;
- qualification status;
- architectural or review acceptance.

Evidence about another domain may be cited or admitted only under R-06.

- *Source / status:* [A0] H2; H3; H10 (separate, nontransferable allocations; no subdivision to evade limits); H12; H17 (no live identity carries; no transfer or refund of capacity); Contract §2 (one attempt, one domain), §6 cross-experiment row and §11 (no promotion); Lifecycle Bindings Part C §10 (no PASS inherited across a materially changed premise); Revision 4 adoption effect 6 (the 64-object envelope stays confined to the narrow profile); Revision 4 §D (a Category 3 revision inherits no prior acceptance); Decision 0010 clause 4 (a changed revision needs renewed review).
- *Dependencies:* none.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for authorization and allocation records; X for actual attribution.
- *Earliest legitimate closure:* K0.
- *If unmet:* lineage and attribution are unreconciled and dependent claims are blocked. An attempt to evade an allocation is an H10 violation.
- *Narrow H18:* protective. Placing a broader case inside the narrow attempt would change that attempt's schedule or allocation, which is I₃ (§N).

**R-06 — Historical evidence: citation and admission.**
- **(a) Citation.** A prior report merely cited as a historical reference is not admitted. The citing record is still accounted for. Calling substantive reliance a "citation" cannot avoid admission and charging or hide adverse lineage.
- **(b) Admission.** A prior report actually relied on as an evidentiary input is admitted to, and charged in, the receiving experiment's inventory. Repeated proven references count once. Separately created copies, excerpts and derivatives are charged separately, and packaging does not merge charges.
- **(c) Receiving-domain rules.** Admission and reliance are decided under the receiving experiment's own authority. It applies its own requirements for:
  - provenance (R-26);
  - currentness, with separately governed justification;
  - adverse lineage (R-04);
  - materiality;
  - accounting (R-36);
  - proposition-specific reliance limits.
- **(d) Original limits are kept.** Historical evidence keeps its original platform, context and evidence-level limits. A date, a matching platform label, copying or admission does not establish current behavior. A prior result is not inherited across a materially changed premise.
- **(e) No substitution for originals.** Admitted evidence may inform proposition-level evaluation and lineage, static analysis and design. It cannot stand in for an original observation that the receiving domain's own requirements assign to its own governed attempt. Later review cannot manufacture missing original evidence.
- **(f) Oversized inputs.** An oversized required historical input is a capacity failure. It may not be replaced by a selectively favorable excerpt, split or substitute representation. Excerpts genuinely permitted by a separately justified narrower proposition are distinct governed derivatives and must not hide relevant adverse content.
- **(g) No semantic change.** Authorized admission is an evidence act within the receiving domain. It changes no adopted semantics and is not, in itself, a Category 3 act.

- *Source / status:* H2; H14; H16; H17; Contract §6 (cross-experiment and copy/export rows), §8 and §10 (historical-input admission, oversized inputs, excerpts); Lifecycle Bindings Part C §§8 and 10 [A0]. Item (e) is drawn from H16, Contract §8 and the Register's definition of X evidence. To the extent it states that rule for broader scope, it is [A1-G].
- *Dependencies:* the receiving domain's authority. G where currentness depends on present platform facts.
- *Abstract/concrete:* abstract. Which reports are admitted is fixed in each authorization.
- *Evidence eventually required:* S for the admission record and provenance; E where currentness requires present platform facts.
- *Earliest legitimate closure:* statement K0. Admission and its reservation are fixed before reliance, and in any case before K8 (H8, H11).
- *If unmet:* the dependent claim is blocked (Contract §10).
- *Narrow H18:* the narrow profile already admits required history within its eight-input allowance (H18 §12.2). Admitting narrow-profile evidence into a broader domain, or broader evidence into the narrow attempt within that allowance, changes no narrow semantics. Requiring a ninth narrow input would be I₃.

**R-07 — Attempt relationships, later attempts and predetermined replication.**
- Failure, uncertainty, conflict or incompleteness grants no retry, repair, replay, replacement or further attempt.
- Except for predetermined replication, a later attempt requires all of:
  - the earlier attempt has stopped;
  - its complete or incomplete closure record is available to you;
  - you have explicitly dispositioned it;
  - new specific authority exists.
- Advance authority conditioned on failure is prohibited.
- Predetermined replication must fix in advance its justification, finite repetitions, cases, domains, allocations, reporting and stops, independently of outcomes. It may not stop at the first success or add repetitions after unfavorable results.
- Each authorization states its relationship to earlier attempts on the same proposition, and states the combined maximum allocation where it covers several experiments.

- *Source / status:* H4; Contract §9; retained notes N2, N3 and N6 [A0]. PO-14 restates this for the narrow profile.
- *Dependencies:* none. P does not apply (R-08).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for authorization and disposition history; X for every attempted repetition.
- *Earliest legitimate closure:* statement K0. Relationships are fixed in each authorization before K8.
- *If unmet:* the attempt is unauthorized, and any effects are violations for your disposition.
- *Narrow H18:* applies to the narrow profile by its own terms.

**R-08 — Concurrency classification.** Every proposal involving simultaneity is classified into exactly one of four types before authorization.
- **(A) Overlapping subject operations within one attempt.** Governed by R-16. Any proposition that needs such overlap is BLOCKED-R.
- **(B) Predetermined replication,** run serially or concurrently. Governed by H4 and Contract §9: interference identification, cross-domain attribution, and a stop where interference or provenance is unresolved. It needs specific H4-compliant authority. P does not apply.
- **(C) Non-replication concurrent attempts on materially overlapping propositions.** Determination C applies: these are neither authorized nor presumed permissible pending your separate policy decision. This is the **only** use of P.
- **(D) Concurrent non-replication attempts on propositions that are not materially overlapping.** Outside determination C. Contract §9's interference and attribution requirements apply to any concurrent design, and the Contract grants no concurrent execution authority. Whether H4's later-attempt condition reaches unrelated attempts is the scope question kept in note N3, and this candidate does not resolve it. Without specific authority none may dispatch. Where material overlap is uncertain, the proposal is treated as (C) (H13; Contract §2).

Resolving determination C cannot:
- relax (A);
- authorize a prohibited writer topology, which cannot be qualified by exercising it (Contract §3);
- decide (B) or (D).

- *Source / status:*
  - [A0] Types (B) to (D) and the effects of determination C: the Contract's concurrency disposition and retained conditions, §§3, 9; H4; H13; N1; N3. H18 §14 states the same for the narrow profile.
  - [A1-G] Type (A), through R-16.
  - [A1-N] The four-way classification rule itself. Justification: it is the minimal device that keeps P confined to determination C, as the sources require, and it decides no policy question.
- *Dependencies:* P for (C) only.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S.
- *Earliest legitimate closure:* statement K0. Each proposal is classified before its authorization.
- *If unmet:* an unclassified proposal is not authorized.
- *Narrow H18:* consistent with H18 §14 and Register §7. No change.

### Group II — Schedule, dispatch and lifecycle

**R-09 — Finite predetermined schedule.**
- Each broader attempt has a finite, ordered set of slots, fixed before the first governed effect and independent of outcomes.
- Each slot names its operation and its dispatch-eligibility predicates. Each terminal slot also names its terminal-eligibility predicates (R-20).
- Each slot has at most one attempt. There is no substitution and no added slot.
- The schedule fixes outcome-independent rules for when ordinary dispatch ends: on failure or uncertainty of a prerequisite slot, on any stop, and at planned completion. Terminal slots are part of the schedule, not left to later design.

- *Source / status:* [A0] H3 (operations and cases fixed before first effect); H4 (no retry or replacement). [A1-G] H18 §4.2 and Register §2: a fixed slot set, one attempt per slot, no substitution, no extra event, fixed end-of-ordinary-dispatch rules, and fixed terminal slots.
- *Dependencies:* D (operations); F (the actual schedule).
- *Abstract/concrete:* abstract. A specific schedule is concrete.
- *Evidence eventually required:* S for the fixed schedule; X for adherence.
- *Earliest legitimate closure:* statement K0; schedule K5; fixed by K8.
- *If unmet:* no dispatch.
- *Narrow H18:* generalizes the seven-event schedule without altering it.

**R-10 — Dispatch eligibility is distinct from interval evaluation.**
- Eligibility to dispatch a slot is established at the dispatch decision, from predicates that can be evaluated then, including earlier original observations where required.
- Premises about the interval through the slot's dispatch boundary, such as continued absence or continued sameness, are evaluated afterward from originally declared observations and enforcement evidence only. A pre-dispatch check does not prove them, and no new probe is authorized.
- If such a premise is unproven, the original result is preserved and the intended proposition is classified uncertain.
- If it is contradicted, both are preserved, the proposition is uncertain for that attempt, and the continuity-conflict stop applies.
- A missing original observation is unobserved or unavailable. Directly adverse observations are preserved on their own terms.

- *Source / status:* [A1-G] H18 §§4.3 and 9; PO-07; PO-08. [A0] the continuity-conflict stop (H13; Contract §8).
- *Dependencies:* F (predicates and declared observations); G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; predicates K5; eligibility at each K9; interval evaluation K11.
- *If unmet:* cases evaluated as if a failed premise held are nonconforming.
- *Narrow H18:* generalizes PO-07 and PO-08.

**R-11 — Execution state, reporting disposition and dispatch classification are separate.** Each slot carries three distinct records:
- an **execution state:** what is known about whether its operation may still execute or produce effects;
- a **dispatch-evidence classification:** proven withheld or not dispatched; dispatch uncertain; dispatch observed with outcome unavailable; original outcome observed; or material conflict;
- a **reporting disposition:** how the attempt finally records the slot.

None substitutes for another. A final "unavailable" or "in flight, unresolved at cutoff" disposition does not claim the operation ceased. Reporting closure is not physical quiescence.

- *Source / status:* [A1-G] H18 §§3.1, 6 and 7.1; PO-03. [A0] Contract §8: physical validity, synchronization, closure and custody are separate predicates, and complete reporting is not success.
- *Dependencies:* F (state mapping).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; mapping K5.
- *If unmet:* an optimistic label could license dispatch, which is nonconforming.
- *Narrow H18:* generalizes.

**R-12 — Entry into `IN_FLIGHT`: definite and possible dispatch.**
- A slot enters `IN_FLIGHT` when dispatch crossed, or may have crossed, its governed boundary, and no admissible original completion has shown the operation ended.
- The record keeps the basis of entry: **definite dispatch** or **possible dispatch only**. Both obstruct `Q` (R-16).
- Once the evidence establishes definite dispatch, no later finding converts it to possible-only.

- *Source / status:* [A1-G] H18 §3.2 (entry, and both bases prohibit later dispatch); the clarification (the non-dispatch route is unavailable to definite dispatch); PO-03 (a non-dispatch finding cannot erase definite dispatch).
- *Dependencies:* F; G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for dispatch semantics; X for dispatch evidence.
- *Earliest legitimate closure:* statement K0; mapping K5; applied at K9.
- *If unmet:* `Q` would be treated as true while an operation may be executing, which is nonconforming.
- *Narrow H18:* generalizes.

**R-13 — Exit from `IN_FLIGHT` by original completion.**
- Exit by completion requires admissible evidence that the original operation ended under the applicable backend semantics. Normally this is the original terminal return, under a backend contract showing that the return ends the relevant effect interval.
- None of the following is completion: acknowledgement of asynchronous submission; timeout or elapsed time; abandonment; cancellation intent; interruption; a stop decision; reporting closure; a state label or reporting disposition; component disappearance.
- A hung or blocked component is not a lost component. No cancellation operation or completion probe is granted.
- Completion concerns an operation that crossed, or may have crossed, and then ended. It is a different proposition from non-dispatch resolution (R-14).

- *Source / status:* H18 §3.2 as clarified; PO-03; the clarification §C [A1-G].
- *Dependencies:* E (backend semantics); F; G.
- *Abstract/concrete:* abstract. Completion semantics and the state mapping for a design are concrete.
- *Evidence eventually required:* S for completion semantics; E for deployed applicability; X for original completion.
- *Earliest legitimate closure:* statement K0; credible mechanism K2; mapping K5; deployment premises K8; resolution before any dependent dispatch at K9.
- *If unmet:* the slot stays in flight, `Q` stays false, and dependent dispatch stays blocked.
- *Narrow H18:* generalizes.

**R-14 — Limited non-dispatch resolution.**
- **Availability.** Only for a slot whose `IN_FLIGHT` entry rested solely on possible dispatch (R-12). Never for a definitely dispatched operation.
- **Requirement.** Positive admissible evidence establishing **both**:
  1. **Historical non-crossing.** The operation did not cross its governed boundary at any time in the interval running from the earliest point the slot became technically reachable through the moment of resolution, to the R-18 standard.
  2. **Exclusion of future crossing.** That same operation can no longer cross by any route, whether pending, queued, delegated or other.
- Evidence of (1) without (2) is insufficient while any crossing route remains possible. Where a relevant loss has occurred, R-15 also applies.
- **Effect.** Removes only that slot's execution-state obstruction to `Q`. `Q` still requires every other slot to be unobstructed.
- **Limits.**
  - `U(k)` stays false.
  - The original dispatch-uncertain assessment and its potential-effect uncertainty are preserved alongside the resolution.
  - It permits no retry or redispatch and reverses no stop.
  - It changes no frozen reporting disposition. After the slot's disposition freezes it cannot alter that disposition, and any record of it uses only routes already authorized (R-21).
  - It creates no terminal target and confers no terminal eligibility, because terminal actions keep their own predicates (R-20).
  - It grants no observation, probe, cancellation or recovery operation and does not relax R-16.
  - It adds no evidence route, artifact allowance, reservation refund or capacity transfer.

- *Source / status:* the adopted clarification §§C and D and its adopted semantic scope; PO-09 [A1-G, faithful, with no deliberate change of strength].
- *Dependencies:* F (method); E; G.
- *Abstract/concrete:* abstract. The resolution method is concrete.
- *Evidence eventually required:* S; E; X for interval and exclusion evidence.
- *Earliest legitimate closure:* statement K0; credible route K2; method K5; resolution at K9 where a dependent dispatch or terminal evaluation depends on it.
- *If unmet:* the slot stays in flight on possible dispatch only, `Q` stays false, and actions requiring `Q` stay unavailable.
- *Narrow H18:* generalizes the clarification. The narrow text controls the narrow profile.

**R-15 — Executor loss and post-loss evidence.**
- Loss of any of the following does not establish cessation: an executing component, the dispatch-gating component, the subject, a writer, a child, a framework component, the evaluator or the runner. Nor does an OS crash or reboot.
- Where delegated, kernel-mediated or other effects may continue, the slot's execution state becomes **executor lost, effect interval unresolved**. It obstructs `Q` in the same way as `IN_FLIGHT`.
- Evidence acquired after a relevant loss may support completion (R-13), resolve possible dispatch (R-14) or resolve executor loss **only if** that exact post-loss observation belongs to the originally authorized sequence and has the applicable adopted method. Otherwise the interval stays unresolved, `Q` stays false and actions requiring `Q` are unavailable.
- None of the following can supply that evidence: an unplanned reap or exit status, a non-dispatch argument, a diagnostic observation, or later review.
- Loss stops dependent dispatch and grants no resumption, retry, repair or replacement. Restarting the runner reopens nothing.

- *Source / status:* [A0] Contract §6 (unexpected-termination and runner rows; planned writer termination). [A1-G] H18 §3.2 (the executor-lost state); PO-03 (the post-loss conditions, as kept by the clarification).
- *Dependencies:* F; G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X from the authorized sequence only.
- *Earliest legitimate closure:* statement K0. Any post-loss observation is placed in the sequence before K8, and its method is adopted before reliance.
- *If unmet:* the interval stays unresolved and closure is incomplete for that slot.
- *Narrow H18:* generalizes.

**R-16 — Serial dispatch and the attempt-wide obstruction to `Q`.**
- For an attempt, `Q` holds only when no earlier subject operation is in flight, executor-lost, or carrying an unresolved continuing-effect interval.
- While `Q` is false: no later subject slot dispatches; no terminal action that requires `Q` dispatches; and no target or parent is closed merely because a result has not appeared.
- A synchronous backend may satisfy this rule, provided its normal return carries the required completion meaning.
- **Consequence.** At any instant, at most one subject operation of an attempt can be unresolved. A proposition whose observation needs two subject operations of the same attempt to be unresolved at once is **BLOCKED-R**. Determination C does not reach it.

- *Source / status:* [A1-G] H18 §§3.3, 4.1 and 5.3; PO-03. [A1-N] the BLOCKED-R consequence, stated explicitly so that no such proposition is routed to P.
- *Dependencies:* F.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the serial-dispatch design; E; X.
- *Earliest legitimate closure:* statement K0; design K5; enforced at each K9.
- *If unmet:* the design is nonconforming, and the affected proposition cannot be reached under this architecture.
- *Narrow H18:* generalizes H18 §3.3.

**R-17 — Permanent attempt ineligibility.**
- A slot that has been attempted, has become dispatch-uncertain, or has received a final withheld or unavailable disposition is never again dispatch-eligible in that attempt.
- Nothing restores eligibility: not completion (R-13), not non-dispatch resolution (R-14), not a late return, review, reclassification or new authority.
- Later activity is a new attempt under R-07.

- *Source / status:* [A1-G] H18 §4.1; PO-03 (`U(k)` stays false); the clarification. [A0] H3 and H4 (no resumption).
- *Dependencies:* statement none; F for the mechanism.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; enforced at K9.
- *If unmet:* retry becomes possible, and the design is nonconforming.
- *Narrow H18:* identical in effect for the eligibility invariant. It does not restate the whole clarification, which R-14 covers.

**R-18 — Proven withheld or not dispatched: a historical showing.**
- A slot is classified as proven withheld or not dispatched only on positive admissible evidence that it **could not have crossed** its boundary throughout the relevant interval. That interval begins at the earliest point the slot became technically reachable; where reachability precedes eligibility, reachability controls.
- A later inhibit or stop decision cannot substitute for the earlier interval.
- None of these is sufficient: the absence of prepared, issued, observed or completion records; or the producing component's journal alone.
- Loss of the required evidence leaves dispatch uncertain.
- Fixing the end of the relevant interval is a design binding.
- This showing is historical. It does not by itself establish that future crossing is impossible. Where a decision depends on that (R-14), it is a separate showing.

- *Source / status:* [A1-G] H18 §7.1; PO-09. [A0] H13 (missing output does not prove non-dispatch); the Amendment 1a §7 statement preserved in Contract §14 (uncertain dispatch is not proof of non-dispatch).
- *Dependencies:* F; G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; E; X for the interval.
- *Earliest legitimate closure:* statement K0; method K5; at K9 where a dependent dispatch relies on it; interval proof K11.
- *If unmet:* the slot stays dispatch-uncertain.
- *Narrow H18:* generalizes PO-09.

**R-19 — Stopping, fixed bounds and the terminal phase.**
- A stop takes effect at once, ending ordinary dispatch, and cannot be made conditional on any later capture succeeding.
- Only expressly preauthorized, bounded terminal actions may follow. A terminated attempt never resumes. Failure grants no inspection, capture, cleanup or recovery authority.
- Before the first governed effect, the attempt fixes outcome-independent bounds and the mechanisms that enforce them:
  - the maximum ordinary execution interval;
  - the source-finalization bound;
  - the original-return capture window;
  - the terminal and finalization bound.
- A late result cannot extend a bound. Neither stopping nor reporting waits indefinitely on an in-flight operation.
- Where no surviving authorized mechanism can seal or report, those outputs are unavailable, and their absence authorizes nothing.

- *Source / status:* [A0] H3; Contract §§2 and 8. [A1-G] H18 §3.4 and PO-14 (fixed, outcome-independent bounds).
- *Dependencies:* F (bounds and mechanisms); G.
- *Abstract/concrete:* abstract. The values are concrete.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; values K5; fixed by K8.
- *If unmet:* indefinite waiting is nonconforming, and no terminal action is available.
- *Narrow H18:* generalizes.

**R-20 — Terminal-action eligibility.**
- Each terminal action is a predeclared slot with its own eligibility, all of which must hold:
  - original bounded terminal authority;
  - a surviving execution path;
  - a safe target tied to the action's origin;
  - the applicable capability restrictions;
  - `Q` and `U(k)`.
- A `Q` restored under R-13 or R-14 does not by itself make a terminal action eligible.
- A terminal action must neither use a confined capability nor change its validity through aliasing, ownership, lifetime or parent dependency. If that independence cannot be shown, the action is unavailable and is not replaced by another close or cleanup.
- A frozen or otherwise ineligible terminal slot stays unavailable.
- A capability returned after its admission window never becomes a terminal target.
- Terminal actions confer no cleanup authority beyond what was preauthorized.

- *Source / status:* H18 §§4.1–4.2 and 5.4; PO-13; the clarification (restoring `Q` neither makes E6/E7 eligible nor guarantees them); H3 for cleanup [A1-G, with H3 as A0].
- *Dependencies:* F (which terminal actions exist); D (what the actual case leaves open); G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; actions K5; fixed by K8; evaluated before freeze, within K10.
- *If unmet:* the terminal action is unavailable, and any residual capability is recorded as confined, not proven closed.
- *Narrow H18:* generalizes E6 and E7.

**R-21 — Late returns: three distinct mechanisms.**
- **(a) Capability-admission closure.** Each slot that can return a capability has a fixed admission window. A reference arriving after it never establishes the admission predicate, the generalized P or L3, so it never enables a dispatch or a terminal target.
- **(b) Original-return capture.** A return counts as late when it arrives after any of these: ordinary dispatch ended; its slot became uncertain or was finally marked unavailable; its admission window closed; an earlier stop.
  - It is attributed through a pre-established association with its event and attempt. No subject lookup is performed.
  - Any returned capability goes into a non-invocable compartment and is recorded as **confined, not proven closed**.
  - Before the source fence, the original return may be recorded in its still-available assigned record, without retrying failed production.
  - After sealing, it may be recorded only through a pre-established, bounded exception route within a fixed capture window that ends before the creation frontier.
  - Outside the window it is unavailable to the experiment.
  - Continued confinement must create no undeclared governed evidence.
- **(c) Frozen-disposition finality.** Before a slot's reporting disposition freezes, and within the source-finalization bound, a late original return may serve as completion evidence for `Q` under R-13 (and R-15 where loss occurred). That may let a terminal action be evaluated under its own predicates (R-20). Once the disposition is frozen, no return reopens the slot or changes its disposition.
- **Common limits.** Under none of (a) to (c) does a late capability become a new terminal target. Nor does it grant inspection, closure, cancellation, cleanup, retry or recovery authority.
- **Capture bound.** Under R-16, at most one subject operation can be unresolved at a stop. The abstract worst case for subject-operation capture is therefore one unresolved operation. A design that needs capture for more is nonconforming, either through overlap or through an undeclared route. The number and size of capture objects are concrete design matters (F).

- *Source / status:* H18 §§5.2, 5.3 and 6; PO-12; PO-13; the retained Kimi caution on source-write cutoff clarity [A1-G].
- *Dependencies:* F; G.
- *Abstract/concrete:* abstract. The route and its bounds are concrete.
- *Evidence eventually required:* S; E; X.
- *Earliest legitimate closure:* statement K0; route K5; windows fixed by K8; sealing within K10; reconciliation K11.
- *If unmet:* a return that escapes confinement is nonconforming, and positive qualification is barred.
- *Narrow H18:* generalizes H18 §5. The narrow single X-L object and its slot assignment are not carried over.

**R-22 — Freezing, source fencing and sealing, and finite finalization.**
- **Order:**
  1. ordinary dispatch ends;
  2. terminal actions are attempted once or finally marked withheld or unavailable;
  3. every slot's reporting disposition freezes, with execution state kept separately;
  4. each source record's status is established;
  5. the source-write route is fenced before the final source state is captured;
  6. the source artifacts are sealed.
- **After sealing,** no slot dispatches and no terminal-action record first appears.
- **Finalization** is a finite, predeclared sequence. It ends at a creation frontier, and no new governed artifact may come into existence beyond that frontier. Final objects are established and charged before the frontier.
- **No self-certification.** No final record certifies its own production, write, synchronization or delivery. No successor record repairs a missing final record; a missing final record means closure is incomplete or unproven.
- **The closure record** names the unresolved operations, their last known holders, open effect intervals, blocked terminal actions, and known or possibly arriving capabilities. It distinguishes complete from incomplete closure, and complete reporting is not success.

- *Source / status:* [A1-G] H18 §§6 and 11; PO-12; PO-17. [A0] H3; H15 (the record does not authenticate itself and needs no endless chain of reports); Contract §8 (closure contents).
- *Dependencies:* F (sequence and objects).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; E; X.
- *Earliest legitimate closure:* statement K0; design K5; cutoffs within K10; reconciliation K11.
- *If unmet:* closure is incomplete or unproven, and positive qualification is barred.
- *Narrow H18:* the eight-step sequence and the fixed 8,192-byte E/C/T0/T1 objects are not carried over.

### Group III — Mediation, enforcement and independence

**R-23 — Complete mediation.**
- Throughout each interval on which a claim relies, every route capable of affecting the subject is either mediated by the designated dispatch-gating enforcer or blocked by controls whose effect is evidenced.
- The paths include:
  - direct, inherited and aliased references;
  - ambient namespace access;
  - callbacks, helpers, subprocesses and privileged intermediaries;
  - frameworks;
  - independent agents such as indexing, backup, synchronization and autonomous cleanup.
- An agent is not excluded because the experiment did not invoke it. The enforcer's own journal cannot prove the absence of a bypass.

- *Source / status:* [A1-G] H18 §7.2; PO-02. [A0] Contract §3 write-capability coverage.
- *Dependencies:* H (agent characterization or exclusion); E; F; G.
- *Abstract/concrete:* abstract. Naming the enforcer is concrete.
- *Evidence eventually required:* S for surface and bypass analysis; E for deployed correspondence.
- *Earliest legitimate closure:* statement K0; credible K2; assurance K5; premises K8. Agent-dependent reliance comes only after B5 clears through its own process.
- *If unmet:* interval claims are unestablished.
- *Narrow H18:* generalizes.

**R-24 — Effective capability, protection-domain union and a closed enforcing set.**
- An effective capability is any operation reachable through the component's actual environment. A policy prohibition alone does not remove it.
- Components in an unseparated protection domain are assessed as holding the union of capabilities reachable in that domain. A claimed internal boundary needs assurance of its implementation, deployment and bypass resistance.
- The enforcing set is closed and identified. Ordinary components are restricted by enforcement outside themselves and cannot exempt themselves or reconfigure enforcement.
- Membership in the enforcing set supplies no independent proof of completeness.
- Expanding the enforcing set of an adopted broader architecture requires revising that architecture.

- *Source / status:* H18 §§8.1–8.4; PO-04; PO-05 [A1-G].
- *Dependencies:* F (membership is concrete under Revision 4 §F); E; G.
- *Abstract/concrete:* abstract. Membership and composition are concrete.
- *Evidence eventually required:* S for topology and capability maps; E for deployment.
- *Earliest legitimate closure:* statement K0; credible K2; design K5; deployment K8.
- *If unmet:* enforcement claims fail.
- *Narrow H18:* the narrow set (G, store enforcement, M-S/M-T/M-R) is not carried over. Expanding it is I₃.

**R-25 — Evaluated-producer independence.**
- No completeness, provenance, transfer-completeness or accounting conclusion rests solely on the account of the producer being evaluated.
- A caller-supplied inventory is insufficient. An accountant sharing the producer's protection domain gains no independence from having a separate name or logical role.
- For each class of evidence question, the design identifies the producer whose account is under assessment and the independent basis relied on. The classes are: source observations; source production completeness; transfer completeness; receiver production and completeness; and accounting and finalization.

- *Source / status:* [A0] Contract §§5 and 7; H8; H18 (policy). [A1-G] the five-question structure of H18 Draft 4 §8.6 and retained note NB-R1.
- *Dependencies:* F.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the independence basis; E; X.
- *Earliest legitimate closure:* statement K0; basis K5; deployment K8.
- *If unmet:* completeness is unproven, and the H9 stop applies.
- *Narrow H18:* consistent with H18 §8.6.

### Group IV — Provenance, identity, continuity, custody and retention

**R-26 — Observation provenance.** For any empirical observation a claim relies on, each of the nine Contract §4 relationships must remain traceable. Names, hashes, serialization labels and self-consistent records do not independently prove authority, original acquisition, identity, completeness or currentness.
- *Source / status:* Contract §4; H15 [A0].
- *Dependencies:* F (how each relationship is established).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the acquisition design; X for the chain.
- *Earliest legitimate closure:* statement K0; acquisition design K5.
- *If unmet:* the observation is inadmissible for reliance.
- *Narrow H18:* applies by its own terms.

**R-27 — Identity concepts, and identifiers that prove nothing alone.**
- Live experimental identity, evidence-artifact identity, reference identity, accounting identity and later operational identity stay distinct.
- None of the following independently establishes governed identity, though each may contribute to a separately reviewed proof: names, labels, wrappers, paths, inodes, UUIDs, digests, content equality, serialization identity.
- Counting a reference once needs H6 evidence. Separate creation or recreation produces distinct objects. Replacement transfers no predecessor identity. Parent replacement invalidates unsupported namespace continuity.

- *Source / status:* H2; H5; H6; H7 [A0].
- *Dependencies:* F.
- *Abstract/concrete:* abstract. Identifier choice is concrete.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0.
- *If unmet:* identity and deduplication claims fail, and conservative separate accounting applies (H13).
- *Narrow H18:* applies by its own terms.

**R-28 — Continuity methods, confined to the matrix.**
- Where the Contract §6 matrix requires a method, reliance needs a concrete method that has been separately reviewed and adopted and is covered by authority before reliance. The matrix requires one for pathname reopening, reacquisition after losing all bindings, planned writer termination, post-loss reliance, live cross-process transfer, and pathname observation after parent replacement.
- Where the matrix requires **no additional method**, this requirement adds none: successive observations through an uninterrupted binding, and the closing of one alias while another proven binding survives. The row's own showing still applies.
- A copy, export or derivative never inherits live identity. Cross-experiment use follows R-06.
- No method overrides H3 or H4.

- *Source / status:* Contract §6; H7 [A0].
- *Dependencies:* F (each method); D and E (which situations arise).
- *Abstract/concrete:* abstract. Each method is concrete.
- *Evidence eventually required:* S for the method; E; X for interval evidence.
- *Earliest legitimate closure:* statement K0; methods K5, and in any case before reliance.
- *If unmet:* the dependent claim is unavailable.
- *Narrow H18:* Register §7 is the narrow instance.

**R-29 — Post-loss and fault-dependent propositions.**
- A proposition that depends on observing the subject after an unexpected termination, crash or reboot is available only where all of these hold:
  - that exact observation is in the originally authorized sequence;
  - an applicable method has been adopted;
  - the platform premises are established;
  - any fault execution is separately authorized.
- Otherwise the proposition is unestablished.
- Synchronization status and same-instance readback do not establish crash survival.
- No post-crash mechanism has been adopted in the controlling record I inspected.
- This requirement confers no authority to recover, resume, run an unplanned diagnostic, or rebuild observations that were never made.

- *Source / status:* Contract §3 durability paragraph; §6 [A0].
- *Dependencies:* F; G.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; E; X from an authorized fault execution only.
- *Earliest legitimate closure:* statement K0. A realization comes no earlier than K5 and needs its own authority.
- *If unmet:* survival claims stay unestablished.
- *Narrow H18:* the narrow profile excludes crash survival.

**R-30 — A custody basis that does not depend on the artifact itself.**
- Each relied-upon artifact needs a demonstrated custody chain from admission to retrieval, and the chain cannot rest on the artifact's own claims about itself.
- The custody basis is either an uninterrupted binding or a bounded method connecting the retrieved artifact to independently protected provenance.
- *Independently protected* means the anchor cannot be modified through capabilities available to the writer, reader, sender, receiver, or any party whose account it validates. The test is applied after the capability-union analysis of R-24.
- An unverified pathname lookup or matching digest is insufficient. Losing all bindings does not authorize reacquisition.

- *Source / status:* [A1-G] H18 §9.3; PO-10; PO-11. [A0] H15 (the record does not authenticate itself); Contract §4.
- *Dependencies:* F; G; H (retention noninterference).
- *Abstract/concrete:* abstract. A particular route is concrete. Whether broader scope must use exactly the narrow Route A and Route B classes is held as class B and not proposed (§J).
- *Evidence eventually required:* S; E for actual protection; X.
- *Earliest legitimate closure:* statement K0; credible K2; method K5; deployment K8; chain assessment K11.
- *If unmet:* the artifact cannot support reliance.
- *Narrow H18:* PO-10 and PO-11 are the narrow instances.

**R-31 — Retention.**
- The retention interval covers acquisition and admission, transfer, closure, required independent review, and applicable later proposition-level evaluation, until separate release authority.
- Duration and preservation conditions are fixed before execution.
- Cleanup does not remove retained governed evidence without release authority.
- Required adverse evidence stays available, and release or loss is not concealed.
- B5-dependent noninterference premises stay under the HOLD.

- *Source / status:* [A0] H3; H15; H16. [A1-G] H18 §14; PO-20 (the interval and its fixing before execution).
- *Dependencies:* F; G; H.
- *Abstract/concrete:* abstract. The duration and conditions are concrete.
- *Evidence eventually required:* S; E for actual conditions.
- *Earliest legitimate closure:* statement K0; conditions fixed by K8.
- *If unmet:* the evidence chain cannot be assessed.
- *Narrow H18:* generalizes PO-20.

### Group V — Acquisition, transfer and representation

**R-32 — Acquisition authority.**
- That a proposition will eventually require evidence does not authorize acquiring it.
- Each empirical or execution observation needs specific prior authority naming its scope, together with every applicable predecessor gate.
- Acquiring platform premises is itself a host observation. It must respect the unopened host-observation envelope.
- Appearing in adopted architecture grants no acquisition authority, and this candidate grants none.

- *Source / status:* Contract §4 closing paragraph; retained note N5; Register §3 (E-class acquisition requires specific authority and predecessor gates) [A0].
- *Dependencies:* none.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the authorization record.
- *Earliest legitimate closure:* K0.
- *If unmet:* acquisition is unauthorized.
- *Narrow H18:* applies by its own terms.

**R-33 — Transfer and provenance integrity.**
- **[A0] Contract §7.** Each design needs a concrete transfer and provenance contract. That contract covers:
  - original acquisition, producer, authority and interval;
  - what was emitted, transferred, received, transformed and retained;
  - proven identity versus copies, derivatives or unresolved status;
  - detection and reporting of omission, truncation, duplication, reordering, conflicting versions, regeneration or re-derivation, and selective emission;
  - preservation of original outcomes;
  - inventory coverage;
  - independent reconstruction.

  Transfer failure grants no retransmission, replacement representation, spool, fallback, repair or recapture. Adopting the general contract does not satisfy the concrete one.
- **[A1-G] From PO-16 and H18 §13:**
  - declaration, start, emission, receipt, validation, acceptance for a stated use, and retention are separate states;
  - a partial transfer is an original failure state;
  - replay or staleness and wrong-attempt substitution join the detection list;
  - a required failure condition that can be neither detected nor validly excluded bars positive reliance;
  - the number of forward transfers per artifact is fixed in advance, and no transfer is added on failure.

- *Dependencies:* F (transfer design); E; G (transport premises).
- *Abstract/concrete:* abstract. The forward-transfer count and the route are concrete.
- *Evidence eventually required:* S; E; X for emission, receipt and validation.
- *Earliest legitimate closure:* statement K0; credible K2; design K5; premises K8; reconciliation K11.
- *If unmet:* the affected conclusion stays uncertain or unproven.
- *Narrow H18:* generalizes PO-16. The narrow one-transfer and ten-transfer figures are not carried over.

**R-34 — Lossless, bounded native-result representation.**
- The original request, the native result or error, malformed, partial and adverse observations, uncertainty, provenance and framing are all represented without loss within a declared bound.
- A summary does not substitute. Framing is charged. Malformed and error cases have a supported bound.

- *Source / status:* [A0] Contract §3 short/error/uncertain row; §8 (preserve original outcomes); H11 (no truncation). [A1-G] PO-18.
- *Dependencies:* D and G (result modes); E; F (fixing a representation is concrete).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for encoding and size analysis; E; X.
- *Earliest legitimate closure:* statement K0; credible K2; fit K5; binding K8.
- *If unmet:* results could truncate, and reliance is barred.
- *Narrow H18:* the 4,096-byte record and its groups are not carried over.

### Group VI — Inventory, capacity and accounting

**R-35 — Closed inventory and production-route coverage.**
- Every object produced or admitted is classified as governed support, test subject or contextual object, with its accounting treatment stated.
- Every production and admission route is either declared, with its class, producer, operations, destination, bounds, references, retention and accounting, or excluded on evidence. This includes failure, platform-mediated, diagnostic, reporting and teardown routes.
- Unknown output is never zero.
- Unexpected or unreconciled potentially governed production triggers H9: completeness is unproven, further governed dispatch stops, and dependent positive qualification is blocked.
- Reclassification never cures unauthorized production (N4).

- *Source / status:* Contract §5; H5; H8; H9; retained note N4 [A0].
- *Dependencies:* F (route map); G and H (platform and agent outputs).
- *Abstract/concrete:* abstract. The route map is concrete.
- *Evidence eventually required:* S for route analysis; E for exclusions; X for reconciliation.
- *Earliest legitimate closure:* statement K0; credible K2; map K5; reservations K8; reconciliation K11.
- *If unmet:* completeness is unproven.
- *Narrow H18:* PO-15 is the narrow instance.

**R-36 — Capacity conservation.** Each broader attempt satisfies the abstract capacity model in §K, within the generally applicable H10 ceilings and any smaller authorized bound.
- *Source / status:* §K attributes each invariant separately. Most are [A0] under Contract §10 and H8–H12 and H17. Those marked [A1-G] are generalized from H18 §12.
- *Dependencies:* F (allocation); G (platform bounds); H.
- *Abstract/concrete:* abstract. Any allocation among a design's parts is concrete.
- *Evidence eventually required:* S for worst-case analysis; E for platform-output bounds; X for reconciliation.
- *Earliest legitimate closure:* statement K0; credible fit K2; allocation K5; reservations K8; frontier accounting K10; reconciliation K11.
- *If unmet:* a capacity failure, which brings no enlargement (H11).
- *Narrow H18:* no narrow quantity is carried over. The 64-object envelope is unchanged.

**R-37 — Design sufficiency is distinct from execution reconciliation.**
- Showing that a design is sufficient in the worst case is one conclusion. Showing from original evidence that an actual attempt conformed to that design is another. Neither stands in for the other.
- Conservative accounting gives at most a provisional bound. It proves no identity, completeness or permission to continue.

- *Source / status:* [A0] Contract §10; H13. [A1-G] PO-23.
- *Dependencies:* none for the statement.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S and E for design; X for reconciliation.
- *Earliest legitimate closure:* statement K0; design K5; reconciliation K11.
- *If unmet:* feasibility could be misreported as satisfaction.
- *Narrow H18:* generalizes PO-23.

### Group VII — Premises, gates and operational separation

**R-38 — Premise classification and premise-failure handling.** Every material premise is classified as one of two kinds:
- **Pre-execution:** needed for a lawful or safe first effect, and establishable without the governed operation. It is established under specific authority before K8.
- **Execution-observable:** obtainable only through the governed operation. Before execution, the design must:
  - reserve the observation route;
  - define the admissible observation and its failure or uncertainty classification;
  - show that behavior stays safe and bounded if the premise is false;
  - name the applicable stop.

  The fact is acquired at the authorized event. Its consequence is applied at the decision point that depends on it: **before any dependent dispatch (K9)** and **before sealing or finalization (K10)** where those depend on it.

Further rules:
- Positive qualification (K11) cannot defer a premise needed earlier.
- No operation may require the fact it is meant to produce.
- When an execution-observable premise fails (PF), the affected dispatch stops or the claim is classified, as the design specified. The failure never grants retry, a new probe or any extension.
- Platform premises carry their acquisition interval and currentness, and no earlier result is inherited across a materially changed premise.

- *Source / status:* [A1-G] PO-21. [A0] Contract §§2 and 4 item 7; H4; H15; Lifecycle Bindings Part C §§8 and 10.
- *Dependencies:* G; C where the premise is P0-gated; H where it is B5-governed; F (acquisition design).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the premise inventory; E for pre-execution premises; X for execution-observable ones.
- *Earliest legitimate closure:* statement K0; classification K5; pre-execution evidence and readiness controls K8; consequences at K9 and K10 when triggered; reconciliation K11.
- *If unmet:* a gate could be bypassed, so the affected reliance is blocked.
- *Narrow H18:* generalizes PO-21.

**R-39 — Gate tagging and the categorical sequence.**
- Every element is tagged as one of: generic or pre-gate; P0-dependent; B5-dependent; Approval-B-dependent; or later operational.
- All V2-2B implementation authorization and execution stay behind P0 qualification, then separately authorized Approval B, then interface-tailored V2-2B, then any later implementation or execution decision. This holds however interface-independent an element appears.
- Only a separately authorized governance decision can change that sequence.
- Each gated dependency closes only through its own process.

- *Source / status:* Register §5 and PO-22 (whose text applies to all V2-2B implementation and execution); Revision 4 adoption effects 3–5; Contract §12 item 9; Plan §E (untracked working-copy source) [A0].
- *Dependencies:* none for the statement.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S for the dependency analysis.
- *Earliest legitimate closure:* K0. Tags are complete by K5.
- *If unmet:* risk of bypassing a gate, so the affected work is blocked.
- *Narrow H18:* identical in content to the narrow PO-22.

**R-40 — Operational separation and representativeness.**
- Level-2 conclusions apply only to the disposable mechanisms, subjects, intervals, fault conditions and premises actually demonstrated.
- They establish nothing about actual F/Q/O identity, qualification, custody, parent suitability, candidate correctness, restoration, release or service authority.
- Actual F/Q/O, their actual parents, protected P/I/O and P0 candidates are never subjects or destinations.
- Where a conclusion is meant to bear on an actual parent environment, the premise that the disposable setting is representative of it must be stated as a premise.

- *Source / status:* Contract §§1 and 11; H19; Plan §D1 [A0].
- *Dependencies:* C, and only for reliance on actual Q-parent qualification or some other fact gated by P0 (Register §5).
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; E only through P0's own process.
- *Earliest legitimate closure:* statement K0. P0-tagged premises are settled only after P0.
- *If unmet:* the conclusion stays confined to the disposable subject.
- *Narrow H18:* applies by its own terms.

### Group VIII — Reporting, review and the implementation boundary

**R-41 — Outcome classification, conflicts, anti-selection and reporting-execution separation.**
- Supported, violated, uncertain and unobserved results stay distinct. Known adverse results stay visible.
- Conflicts keep their sources and dependencies. They are not averaged, merged, overwritten, regenerated away or omitted.
- There is no favorable-candidate or first-valid selection.
- A failure to report cannot postpone a stop or turn the outcome into a pass (Contract §8). Reporting closure is not physical quiescence (R-11).

- *Source / status:* Contract §8; H13; H14 [A0]. PO-14 is the narrow statement.
- *Dependencies:* F.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S; X.
- *Earliest legitimate closure:* statement K0; rules K5; final classification K11.
- *If unmet:* positive qualification is barred.
- *Narrow H18:* applies by its own terms.

**R-42 — Authorization package and independent review.**
- **[A0] Review rules.** No model provides the qualifying review of its own current revision. Tier, findings-record, clause-2 and provenance-record requirements apply. Adoption belongs to you. The H16 rule on author and reviewer difference also applies.
- **[A1-G] Package contents.** Generalized from PO-24, an implementation-authorization package identifies:
  - the exact design;
  - the conformance showing;
  - methods;
  - route and capacity analysis;
  - the premise schedule;
  - gates, stops and limitations;
  - reviewer eligibility and disposition;
  - your decision.
- Execution needs its own authority. Applicable concrete matters cannot be deferred past concrete-design closure.

- *Source / status:* as attributed above, from Decision 0010, H16, H20 and PO-24.
- *Dependencies:* F.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S.
- *Earliest legitimate closure:* statement K0; package by K7.
- *If unmet:* no authorization.
- *Narrow H18:* generalizes PO-24.

**R-43 — No resolution by implementation.**
- Writing code, or choosing how to implement something, cannot decide a disputed governing interpretation, fill an open architectural variable or discharge a gated dependency. Implementation stays behind the categorical sequence.
- This does not bar implementation choices that an adopted design already leaves to implementation, such as the "implementation choice" label in H18 Draft 4 §1.

- *Source / status:* Contract §12, closing paragraph; Plan §B (derived aids cannot reinterpret adopted text); Register §5 (a generic design argument confers no implementation authority) [A0].
- *Dependencies:* none.
- *Abstract/concrete:* abstract.
- *Evidence eventually required:* S.
- *Earliest legitimate closure:* K0.
- *If unmet:* concrete design is adopted silently, which is nonconforming.
- *Narrow H18:* identical boundary.

### E.9 Crosswalk from the superseded BR-01 to BR-30

| Fable entry | Successor | Treatment |
|---|---|---|
| BR-01 | R-01 | Retained, reworded |
| BR-02 | R-02 | Rewritten. A0 and A1-G elements separated. The blanket E3 Category 3 claim removed (§N.2) |
| BR-03 | R-04, R-05, R-06, R-08 | Split. The blanket ban on evidence moving between domains replaced by R-06. P narrowed to determination C |
| BR-04 | R-09 | Retained, with fixed end-of-dispatch rules and terminal slots added |
| BR-05 | R-11, R-12, R-13, R-14, R-15 | Split and rebuilt. The non-dispatch resolution route restored; definite and possible entry separated; post-loss rules made explicit |
| BR-06 | R-16 | P dependency removed. The BLOCKED-R consequence made explicit |
| BR-07 | R-17 | Retained, scoped to the eligibility invariant |
| BR-08 | R-19, R-20 | Split. Terminal eligibility given its own entry |
| BR-09 | R-21, R-22 | Rebuilt. Three late-return mechanisms separated; freezing moved to R-22 |
| BR-10 | R-18 | Rewritten. Historical showing separated from exclusion of future crossing |
| BR-11 | R-23 | Retained |
| BR-12 | R-24 | Retained |
| BR-13 | R-25 | Retained, with A0 and A1-G attribution separated |
| BR-14 | R-26 | Retained |
| BR-15 | R-28 | Corrected. Confined to the rows of the matrix that require a method |
| BR-16 | R-29, R-15 | Retained. "No mechanism exists" narrowed to the inspected record |
| BR-17 | R-32 | Retained |
| BR-18 | R-33 | Retained, with general (A0) and PO-16-derived (A1-G) elements separated |
| BR-19 | R-30 | Retained. Route classes held as class B |
| BR-20 | R-22 | Retained and expanded |
| BR-21 | R-34 | Retained |
| BR-22 | R-35 | Retained, with object classification added |
| BR-23 | R-36 and §K | Retained, attributed invariant by invariant |
| BR-24 | R-37 | Retained |
| BR-25 | R-38, R-39 | Split. Safe handling of a false execution-observable premise and its K9/K10 consequence added |
| BR-26 | R-40 | Retained. C scoped to each proposition |
| BR-27 | R-41, R-11 | Retained |
| BR-28 | R-31 | Retained |
| BR-29 | R-42 | Retained |
| BR-30 | R-43 | Retained, scoped |
| — | R-03, R-06, R-07, R-08, R-10, R-20, R-27 | New: entries missing from the superseded catalogue |

---

## F. Candidate closure and dependency architecture

### F.1 Status

This is a **dependency model**. It is not a closure ladder.
- It adopts nothing.
- It does not extend the Register's CP0–CP6 to broader scope.
- It does not supply the formal feasibility standard for broader scope.

The Revision 4 adoption record states that no new ladder is adopted and that Category 2 does not silently inherit the narrow ladder. The narrow Register's CP0–CP6 continue to govern the narrow profile unchanged.

A selection made on the narrow CP1 establishes nothing about broader obligations. This candidate adds no precondition to such a selection.

### F.2 Candidate closure points

| Point | What it is | What must already hold | Permissible evidence | May remain symbolic | Stop when |
|---|---|---|---|---|---|
| **K0 Statement adoption** | Your architectural adoption of abstract statements | Qualifying cross-family review of the exact pinned text; the Revision 4 reliance test met | S, limited to adopted governance records | All bindings | A provision needs a protected or empirical fact, carries narrow-profile acceptance, or classifies as concrete or in doubt |
| **K1 Exploratory documentary comparison** | Findings about candidates against stated requirements | A specific assignment. It may compare against **non-adopted** candidate requirements if labeled as such | S, documentary only | Capacity values, representations, D-tagged bindings | The comparison would commit later work to one candidate, shape a requirement to fit a candidate, need a protected fact, or present itself as closure. **K1 closes, selects and eliminates nothing** |
| **K2 Formal feasibility showing** | A feasibility determination under an adopted standard | **Broader closure arrangements that you have adopted, stating the standard. This candidate supplies none.** The Register's five-part CP1 test is the obvious template, but it is not adopted for broader scope | S. E only where its own gate has already lawfully produced it | Gated unknowns, if recorded and not fatal to credibility | A known incompatibility exists, a gated unknown prevents a credible showing, or a protected fact is indispensable (see F.3 J1) |
| **K3 Backend selection** | Your decision | Applicable K2 for every obligation the selection relies on; qualifying review | The K2 record | All concrete-design matters | Analysis would itself select or eliminate |
| **K4R Approval B read** | One bounded, read-only document inspection | P0 qualified through its own process (Revision 4; Register §5). Plan §J, an untracked working-copy source, also places V2-0, V2-1, M0-1 and V2-2A before the read. Approval B separately authorized; inspection inside its adopted envelope | The bounded read record, with provenance | — | The read would exceed its envelope or seek deployment facts. **The read establishes no feasibility and no deployment fact** |
| **K4T Tailoring** | Determination of material properties, cases, oracle sources and continuity triggers from the admitted read record | K4R completed and its record admitted. Pre-read neutral architecture pinned. Tailoring is itself candidate work needing review and adoption | The admitted read record; S | Realizations specific to a backend; G- and H-tagged items | Tailoring would settle concrete design or need facts beyond the read |
| **K5 Concrete-design closure** | The CP2 analogue | Methods, routes, allocations, dependencies and conformance arguments resolved or expressly dispositioned. A disposition cannot waive a prerequisite | S; E through its own gates | Execution-observable facts with reserved routes | A disposition would waive an applicable prerequisite |
| **K6 Concrete-design adoption** | Your adoption | K5; qualifying review of the exact pinned text | The K5 record | As K5 | The classification of any provision is in doubt (treated as concrete) |
| **K7 Implementation authorization** | A separate decision | The categorical sequence (R-39); K5; the R-42 package | S | Execution-time facts | Any predecessor is open |
| **K8 First governed effect** | The CP3 analogue | Specific execution authority, with the items listed under K8 in F.4 in place | E and X, each under specific authority | No item that F.4 requires at K8 | Any K8 item is missing |
| **K9 Each dependent dispatch** | The CP4 analogue | See F.4 | X; S | — | Any eligibility predicate fails |
| **K10 Sealing and finalization cutoffs** | The CP5 analogue | See F.4 | X; S | — | The order or frontier cannot be kept |
| **K11 Positive qualification** | The CP6 analogue | See F.4 | X; S; E | — | Any predicate is unmet. K11 never defers an earlier predicate |
| **PF Execution-observable premise failure** | An event, not a point | The predeclared classification and stop under R-38 | X | — | Applied at the earliest affected K9, K10 or K11 |

### F.3 Partial order

Two chains run independently.
- **Documentary chain:** K0, then K1 (optional), then K2, then K3.
- **Gate chain:** P0, then K4R, then K4T.

They join only as follows.

- **J1. Conditional protected-fact dependency.** For an obligation whose credible feasibility showing *indispensably* requires a protected-interface fact, two things wait for the authorized read and the lawful admission of its record: K2 for that obligation, and any K3 relying on that K2. Because the read itself follows P0, the resulting order for that obligation is: P0, then the authorized read, then the indispensable protected evidence, then the remaining feasibility closure, then your selection. K2 for obligations that need no protected fact may come before K4R. The read does not establish feasibility. This is a consequence of R-39, R-32 and the feasibility rule, not a new rule. **It does not mean that every selection must follow Approval B.** Whether J1 applies is decided obligation by obligation at K2.
- **J2.** K5 for any D-tagged binding follows K4T.
- **J3.** K5 for any E-tagged binding follows K3.
- **J4.** K7 follows the categorical sequence in R-39, however interface-independent an element appears.
- **J5.** K8 follows K7 and its own authority. K9, K10 and K11 then follow in execution order.

K1 may come before everything else under a specific assignment, using no protected facts.

### F.4 Obligations at execution-time points

| Point | Obligations that must be satisfied or applied |
|---|---|
| **K8 First governed effect** | R-01, R-02 (binding), R-03 (coverage), R-05 (allocation), R-06 (admissions), R-07 (relationships), R-09 (schedule), R-19 (bounds), R-20 (terminal actions fixed), R-21 (windows), R-23 and R-24 (enforcement in place), R-31 (retention conditions), R-32 (authority), R-35 and R-36 (inventory and reservations), R-38 (pre-execution premises; readiness for execution-observable premises), R-39 (gates satisfied) |
| **K9 Each dependent dispatch** | R-10 (eligibility); R-12 through R-17 (`Q`, `U(k)`, resolution of any earlier `IN_FLIGHT` or possible dispatch, post-loss conditions); R-21(a) (admission predicates); R-38 (consequences of any execution-observable premise the dispatch depends on); R-35 (H9 stop on unexpected production); R-19 (stops) |
| **K10 Sealing and finalization** | R-20 (terminal evaluation before freeze); R-21(b) and (c); R-22 (order, fence, frontier, fixed objects and charges); R-36 (frontier accounting); R-38 (consequences of premises that finalization depends on) |
| **K11 Positive qualification** | R-02 (evaluation), R-04 (combined record and lineage completeness), R-10 (interval evaluation), R-18 (interval proof), R-30 (custody chain), R-33 (transfer reconciliation), R-35 to R-37 (production and capacity reconciliation), R-41 (classification). Nothing required earlier may be deferred here |
| **PF** | R-38: the predeclared classification and stop apply at the earliest affected point. No retry, probe or extension |

---

## G. Evidence Contract applicability

**Eventually required is not currently authorized.** Every row below constrains later work. None authorizes acquisition, observation or execution (R-32). This assignment grants no acquisition authority.

| Topic | Controlling source | Constraint on broader architecture | Catalogue |
|---|---|---|---|
| Proposition materiality | Contract §2; H13; H14 | A material mechanism or premise change may create a distinct proposition. Uncertain materiality counts as material. No favorable result transfers across incompatible mechanisms | R-01, R-04 |
| Authorization | Contract §§2, 4 and 12; H3; H19; H20 | The first effect needs specific authority fixing the H3 matters. Platform-premise acquisition is host observation (N5) | R-01, R-32 |
| Provenance | Contract §4; H15 | Nine relationships for every relied-upon observation. Names, hashes and labels prove nothing alone | R-26, R-27 |
| Continuity | Contract §6; H7 | A method only where the matrix requires one. No method overrides termination or no-retry | R-28 |
| Custody | Contract §§4 and 7; H15; H18 policy | The record does not authenticate itself. A concrete transfer and provenance contract is required for each design | R-30, R-33 |
| Adverse lineage | Contract §§2 and 9; H14; N1 | Earlier and concurrent attempts stay in lineage. Uncertain relevance means inclusion | R-04, R-06 |
| Inventory | Contract §5; H5; H8; H9; N4 | Closed inventory with evidenced exclusions. Unexpected production triggers the H9 stop | R-35 |
| Accounting | Contract §10; H8 to H12; H17 | Worst case, cumulative, no refund, independent ceilings | R-36, §K |
| Stopping | Contract §§2 and 8; H3; H4 | Stopping is unconditional, creates no authority and never resumes | R-19 |
| Reporting | Contract §8; H13 | Four outcome classes. Conflicts preserved. Complete reporting is not success | R-41, R-11 |
| Post-loss evidence | Contract §§3 and 6 | Usable only if originally authorized, with an adopted method | R-15, R-29 |
| Historical admission | Contract §§6 and 10; H17 | Citation and admission are distinct. Charged in the receiving domain. Currentness separately justified | R-06 |
| Reliance limits | Contract §§3 and 11; H19 | The §3 limits column applies per property. No promotion to actual F/Q/O | R-03, R-40 |
| Concurrency | Contract concurrency disposition; §9 | Determination C is unresolved. Replication falls under H4. No concurrent execution authority | R-08 |
| Concrete H18 contract | Contract retained condition 3; §7 | Adopting general contracts does not satisfy a design's concrete transfer, continuity, inventory, premise or case prerequisites | R-33, R-28, R-35, R-38 |

---

## H. Concurrency treatment

| Question | Governing source | Status in this candidate | Effect of resolving determination C |
|---|---|---|---|
| **A. Overlapping subject operations within one attempt** | Retained serial-dispatch architecture: H18 §3.3, generalized by R-16 | Prohibited. A proposition that needs it is **BLOCKED-R** | None. C does not reach it |
| **B. Predetermined replication** | H4; Contract §9; N2; N6 | Permitted only under specific, advance, outcome-independent authority. Concurrent replication also needs §9 interference and attribution controls | None. C does not decide it, and replication does not reopen C |
| **C. Non-replication concurrent attempts on materially overlapping propositions** | Contract concurrency disposition (determination C) | **P**. Neither authorized nor presumed permissible | This is the question C decides |
| **D. Concurrent non-replication attempts on propositions that are not materially overlapping** | Contract §9; H4 scope question in N3 | Outside C. No concurrent execution authority exists. Not dispatchable without specific authority. Uncertain overlap is treated as C | None directly. The N3 scope question stays for authorization practice |

**Blocked propositions.** Within V2-2B scope, any proposition about races, overlapping writers or concurrent subject effects inside one attempt is BLOCKED-R under R-16. That includes the asynchronous and concurrent activity that Contract §3 lists as write-capability coverage, so far as observing it would require overlapping subject operations. Such propositions are not policy-dependent. Making them reachable would take a separately proposed and adopted architectural change. In any event no prohibited writer topology can be qualified by exercising it. **This candidate does not propose that change and does not decide determination C.**

---

## I. Historical evidence admission

| Concept | Crosses domains? | Basis |
|---|---|---|
| Live experimental identity and capability | **Never** | H2; H17; Contract §6 |
| Live capacity allocation, including unused capacity | **Never** | H10; H17 |
| Qualification status (a PASS or other disposition) | **Never automatically.** It is not inherited across a materially changed premise, and its applicability must be separately justified | Contract §11; Lifecycle Bindings Part C §10; H17 currentness |
| Architectural or review acceptance | **Never** | Revision 4 §D; Decision 0010 clause 4 |
| **Historical evidence**, as cited or admitted artifacts | **Yes, as evidence**, under the receiving domain's own rules | H17; Contract §§6 and 10; H14 |

When historical evidence is admitted, the receiving domain applies its own:
- authority;
- provenance requirements (R-26);
- currentness justification;
- adverse-lineage completeness (R-04);
- materiality judgment;
- accounting, with the admitted report charged once and derivatives charged separately;
- proposition-specific reliance limits (R-03).

The evidence keeps its original evidence level and platform limits. It cannot supply an original observation that the receiving attempt's own requirements assign to that attempt (R-06(e)).

**Classification.** Authorized admission is not in itself Category 3 or a general-policy amendment. It would become I₃ only if accommodating it changed narrow-profile limits or semantics. Examples: a ninth admitted input for the narrow attempt; or counting admitted evidence as the narrow attempt's own required X evidence, which would change conformance acceptance. It would become I_G only if it required changing H17 or the Contract.

---

## J. Abstract/concrete classification

Each provision was tested against Revision 4 §F on its own: what adopting it would settle, and what later work could then treat as settled. As the retained caution requires, names and terminology played no part.

**Abstract.** R-01 to R-43 as worded. Each settles *what* must hold. None settles, or lets later work treat as settled, any of the following:
- a procedure or component;
- an evidence or capability path;
- a representation;
- an enforcing component;
- an allocation among a design's parts;
- an external dependency;
- a conformance argument.

R-08's classification rule and R-21's capture bound of one unresolved operation are abstract consequences, not allocations. The number of capture objects stays concrete.

**Concrete if specified, and left as unresolved variables:**
- the slot schedule and terminal actions;
- completion-detection semantics and the state mapping;
- non-dispatch resolution and withholding-proof methods, including the end of the relevant interval;
- enforcing-set membership;
- each continuity method;
- the custody route;
- transfer routes and counts;
- representations and record sizes;
- capacity allocation among roles;
- bounds and windows;
- retention duration;
- any named component or version;
- any conformance argument.

**Doubt cases, treated as concrete or held:**

| Provision | Why in doubt | Treatment |
|---|---|---|
| Requiring exactly the narrow Route A and Route B custody classes for broader scope | May fix the arrangement of evidence-handling parts, or exclude other non-circular bases | Held as **B**. R-30 states only the abstract obligation |
| Fixed field groups for evidence records | Fixes a representation | Concrete; excluded |
| A role list for capacity | Dimensions are abstract; a list of separate objects is an allocation | §K states coverage dimensions only |
| Whether R-11 to R-16's execution-state categories suffice for propositions whose completion is signaled other than by an original terminal return (long-running or delegated effects) | Suitability depends on the material cases | The categories are offered as A1-G. Their suitability for such cases is **B** until K4T. Any finer state machine is F |

**Separability.** Adopting the A0, A1-G and A1-N statements does not require adopting any B item. None of those statements assumes an answer to a deferred concrete question.

**Backend population.** Some statements may turn out to be satisfiable by few backends, or by none. Classification does not depend on that count. I tested no candidate.

---

## K. Abstract capacity model

**Universally controlling values (H10; Contract §10):**
- 128 governed support objects;
- 65,536 bytes per object;
- 4,194,304 aggregate bytes.

Each is enforced independently, per specifically authorized experiment, and a smaller authorized bound controls. There is no cumulative V2-2B cap, and authority covering several experiments states their combined maximum (N6). **No narrow-profile quantity is carried over:** not the 64 objects, not the 2,531,328 bytes, not the headroom, not any role row or fixed object size.

**Coverage dimensions, by function.** These name what must be accounted for. They are not mandatory separate objects or components:
- inputs admitted to the domain, including relied-upon history;
- records of original source observations;
- acquisition journals and accounting ledgers;
- governed artifacts created in transit;
- copies held on the receiving side;
- outputs produced by the platform or framework;
- records of exceptions, failures and late returns;
- reconciliation, evaluation and closure records.

| # | Invariant | Source | Status | Scope note |
|---|---|---|---|---|
| 1 | Object-count, per-object and aggregate ceilings are each enforced independently, with smaller bounds controlling | H10; Contract §10 | A0 | Governed experimental support |
| 2 | Reserve the worst-case cumulative demand across all permitted paths through closure. Mutually exclusive paths share a maximum only where the exclusion is established | H8; Contract §10 | A0 | — |
| 3 | Accounting is cumulative. Each object keeps its maximum incurred charge. Deletion, shrinking, phase change, termination, branch selection, cleanup or replacement refund nothing | H11; Contract §10 | **A0. The Contract text states this explicitly, so it is not a strengthening** | — |
| 4 | Role reservations bind independently. Aggregate headroom gives no role capacity, and borrowing is prohibited | H8 (roles, maxima, no silent expansion); H11 (no borrowing) | A0 | No narrow role allocation is inherited |
| 5 | Governed intermediate artifacts are charged at their peak to a declared role | Contract §10 (transfers and normalization are in the reservation); H5; H6 | A0 | Applies to produced or admitted artifacts classified as governed support. Runtime state that is not such an artifact is not governed support by default. The boundary is demonstrated under Contract §5 and never presumed |
| 6 | Governed framing, metadata and serialization have no free allowance and are charged to a declared role or object | H6; Contract §10 (packaging does not merge charges) | A0 (the narrow analogue is H18 §12.2) | **Ambient** platform metadata is neither presumed governed nor presumed exempt. It needs a justified boundary determination under Contract §5 |
| 7 | An uncertain creation keeps its full potential charge and grants no replacement | H8; Contract §5 | A0 | — |
| 8 | Repeated proven references count once. Distinct creations, replacements, copies, derivatives and governed containers each count. Packaging merges nothing | H6; H11; Contract §10 | A0 | — |
| 9 | Failure, terminal and stopping evidence is reserved before the first effect. If closure cannot fit, it is recorded as incomplete by already authorized means, and nothing is enlarged | H8; H11; Contract §§8 and 10 | A0 | The late-return capture reservation is **A1-G** (R-21) |
| 10 | Each class of platform or framework output is declared with a reserved maximum, or excluded on evidence. Unknown is not zero | Contract §§5 and 10; H9 | A0 | — |
| 11 | History that a claim relies on is admitted and charged. When a required input is too large, that is a capacity failure, and it cannot be met with a favorable excerpt | H11; H17; Contract §10 | A0 | Excerpts permitted by a separately justified narrower proposition stay distinct derivatives |
| 12 | Moving required production to after closure does not take it out of the reservation. Artifacts that are genuinely later review fall outside the closed allocation | Contract §10; H16 | A0 | A specific operational creation frontier is concrete design (R-22) |
| 13 | Experimental accounting is separate from actual lifecycle accounting and from other experiments | H10; H12; H17 | A0 | — |
| 14 | Exceeding a reservation or ceiling is a capacity failure. No enlargement, splitting, truncation, borrowing or replacement representation cures it | H11; Contract §10 | A0 | Compression cannot merge distinct-object charges or cure a breach. It does not bar an encoding chosen and reviewed in advance as part of the design |
| 15 | Test subjects and contextual objects are not governed support. Observation records about them are. Classification is fixed before execution | H5; H18 §12.1; PO-19 | A0 (H5) plus A1-G | — |
| 16 | Conservative separate accounting gives only a provisional bound | Contract §10; H13 | A0 | — |
| 17 | No subdividing or relabeling experiments to evade a limit | H10 | A0 | — |

**Unresolved variables:**
- the realized role set;
- every per-role count, per-object maximum and aggregate;
- slot count;
- transfers per artifact and intermediates per transfer;
- exception and late-return object counts;
- platform-output and admitted-input counts.

**Evidence that would bind them:**
- **S:** worst-case route and encoding analysis.
- **E:** platform-output bounds or exclusions, partly B5-dependent.
- **X:** actual reconciliation.

**Concrete design choices (F):** dividing capacity among the roles of a particular design; choosing record sizes or representations; choosing how many intermediates a transfer uses; deciding which object carries which framing. All concrete role allocations are matters for concrete-design closure.

**Open question.** No one yet knows whether a broader profile can be accommodated within the general ceilings. If a profile required more, that would be an **I_G amendment of H10**, not a Category 3 revision. It cannot be solved here.

---

## L. Approval-B dependency map

This is a **requirements dependency map**. It is not an inspection envelope and not the output list in Plan §J. I have not used, inferred or predicted any protected content. Each row states a class of information; what an authorized document read could show; what would still need separate evidence; and what the information would bind.

| Information class | Visible in an authorized document read | Still needs other evidence | Would bind |
|---|---|---|---|
| Exact identity of the inspected files | Byte size and digest of each inspected file | — | Provenance and admission of the read record (R-06, R-26) |
| Operations and mechanisms the interface code exercises | The declared and coded operations | Actual runtime behavior (G) | Which Contract §3 properties are material; cases; schedule (R-01, R-03, R-09) |
| Result and error handling | The coded handling of results and errors | Actual platform result and error modes (G) | Oracle domain, native mapping, representation bounds (R-02, R-34) |
| Capability and resource posture as declared | The declared descriptor, inheritance and limit-related code paths | Actual process state and inheritance (G) | Applicability of the write-capability and resource-limit rows; mediation surface (R-03, R-23) |
| Package and profile binding points; declared runtime configuration | Declared configuration content | Actual deployed or loaded configuration (G; possibly C or H) | Producer identity and configuration premises (R-26, R-38) |
| Declared external dependencies | Dependencies as named in the documents | Installed versions and behavior (G) | Premise inventory (R-38) |
| Inconsistencies between declared items | Documentary mismatches between the inspected files | Any claim about actual runtime mismatch (G) | Premise classification; case selection |
| Integration seams; V1 logic to be removed or replaced | Documentary only | — | Later candidate work outside this catalogue. Tailoring only |

**Declared configuration is not deployment evidence.** A read shows what a document declares, not what is installed, loaded or executing.

**Plan §J's listed outputs** (exact sizes and digests, interfaces, binding points, plist/runtime mismatch evidence if any, V1 logic, integration seams, tailored V2-2B tests, no acceptance) belong to the future envelope architecture, not to this map.

**Designable before the read:**
- every R-nn statement;
- the maturity and tagging scheme;
- the capacity invariants;
- the general ceilings, which are already known.

**Not responsibly decidable before the read:**
- material case selection;
- ranking propositions by importance;
- any claim that a §3 row is inapplicable;
- slot count;
- **interface-dependent** allocations and fit claims.

---

## M. Safety analysis

| Safeguard | Result | Basis |
|---|---|---|
| No retry or redispatch | Preserved | R-07, R-14, R-17, R-19 |
| No subject-operation overlap | Preserved; not made policy-dependent | R-16; R-08(A) |
| Permanent `U(k)`-type ineligibility | Preserved | R-17 |
| Non-dispatch resolution limited to possible-dispatch-only, with both showings | Preserved faithfully; unavailable to definite dispatch | R-12, R-14 |
| Completion and non-dispatch kept as distinct propositions | Preserved | R-13, R-14 |
| Frozen dispositions | Preserved; no resolution or return reopens them | R-14, R-21(c), R-22 |
| Terminal eligibility | Preserved; restored `Q` is not eligibility; no late terminal target | R-20, R-21 |
| Late-return confinement | Preserved, with three mechanisms separated | R-21 |
| Post-loss controls | Preserved | R-15, R-29 |
| Evidence provenance and custody | Preserved | R-26, R-27, R-30, R-33 |
| Historical admission | Permitted only under receiving-domain rules; nothing live, no capacity, no status | R-05, R-06, §I |
| Capacity | General ceilings only; narrow envelope untouched | R-36, §K |
| Reporting and execution separation | Preserved | R-11, R-41 |
| Backend neutrality | No candidate named; B items held back | §J |
| Protected-information boundary | Not crossed; the read is distinct from tailoring | §F, §L |
| Categorical sequence; B5 HOLD; P0 NOT QUALIFIED | Unchanged | R-39 |
| Human Chair authority; cross-family review | Unchanged; this candidate is not self-certified | §R |
| Determination C | Unresolved and confined to its own question | R-08, §H |

**Residual risks:**
- **Read-back.** Someone could invoke A1-G text to reread the narrow profile. E.0 and every entry forbid it.
- **A0 drift.** A restatement could depart from its source. The source controls, and §R asks for clause-by-clause checking.
- **A1-N overreach.** Two A1-N items exist: R-08's classification rule and R-16's BLOCKED-R consequence. Each is justified and open to challenge.
- **Misuse of admission.** R-06 could be used to import favorable status. R-05 and R-06(d) and (e) block this.
- **Misplaced ordering.** J1 could be generalized into a universal rule that selection follows Approval B. §F.3 states its condition expressly.

---

## N. Category-3 versus general-policy triggers

### N.1 Principle

A change is classified by its substantive effect. One proposal can have both effects, and each is classified separately.

**Nonconformance is not revision.** A design that fails an adopted requirement is rejected under that requirement. Failure does not make it a Category 3 proposal.

### N.2 E3 — where the line actually falls

Evaluating E3 as an independent pass/fail proposition is **within the adopted profile** when all of the following hold:
- its own independent expected-outcome source, revision and native-result mapping are bound before the first governed effect (PO-01; the retained Kimi caution);
- the oracle package and any added records fit within the existing role bounds, including the eight-input allowance and the record envelope (H18 §12.2; PO-18; PO-19);
- E3's dispatch, outcome-classification, stop and evidence rules are unchanged.

Claiming E3 support **without** that package is implicit broadening. It is rejected as nonconformance under PO-01; it is not a revision.

An E3 treatment becomes **I₃** only if it would do one of the following:
- add, repeat, replace or reorder a slot, or change any E1–E7 eligibility predicate;
- change the rule that E3 failure or uncertainty ends ordinary dispatch and withholds Case 2;
- change H18 §4.3's treatment of an E3 result under an unproven E2-to-E3 absence premise, for example by counting refusal under an unproven absence as adverse;
- widen the §2 profile (link variants, races, general exclusive-creation qualification);
- require objects or bytes beyond the role bounds;
- change conformance acceptance, by accepting E3 evidence that PO-01 or PO-18 would reject.

### N.3 Category 3 (I₃) triggers

A change to any of the following:
- the seven-slot schedule, or the predicates P, L3, A, `Q`, `U(k)` and `T(k)`;
- in-flight, completion or non-dispatch rules, including the clarification;
- late-return confinement or X-L;
- the source-sealing order or the finalization sequence;
- enforcing-set membership (H18 §8.3);
- Route A or Route B custody requirements;
- the 64-object / 2,531,328-byte role table, fixed object sizes or the record envelope;
- the §2 exclusions;
- conformance acceptance or the Register's closure assignments.

Also: placing a broader case inside the narrow attempt, or reading a broader generalization back onto the narrow profile so that its semantics change. Backend variation within the existing constraints is not a revision.

### N.4 General governance amendment (I_G) triggers

- Raising or lowering H10's ceilings, or amending any other H1–H20 provision.
- Changing a Contract requirement.
- Resolving determination C. This is a policy decision that supplements general policy, and it would be recorded as such.
- Changing the categorical gate order, which needs a separately authorized governance decision (Register §5; Revision 4).
- Amending Decision 0010 or Revision 4.

Lowering H10 below the narrow profile's arithmetic would also require an assessment of its impact on the narrow profile. Raising H10 confers nothing on the narrow profile, whose own role bounds stay binding (H18 §12.2).

### N.5 Neither

- Authorized historical admission within allocations.
- Backend variation within constraints.
- Adopting this candidate's statements for broader scope, which is Category 2 adoption.
- Bounded investigation of concrete answers that adopts or relies on none of them.

---

## O. Astra B1–B4 closure table — author position only

Only Astra may mark these findings resolved or withdrawn (Decision 0010 clause 3). The entries below are my author position.

| Finding | Author position | Where | What changed |
|---|---|---|---|
| **B1 — lifecycle fidelity** | **Addressed** | R-11 to R-22; §M | Definite and possible-only entry separated (R-12). Completion (R-13) and non-dispatch resolution (R-14) are distinct propositions; the resolution requires both historical non-crossing and exclusion of future crossing, and is unavailable to definite dispatch. Post-loss conditions apply (R-15). Effects confined to that slot's `Q` obstruction, with no `U(k)` restoration, retry, stop reversal, frozen-disposition change or terminal target. The withholding proof is distinguished as historical (R-18). Terminal eligibility given its own entry (R-20). Admission closure, return capture and frozen-disposition finality separated (R-21). The "several outstanding operations" inconsistency removed: the capture bound follows from R-16. Faithful generalization, with no deliberately stricter rule |
| **B2 — concurrency** | **Addressed** | R-08, R-16; §H | Four-way classification. P used only for determination C. In-attempt overlap is BLOCKED-R. Replication stays under H4. Resolving C cannot relax no-overlap, authorize a prohibited writer topology or decide replication |
| **B3 — historical admission** | **Addressed** | R-05, R-06; §I | The blanket prohibition removed. Live identity, capacity, qualification and acceptance kept separate from admission of historical evidence under receiving-domain rules. Admission is not in itself Category 3 |
| **B4 — Category 3 precision** | **Addressed** | R-02; §N | The blanket E3 trigger removed, and the actual I₃ conditions for E3 stated. I₃ separated from I_G. Nonconformance separated from revision |

---

## P. Non-blocking-note treatment

| Note | Treatment | Where |
|---|---|---|
| **N1 — closure wording** | Exploratory comparison (K1) closes nothing and may run against non-adopted requirements. Formal feasibility (K2) requires adopted broader arrangements. The read (K4R), tailoring (K4T) and selection (K3) are separate points | §F.2, §F.3 |
| **N2 — attribution precision** | Invariant 3 marked A0, with the Contract stating it explicitly. Every entry attributes its A0 and A1-G elements separately | §K, §E |
| **N3 — future closure completeness** | Obligations stated at the first effect, each dependent dispatch, sealing and finalization, and positive qualification, plus the premise-failure event and safe handling of a false execution-observable premise | §F.4; R-38 |
| **N4 — scope qualifiers** | Capacity charging limited to governed support, with ambient metadata needing a boundary determination. Declared configuration distinguished from deployment evidence | §K invariants 5–6; §L |
| **N5 — provenance** | Both status enumeration modes recorded. The untracked Plan's exact identity kept, without presenting it as committed. The untracked Decision 0010 proposal file identified and not treated as governing | §B.1, §B.3 |

---

## Q. Recommended next bounded assignment

**One: the Approval B inspection-envelope architecture, as a bounded Category 2 candidate.** It should begin only after this candidate's review cycle closes, and preferably after your disposition of it.

**Reasons:**
- It is step 3 of Revision 4's recommended sequence.
- It lies on the path every tailored broader proposition must cross.
- §L now states what the read would bind, which the envelope needs as its requirements input.

**Why not the alternatives:**
- **Broader closure arrangements.** These are not needed until a broader formal feasibility showing or selection is actually proposed. K1 can proceed without them.
- **Determination C.** This is your policy decision, not an architecture assignment.

**I do not authorize or begin it.**

---

## R. Independent-review requirements

1. **Tier.** Yours to assign. Astra reviewed the superseded candidate at FORMAL ADOPTION / QUALIFICATION.
2. **Reviewer eligibility.**
   - The author family is Anthropic / Claude. The superseded author, Fable 5.2, is also Anthropic / Claude. A qualifying reviewer must come from a different, verified foundation-model family (Decision 0010 clauses 7–8).
   - Historical Anthropic contributions elsewhere in the lineage are not authorship of this revision. They include: Opus's review of H1–H20; review findings on the Contract; the O1–O3 findings on H18; and correction-verification of the Register.
   - Astra's B1–B4 and N1–N5 findings were inputs that I resolved in my own words (clause 1).
3. **Clause 2 disclosure.**
   - I adopted no reviewer-authored substantive language verbatim. Finding identifiers and fixed labels are reproduced as labels.
   - Short phrases quoted from **adopted governing text** are citations of the controlling source, not adoption of reviewer language. Examples are "confined, not proven closed" and "could not have crossed".
   - Some adopted texts that I restate or generalize were authored within the OpenAI/Astra workstream: H1–H20, the Contract, H18 Draft 4, the Register and the clarification. If the reviewer considers that this bears on its eligibility to qualify any passage, it should say so. You resolve any disagreement (clause 2(e)).
4. **Scope.** The complete pinned artifact. The pin is its SHA-256 as delivered.
5. **Review should cover at least:**
   - A0 fidelity, clause by clause, against the cited Contract and H1–H20 text;
   - element-by-element A1-G fidelity of R-11 to R-22 against H18 §§3–7 and 11, PO-03, PO-09, PO-12, PO-13 and PO-17, and the clarification;
   - the two A1-N justifications;
   - §F as a non-ladder;
   - §K attribution;
   - §L's boundary;
   - §N's classifications.
6. **Suggested adversarial cases:**
   1. A definitely dispatched operation attempts the non-dispatch route.
   2. A possibly dispatched operation shows non-crossing so far while delegated dispatch remains pending.
   3. An unplanned reap status is offered after a loss.
   4. A late capability is offered as a terminal target after `Q` is restored.
   5. Resolution is attempted after the slot's disposition has frozen.
   6. A resolution of determination C is used to permit in-attempt overlap.
   7. Historical admission is used to import acceptance or a PASS.
   8. An oversized history is excerpted favorably.
   9. E3 is evaluated under PO-01 inside the narrow profile and wrongly flagged as Category 3.
   10. Raising H10 is labeled Category 3.
   11. K1 comparison is presented as K2 closure.
   12. The Approval B read is presented as a feasibility finding.
   13. J1 is generalized into a universal rule that selection follows Approval B.
   14. Ambient metadata is presumed exempt, or presumed charged.

---

## S. Explicit non-authority statement

This candidate grants no:

- P0 qualification;
- Approval B;
- Approval B envelope execution;
- protected read;
- CP1 or CP2 closure, or closure of any candidate K-point;
- backend selection;
- backend elimination authority;
- concrete-design adoption;
- implementation authority;
- execution authority;
- F/Q/O authority;
- B5 progression;
- protected observation;
- platform observation;
- cleanup authority;
- new closure-ladder authority;
- standing Category 2 authority;
- evidence-acquisition authority;
- resolution of determination C;
- repository mutation authority.

My only actions were read-only: Git queries and file reads. Nothing was written to the repository, and no protected artifact was opened. This candidate is not adopted and not self-certified. **Stop: returned for whole-artifact cross-family review.**
