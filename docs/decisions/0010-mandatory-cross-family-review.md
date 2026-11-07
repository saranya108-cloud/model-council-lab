# Decision 0010 — Revision-Scoped Reviewer Independence and Role Rotation

## Status

Accepted by the Human Chair on 2026-11-02; amended with Human Chair approval on 2026-11-07 to establish revision-scoped reviewer independence. This decision establishes a binding governance requirement for operational MCL council review. This documentation change does not claim that automated technical enforcement is already implemented.

## Context

[Decision 0002](0002-mvp-experiment-design.md) prohibits a Solver from approving its own work and separates authoring, verification, and revision roles. It does not explicitly prevent same-family approval after roles rotate, nor does it distinguish the independent-review standard for operational acceptance from the deliberately homogeneous research conditions.

The Human Chair has affirmed that no model may independently certify its own authored revision. The original requirement for a reviewer from a family different from every substantive contributor is replaced by revision-scoped independence: two families may collaborate repeatedly without historical contributions permanently excluding either family from future review. Genuine independent challenge remains required at formal adoption and qualification gates.

## Binding Decision

**Author ≠ Reviewer for the current revision. No model may independently certify, qualify, approve, or provide the qualifying review of a revision it authored or materially co-authored. Cross-family independence is required at formal adoption/qualification gates when needed for genuine independent challenge, not as permanent family exclusion.**

This rule applies to operational council review of code, patches, governance changes, technical proposals, security assessments, reports, and other artifacts offered as independently reviewed evidence for acceptance.

1. **Evaluate independence for the current review.** Eligibility depends on the current revision, the specific changes under review, the purpose of the review, and whether the reviewer would be judging its own current work. Role rotation does not erase material authorship or co-authorship. A new revision label alone does not establish independence. Where review scope is narrowed, the material, changes, and contributor scope must be explicit; the review cannot be represented as approval of unreviewed portions.
2. **Permit repeated iterative collaboration.** Model families may iterate repeatedly on the same workstream. Earlier review, findings incorporated upstream, collaboration in the same area, or historical contribution alone does not permanently disqualify a family. Eligibility must still satisfy the current-revision and review-scope requirements above.
3. **Distinguish correction-verification from independent adoption.** When Reviewer B identifies defects and Author A produces a later revision, Reviewer B may verify whether its findings were addressed. If Reviewer B materially shaped the corrected design, that correction-verification alone is not the final independent adoption gate; another genuinely independent reviewer must assess the candidate. A reviewer who materially authors or co-authors the candidate cannot provide its qualifying independent review. Material changes after review require renewed eligible review of the resulting candidate.
4. **Require a genuinely independent formal gate.** Formal adoption or qualification requires at least one genuinely independent reviewer. For major or high-risk gates, a different underlying foundation-model family from the principal author is preferred and is required when needed for genuine independent challenge. A different family alone does not establish independence if the reviewer materially co-authored the current revision or the specific changes being qualified.
5. **Use a fresh third-family reviewer when needed.** When two families have iterated extensively, disputes exist, both families materially shaped the current architecture, or the Human Chair requests a clean challenge, use a fresh third-family reviewer outside that author–review cycle for the independent gate. The reviewer must not have materially authored or co-authored the current revision or the specific changes being qualified; historical contribution elsewhere in the lineage alone is not permanent disqualification.
6. **Substantiate cross-family claims.** Where cross-family review is required, distinct agents, instances, model versions, sizes, fine-tunes, providers, or personas do not suffice if they share the same underlying foundation-model family or lineage. A different provider label alone does not establish independence. Family identity must be supported by model-identity evidence; unknown or ambiguous lineage does not qualify as cross-family review.
7. **Record provenance and disposition.** The council record must identify the reviewed artifact/revision, material model authors and co-authors, reviewer, observed or verified model identities, underlying families, relevant role changes and contributions, scope and purpose of review, the gate's required independence level, eligibility rationale, findings, and disposition. Self-review, correction-verification, same-family review, and unknown-family review must be labeled accurately, never passed off as qualifying independent or cross-family approval without satisfying the applicable requirements.
8. **Fail closed against the applicable gate.** If no reviewer satisfies the gate's required independence level, independent review remains **PENDING / NOT QUALIFIED**; the work cannot be marked as independently approved. Escalate availability or identity problems to the Human Chair without silently waiving or relabeling the requirement.
9. **Preserve Human Chair authority and the no-self-certification rule.** The Human Chair determines the independence level for each gate and may require fresh-family review. The Chair retains all consequential-action and final-acceptance authority under Decision 0002. Chair authorization is not evidence that the required independent review happened and does not turn a model's certification of its own authored or materially co-authored revision into qualifying independent review.

## Experimental Controls Are Preserved

This governance requirement does **not** cancel or retroactively relabel the M1 experimental conditions in Decision 0002.

- **Condition B** intentionally studies same-agent self-refinement. Its self-review is an experimental step, **not** qualifying operational independent review.
- **Condition C** intentionally studies isolated, homogeneous instances with role-separated verification. Its experimental "Independent Verifier" label refers to role/context separation, **not** qualification under this operational reviewer-independence rule.
- **Condition D** studies heterogeneous councils with counterbalanced role assignments. A D review meets the operational standard only where actual author/reviewer identities, relevant contributions to the current revision and changes under review, and the gate's required independence level satisfy this decision.
- An **External Evaluator** assesses objective experimental outcomes; its evaluation does not silently replace a required operational independent model review, including cross-family review where required for the gate.

Research results must retain their intended experimental classification even where they do not meet the operational acceptance standard.

## Enforcement and Evidence Boundary

Effective immediately as governance policy, reviewer eligibility must be checked against the current revision, review scope and purpose, and the gate's required independence level at initial review assignment, whenever the revision, scope, roles, or material contributors change, and before a claim of independent approval is accepted. Where the current harness lacks automated checks, the council must apply the rule procedurally and record the resulting evidence and any unqualified disposition.

This decision is **documentation-only**. It does not authorize modification of the MCL runner, tests, configuration, historical records, live execution, or external systems. Future code-level enforcement, migration, and verification require a separately scoped and authorized implementation.

## Relationship to Existing Governance

This decision supplements Decision 0002's operational review and Human Chair authority; it does not supersede Decision 0002's experimental design, its Condition B/C/D definitions, or historical accepted evidence.
