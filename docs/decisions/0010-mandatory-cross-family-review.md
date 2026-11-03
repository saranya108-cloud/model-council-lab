# Decision 0010 — Mandatory Cross-Family Review and Role Rotation

## Status

Accepted by the Human Chair on 2026-11-02. This decision establishes a binding governance requirement for operational MCL council review. This documentation change does not claim that automated technical enforcement is already implemented.

## Context

[Decision 0002](0002-mvp-experiment-design.md) prohibits a Solver from approving its own work and separates authoring, verification, and revision roles. It does not explicitly prevent same-family approval after roles rotate, nor does it distinguish the independent-review standard for operational acceptance from the deliberately homogeneous research conditions.

The Human Chair has affirmed the existing operational practice: authors must not independently review their own work, and qualifying reviewers must come from a **different underlying foundation-model family**, not merely a different model, version, persona, agent instance, or configuration.

## Binding Decision

**No model may provide qualifying independent review or approval of material it substantively authored. A qualifying independent reviewer must belong to a foundation-model family different from every substantive model author of the material being approved.**

This rule applies to operational council review of code, patches, governance changes, technical proposals, security assessments, reports, and other artifacts offered as independently reviewed evidence for acceptance.

1. **Family separation is mandatory.** Two distinct agents, instances, model versions, sizes, fine-tunes, providers, or personas are insufficient if they share the same underlying foundation-model family or lineage. A different provider label alone does not establish independence when the underlying lineage is shared. Family identity must be supported by model-identity evidence; unknown or ambiguous lineage does not qualify.
2. **Authorship survives role rotation.** Reviewer eligibility is determined by substantive contribution history for the specific material, not the current Solver, Reviser, Verifier, or other title. Reassigning a role does not erase authorship or make an author eligible to independently approve that work.
3. **Multiple model-family contributors.** When material substantively incorporates contributions from several model families, the qualifying reviewer must be from a family that did not substantively contribute to the material under review. If the review scope is narrowed, the material and contributor scope must be explicit; the review cannot be represented as approval of unreviewed portions.
4. **Reviewers who revise become contributors.** A reviewer who substantively changes the reviewed material is an author of that changed material. Another eligible cross-family reviewer must assess the resulting candidate before it can carry an independent-approval disposition. Material changes after review require renewed eligible review of the resulting candidate.
5. **Record provenance and disposition.** The council record must identify the reviewed artifact/revision, substantive model authors, reviewer, observed or verified model identities, underlying families, relevant role changes, scope of review, findings, and disposition. Self-review, same-family review, and unknown-family review must be labeled accurately, never passed off as cross-family approval.
6. **Fail closed.** If there is no eligible cross-family reviewer, independent review remains **PENDING / NOT QUALIFIED**; the work cannot be marked as independently approved. Escalate the availability or identity problem to the Human Chair without silently waiving or relabeling the requirement.
7. **Human Chair authority remains separate.** The Human Chair retains all consequential-action and final-acceptance authority under Decision 0002. Chair authorization is not evidence that the required cross-family review happened and does not turn an ineligible model review into a qualified one.

## Experimental Controls Are Preserved

This governance requirement does **not** cancel or retroactively relabel the M1 experimental conditions in Decision 0002.

- **Condition B** intentionally studies same-agent self-refinement. Its self-review is an experimental step, **not** operational cross-family independent review.
- **Condition C** intentionally studies isolated, homogeneous instances with role-separated verification. Its experimental "Independent Verifier" label refers to role/context separation, **not** qualification under this operational cross-family-family rule.
- **Condition D** studies heterogeneous councils with counterbalanced role assignments. A D review meets the operational standard only where actual author/reviewer family identities and contribution history satisfy this decision.
- An **External Evaluator** assesses objective experimental outcomes; its evaluation does not silently replace a required operational cross-family model review.

Research results must retain their intended experimental classification even where they do not meet the operational acceptance standard.

## Enforcement and Evidence Boundary

Effective immediately as governance policy, reviewer eligibility must be checked at initial review assignment, whenever roles or substantive contributors change, and before a claim of independent approval is accepted. Where the current harness lacks automated checks, the council must apply the rule procedurally and record the resulting evidence and any unqualified disposition.

This decision is **documentation-only**. It does not authorize modification of the MCL runner, tests, configuration, historical records, live execution, or external systems. Future code-level enforcement, migration, and verification require a separately scoped and authorized implementation.

## Relationship to Existing Governance

This decision supplements Decision 0002's operational review and Human Chair authority; it does not supersede Decision 0002's experimental design, its Condition B/C/D definitions, or historical accepted evidence.
