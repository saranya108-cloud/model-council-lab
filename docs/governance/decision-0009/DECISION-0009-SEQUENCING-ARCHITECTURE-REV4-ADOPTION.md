# Decision 0009 — Sequencing Architecture Revision 4 adoption

**Recorded:** November 12, 2026  
**Human Chair:** Amy  
**Scope:** Recording of architectural adoption only.  
**Repository checkpoint:** `m1-live-adapter-dev` at `34924aa5e2de73250f9e88008f52cbc361066e4b` (local HEAD and cached tracking ref; no live remote verification).

## Human Chair adoption and qualification

Amy architecturally adopted the exact **Sequencing Architecture Revision 4** identified by SHA-256 `fbd2790d9e58dad673ca996487ba63413233c82c7c07d0f80533a32062096c4c`. **Option 1 — bounded scope split** is the adopted sequencing architecture. This additive record documents that adoption and the separately approved four-file repository recording; it does not conduct a new architectural review or authorize successor work.

The author is **Fable 5.2 / Anthropic-Claude family**. The qualifying reviewer is the **OpenAI/GPT-family reviewer serving the Astra review role**, observed as OpenAI/Codex. The role name “Astra” does not establish a more precise runtime identity.

The Decision 0010 tier is **FORMAL ADOPTION / QUALIFICATION**, and the final qualification disposition is **FORMALLY QUALIFIED — ACCEPT WITH NON-BLOCKING NOTES**.

The preserved whole-revision review covers the complete Revision 4, returns **ACCEPT WITH NON-BLOCKING NOTES**, closes B1, B2, N1–N3, R2-B1, R2-N1–R2-N3 and all five Revision-4 completion points, and identifies no new blocking finding. Its §I independently assesses the author's substantive reformulation of §F and identifies no remaining clause-2 rewrite or additional independent check. Historical reviewer influence is not treated as authorship of the current revision.

The later final qualification determination records resolution of the author-family deficiency, the accepted Human Chair session-to-artifact attestation, independently accessed provider documentation supporting Anthropic/Claude lineage, and established Anthropic/Claude author versus OpenAI/GPT reviewer independence. It retains the prior whole-revision findings and clause-2 determination. These are the supplied review and qualification findings, preserved here; this recording task does not claim to have independently repeated the provider-documentation investigation.

Qualification and adoption are separate acts. The original Revision 4's candidate status and the whole-review's pending qualification status remain intact as historical statements. The final qualification determination supplies the later qualification disposition; Amy's architectural adoption is recorded above. No source artifact is rewritten to erase its historical status.

## Exact pinned artifacts

Paths below are relative to this record.

| Artifact | Pinned file | Bytes | SHA-256 |
|---|---|---:|---|
| Fable Sequencing Architecture Revision 4 | [FABLE-SEQUENCING-ARCHITECTURE-REV4.txt](provenance/sequencing-rev4-2026-11-12/FABLE-SEQUENCING-ARCHITECTURE-REV4.txt) | 23,741 | `fbd2790d9e58dad673ca996487ba63413233c82c7c07d0f80533a32062096c4c` |
| Astra whole-revision review | [ASTRA-REV4-WHOLE-REVISION-REVIEW.txt](provenance/sequencing-rev4-2026-11-12/ASTRA-REV4-WHOLE-REVISION-REVIEW.txt) | 14,771 | `bdefbbaafc640fc09d769e4a474e07368c7ef705b0d3314a7763d7db62330bfe` |
| Final formal qualification determination | [ASTRA-REV4-FINAL-QUALIFICATION.md](provenance/sequencing-rev4-2026-11-12/ASTRA-REV4-FINAL-QUALIFICATION.md) | 2,303 | `0b1f2d945901f08cc9e18c693cb7c67f4c79f9e3edbc320ee54dec406c188391` |

**Source and byte preservation.** The Human Chair supplied the recording handoff and source attachments in the recording chat, continuing [Verify MCL Checkpoint](chatgpt-conversation://6af62ff6-f094-83e8-b43f-a0e6efbc9b3b).

- Revision 4 is copied byte-for-byte from the supplied attachment corresponding to `Pasted text(10).txt`; its 23,741 bytes match the approved hash.
- The supplied paste corresponding to `Pasted text(20261112-222435).txt` contains 14,769 bytes with SHA-256 `06b7bdf428994b440a9e6a58dce5d8b0bdc3bd9da81f052dcbe0f3f5e936c3a6`. It lacks the two opening ASCII `#` bytes. Amy specifically approved restoring only those two bytes. The pinned review is exactly `b"##" + supplied_review_bytes`, without any other change, and matches the independently reported original 14,771-byte hash above. The uploaded paste remains unchanged. The review itself identifies the exact Revision 4 hash.
- The qualification artifact is extracted directly from handoff §2.C, beginning with the bold qualification disposition and ending with “A bounded Category 2 assignment remains a separate Human Chair decision.” The surrounding handoff introduction, separator and subsequent section are excluded. All bytes inside that text span, including Markdown, Unicode and internal whitespace, are preserved; no terminal newline is added. This is the exact supplied qualification text, not a reconstructed summary.

## Adopted architectural effect

The exact pinned Revision 4 controls the sequencing architecture, including:

1. **Category 1 / Category 2 / Category 3 separation:** adopted narrow-H18 work; broader pre-gate candidate architecture; and revisions to adopted narrow-profile semantics or limits, respectively.
2. The reliance-and-effects boundary for pre-gate work, the effect-based abstract/concrete distinction in §F, and the separation of documentary comparison, feasibility findings, recommendations/rankings, consequential dispositions and backend selection.
3. A bounded Approval B inspection-envelope architecture may be developed as Category 2 candidate work before P0 only under its own bounded assignment. **P0 remains before Approval B**, and Approval B remains before protected-interface-tailored V2-2B.
4. **CP1 precedes backend selection; applicable CP2 closure precedes concrete-design adoption or implementation authorization.** CP1 and CP2 are requirements, not permissions. Revision 4's Register-precedence rule remains effective.
5. **Category 2 has no standing work authority** and does not silently inherit the narrow-H18 closure ladder. Until broader closure arrangements are adopted, every generally applicable Evidence Contract requirement, proposition-specific materiality, protected-information gate, categorical V2-2B sequencing requirement, and separate implementation/execution authorization continues to apply.
6. The current **64-object / 2,531,328-byte** envelope stays confined to the existing narrow profile and remains **CANDIDATE ENVELOPE NOT YET PROVEN SUFFICIENT**. It is not extended to Category 2 and establishes no backend fit.

No new closure ladder is adopted by this recording. H18, the Proof-Obligation Register, the adopted H18 §3.2 / PO-03 clarification, and the existing safety, evidence and capacity constraints remain in force. B5 G1 remains **HOLD**; this recording provides no P0 qualification or other gate progression.

## Retained §F application caution

> Apply Revision 4 §F according to substantive effect and downstream reliance, distinguishing abstract architectural constraints from a settled concrete realization. Terminology alone does not determine CP2 classification.

An abstract constraint does not become concrete merely because only one known backend satisfies it; a concrete realization does not become abstract merely because several backends could implement it. Within mixed artifacts, abstract provisions may proceed separately only where their adoption neither settles nor depends on treating as settled the deferred concrete answer. The retained non-blocking caution does not require an author revision.

## Explicit non-authority

**Architectural adoption only.** This adoption grants no:

- P0 qualification;
- Approval B;
- Approval B envelope execution;
- protected read;
- CP1 closure;
- CP2 closure;
- new closure-ladder authority;
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
- standing Category 2 authority;
- repository mutation authority beyond this separately approved recording task;
- other operational authority.

**This adoption and this recording do not authorize the first bounded Category 2 assignment.** That requires a separate Human Chair decision with its own scope, stopping point, authority limits and review requirements. No gate or successor action is self-executing.

The separately approved recording creates only this governance record and the three pinned artifacts above. It does not edit Revision 4, H18, the Register, existing clarification records, Decision 0010, existing provenance, or any of the 24 pre-existing working-tree entries. Staging, commit, push and upload remain outside this authorization.
