# Decision 0009 — H18 Draft 4 and Proof-Obligation Register Draft 4 provenance record

**Recorded:** November 9, 2026

**Human Chair:** Amy

**Scope:** Approved documentary provenance recording only

**Read-only repository checkpoint:** `m1-live-adapter-dev` at `97cab84c485e234e0ef69b0dc4f10de8a4124f7e`; 24 pre-existing working-tree entries; no staged changes.

## Recorded provenance disposition

**ARTIFACTS RECOVERED AND PINNED; CONTENT IDENTITY STRONGLY CORROBORATED; HISTORICAL REVIEW-INPUT BYTE IDENTITY NOT RETROACTIVELY PROVABLE; NO EVIDENCE OF COMPETING DRAFT 4 VERSIONS; NO RE-REVIEW REQUIRED.**

This records the Human Chair-approved provenance disposition following the recovery assessment in [Use Fable As Supervisor](chatgpt-conversation://6af231fe-1524-83e8-9c30-aa0be3c5b0c1). It is not a new independent architectural review, an amendment to either candidate, or a new adoption decision.

## Controlling documentary referents

The following four repository files, identified by their exact byte counts and SHA-256 digests, are the controlling documentary referents going forward for the recovered H18 Architecture Draft 4, its Kimi qualifying review, the H18 Proof-Obligation Register Draft 4, and its Argon qualifying review. Chat/Codex locators and Library references remain historical discovery context; they do not control the identity of these four texts.

| Artifact | Exact pinned repository copy (original filename retained) | Bytes | SHA-256 |
|---|---|---:|---|
| H18 Architecture Draft 4 | [Pasted text(20261107-223309).txt](provenance/h18-draft4-2026-11/Pasted%20text%2820261107-223309%29.txt) | 49,052 | `528ac9212b207f439e236adc74518e075abe4fd2c39bbeff7457f0c31c114629` |
| Kimi qualifying H18 review | [Pasted text(20261107-225744).txt](provenance/h18-draft4-2026-11/Pasted%20text%2820261107-225744%29.txt) | 24,276 | `0ba7c2d0cf28e27270358130ad74b39c249124a639770c7f1ce819e207c44f2a` |
| H18 Proof-Obligation Register Draft 4 | [Pasted text(20261108-190715).txt](provenance/h18-draft4-2026-11/Pasted%20text%2820261108-190715%29.txt) | 63,425 | `16c224d956a1b643d294b9fceb1cf73c7dddf2bdc469e2f14d378069d0db96ab` |
| Argon qualifying Register review | [Pasted text(20261108-192107).txt](provenance/h18-draft4-2026-11/Pasted%20text%2820261108-192107%29.txt) | 33,653 | `6ca921f5f088c9ac39ae48b1cf121c993b73f1cba67e59e3c08b905954728481` |

The four bodies were extracted as byte slices from the supplied provenance packet and independently matched against the Human Chair-supplied individual byte counts and hashes before repository creation. Packet headers, separators, and end markers are excluded. No spelling, formatting, line endings, historical status labels, footers, or reviewer wording has been corrected. None of the four original bodies ends with a newline; this is preserved.

The [Level-2 Evidence Contract](DECISION-0009-V2-2B-LEVEL-2-EVIDENCE-CONTRACT.md), specifically its November 7 architecture adoption and November 8 Register adoption entries, continues to govern adoption status, review dispositions, retained cautions, gates, and authority. The pinned texts preserve the candidates and reviews as recovered, including their historical pre-adoption language. In particular, the Register's superseded pre-verification footer remains verbatim and is read with the existing NB-R2 disposition. Pinning does not revive superseded candidate status or override either adoption entry.

## Correspondence evidence and residual limitation

The supplied Fable recovery assessment reported the following corroboration:

- H18 Draft 4 matches the sections, six-step sealing sequence, closed enforcing set, five producer rows, Routes A/B, finalization and inventory cited by Kimi. The reported arithmetic reproduces 64 objects, 2,531,328 bytes, 1,662,976 bytes of headroom and 53,248 receiver-copy bytes; retained cautions and the review checkpoint also agree.
- Register Draft 4 matches Argon's reported 548 lines, Appendix E at lines 541–548, quoted wording, 24 obligations, CP0–CP6, five-part CP1 standard and eight-step finalization. The historical footer and reported source checkpoint also agree.
- No contradiction or evidence of competing Draft 4 versions was found. The assessment treated Argon's “nine” versus ten failure-mode count as a reviewer miscount, not a version signal. H18 V1–V4 material was not found incorporated into the recovered candidate.

These are recorded findings of the supplied assessment, not a new qualifying review performed by this recording. The fresh verification here establishes the byte identity of the pinned copies with the recovered artifact bodies and the approved individual metadata.

Neither qualifying review preserves a candidate-input digest sufficient to prove what exact bytes the historical reviewer received. The recovered texts are conversation pastes, not independently retained reviewer-side inputs or Claude-side attachments, and the original review prompts are not preserved in these four artifacts. Current hash equality cannot retrospectively supply those missing historical bindings. Substantive correspondence is therefore strongly corroborated; historical reviewer-input byte identity remains unprovable on this record. The approved disposition requires no fresh re-review for this recordkeeping repair.

The historical H18 locator discrepancy is retained explicitly: the Register cites `codex://threads/01a1b790-6adc-7b42-957a-ee46853dbd3e`, while the repository's November 7 adoption entry cites `chatgpt-conversation://6aef8068-27b0-83e8-92f8-9e914d10baf0`. Neither locator establishes historical input-byte identity. The pinned H18 file above controls the documentary text; this record does not assert that the two locators are byte-identical views.

## Non-canonical packet and normalization discrepancy

The transfer wrapper was named `MCL-Fable-Provenance-Packet-Nov-2026.txt`; the supplied Library locator was `libfile_479ef11ed2cc8191a1d9d4e76035cbc3`. Those are transport/discovery references only.

- The reported original packet was **172,774 bytes**, SHA-256 `808eb1ef2244e44163e284b0949722acbfa6cc71a34dcdd31d3d615530d5cb7a`.
- Fable reported receiving **172,773 bytes** while independently matching all four individual artifact byte counts and hashes.
- The attachment supplied for this recording (`Pasted text.txt`) is also **172,773 bytes**, SHA-256 `fd125378475bfd499dbf9de925ca61ea94c2942825bbad059bdba73b7f82d0d3`.
- Appending one LF byte to that attachment **in memory only** yields 172,774 bytes and exactly the reported original packet SHA-256. This confirms a terminal-newline difference for this supplied copy; it does not independently reconstruct Fable's transfer history.

The packet-level 172,773 versus 172,774 byte normalization discrepancy is **non-canonical and irrelevant to the four individual artifact hashes**. All four embedded bodies match exactly without any normalization. The combined packet is not the canonical artifact or a substitute for the individual pinned identities. Neither the source attachment nor any original artifact was altered to reconcile the wrapper.

## Unchanged scope and authority

This record changes documentary referents only. It does not change architecture, review dispositions or cautions, Decision 0010 substance, gates, or implementation authority. It does not adjudicate PO-03 versus H18 §3.2 or incorporate additional architecture observations.

Backend conformance and empirical H18 satisfaction remain **NOT ESTABLISHED**. The candidate envelope remains **64 governed-support objects / 2,531,328 aggregate bytes**, **CANDIDATE ENVELOPE NOT YET PROVEN SUFFICIENT**. B5 G1 remains **HOLD**; both P0 candidates remain **NOT QUALIFIED**; Approval B and V2-2B implementation/execution remain **unauthorized**.

No backend selection or qualification, capacity allocation, host/platform observation, P0 inspection, B5 progression, F/Q/O activity, cleanup, custody transition, or successor activity is authorized. Existing repository documents and unrelated working-tree contents are preserved. Staging, commit and push require separate authorization; this bounded work stops after presenting the proposed files and verification to the Human Chair.
