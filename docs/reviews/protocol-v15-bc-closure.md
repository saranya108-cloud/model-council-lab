# Protocol v15 B/C Milestone Closure

## Status

Protocol v15 B/C live validation: **PASS / CLOSED**.
This record closes the accepted live-validation and local-preservation milestone.

## Accepted baseline

- Branch: `m1-live-adapter-dev`
- Pre-closure source SHA: `c12b29122518c241033c2a3218183482eec6a62d`
- Canonical evidence root: `/private/tmp/model-council-lab-v15-validation-c12b291-20260909-01/runs/`

## Canonical live evidence

| Condition | Run ID | Result | Files | Bytes |
| --- | --- | --- | ---: | ---: |
| B | `openai-condition-b-v15-c12b291-20260909-001` | PASS | 29 | 71,013 |
| C | `openai-condition-c-v15-c12b291-20260909-001` | PASS | 30 | 77,890 |

Canonical inventory fingerprints:

- B: `d8ad4d9b0f5cd74e6580b2d22dcf7362763520296491d89eefa1579b7750b993`
- C: `f9b0fbb31af9655d8f69f26808f7f6f04b29ff257642818d986be20aa2945213`

Each fingerprint is SHA-256 of a compact, sorted-key JSON array of
`path`/`size`/`sha256` entries ordered by relative path.
Condition C semantic reconciliation: **PASS**, with 2 findings, 0 material
findings, and 2 dispositions; canonical findings, reviser input, and disposition
checks passed.

## Preservation record

- Package: `/Users/aclab/aclab/model-council-evidence/v15-c12b291-20260909-001/`
- Preservation status: `LOCAL_VERIFIED`
- Source archive: `source-c12b291.tar`
- Archive SHA-256: `ff3cad5e54fbd615f2e8241fac730f40c9540c8f864875480db7fb3b000f4af6`

The preserved evidence package is outside Git. Canonical B/C evidence is not
being added to the repository; this Git closure record stores identifiers,
hashes, conclusions, and limitations only. The originals remain canonical.
Local verified preservation is complete. An independently backed-up second
copy has not yet been established.

## Independent acceptance

Result: **ACCEPT WITH NOTES**. The accepted review record confirms:

- Exact B/C counts, byte totals, fingerprints, and relative layouts; originals
  and preservation copies matched.
- The source archive matched `git archive` of the accepted source SHA and
  contained no dirty-tree material.
- Originals and copies passed accepted terminal, artifact-integrity,
  identity-policy, and lifecycle verification.
- Condition C semantic reconciliation passed.
- The corrected B/C provenance narrative matched the underlying evidence.
- `LOCAL_VERIFIED.json` reflected the corrected package state and was written
  after the package's `closure.md`.

## Provenance clarification

Both runs record the accepted source SHA. Their historical provenance values
are preserved exactly:

| Condition | `uncommitted_implementation` | `working_tree_dirty` |
| --- | --- | --- |
| B | `false` | `false` |
| C | `true` | `true` |

These historical labels are not reinterpreted or corrected here. They do not
mean that the committed source archive contains dirty checkout material.
The existing dirty checkout remains outside this milestone and was not
incorporated into validation or preservation.

## Accepted limitations / verification notes

The acceptance notes are verification limitations, not known defects:

1. No pre-correction metadata baseline was available to independently prove
   that no unrelated wording changed during the one-line `closure.md` correction.
2. Package evidence alone cannot independently prove the historical absence of
   transient repository, Git, provider, or F5/F6 mutations during the prior
   implementation session. Current evidence found no such additional mutation.

Local preservation is not independent backup or external attestation.
Inventory fingerprints supplement the accepted verifier; preservation metadata
is not harness authority or stage-seal evidence. The live canaries establish
the accepted plumbing milestone, not general task-quality performance.

## Explicitly deferred work

Completion of Protocol v15 B/C does not resolve every deferred architecture issue:

- The accepted F5 foundation remains closed except for separately scoped future work.
- Provenance-label semantics remain a possible independent future design issue.
- The original dirty checkout requires separate disposition if ever revisited.
- F6 response/materialization bounds remain the strongest identified substantive
  next architecture candidate.

This tranche does not design F6 or authorize F6 implementation, provider
execution, or any subsequent tranche.

## Final milestone state

- Protocol v15 B/C live validation: **CLOSED**
- Protocol v15 B/C preservation: **ACCEPTED WITH NOTES / CLOSED**
