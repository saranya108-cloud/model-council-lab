# MODEL COUNCIL LAB — DECISION 0009

## HUMAN CHAIR POLICY CLARIFICATION
### EFFECT ACCEPTANCE BOUNDARIES, JEV, AND POST-CUTOFF COMPLETION

**Date:** October 23, 2026  
**Human Chair:** Amy  
**Status:** APPROVED  
**Scope:** Prospective Failure-Time Finalization Policy V1 only  
**Implementation authority:** NONE

---

## 1. JEV / SEMANTIC POLICY EVALUATOR

Jev is **not adopted as a required Version 1 component**.

A future semantic policy evaluator, including Jev or an equivalent model-independent implementation, may be used as an additional screening layer for natural-language scope, ambiguity, risk classification, or Human Chair escalation.

Such a semantic evaluator:

- may not create authority;
- may not act as the authoritative clock;
- may not override deterministic authorization;
- may not replace principal separation or containment;
- may not establish effect acceptance;
- may not grant provider credentials or execution scope;
- must fail closed where its output is unavailable, invalid, ambiguous, or inconsistent with deterministic policy.

The long-term architecture should prefer an abstract interface such as:

`SemanticPolicyEvaluator`

rather than coupling MCL governance specifically to Jev.

---

## 2. AUTHORITATIVE TIMEKEEPING

The authoritative cutoff remains based on a **qualified deterministic local clock**.

Semantic-model output does not participate in authoritative elapsed-time comparison.

The governing timing question remains deterministic:

`now < B`

or

`now >= B`

subject to the qualified clock, host, boot, and enforcement contract.

---

## 3. PROVIDER REQUEST ACCEPTANCE

For Version 1:

> A local broker commitment or queue record does not itself constitute provider submission.

The first qualified irreversible provider handoff must occur before cutoff `B`.

Accordingly:

- a request merely queued locally before `B` may not begin its first transmission after `B`;
- a broker may not use an expired attempt's authority to initiate a new provider submission;
- if a request has already crossed a separately qualified irreversible provider/transport acceptance boundary before `B`, later delivery, provider processing, acknowledgment, or result arrival may constitute completion of that already-accepted effect;
- ambiguous submission remains subject to the Version 1 no-replay rule;
- remote liability remains separately reserved and settled.

No provider-side deadline or idempotency guarantee is assumed unless separately qualified.

---

## 4. FILESYSTEM TRANSACTION QUALIFICATION

The Human Chair authorizes **further read-only qualification** of a narrowly defined filesystem transaction model.

The candidate model is:

> An exact, finite, predeclared filesystem transaction may be irrevocably accepted before `B` and subsequently completed under a separate, narrowly constrained completion authority.

The representative operation is limited to something equivalent to:

`replace this exact predeclared file with these exact precommitted bytes`

This does not authorize:

- arbitrary filesystem mutation;
- arbitrary repository mutation;
- Git mutation generally;
- dynamic path selection;
- expansion of effect scope;
- implementation.

The candidate transaction must still prove:

- exact transaction identity;
- exact destination;
- exact bytes/content;
- one-shot authority consumption;
- qualified acceptance before `B`;
- crash-safe recovery;
- no duplicate transaction creation;
- bounded completion authority;
- defined staging, metadata, cleanup, and failure behavior.

---

## 5. POST-CUTOFF COMPLETION AUTHORITY

No blanket post-cutoff execution authority is created.

A future completion role may act after `B` only if all of the following are established:

1. the exact effect was already validly and irrevocably accepted before `B`;
2. the effect is finite and fully specified;
3. the worker can no longer redirect, expand, cancel-and-replace, or otherwise alter it;
4. completion authority is narrower than ordinary execution authority;
5. crash recovery cannot generate a second independent effect;
6. the acceptance/time/durability protocol itself has been qualified.

“Complete whatever remains necessary” is not sufficient authority.

---

## 6. FILESYSTEM VS PROVIDER DISTINCTION

Version 1 intentionally distinguishes the two cases.

### Filesystem

Further qualification of pre-B exact-transaction acceptance with bounded post-B completion is permitted.

### Provider

A locally queued request does not receive post-B first-transmission authority.

Provider transmission must cross its qualified irreversible handoff while the attempt remains authorized.

This distinction is deliberate.

---

## 7. DECISION 7

The numerical per-attempt reservation ceiling remains deferred.

No number is selected by this clarification.

The sequence remains:

`mechanism qualification`

→ `evidence-informed numerical proposal`

→ `Human Chair Decision 7 numerical approval`

→ `future implementation/execution authorization`

---

## 8. NEXT GATE

The next permitted gate is a **bounded read-only qualification pass** focused on:

1. whether a concrete filesystem transaction can establish a truthful pre-B acceptance point with safe bounded completion;
2. what exact irreversible pre-B handoff can qualify for the synchronous provider path;
3. the timing, durability, crash-recovery, and one-shot-authority properties required for those mechanisms.

No implementation is authorized.

---

## 9. HUMAN CHAIR DISPOSITION

**APPROVED**

> I adopt this clarification for Failure-Time Finalization Policy V1. Jev is not required for Version 1 and does not hold authoritative timing or execution authority. Provider requests must cross a qualified irreversible submission boundary before cutoff B; local queueing alone is insufficient. Further read-only qualification is authorized for a narrowly defined filesystem transaction model in which an exact effect may be irrevocably accepted before B and completed afterward only under separately qualified, bounded completion authority. Decision 7 remains deferred.

**Human Chair:** Amy  
**Date:** October 23, 2026
