# MODEL COUNCIL LAB — DECISION 0009

## HUMAN CHAIR PROSPECTIVE GOVERNANCE RULING  
### FAILURE-TIME FINALIZATION POLICY — VERSION 1

**Date:** October 23, 2026  
**Human Chair:** Amy  
**Status:** **APPROVED AS WRITTEN WITH DECISION 7 ADDENDUM**  
**Scope:** Future execution envelopes only  
**Implementation authority:** NONE  
**Execution authority:** NONE  
**Validation authority:** NONE  

---

# 1. PURPOSE

This ruling establishes the prospective governance profile for future Model Council Lab execution envelopes following the Decision 0009 failed-epoch governance failure.

The purpose is to ensure that a future admitted execution attempt can reach defensible accounting finality even if:

- the worker disappears;
- terminal worker evidence is lost;
- the parent or governance process fails;
- local execution and remote/provider work have different lifetimes;
- ordinary completion evidence is unavailable.

The architecture supporting this policy has completed independent architectural review.

This ruling selects governance policy.

It does **not**:

- implement the architecture;
- qualify an enforcement backend;
- qualify a clock;
- qualify storage durability;
- qualify a provider/API profile;
- authorize execution;
- authorize validation;
- authorize regression;
- alter the closed Decision 0009 failed epoch.

---

# 2. HISTORICAL NON-RETROACTIVITY

The existing Decision 0009 failed epoch remains closed under the Human Chair ruling recorded at:

`docs/governance/decision-0009/DECISION-0009-FAILED-EPOCH-CLOSURE.md`

Authoritative closure commit:

`25541da3da575de76e1bb9bf8272c865888146c5`

Historical classification:

`EXECUTION-BLOCKED UNDER EXISTING GOVERNANCE — NOT TERMINALLY EXHAUSTED BY AN ACCEPTED FINAL CHARGE`

Historical accounting remains:

- PB01 accepted charge: `75,501,376 ns`
- Accepted failed-time charge: `NOT ESTABLISHED`
- Unresolved failed-time hold: `899,924,498,624 ns`
- Available execution capacity: `0 ns`

Nothing in this prospective ruling applies retroactively to that failed epoch.

No capacity is released.

No historical charge is reconstructed.

No historical refund is created.

The failed epoch will not resume.

---

# 3. GOVERNING PRINCIPLE

For future execution envelopes:

> Capacity may be released from a reservation only through an admissible, evidence-supported settlement established under a prospectively authorized rule.

Future failure-time finalization may use:

1. a qualified observed conservative bound; or
2. a prospectively authorized and independently enforceable reservation ceiling.

If neither is admissible:

`HOLD`

remains the required result.

No deadline, timeout, missing PID, absent heartbeat, or missing worker record alone proves execution ended.

---

# 4. DECISION 1 — LOCAL CHARGE METRIC

### Human Chair disposition: **ADOPTED**

Future local execution envelopes will use:

**sleep-inclusive continuous elapsed envelope time**

rather than historical reconstruction of active-process time.

The authoritative clock must be:

- monotonic;
- continuous through sleep where the selected platform supports that semantic;
- bound to host and boot identity;
- qualified before execution;
- used consistently for the execution envelope and its absolute cutoff.

Wall-clock timestamps may label records but must not be used after failure to reconstruct elapsed execution duration.

---

# 5. DECISION 2 — MEANING OF “EXECUTION ENDED”

### Human Chair disposition: **ADOPTED — EFFECT-BOUNDED SEMANTICS**

For Version 1, the governed cutoff will be **effect-bounded**.

After the authorized cutoff:

> No new governed effect may be accepted on behalf of the expired attempt.

Governed effects include, as applicable:

- provider/API submission;
- network egress;
- file or repository mutation;
- external message delivery;
- persistent state change;
- tool invocation producing external consequences;
- acceptance of a model/provider result into the attempt;
- creation of persistent background execution;
- any other operation classified as consequential under the execution policy.

This policy does **not** claim that every CPU instruction, memory operation, or physical computation ceases exactly at the cutoff.

Residual computation after the cutoff has no governed authority.

### Consequence

Version 1 governs **authority and effects**, not exact physical CPU cessation.

---

# 6. DECISION 3 — LOCAL / REMOTE ACCOUNTING BOUNDARY

### Human Chair disposition: **ADOPTED**

Local execution time and delegated/remote liability are separate accounting domains.

Local envelope closure:

- settles local time only;
- does not prove provider execution ended;
- does not eliminate remote liability;
- does not authorize accepting a late provider result.

Provider timestamps must never be subtracted from the local host clock to reconstruct local elapsed time.

---

# 7. DECISION 4 — REMOTE LIABILITY MODEL

### Human Chair disposition: **ADOPTED**

Every admitted remote/provider operation must have its own prospective bounded reservation.

The reservation should include, where applicable:

- maximum input quantity;
- maximum output quantity;
- reasoning/thinking quantity;
- tool/search/call charges;
- media/storage/duration charges;
- model/provider route;
- approved price ceiling;
- approved rounding;
- any explicitly authorized retry/fallback paths.

Version 1 will retain:

- a fixed-point monetary ceiling; and
- relevant quantity maxima.

Money, tokens, and local nanoseconds remain separate accounting domains.

They must not be numerically combined.

---

# 8. DECISION 5 — ELIGIBLE PROVIDER/API CLASSES

### Human Chair disposition: **ADOPTED — CLOSED ALLOWLIST**

Version 1 will permit only provider/API classes that have been individually qualified to possess a finite prospective liability bound.

Initial eligibility should favor:

- synchronous;
- bounded;
- single-request;
- non-agentic provider operations.

The following are excluded unless separately qualified:

- unbounded asynchronous jobs;
- provider agents;
- batch jobs with unbounded lifetime liability;
- open-ended tool execution;
- operations with uncontrolled duration/storage fees;
- API classes whose total prospective liability cannot be bounded before admission.

---

# 9. DECISION 6 — RETRIES AND ROUTER FALLBACKS

### Human Chair disposition: **ADOPTED — DISABLED FOR VERSION 1**

Automatic SDK retries will be disabled.

Automatic router/provider fallbacks will be disabled.

An ambiguous provider submission must not be replayed merely because acknowledgment was lost.

A future governance version may permit retries only if:

- each execution receives a separate reservation; or
- a finite set of execution paths is prospectively reserved under a proven aggregate ceiling.

Unused remote reservation does not itself authorize another request.

---

# 10. DECISION 7 — MAXIMUM LOCAL RESERVATION

### Human Chair disposition: **ADOPTED — BOUNDED PER-ATTEMPT RESERVATIONS**

Each attempt must receive a bounded local reservation.

No attempt may automatically reserve all remaining envelope capacity merely because that capacity exists.

The reservation must be established before the attempt becomes effective.

The actual numerical per-attempt ceiling is intentionally **not fixed by this governance ruling**.

---

## DECISION 7 ADDENDUM — NUMERICAL CEILING INTENTIONALLY DEFERRED

The Human Chair adopts the architectural and governance requirement that every attempt have a bounded reservation, while deliberately deferring selection of the numerical reservation ceiling.

This deferral is intentional and is **not** an unresolved governance defect.

A defensible numerical ceiling should be selected only after the mechanism-qualification stage establishes enough information about the actual execution environment to make the number meaningful.

Relevant information may include:

- the enforcement mechanism that qualifies;
- its demonstrated cutoff semantics;
- the selected effect-boundary implementation;
- clock behavior and uncertainty;
- normal execution durations;
- conservative settlement behavior;
- operational overhead;
- provider interaction patterns;
- the expected size and structure of future execution envelopes.

Setting the number before those facts are known would risk creating an arbitrary limit without an evidentiary or operational basis.

Accordingly:

1. **The bounded-reservation principle is adopted now.**
2. **No default numerical ceiling is created by this ruling.**
3. **No implementation may interpret the absence of a number as authority to reserve all remaining capacity.**
4. **No implementation may choose a ceiling autonomously.**
5. **Mechanism qualification must not silently select the governance number.**
6. After qualification provides the relevant evidence, the numerical ceiling must return to the Human Chair for an explicit bounded decision before governed execution relying on that ceiling is authorized.
7. Different qualified execution profiles may justify different ceilings; a single universal number is not assumed.
8. Any future numerical ceiling remains subject to the enclosing execution-envelope budget and authorization.

The sequence is therefore:

`bounded-reservation principle adopted`

→ `mechanism qualification`

→ `evidence-informed numerical proposal`

→ `Human Chair numerical approval`

→ `future execution authorization`

This addendum prevents both premature numerical policy and silent implementation discretion.

---

# 11. DECISION 8 — ENFORCEMENT BACKEND

### Human Chair disposition: **ADOPTED — SELECTION DEFERRED PENDING QUALIFICATION**

No specific Mac, VM, container, process-control, or other backend is declared qualified by this policy ruling.

Before implementation or execution, a separate read-only qualification gate must determine whether a candidate mechanism can actually provide the selected effect-bounded cutoff.

The required property is:

> Governed effects are possible only through an admitted trusted enforcement boundary, and loss, stall, suspension, restart, or failure of the enforcement mechanism cannot extend governed permission beyond the authorized absolute cutoff.

A timer being scheduled or armed is not sufficient.

---

# 12. DECISION 9 — SLEEP POLICY

### Human Chair disposition: **ADOPTED — CONSERVATIVE VERSION 1 POLICY**

Intentional sleep should be avoided while an execution lease is active.

A sleep-prevention request is operational mitigation, not evidence that sleep cannot occur.

Unexpected sleep must be handled according to the qualification of the selected enforcement backend.

If sleep invalidates the enforcement guarantee:

- do not manufacture a charge;
- do not silently assume the deadline was enforced;
- apply the appropriate hold/integrity policy.

Effect-bounded architectures may support sleep where every post-resume governed effect remains properly cutoff-gated.

---

# 13. DECISION 10 — DURABILITY AND FAILURE SCOPE

### Human Chair disposition: **ADOPTED — INITIAL SCOPE**

Version 1 will initially require qualification for:

1. process crash; and
2. operating-system crash/reboot.

Power-loss durability is a separate stronger qualification.

Permanent device loss is outside the minimum Version 1 guarantee unless an independently retained sufficient copy is later adopted.

No existing `fsync`-based behavior is automatically promoted into a stronger power-loss durability guarantee.

---

# 14. DECISION 11 — WORKER PRINCIPAL / TRUST BOUNDARY

### Human Chair disposition: **ADOPTED**

The execution worker must operate behind an enforceable OS or virtualization trust boundary.

A coding convention is insufficient.

The worker must not possess direct authority to:

- modify the accounting ledger;
- modify the lease or cutoff;
- modify authorization records;
- access provider credentials;
- use unrestricted network egress;
- install persistence;
- escape containment;
- impersonate authority processes;
- create arbitrary broker requests;
- signal or control governance components outside explicitly authorized interfaces.

Provider credentials belong only to the governed broker.

The exact isolation mechanism remains subject to qualification.

---

# 15. DECISION 12 — BREACH AND INTEGRITY SCOPE

### Human Chair disposition: **ADOPTED — DEPENDENCY-BASED SUSPENSION**

A proven or unresolved enforcement breach must not automatically freeze unrelated MCL work.

The suspension scope should follow the compromised dependency.

At minimum:

### Attempt

The affected attempt's reservation remains unavailable.

### Envelope

New admission for the affected envelope is suspended where unknown liability or qualification failure makes continued admission unsafe.

### Enforcement backend

The implicated backend qualification is quarantined.

Other open reservations relying on that same qualification lose ordinary ceiling-finalization eligibility unless independently supported.

### Independent backends

Evidence and settlement from independently qualified backends remain valid unless they share the compromised dependency.

### Shared accounts/resources

If unknown liability affects a shared unpartitioned budget, credential pool, ledger, clock authority, or broker, the affected shared scope is suspended.

Exceptional resolution requires Human Chair authority.

---

# 16. DECISION 13 — AUTHORIZATION GRANULARITY

### Human Chair disposition: **ADOPTED — BOUNDED BATCH AUTHORIZATION**

The Human Chair need not manually approve every individual low-level reservation where a governing execution envelope explicitly pre-authorizes a bounded batch.

A batch authorization must specify:

- total budget;
- permitted stage/case/task class;
- reservation ceiling;
- eligible backend;
- eligible provider/API profile;
- source/version identity where required;
- expiration/cutoff;
- retry/fallback policy;
- scope of automatic settlement authority.

Anything outside the envelope requires separate authorization.

No batch authority may silently expand its own scope.

---

# 17. DECISION 14 — PROVIDER RECOVERY AUTHORITY

### Human Chair disposition: **ADOPTED — READ-ONLY RECOVERY FOR VERSION 1**

Settlement/recovery authority may query status or usage for an **already-bound provider request** through a narrowly constrained broker interface.

It may not:

- submit a new provider request;
- retry an ambiguous request;
- change model/provider;
- increase limits;
- create another execution.

### Automatic cancellation

**Not authorized for Version 1.**

Cancellation is an external side effect and does not itself prove provider-side computation ended or remaining liability became zero.

A future governance decision may authorize constrained cancellation of already-bound requests.

---

# 18. DECISION 15 — LATE / QUARANTINED PROVIDER RESULTS

### Human Chair disposition: **ADOPTED — AUDIT-ONLY FOR VERSION 1**

A provider result arriving after the local attempt has lost authority or closed may be retained as evidence if policy permits.

For Version 1, that late result:

- must not become output of the closed attempt;
- must not automatically trigger further work;
- must not become input to a later attempt;
- must not reopen the original settlement;
- must not create a refund.

Its permitted use is:

**audit/evidence only.**

A future policy may permit quarantined content to become input to a newly and separately authorized attempt, but that capability is not authorized in Version 1.

---

# 19. VERSION 1 RETRY / REMOTE SAFETY PROFILE

Under the adopted Decisions 3–6 and 14–15, Version 1 remote behavior is:

- broker-only provider access;
- no provider credentials in worker context;
- one prospective reservation before submission;
- one-shot send authority;
- no hidden SDK retry;
- no automatic router fallback;
- no replay after ambiguous submission;
- no unbounded async/batch execution;
- no automatic cancellation;
- read-only status/usage recovery for already-bound requests;
- late results quarantined for audit only.

This profile is intentionally conservative.

---

# 20. FUTURE ACCOUNTING STATE

The adopted future policy retains the principle:

`observed conservative bound → accepted observed charge`

otherwise:

`qualified prospective ceiling → accepted ceiling charge`

otherwise:

`HOLD`

For a future local reservation:

`R = B − s⁻`

Fallback:

`C_fallback = R`

An unsupported deadline may not be transformed into a charge.

A proven enforcement breach may not be silently clamped to `R`.

A missing record may not be interpreted as proof of zero execution.

---

# 21. AUTHORITY AFTER CUTOFF

Settlement authority may outlive execution authority only for:

- evidence verification;
- accounting settlement;
- integrity incident recording;
- permitted status/usage retrieval;
- audit retention.

Settlement authority does not permit:

- execution;
- retry;
- renewal;
- new provider submission;
- source modification;
- lease extension;
- new delegation;
- acceptance of late output into the closed attempt.

---

# 22. NEXT GATE — MECHANISM QUALIFICATION

The next permitted conceptual gate is:

**READ-ONLY MECHANISM QUALIFICATION**

That review should determine whether candidate mechanisms can satisfy the selected Version 1 policy.

At minimum it should examine:

1. local containment and effect cutoff;
2. first-instruction containment;
3. Mac sleep/resume behavior;
4. absolute continuous-clock use;
5. principal separation;
6. credential custody;
7. governed egress/provider broker;
8. storage durability for the selected tier;
9. provider/API finite-liability profiles;
10. request-ID and ambiguous-send behavior;
11. effect acceptance / irreversible handoff boundaries;
12. settlement reducer determinism.

Failure to qualify a mechanism means:

`BACKEND/API PROFILE INELIGIBLE`

not:

`LOWER THE EVIDENCE STANDARD`

Decision 7 additionally requires that mechanism qualification provide the evidence needed to return a numerical per-attempt reservation proposal to the Human Chair.

Mechanism qualification does **not** itself authorize or select that number.

---

# 23. IMPLEMENTATION REMAINS UNAUTHORIZED

Approval of this governance ruling does not authorize:

- source changes;
- test changes;
- accounting migration;
- runtime execution;
- Stage 2;
- validation;
- regression;
- provider experimentation;
- API calls;
- background jobs;
- implementation of the prospective architecture.

Recording this approved ruling in the project governance record may be separately authorized by the Human Chair.

Implementation requires a separate Human Chair gate after mechanism qualification.

---

# 24. ARCHITECTURE REVIEW STATUS

The prospective architecture has completed:

1. Astra architecture proposal;
2. Claude / Opus independent adversarial review;
3. Astra amendment pass resolving RA-1 through RA-9;
4. Claude / Opus final acceptance review.

Final architecture-review verdict:

**ACCEPT**

No blocking architectural findings remain.

The architecture-review gate is complete.

---

# 25. HUMAN CHAIR DISPOSITION

The prospective policy is hereby adopted as:

**FAILURE-TIME FINALIZATION POLICY V1 — GOVERNANCE PROFILE ADOPTED, IMPLEMENTATION NOT AUTHORIZED**

The historical failed epoch remains unchanged.

The Decision 7 numerical per-attempt ceiling remains intentionally deferred under the addendum above.

The next permitted gate is bounded read-only mechanism qualification.

No implementation authority arises from this ruling.

---

# 26. HUMAN CHAIR APPROVAL

**Overall disposition:**\
**APPROVED AS WRITTEN WITH DECISION 7 ADDENDUM**

> I adopt the prospective Model Council Lab Failure-Time Finalization Policy Version 1 as specified above, including the Decision 7 addendum intentionally deferring selection of the numerical per-attempt reservation ceiling until mechanism qualification provides an evidence-informed basis for a separate Human Chair decision. This policy applies only to future execution envelopes. It does not alter the closed Decision 0009 failed epoch, does not qualify any implementation mechanism, and does not authorize implementation or execution. The next permitted gate is a bounded read-only mechanism-qualification review.

**Human Chair:** Amy\
**Date:** October 23, 2026
