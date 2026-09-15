# P3-A — Provider Capability Dossier and Selection Gate

## Status and decision

Prepared by Astra for Amy's review on 2026-09-14. Documentation only; not an
accepted admission decision, provider selection, or implementation authorization.

**Selection remains premature. No candidate qualifies for a named-provider
proposal under the approved six-part selection threshold.** Amy does not yet
have multiple qualified providers to choose between.

Two detailed dossiers follow the initial screen:

1. Anthropic direct Claude Messages API, `claude-sonnet-5` as the primary
   qualification target, with `claude-sonnet-4-6` as a treatment-comparison option:
   **PROMISING — MORE EVIDENCE REQUIRED**. It has the stronger inspected identity
   and native-client evidence, but unresolved service and capability obligations.
2. Meta Model API Chat Completions, `muse-spark-1.3`:
   **DEFER — ASSESSED, NOT READY**. Public examples establish a concrete investigation target and
   expose compatibility differences; identity provenance, closure and other
   service guarantees remain unresolved.

This is an evidence ranking within this bounded investigation, not a ranking of
model quality or all available providers. No live canary is proposed: multiple
structural unknowns remain, and a successful response cannot resolve them.

## 1. Canonical baseline and scope

The following read-only gate passed before initial research and authorship,
when the proposed artifact did not exist. These are the original baseline facts.

| Check | Observed |
| --- | --- |
| Repository | `/Users/aclab/aclab/model-council-lab` |
| Branch | `m1-live-adapter-dev` |
| HEAD | `e6eb6650e3e6b5ba72f6823758f97e9c5ae13ec7` |
| Worktree / index | Clean / clean |
| Existing upstream divergence | 0 ahead / 0 behind |
| Decision 0006 SHA-256 | `b98a49b3705a54d41ea46560576a3d11918b8d91d3c02f8daf62a792b19bcda9` |
| Decision 0007 SHA-256 | `1d714648da91a931f029b4ba76345ab1567a482b51ee6be8b1d5fda0149b6b12` |

Amy subsequently authorized this bounded Anthropic revision. Its read-only gate
on 2026-09-14 reconfirmed the branch, HEAD, divergence and both decision hashes
above. The index and tracked paths were clean; this dossier was the only
untracked/changed project path. The session recorded the superseded snapshot hash
`cb662a5cfb6acb638cb382ca306f31a093515a6f106a0fda32b841ca83140ef8`.
Those superseded untracked bytes were not retained in the repository; this is
session-reported provenance, not an independently repository-verifiable chain.
The present F1–F15 revision began from freshly verified bytes with SHA-256
`0810e9008cf266caec29aac044a64b1e7784f96a51b3ec08efb9660f9a456d4b`.
Branch, HEAD, decision hashes, sole changed path, clean tracked files and clean
index were rechecked before writing. This does not retain that superseded
snapshot either. Future exact historical reconstruction requires retaining the
reviewed bytes or committing an accepted checkpoint under separate authorization;
no extra artifact or Git action is authorized here.
The revision changes the investigation priority, not admission status. Sonnet
4.6 is an alternative for a future Chair decision, never runtime fallback.
Haiku remains only a historical comparison. No third full provider dossier is
added by comparing models within the same Anthropic boundary.

Divergence describes existing tracking data; no fetch or fresh remote-ref check
was performed. The sole authorized persistent artifact is this file. Public
documentation/source retrieval was read-only. No notebooks or downloaded code
were executed. No provider client was instantiated, no inference server was run,
and no credentials were accessed.
No application tests, installs, Git mutations or agents/subagents were used.

Controlling documents are [Decision 0006](../decisions/0006-second-provider-admission-contract.md)
and [Decision 0007](../decisions/0007-second-provider-versioned-admission-boundary.md).
They remain unchanged. P1/P2 are not reopened.

### Controlling requirements

- Trusted project-controlled adapter; one frozen provider/model identity across
  homogeneous A/B/C; no Condition D or per-stage routing.
- One bounded provider request per authorized stage attempt; zero internal and
  automatic harness retries; no fallback, redispatch or hidden child execution.
- Closed, frozen, non-secret treatment. Unsupported capabilities fail before
  dispatch rather than being ignored or translated into another meaning.
- Otherwise eligible success needs exact observed identity from the admitted
  response field. Configured labels, aliases and inferred equivalence cannot
  replace observation. Failure responses retain their applicable categories.
- A pinned provider model that becomes unavailable must fail closed. MCL must
  never automatically substitute a successor model. A successor requires explicit
  identity/treatment review and a separately authorized admission change;
  historical records retain their original meaning.
- Independent request reconstruction and explicit resource/materialization/time
  bounds. Return/exception observation, normalization, owned cleanup, outcome
  publication, reaping, EOF and promotion are distinct facts.
- A future explicit provider-specific/versioned branch selected from trusted
  authority, consistently interpreted by parent, worker, persistence and
  verifier. Unsupported selection fails closed without historical fallback.
- Existing OpenAI, F6b, legacy, `live_stub`, v13/v14/v15 verification and run
  emission remain unchanged. No version, discriminator, schema, event or API is
  allocated here.

### Human Chair ruling — hosted-service execution boundary (F4)

Amy's ruling in this revision is the controlling P3 interpretation of Decisions
0006/0007. It does not reopen or weaken them. The one-request, no-fallback,
no-hidden-child and no-redispatch requirements apply to semantically distinct
provider executions capable of changing the effective model, request, authority
or result path, not unknowable ordinary numerical internals.

| Boundary | Controlling interpretation |
| --- | --- |
| MCL/client request | Exactly one authorized provider request per stage attempt. No discovery, retry, continuation, diagnostic follow-up, tool loop, successor-model request or second model request. |
| SDK/transport | Retries, redirects, middleware redispatch, authentication replay and equivalent reissuance must be disabled, bounded or prevented and independently testable. Bounds cannot authorize a second effective request. One SDK invocation does not prove one effective request. |
| Provider-service semantics | Affirmatively known or documented alternate-model routing, fallback, semantic redispatch, delegated/agentic work or replay/retry constituting another semantic execution is incompatible with the initial path unless a later versioned architecture admits it. |
| Opaque inference internals | Numerical computation, scheduling, batching, parallelism, speculative decoding, redundancy and equivalent mechanics are not extra requests/hidden children when they do not change admitted model identity, submitted semantic request, capability set, authorization path or result authority. |

A documented or observable same-model replay/retry that executes the submitted
semantic request again counts as a retry. A gateway, unchanged model name or one
visible final response cannot turn it into ordinary inference internals.

Do not demand proof of every internal operation. Equally, one outbound HTTP
request and documentary silence do not prove absence of service fallback or
semantic redispatch. Section 10 separates blocking UNKNOWNs from hosted-service
residual uncertainty. The ruling defines the boundary; it does not establish
that either candidate satisfies it or close U1 by fiat.

## 2. Evidence method and source register

**ESTABLISHED** means directly supported by inspected source or authoritative
documentation, with the stated scope. It does not mean tested against the live
service. **LIKELY** means a supported feasibility inference with an outstanding
implementation proof. **UNKNOWN** means insufficient evidence. **DISQUALIFYING**
means a demonstrated conflict that cannot reasonably be disabled or bounded for
the assessed initial path. Absence of documentation is not proof of absence of
behavior, or proof that no remedy exists.

**Blocking UNKNOWN** concerns admission-critical semantics that could invalidate
the architecture. **Implementation-verifiable LIKELY** has a credible bounded
proof obligation. **Residual uncertainty / residual risk** concerns ordinary
opaque hosted implementation only when no affirmative incompatible behavior is
known, client behavior is bounded, the semantic service boundary is adequately
supported, and the unknown does not concern admission-critical semantics.
Residual uncertainty is not automatic acceptance; it must be identified and
considered explicitly at the selection gate. These categories are not synonyms.
An inadequately supported semantic boundary remains blocking, not residual.

Each candidate ledger below inherits its exact provider/API/model/client tuple.
Every ledger row supplies evidence, limitations and references to proposed
enforcement/verification obligations in Section 6. Those obligations are design
requirements, not claims of implemented compatibility.

All public sources were inspected on **2026-09-14** through read-only web
retrieval. Rolling documentation is a dated observation, not an immutable
specification. Crawl dates are not release dates. Source tags are identified
below; no claim is made that a chosen SDK tag is the newest or production-ready.
Rendered/retrieved source is inspection evidence, not a locally verified package
artifact. Package integrity, complete dependency closure and runtime compatibility
remain future prerequisites.

### Repository and installed dependency sources

| ID | Version/path and inspected symbols | Established scope |
| --- | --- | --- |
| R1 | Canonical HEAD; `src/model_council/artifacts.py`: `_verify_provider_identity_policy_evidence`, `_verify_lifecycle_evidence`; `protocol.py`; `runner.py`; `worker.py`; `executor.py` | Existing identity/lifecycle dispatch and reconstruction have explicit OpenAI-specific branches. Registry reachability cannot admit a new provider. |
| R2 | Canonical HEAD; `openai_adapter.py`: `build_openai_responses_request`, `_OwnedOpenAIClient`, `_perform_openai_responses_transport`; `openai_response_guard.py` | Existing deterministic request, owned-client and early body-boundary examples. These are protected provider-specific behavior, not second-provider qualification. |
| R3 | Canonical HEAD; `live_contract.py`: `ProviderErrorCategory`; `tests/test_openai_response_guard.py`: fake transport/stream and cleanup fixtures; Decision 0007 Section 7 | Neutral categories and checked-in conformance references. No test result is claimed. |
| R4 | Canonical HEAD; `security.py`: `normalize_provider_treatment_config`; `openai_adapter.py`: `_require_closed_openai_treatment`; Decision 0006 Section 8 | Neutral treatment normalization preserves opaque JSON subject to safety/size restrictions; provider semantics need a separate closed validator. It does not mandate a temperature field. The OpenAI validator is not reusable Anthropic admission. |
| L1 | `.venv/lib/python3.14/site-packages/openai/`, installed `2.54.0`; `_base_client.py`, `_client.py`, `_constants.py`, `resources/chat/completions/completions.py`, `types/chat/chat_completion.py`; `requirements-openai.txt` | Default two SDK retries, configurable retry budget, redirect-following SDK HTTP default, one Chat Completions POST construction, `model` response type and client close mechanism. Endpoint semantics are not established by these types. |
| L2 | Same site-packages; HTTPX `0.28.1`: `_client.py`, `_models.py`, `_transports/default.py`; HTTPcore `1.0.9`: `_sync/connection.py`, `_sync/http11.py` | Explicit transport, redirects, environment/proxy and HTTP-version controls; zero default connection retries; response hooks; raw versus decoded iteration; close mechanisms. HTTP/1.1 parser has a 100 KiB incomplete-event limit, not a demonstrated complete MCL header-bound policy. |

### Anthropic primary sources

| ID | Source/version | Passage or symbol inspected |
| --- | --- | --- |
| A1 | [Model IDs and versioning](https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions), rolling | Canonical Sonnet 4.6/5 dateless IDs are pinned snapshots, unlike pre-4.6 convenience aliases; infrastructure may change around fixed weights. |
| A2 | [Models overview](https://platform.claude.com/docs/en/models/overview), rolling | Current Sonnet and historical Haiku model identifiers/categories. Availability to Amy was not checked. |
| A3 | [Messages HTTP reference](https://platform.claude.com/docs/en/api/http/messages/create), rolling | `POST /v1/messages`, stateless conversations, tools and thinking request fields. |
| A4 | [Message type source](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/types/message.py), SDK `v0.84.0` | `Message.model`, content, stop reason and usage. |
| A5 | [Base client source](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/_base_client.py), `v0.84.0` | `request`, `_build_headers`, `_idempotency_key`, `_DefaultHttpxClient`, `close`; retry loop, redirect/proxy defaults, metadata and ownership hooks. |
| A6 | [Messages resource source](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/resources/messages/messages.py), `v0.84.0` | `Messages.create` builds a POST; omission, extra-body escape hatches and non-streaming timeout calculation. |
| A7 | [Client source](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/_client.py) and [dependency manifest](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/pyproject.toml), `v0.84.0` | Direct client injection/base URL; manifest version and dependency ranges. Includes HTTPX, Pydantic, AnyIO, jiter and docstring-parser. No installation performed. |
| A8 | [API errors](https://platform.claude.com/docs/en/api/errors), rolling | HTTP/error types, 32 MB Messages request limit, request IDs, retry defaults and 429 ambiguity. |
| A9 | [Stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons), rolling | End, truncation, refusal, tool use and paused-turn observations; application continuation/fallback advice. |
| A10 | [Structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs), rolling | Sonnet 5/4.6 and Haiku 4.5 support, `output_config.format`, helper schema transformations, schema caching. Exact MCL schema compatibility remains unproved. |
| A11 | [Prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching), rolling | Top-level or block-level `cache_control` opts into documented cache behavior. |
| A12 | [API/data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention), rolling | Feature-specific retention, organization-level ZDR arrangements and exceptions. This is technical scope evidence, not legal advice or account verification. |
| A13 | [API versioning](https://platform.claude.com/docs/en/api/versioning), rolling | `anthropic-version: 2023-06-01`; optional inputs/output variants and error conditions can evolve within an API version. |
| A14 | [Rate and spend limits](https://platform.claude.com/docs/en/api/rate-limits), rolling | `error.details.error_code` distinguishes enforced monthly spend caps; separately documented user-set spend-limit errors. |
| A15 | [Context windows](https://platform.claude.com/docs/en/build-with-claude/context-windows), rolling | Input overflow returns 400; generation can end at the context limit. Documented context-budget tags are provider-added content, distinct from the client wire request. |
| A16 | [Model deprecations](https://platform.claude.com/docs/en/about-claude/model-deprecations), rolling, rechecked 2026-09-14 | Direct-platform lifecycle table; retirement lower bounds, no announced deprecation for these three models, notice policy and failure after retirement. |
| A17 | [Sonnet 5 migration guide](https://platform.claude.com/docs/en/models/sonnet-5/migration-guide), rolling, rechecked 2026-09-14 | Thinking disablement/default changes, prefill restriction, changed tokenizer, total output cap and HTTP-200 refusal. Instructions to migrate or count tokens are documentation, not MCL authorization. |
| A18 | [Sonnet 5 overview](https://platform.claude.com/docs/en/models/sonnet-5/overview), rolling, inspected 2026-09-14 | Canonical ID, June 30, 2026 release, active/latest status, non-default sampling rejection. |
| A19 | [Sonnet 4.6 overview](https://platform.claude.com/docs/en/models/sonnet-4-6/overview), rolling, inspected 2026-09-14 | Canonical ID; active/legacy classification, February 17, 2026 release and retirement lower bound. |
| A20 | [Model response type](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/types/model.py) and [thinking union](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/types/thinking_config_param.py), SDK `v0.84.0`, inspected 2026-09-14 | Response `Model` union includes `str`, Sonnet 4.6 literal but no Sonnet 5 literal. Thinking union references disabled/enabled/adaptive variants. This is not complete request-type verification. |
| A21 | [Transform source](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/_utils/_transform.py), SDK `v0.84.0`, inspected 2026-09-14 | `maybe_transform`, `_transform_recursive`, `_transform_typeddict`: metadata-driven transformations, omission and pass-through behavior; no provider capability validator. |

Revision retrieval limitation: the `v0.84.0` request resource (A6) references
`types/model_param.py`. Attempts to retrieve that file and
`types/thinking_config_disabled_param.py` through both raw and GitHub URLs failed.
Their contents are **UNKNOWN** here; neither the response `Model` union nor a
thinking-union import proves the missing definitions. Do not substitute a moving
branch or claim a complete, internally verified package from these page excerpts.

### Additional Anthropic reconciliation sources

| ID | Source/version | Passage or symbol inspected |
| --- | --- | --- |
| A22 | [Effort](https://platform.claude.com/docs/en/build-with-claude/effort) and [thinking configuration table](https://platform.claude.com/docs/en/build-with-claude/thinking-troubleshooting), rolling, retrieved 2026-09-14 | Sonnet 5 effort support/default/levels; effort with or without thinking; model-specific rejected configurations. No exhaustive combination guarantee. |
| A23 | [Output configuration type](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/src/anthropic/types/output_config_param.py), `v0.84.0`, retrieved 2026-09-14 | `OutputConfigParam.effort` lists low/medium/high/max, omits xhigh, and has sibling `format`. Typing alone does not prove runtime acceptance/rejection. |
| A24 | [SDK release](https://github.com/anthropics/anthropic-sdk-python/releases/tag/v0.84.0) and [tagged changelog](https://raw.githubusercontent.com/anthropics/anthropic-sdk-python/v0.84.0/CHANGELOG.md), retrieved 2026-09-14 | Release v0.84.0 dated 2026-02-25; this predates Sonnet 5's 2026-06-30 release (A18). Release date is not retrieval date or an independently established tag-creation timestamp. |

### Meta primary-source material and retrieval limits

Meta's [July 9, 2026 announcement](https://ai.meta.com/blog/introducing-muse-spark-meta-model-api/)
establishes the Meta Model API/Muse product relationship. The public
`meta-models/meta-model-cookbook` supplies concrete API recipes. Recipes establish
documented example behavior, not an exhaustive service contract or observed
successful execution: inspected notebook cells had no execution results.

| ID | Source/version | Passage or symbol inspected |
| --- | --- | --- |
| M1 | [API fundamentals README](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/README.md), `main` observed 2026-09-14 | `https://api.meta.ai/v1`, `muse-spark-1.3`, OpenAI Python client recommendation; no exact SDK pin. |
| M2 | [Chat recipe](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/01_chat_completions.ipynb), same observation date | Stateless Chat versus stateful Responses; developer/system translation; basic response fields; setup includes an extra connectivity completion. |
| M3 | [Tool recipe](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/03_tool_calling.ipynb), same date | Tool execution loop and restriction to `tool_choice="auto"`; `none`/required/named choices rejected. |
| M4 | [Structured-output recipe](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/04_structured_output.ipynb), same date | `response_format` JSON schema examples. No MCL schema compatibility test. |
| M5 | [Caching recipe at commit fb440d68f9f1eb735faca57092b0729ad6195d96](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/fb440d68f9f1eb735faca57092b0729ad6195d96/01_api_fundamentals/05_prompt_caching.ipynb), commit history dated 2026-09-04; also inspected at `main` | Automatic caching, optional key, retention hints. This is the only cookbook file successfully inspected at this immutable revision; it does not pin the other files. |
| M6 | [Reasoning recipe](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/06_reasoning_tokens.ipynb), observed 2026-09-14 | Reasoning-token accounting, unstable omitted default, warning that `none` is not reliably available. |
| M7 | [Error recipe](https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/09_error_handling.ipynb), same date | Error type/status handling; explicit multi-call retry helper; rate-limit observations. |
| M8 | [Chat documentation](https://dev.meta.ai/docs/features/chat-completion), [models documentation](https://dev.meta.ai/docs/getting-started/models), and [overview](https://ai.developer.meta.com/docs/overview/), attempted 2026-09-14 | Returned a login-required page. Their underlying contents were not inspected or treated as evidence. No login attempted. |

The cookbook's moving `main` references are a reproducibility limitation, not
immutable pins. An attempted immutable README/tool-recipe retrieval failed;
the readable cache file must not be used to imply that all other observations
belong to that commit. Some public Meta landing pages also failed retrieval.
No access-control bypass or authenticated research was attempted.

**F1 reconciliation — conflicting moving-main observations:** Astra previously
observed `muse-spark-1.3`; independent review subsequently reported
`muse-spark-1.1` in all three exact URLs below. The final bounded re-retrieval
returned the following material through the public web tool:

| Exact URL | Retrieval interval (UTC) | Exact token observed / location |
| --- | --- | --- |
| https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/README.md | 2026-09-15 01:25:21–01:25:22 | `muse-spark-1.3` — default-model prose and request example |
| https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/README.md | 2026-09-15 01:25:21–01:25:22 | `muse-spark-1.3` — canonical configuration Model row |
| https://raw.githubusercontent.com/meta-models/meta-model-cookbook/main/01_api_fundamentals/01_chat_completions.ipynb | 2026-09-15 01:25:21–01:25:22; field inspection 01:25:31–01:25:33 | `muse-spark-1.3` — introductory Model field and request examples |

These intervals bracket tool retrieval/inspection, not an origin-server update
or immutable Git revision; web results may reflect cached material. UTC dates
above correspond to September 14 in the project timezone. The root README's
`1.3` is supported only as this timestamped retrieval observation, not a settled
current-model identity. Claude's `1.1` observation at the same cited URLs remains
**UNRECONCILED**. No immutable revision currently establishes continuity or
replacement; neither supersession direction nor a reason for the disagreement
is inferred. The timestamped results do not establish account availability,
model attestation or endpoint compatibility. See the Meta wire-identity line
and U9; the conflict remains an identity-provenance gap.

M1 explicitly warns that the official Model API client package is outdated and
recommends the OpenAI SDK. This is **ESTABLISHED** cookbook guidance, not
qualification of any OpenAI SDK version for Meta. Keep the ordinary client
candidate unqualified until its exact endpoint/runtime obligations are proved.

### Other initial-screen sources

| ID | Source/version | Inspected scope |
| --- | --- | --- |
| S1 | [Gemini GenerateContent reference](https://ai.google.dev/api/generate-content), rolling, inspected 2026-09-14 | `GenerateContentResponse.modelVersion` is documented as the version used for generation. Exact requested-model equality was not established. |
| S2 | [DeepSeek Chat reference](https://api-docs.deepseek.com/api/create-chat-completion/) and [first-call guide](https://api-docs.deepseek.com/), rolling, same date | Direct Chat API and `deepseek-v4-flash` model token. No immutable model guarantee established. |
| S3 | [DeepSeek cache documentation](https://api-docs.deepseek.com/guides/kv_cache/), rolling, same date | Default disk caching constructed from requests. No disable mechanism established in inspected material. |
| S4 | [vLLM serving models](https://raw.githubusercontent.com/vllm-project/vllm/v0.10.2/vllm/entrypoints/openai/serving_models.py) and [serving chat](https://raw.githubusercontent.com/vllm-project/vllm/v0.10.2/vllm/entrypoints/openai/serving_chat.py), `v0.10.2` | `model_name` selects a LoRA name or `base_model_paths[0].name`; Chat response uses that selected name. |
| S5 | [vLLM serving CLI](https://docs.vllm.ai/en/latest/cli/serve/), rolling, same date | `--served-model-name` controls response naming. This corroborates the concern but is not treated as documentation for every behavior in `v0.10.2`. |

## 3. Initial screen across all four categories

| Category and target | Evidence label and result | Disposition / reason for research depth |
| --- | --- | --- |
| Conventional cloud: Anthropic direct Messages; Sonnet 5 primary, Sonnet 4.6 comparison | **ESTABLISHED:** pinned IDs, relative retirement lower bounds and native source evidence (A1–A7/A16–A21). **UNKNOWN:** complete service execution contract and exact Sonnet 5 client/treatment compatibility. | Detailed dossier 1. Sonnet 5 has the longer published availability horizon; Haiku's dated ID adds no pinning advantage. Investigation priority, not selection. |
| Conventional cloud alternative: Google Gemini `generateContent` | **ESTABLISHED:** observed version field (S1). **UNKNOWN:** exact model-token/version relation, pinned deployment, dependency and execution behavior. | **NOT INVESTIGATED FURTHER — EFFORT BOUND** after this minimal screen. No qualified exact model/client tuple is claimed; not technically rejected. |
| Muse/proprietary API: Meta Model API, `muse-spark-1.3` | **ESTABLISHED:** public recipe identifies a direct API path (M1–M2). **UNKNOWN:** attested identity and complete reference behavior. | Detailed dossier 2. Resolves the earlier ambiguity about Muse and tests whether its concrete compatibility differences can satisfy closure. |
| OpenAI-compatible non-OpenAI: Meta above; DeepSeek `POST https://api.deepseek.com/chat/completions`, `deepseek-v4-flash` | Meta receives the second dossier. For DeepSeek, **ESTABLISHED:** documented request path and default disk cache (S2–S3). **UNKNOWN:** cache disablement, exact identity stability and service execution guarantees. Server release not established; no SDK selected for DeepSeek. | DeepSeek **DEFER — SCREENED**: storage closure needs evidence before more adapter analysis. Default caching is not silently admitted, but absence of a documented switch is not proof that no reasonable remedy exists. |
| Local/open-weight: stock vLLM `v0.10.2` Chat Completions response-identity mechanism | **ESTABLISHED:** configured name feeds response `model` (S4–S5). **DISQUALIFYING:** using that configured label alone as independent observed-model evidence. | **DISQUALIFYING FOR THE INITIAL PATH — INSPECTED IDENTITY MECHANISM ONLY**. No local deployment, concrete weight revision or running endpoint was selected. The source-level naming problem precedes those choices. |

The inspected vLLM served label is controlled by the same configuration being
verified, so reflecting it in a response lacks independent observed-identity
provenance. Anthropic's response field is not cryptographic weight attestation;
commercial status supplies no presumption of cryptographic trust. The initial
trust basis is provider-observed identity under an admitted provider-specific
mechanism, whose provenance must be justified independently of configured labels.

The local verdict does not reject vLLM for all future uses, open weights, or
local providers as a class. A local server with sufficiently trustworthy
provider-observed identity could still meet the initial contract. An identity
scheme requiring weight digests, signed deployment manifests or other new
attestation rules needs a later explicit decision/versioned verifier path;
this dossier neither designs nor admits one.

## 4. Detailed dossier 1 — Anthropic direct Messages

### Exact investigation tuple

- Provider: Anthropic, direct hosted Claude API; no Bedrock, Vertex, gateway,
  agent SDK, Claude Code or Managed Agents boundary.
- Endpoint: `POST https://api.anthropic.com/v1/messages`.
- API header under assessment: `anthropic-version: 2023-06-01` (A13).
- Primary wire-model target: `claude-sonnet-5` (A1/A18).
- Comparison wire-model target: `claude-sonnet-4-6` (A1/A19), considered only
  where different treatment compatibility materially reduces obligations.
  Never substitute it during a Sonnet 5 run or after a failed request.
- Client under reassessment: synchronous `anthropic==0.84.0`, ordinary
  `Anthropic.messages.create`; partially inspected remotely, not installed.
  Sonnet 5 compatibility is **UNKNOWN**, not an approved dependency pin.
- Transport feasibility target: HTTPX `0.28.1` / HTTPcore `1.0.9`, separately
  constructed and owned. Manifest ranges permit these versions; a complete
  resolved dependency set and Python 3.14 compatibility are **UNKNOWN**.
- Hosted server release: not exposed in inspected documentation. The model
  snapshot and API header do not freeze service implementation.

### Identity and availability reassessment

The original Haiku priority rested on its dated snapshot and ordinary native
endpoint; it did not compare model lifecycles. That rationale was insufficient.
**ESTABLISHED (A1):** `claude-sonnet-5`, `claude-sonnet-4-6` and
`claude-haiku-4-5-20251001` all identify pinned snapshots. A date suffix gives
Haiku no stronger pinning guarantee. Exact response-field comparison is still
required; pinned configuration cannot supply missing observed identity.

**ESTABLISHED (A16):** as inspected on 2026-09-14, the direct Claude API table
lists the following. These are retirement lower bounds, not scheduled shutdowns.

| Exact model | Lifecycle-table state / deprecation | Retirement no sooner than | Investigation consequence |
| --- | --- | --- | --- |
| `claude-sonnet-5` | Active / N/A | June 30, 2027 | Primary; longest published horizon of these three |
| `claude-sonnet-4-6` | Active / N/A | February 17, 2027 | Comparison if treatment compatibility materially helps |
| `claude-haiku-4-5-20251001` | Active / N/A | October 15, 2026 | Historical comparison; no longer preferred |

The remaining intervals to those lower bounds are approximately nine and a half,
five, and one month respectively; none predicts actual remaining lifetime.
Anthropic promises at least 60 days' retirement notice for public models (A16).
Haiku is not announced to shut down on October 15. Partner-operated platforms
have separate schedules and are outside this tuple. A19 additionally labels
Sonnet 4.6 active/legacy; the lifecycle table's Active entry is not evidence that
it is the latest model. Actual account availability and final retirement dates
remain **UNKNOWN**. Recheck public lifecycle evidence before a named proposal.

**Assessment:** Sonnet 5 deserves the first evidence effort because it combines
a pinned canonical ID with a longer published availability horizon. This reduces
the risk of completing admission work near a replacement cycle; it does not
prove compatibility or permanent availability. No quality, price or vendor
preference determines this priority. Pinning stabilizes model identity, not the
surrounding serving infrastructure (A1), and never guarantees continued access.

Enforcement/verification: V1/V8 must preserve exact frozen identity on success
and preserve bounded unavailability errors on failure. Synthetic model-unavailable
responses must produce no successor request and no successful promotion. The
normative successor rule in Section 1 governs unavailable
models. If availability expectations prove false, stop use of the unavailable
target, not its verification history.

### Sonnet 5 treatment feasibility — not an allocated schema

All rows below apply to the direct endpoint/header and primary model above;
service documentation is rolling as observed on 2026-09-14, hosted server release
unexposed, and the client candidate remains the unqualified `v0.84.0` boundary.

| Concern / primary evidence | Evidence label and limit | Proposed enforcement / independent proof | Consequence if false |
| --- | --- | --- | --- |
| Thinking (A17) | **ESTABLISHED:** Sonnet 5 defaults to adaptive thinking; explicit `thinking: {"type": "disabled"}` disables it. Manual `enabled`/`budget_tokens` is rejected. | **LIKELY:** admit only explicit no-thinking semantics; bind the disabled field in prepared-request and terminal fixtures. Reject incompatible requests rather than remove their settings. Verify unexpected content blocks cannot become successful text. | An omitted or ignored disable control invalidates the proposed closed treatment; no silent adaptive mode. |
| Effort (A22/A3/A23) | **ESTABLISHED:** Sonnet 5 supports `output_config.effort`, default high, with low/medium/high/xhigh/max. Effort influences response/thinking work and is generally supported with thinking disabled. **UNKNOWN:** exhaustive effort × disabled thinking × format compatibility, exact MCL treatment and SDK/runtime compatibility. | Freeze an admitted effort value or deliberate reliance on a specific admitted default. V3/V4 must bind it, capture prepared output_config including format, and reject unadmitted combinations before dispatch. Disabling thinking does not eliminate effort semantics. | Omission must not silently erase a supplied effort setting. Unexpected defaults/combinations invalidate the treatment; one SDK invocation proves neither semantic closure nor service compatibility. |
| Sampling (A18) | **ESTABLISHED:** non-default `temperature`, `top_p`, `top_k` cause HTTP 400. No claim that every explicit default is forbidden by the service. | Proposed narrow policy rejects all supplied sampling fields, even explicit defaults, before dispatch. It sends none only when the frozen treatment requests none. V3/V4 test each field and override path. | A requested temperature, including zero, must not be dropped or replaced with prompting; incompatible treatment is ineligible. |
| Assistant prefill (A17) | **ESTABLISHED:** rejected by both Sonnet 5 and 4.6. | Build fresh system/user text from frozen inputs; no trailing assistant prefill or continuation. Test input-shape rejection and full output-envelope reconstruction. Output-schema compatibility remains **UNKNOWN**. | If MCL's required output contract depends on prefill, this proposed treatment fails; do not secretly rewrite it. |
| Tokenization/output cap (A17) | **ESTABLISHED:** dated 2026-09-14 observation: roughly 30% more input tokens than 4.6, content-dependent; published maximum 128k output tokens. `max_tokens` caps thinking plus text. These are not permanent constants, MCL conversions, inherited byte ceilings or admission guarantees. | Choose explicit total output ceiling in the later proposal; bound bytes independently. Do not reuse predecessor token counts or multiply by a claimed exact conversion. Offline fixtures cover overflow, truncation and usage extraction; remote token counting is excluded. | Invalid token assumptions cannot justify an extra call, larger grant or unbounded allocation. |
| Refusal (A17/A4/A9) | **ESTABLISHED:** cybersecurity refusal can be HTTP 200 with `stop_reason: "refusal"`. **LIKELY:** neutral `policy_refusal` mapping. | V7 checks stop reason independently of HTTP success or usable-looking text; preserve bounded return observations and still require owned cleanup. Synthetic 200/refusal must never promote, continue or retry. | Status-only success handling loses refusal evidence and violates admission. |

**Repository feasibility (ESTABLISHED, R4):** neutral normalization does not
require sampling controls or interpret their meaning. Decisions 0006/0007 allow
a separately admitted provider-specific closed treatment. The existing OpenAI
validator is a protected example, not the Sonnet treatment contract.

**LIKELY:** MCL can express a narrow fresh text request with explicit thinking
disabled, explicitly defined effort/default semantics, no sampling fields, no
prefill, explicit output ceiling and zero tools.
This is a feasibility judgment, not selection or a new schema allocation.
The later proposal must enumerate every field, omission, default and response
variant; recover them independently from frozen authority; and verify A/B/C
translation plus the exact MCL output schema. An OpenAI reasoning/text treatment
must not be accepted by relabeling it as Anthropic treatment.

Reject supplied unsupported settings before dispatch. Construct a documented
omission only for an already-compatible frozen treatment; never discard a
supplied setting to manufacture compatibility. If the intended experiment requires
non-default sampling, manual thinking budgets, prefill or another excluded
feature, reject that experiment for this candidate. Changing its treatment needs
explicit review before freezing a new run. Service/cache closure (U1/U3), schema
compatibility (U5) and exact-client reconstruction (U7) remain **UNKNOWN**.

The prefill restriction creates a treatment-dependent fork (F11): rejected
assistant prefill → possible native `output_config.format` → provider-managed
schema caching → U3 storage/cache closure. A10 documents schema retention up to
24 hours since last use. This native-format path does not become admissible
because the application omitted an explicit persistent-storage request.
Its admission consequence remains **UNKNOWN**. A prompt-carried output contract
could avoid that particular native-schema feature, but requires its own exact
translation and output-validation proof and does not establish general no-cache
or no-retention behavior. No format choice is allocated here.

### Reassessment of `anthropic==0.84.0`

**ESTABLISHED chronology (A24/A18, retrieved 2026-09-14):** SDK v0.84.0 was
released February 25, 2026; Sonnet 5 was released June 30, 2026. The missing
Sonnet 5 literal in this older SDK is therefore unsurprising, not runtime
incompatibility evidence. Compatibility work must focus on actual fields,
serialization, response interpretation and runtime behavior.

A7's `requires-python = ">= 3.9"` permits Python 3.14 under metadata. The
retrieved manifest also lists a 3.14 classifier. Neither is evidence of executed
Python 3.14 validation for MCL's exact resolved stack; that remains **UNKNOWN**.

This pin remains an investigation artifact. It is neither proved incompatible
nor accepted for Sonnet 5. Evidence about generic client mechanisms survives
only at its original scope; no Haiku execution or compatibility proof existed
to transfer.

| Inspected evidence | Label / Sonnet 5 inference limit | Required independent proof / consequence |
| --- | --- | --- |
| A6 ordinary `create` body and timeout branch | **ESTABLISHED:** sends supplied model/thinking/output fields through `maybe_transform`; timeout calculation can consult a model table. This is not a model-specific capability validator. | Explicit residual timeout; fixture final body and headers for Sonnet 5. Unknown-model timeout defaults must not determine MCL's bounds. |
| A20 response `Model` and thinking union; A4 `Message` | **ESTABLISHED:** response typing includes generic `str`; Sonnet 4.6 is named but Sonnet 5 is not. The thinking union references disabled mode; response structure exposes refusal. **UNKNOWN:** missing request-type definitions and complete runtime behavior. | Obtain coherent exact release/package source, inspect omitted definitions and parser path; synthetic Sonnet 5 identity/refusal/disabled-mode fixtures. A permissive string annotation is not service support or identity attestation. |
| A23 output_config request type | **ESTABLISHED:** effort literals low/medium/high/max and sibling format; xhigh is absent. **UNKNOWN:** actual xhigh runtime handling and full Sonnet 5 combination support. | Inspect/capture the exact prepared request and response under the chosen release; typing alone proves neither acceptance nor rejection. No implicit upgrade, field dropping or SDK escape hatch. |
| A21 transform implementation | **ESTABLISHED:** transforms according to type metadata and preserves untyped data. **LIKELY:** a closed primitive request can survive unchanged semantically. | Capture actual prepared request; reject extras in MCL before calling SDK. Test nested union transforms and omission; no reliance on SDK to reject unsupported capabilities. |
| A5/A7/L2 transport/resource mechanisms | **ESTABLISHED:** retry/client-injection/close controls are source observations. **UNKNOWN:** full resolved package integrity, Python 3.14 compatibility, bounded parsing and Sonnet 5 endpoint compatibility. | Complete dependency review, then separately authorized offline fake-stream/counting/cleanup tests. Any package change requires its own review; no upgrade is implicitly authorized. |

The next evidence step is coherent versioned-source closure, followed only under
separate authorization by offline execution of that exact stack. Do not declare
the old pin sufficient because its response model accepts strings; do not declare
an upgrade mandatory solely because a model literal is absent. If inspection
shows missing necessary semantics, propose a specific replacement version and
review all changed request, error, transport and ownership behavior before use.

### Where Sonnet 4.6 may reduce obligations

It uses the same direct endpoint/header and is assessed against the same
`v0.84.0`/HTTPX/HTTPcore research boundary. **ESTABLISHED (A17/A20):** omission
of thinking does not enable it on 4.6, and the inspected response type names it.
These reduce default/literal uncertainty, not runtime proof. Its sampling
compatibility may help an experiment requiring controls excluded above;
exact combinations and client serialization still need **UNKNOWN** U5/U7 evidence.
Its older tokenizer avoids a migration delta only where verified 4.6 token
evidence already exists; none exists in this dossier. Prefill remains rejected.

**Disposition: COMPARISON ONLY — NOT A QUALIFICATION TARGET AT THIS CHECKPOINT**;
no demonstrated net complexity advantage yet. It retains the same service,
storage, hidden-execution, bounds, cleanup and independent-verifier obligations.
Choose it over Sonnet 5 only if documented treatment compatibility materially
outweighs its shorter published horizon. “Fallback candidate” means an alternative
for Amy's future selection, never request-time or post-failure substitution.

### Capability ledger

Controls V1–V9 are defined in Section 6 and apply to the primary Sonnet 5 tuple.
Generic source mechanisms below are not claims that this exact model/client
combination has executed successfully. The treatment/dependency analysis above
qualifies every feasibility inference; shared service unknowns also apply to 4.6.

| Claim | Evidence / label / limit | Enforcement and independent verification | Consequence if false |
| --- | --- | --- | --- |
| A-ID: observed identity | **ESTABLISHED:** response type exposes `Message.model` (A4); pinned-ID/alias distinction documented (A1). **LIKELY:** exact snapshot response matching is feasible. Documentation is not a captured response or cryptographic weight attestation. | V1: read only the bounded top-level response field; exact equality with frozen wire token; synthetic absent/type/alias/snapshot mismatch fixtures. | Missing or mismatched identity vetoes otherwise successful promotion; configuration cannot fill it. |
| A-REQUEST: SDK call count | **ESTABLISHED:** ordinary create constructs one POST (A6); the outer retry loop's repeated HTTP-client send invocations are controlled by its retry budget (A5). Redirect/auth behavior inside a send requires separate closure. Service execution is not proved. | V2: zero SDK/HTTP retries; no per-request override, tool runner, count-tokens preflight, fallback helper or custom auth redispatch. Count sends across success/errors. | Any extra request breaks initial admission. |
| A-REDIRECT: redirects and endpoint | **ESTABLISHED:** SDK HTTP default follows redirects and includes environment-proxy machinery (A5). **LIKELY:** explicit plain HTTPX client can close these routes (L2). Actual service redirect requirements **UNKNOWN**. | V2: direct fixed origin/path; redirect following off; no ambient proxy/mount/auth handlers. 3xx fixtures must produce one send and no follow-up. | Required redirect makes that proposed direct path unusable; no silent alternate endpoint. |
| A-SERVICE: fallback/hidden execution | **UNKNOWN:** inspected sources do not explicitly establish the admitted semantic service boundary against fallback, semantic redispatch or hidden child execution for this exact closed request (Section 1 ruling). A9's application advice is not evidence of automatic fallback. | V2 plus authoritative service documentation/source establishing the missing behavior; client fixtures cannot prove server internals. | Blocks qualification; a single successful canary cannot repair the gap. |
| A-TRANSLATE: deterministic content | **ESTABLISHED:** A6 enumerates create fields and omission/extra-body paths; A15 describes provider-added context-budget tags. **LIKELY:** a pure closed MCL builder can reconstruct the client request; this is not a byte-for-byte claim about the provider's internal prompt. | V3: bind role instruction, stage inputs, model, output contract and ceilings; exclude arbitrary extras, beta headers and helper schema rewriting. Capture prepared request and document service-added behavior separately. | Unknown defaults or rewriting that changes admitted request meaning block reconstruction. |
| A-METADATA: transport metadata | **ESTABLISHED:** A5 generates an internal UUID key, but emits it only when an idempotency header name is configured; base default is unset. It adds timeout/retry headers. Do not call the UUID automatically transmitted. | V3: verify concrete client's prepared headers; classify non-secret endpoint/version/timeout metadata separately from semantic JSON; prohibit authority-changing overrides. | Unexplained model-visible/routing changes block admission; stored wire digest alone is inadequate. |
| A-TOOLS: tools and child work | **ESTABLISHED:** tools/thinking are explicit API controls (A3); plain create differs from helper execution (A6). **LIKELY:** rejecting all tool definitions, containers, MCP and agent/session features can close the client request. Service semantic-boundary evidence remains A-SERVICE. | V4: closed text-only request; no server/client tools; unexpected tool blocks or pause-turn observations are ineligible, never executed or continued. | No downstream stage/promotion; no recovery request. |
| A-STATE: state, storage, background | **ESTABLISHED:** Messages is documented stateless (A3); explicit prompt cache controls exist (A11). Retention is feature/account-dependent (A12); structured-output schema caching exists (A10). **UNKNOWN:** complete storage closure for the chosen treatment/account. | V4: exclude cache controls, batches, files, containers, sessions, continuation and background features. Obtain precise storage/default evidence; do not infer no storage from statelessness or ZDR eligibility. | Blocks qualification if required storage cannot be disabled/bounded under Decision 0006. |
| A-OUTPUT: structured output/truncation | **ESTABLISHED:** Sonnet structured-output support and helper transformations (A10); input overflow and context exhaustion (A15). **LIKELY:** closed overflow handling. Exact MCL schema compatibility remains **UNKNOWN**. | V3/V4/V7: no automatic schema simplifiers; later specify native schema or a fully bound prompt-carried contract. Apply the Sonnet treatment restrictions above; test malformed/incomplete output and validate locally. | Unsupported constraints must not disappear silently; truncated/malformed results never become success. |
| A-BOUNDS: bytes and encoding | **ESTABLISHED:** service request cap exists (A8); HTTPX supports raw stream interception (L2). **LIKELY:** bounded client implementation. **UNKNOWN:** exact full header/body/decompression policy and endpoint encoding compatibility. | V5: bound request before SDK construction; raw interception before parse/error normalization; explicit parser/header limits. No inherited 8 MB value or automatic F6b reuse. | Unbounded pre-parse allocation blocks admission; incompatible encoding fails closed. |
| A-TIME: deadlines | **ESTABLISHED:** A6 derives a non-streaming timeout when not supplied. **LIKELY:** explicit residual timeout plus MCL absolute deadline is enforceable. Remote cancellation after disconnect is unobservable here; residual treatment is conditional on Section 10, not cleanup attestation. | V5/V6: explicit timeout overrides default calculation; parent deadline governs termination/reaping. Do not equate socket timeout with absolute elapsed time or remote cancellation. | Preserve timeout/cleanup uncertainty; never authorize redispatch or success from ambiguity. |
| A-OWN: ownership/cleanup | **ESTABLISHED:** SDK close calls the underlying HTTP client's close (A5). **LIKELY:** acquisition/close-once wrapper and publication veto feasible; not implemented. | V6: track owned client/transport/response through partial construction, return, exception and cancellation; borrowed fake resources remain explicit. Test close failure after pending success and failure. | Failed required cleanup suppresses pending publication; worker exit is insufficient. |
| A-FAIL: failure semantics | **ESTABLISHED:** provider errors/stop reasons (A8–A9) and a machine-readable monthly spend-cap distinction (A14). **LIKELY:** existing neutral categories can represent documented cases. Exact pinned-client extraction and conservative user-set-limit recognition need verification. | V7 plus Section 7 mapping; retain bounded facts; unrecognized signals remain sanitized failures. Prove category distinctions rather than relying only on HTTP status or retry-after. | Misclassification loses evidence; unknown variants cannot become success or retry authority. |
| A-OFFLINE: tests | **ESTABLISHED:** custom HTTP client injection exists (A7/L2); repository demonstrates fake streams (R3). **LIKELY:** nearly all MCL/client semantics are offline-testable. Full candidate dependency execution was not performed. | V1–V9; exact candidate SDK with fake transport, synthetic errors and fault injection in a separately authorized checkpoint. | Synthetic success cannot establish real service behavior. |
| A-TERMINAL: independent acceptance | **LIKELY:** explicit new provider/version branch can reconstruct this closed request. **ESTABLISHED:** current OpenAI verifier is not that branch (R1). | V8/V9: independently recover inputs/authority and recompute translation, identity, cleanup/publication relation and topology. | Missing semantics/verifier support must prevent dispatch and acceptance. |

### Verdict

**PROMISING — MORE EVIDENCE REQUIRED**, with Sonnet 5 primary and Sonnet 4.6
comparison only. Identity documentation and client mechanisms are comparatively
strong; full qualification is blocked by A-SERVICE and A-STATE. Sonnet-specific
treatment/schema, transport, failure-extraction and exact dependency proofs
remain outstanding. Documented input-overflow and spend-cap semantics narrow the
remaining work; they are not unresolved absence-of-documentation claims.
No claim that a hidden behavior actually occurs is made where evidence is UNKNOWN.

## 5. Detailed dossier 2 — Meta Model API / Muse

### Exact investigation tuple

- Provider: Meta, direct Meta Model API; not the Muse app, Muse Code, a wrapper
  around consumer login, or a multi-agent recipe.
- Endpoint: `POST https://api.meta.ai/v1/chat/completions` (M1–M2 plus L1's
  Chat path construction).
- Wire model identity: **UNRECONCILED** — Astra previously observed
  `muse-spark-1.3` in moving-main sources; independent review subsequently
  observed `muse-spark-1.1` at the same cited URLs. Astra's timestamped
  re-retrieval again returned `1.3` (Section 2). No immutable revision currently
  establishes continuity or replacement; alias/snapshot guarantee **UNKNOWN**.
- Client feasibility target: ordinary synchronous `openai==2.54.0`
  `chat.completions.create`, HTTPX `0.28.1`, HTTPcore `1.0.9` (L1–L2).
  Meta's recipe does not pin this version; endpoint compatibility with this
  exact installed stack is **UNKNOWN**, not implied by general SDK compatibility.
- Hosted server release/API revision beyond URL `/v1`: **UNKNOWN**. Cookbook
  revision information is evidence provenance, not a service release pin.

### Capability ledger

| Claim | Evidence / label / limit | Enforcement and independent verification | Consequence if false |
| --- | --- | --- | --- |
| M-ID: observed identity | **ESTABLISHED:** M1 names a configured model; L1 parses a response `model`. **UNKNOWN:** Meta's actual field provenance, extraction contract, exact-match behavior, alias/snapshot stability. No notebook output establishes these. | V1: authoritative response reference and identity semantics first; then exact-field fixtures. Never synthesize observation from request/model configuration. | Blocks initial qualification. A matching string from one call alone cannot prove provenance. |
| M-REQUEST: client requests | **ESTABLISHED:** L1 has retry controls; M2 setup adds a ping and M7 implements repeated attempts. **LIKELY:** ordinary create without these helpers can have one client send. | V2: zero SDK/HTTP retries; no notebook setup, discovery, ping, retry wrapper, fallback or tool execution loop. Count sends in synthetic failures. | Using recipes unchanged would violate the one-request budget. |
| M-REDIRECT: redirects | **ESTABLISHED:** L1 follows redirects by default independently of SDK retry budget; L2 offers controls. **UNKNOWN:** endpoint requires redirects or applies server-side rerouting. | V2: fixed origin/path, redirects disabled, explicit transport with no ambient proxy; deny per-request overrides. | 3xx must fail without following it; required redirects block this direct design. |
| M-SERVICE: fallback/hidden execution | **UNKNOWN:** the semantic service boundary against fallback, redispatch or hidden child calls remains inadequately supported for this text-only Chat request (Section 1 ruling). Product support for agents neither proves nor disproves hidden execution here. | V2/V4: obtain exact API guarantee; exclude agent SDKs and execution helpers. No client fake can verify service internals. | Blocks qualification; cannot be solved by parsing OpenAI-shaped JSON. |
| M-TRANSLATE: semantic request | **ESTABLISHED:** M2 describes system content as developer-level and Chat as stateless; M6 warns about evolving omitted reasoning behavior. **LIKELY:** explicit developer/user translation can be reconstructed. | V3: bind exact role translation, inputs, model, output contract, explicit admitted reasoning and ceilings. Reject unsupported settings instead of mapping aliases such as effort levels silently. | Unfrozen semantics or silently changed role authority invalidate binding. |
| M-METADATA: generated headers | **ESTABLISHED:** L1 generates internal idempotency UUIDs conditionally emitted through a configured header; default base setting is unset. Retry/timeout/platform headers also exist. Endpoint interpretation **UNKNOWN**. | V3: inspect complete prepared request under exact client; separately bind endpoint/time enforcement; prohibit custom body/query/auth/routing handlers. | Unknown semantic/routing effect blocks deterministic reconstruction. |
| M-TOOLS: no-tools closure | **ESTABLISHED:** M3 says only `tool_choice="auto"` is supported. **UNKNOWN:** complete guarantee that omitted/empty tools disables every server capability. | V4: seek authoritative no-tools contract; do not transplant `tool_choice="none"` or silently discard an unsupported requested setting. Reject returned tool calls without execution. | Unsupported `none` is a known conflict with that particular proposed request, not proof that the provider is impossible to admit. Closure remains blocked. |
| M-STATE: state/storage/background | **ESTABLISHED:** M2 distinguishes stateless Chat from stateful Responses. M5 documents automatic caching even without a cache key. **UNKNOWN:** disablement, retention/storage controls and complete Chat background semantics. | V4: exclude Responses/previous-response IDs, files, search, sessions and cache requests; obtain evidence for defaults and disabling requirements. | Statelessness does not prove storage absence. Unresolved automatic storage prevents qualification. |
| M-OUTPUT: format and truncation | **ESTABLISHED:** M4 demonstrates JSON schema; M6 counts reasoning in completion tokens and warns that reasoning-off is unreliable. **UNKNOWN:** complete schema subset, exact output-cap parameter support and no-input-truncation rule. | V3/V4/V7: inspect authoritative parameter contract, explicitly cap total generation including reasoning, validate full MCL envelope, reject truncation/unknown finish reasons. | Cannot assume visible text bounds total generation or that examples guarantee all MCL schemas. |
| M-BOUNDS: transport/materialization | **LIKELY:** explicit HTTPX interception feasible (L2). **UNKNOWN:** Meta's header/body/encoding behavior and pre-parse complete bounding proof. | V5: same obligation categories as Anthropic, independently specified for Meta; non-streaming application response still requires incremental transport admission. | Overrun or unsupported encoding fails closed; no F6b compatibility assumption. |
| M-TIME: deadlines | **LIKELY:** residual client timeout and parent deadline feasible (L1–L2/R1). Remote completion/cancellation after disconnect is unobservable here; see Section 10 residual conditions. | V5/V6: count time through body/extraction/cleanup; kill/reap worker on parent deadline; preserve unresolved remote facts. | Timeout/EOF do not attest stopped remote execution or safe retry. |
| M-OWN: owned resources | **ESTABLISHED:** L1 close and L2 response/transport close mechanisms exist. **LIKELY:** bounded owned-client publication barrier feasible. No Meta-specific cleanup proof exists. | V6: complete ownership map, partial-acquisition tests, response close and client close distinctions; do not close borrowed clients based on heuristics. | Failed close or uncertain worker collection vetoes eligibility as specified by the later lifecycle proposal. |
| M-FAIL: failures | **ESTABLISHED:** M7 documents type/status handling and common HTTP failures; M2 gives basic finish reasons. **UNKNOWN:** quota, refusal, incomplete/service-failure distinctions across the actual endpoint. | V7: authoritative reference plus synthetic responses; keep unknown sanitized category where evidence cannot distinguish. Do not adopt recipe retry advice. | Blocks complete neutral mapping; hints never authorize another call. |
| M-OFFLINE: testability | **ESTABLISHED:** L1–L2/R3 provide client fake seams. **LIKELY:** transport, request and MCL lifecycle tests can be offline. Cookbook cells are not executed evidence. | V1–V9 against exact client, plus service documentation for claims mocks cannot prove. | Mock agreement alone cannot qualify Meta. |
| M-TERMINAL: verifier | **LIKELY:** a provider-specific branch could reconstruct a fully closed Meta treatment. Critical identity and capability inputs are **UNKNOWN**. | V8/V9 only after gaps close; preserve original OpenAI semantics even though the client package is shared. | No dispatch/admission via aliasing to `openai_responses`. |

### Verdict

**DEFER — ASSESSED, NOT READY.** Meta is concrete enough to assess, but less ready for a named-provider
proposal than the inspected Anthropic tuple. Identity provenance is unresolved;
documented tool-choice and cache behavior demand provider-specific treatment.
No finding justifies treating Muse as an OpenAI admission with another base URL.

## 6. Required enforcement and independent evidence

These are proposed future proof obligations for each serious candidate, not
implemented controls, allocated schemas or permission to write source/tests.
They make the ledger's verification requirements concrete without duplicating
the same MCL invariants in every row.

### V1 — Identity

Extract the admitted field from a bounded provider response before it is lost
through normalization. Require a single well-formed string and exact equality
with frozen requested/configured/wire identity for otherwise eligible success.
Test missing, null, wrong-type, alias, prefix, different snapshot, ambiguity and
cross-stage mismatch. Unsuccessful outcomes keep applicable failure categories.
Terminal verification recomputes the predicate from frozen authority and bounded
observation; it never accepts a stored match verdict as proof.

Also test retired/unavailable pinned targets: retain their exact frozen identity,
publish only an eligible failure after required cleanup, and issue no successor
request. Do not rewrite historical identity or treatment to a current model.

### V2 — One authorized interaction

Prove SDK retries, HTTP connection retries, redirect following, middleware,
auth flows, per-request overrides, preflight discovery and application helpers
cannot issue additional requests. Explicitly choose fixed endpoint, transport
and supported HTTP protocol. Test 3xx, connection/read errors, 408/409/429/5xx,
provider retry hints, extraction failures and cleanup failures with a counting
transport. Unsupported treatment and nonzero harness retry budgets must produce
zero dispatch; an authorized attempted send must never produce a second send.

Apply the four-boundary Human Chair ruling in Section 1. A client send counter
is not a service semantic-execution counter; adequate service-boundary evidence
is still required. Documented/observable same-model replay is a prohibited retry.
Do not require proof of all ordinary inference mechanics or relabel an
admission-critical service UNKNOWN as residual uncertainty.

### V3 — Reconstruction

Specify a pure translation from frozen identity, treatment, role instruction,
stage inputs, output contract and ceilings. Bind endpoint/API version and
separately bound timeout enforcement. Distinguish semantic JSON from HTTP
serialization, transport-generated IDs, retry counters and platform headers.
Any metadata that affects routing, model-visible content or execution authority
must be controlled and accounted for, not dismissed as incidental.

Use golden A/B/C request fixtures and capture the final prepared HTTP request
under the exact client. Exercise omitted/default versus explicit fields, extra
body/query/header rejection and deterministic schema handling. Independent
terminal reconstruction must recover prior-stage inputs from trusted artifacts,
not merely hash the stored request or compare two stored digests. This does not
require reproducing stochastic generated text or undocumented model internals.

### V4 — Capability closure

Enumerate every supported field and reject all others before permission/call
boundary. Close tools, sessions, continuation, files, background execution,
storage/cache controls, fallback, automatic truncation, external URLs and hidden
children. Excluding optional features is not proof that defaults disable them.
Obtain service evidence where omission semantics matter. Test one unsupported
field at a time and nested escape paths; do not silently drop an unsupported
request. No convenience tool runner, code execution, agent SDK or remote token
counting call belongs in the initial path.

Keep three questions distinct: conversation state, feature storage such as
prompt/schema caching, and service retention. This document grants no exception
for any of them. When the contract's application to a documented feature is
unresolved, record the exact facts and block qualification; do not quietly
weaken Decision 0006 or expand it into an unsupported universal retention claim.

### V5 — Bounds and time

The named-provider proposal must assign and justify numeric limits for request
construction/encoded bytes, response headers, raw body, any decoded body,
JSON nesting/items/strings, extraction, normalized outcome, raw/structured
evidence, worker protocol and diagnostics. This dossier allocates none.

HTTPX response hooks receive already-parsed headers; a hook alone does not prove
pre-materialization header bounds. The inspected HTTPcore incomplete-event limit
is not by itself a total header/response bound. Inspect the chosen parser and
HTTP version, including repeated informational responses and trailers where
applicable. Prefer a smaller explicit protocol surface if evidence supports it.

Require early raw-body admission on success and error paths before SDK parsing.
Reject unsupported content encoding before decompression, or prove separately
bounded decompression. Decoded iterator chunk size alone does not bound decoder
allocation. `Accept-Encoding: identity` is a possible future policy requiring
its own endpoint evidence; it is not adopted from F6b by analogy.

Test exact-limit/one-over, dishonest Content-Length, chunked bodies, compressed
expansion, malformed JSON, deep nesting, huge strings, wrong content types,
slow/trickled responses and timeout during extraction/cleanup. HTTP read timeout
alone is not an absolute deadline. MCL's remaining grant and parent deadline
must govern the complete attempt.

### V6 — Ownership, EOF and publication

The future ownership map must name SDK client, HTTP client/pool, response stream,
sockets, direct worker and communication descriptors; acquisition and transfer
must be explicit. It must cover partial initialization, ordinary return,
exception, timeout, cancellation and cleanup failure. Successful `is_closed`
inspection or worker exit is not sufficient cleanup attestation.

Test close-once ownership, stream/client close failures, pending success and
pending normalized failure vetoes, primary-exception preservation, child reaping,
missing EOF and inherited-descriptor uncertainty. Preserve valid earlier
return/exception observations. Unpublished or ambiguous outcomes cannot support
promotion, downstream execution or successful-candidate evaluation.

Closing a client does not establish remote cancellation. A separately operated
local inference server is not automatically owned by the stage worker either.
State exactly which resources MCL owns and which remote/server observations
remain unavailable; never fabricate cleanup or safe-redispatch evidence.

### V7 — Failures

Use Section 7's mapping obligations with bounded IDs, HTTP status, provider error
type, finish reason, permitted text/structured evidence, usage and timing. Never
persist credentials or arbitrary exception representations. Preserve valid
return/exception observations through extraction and normalization failure.
Retry hints remain observations. Unknown signals remain conservatively
classified; absence of identity on an error does not overwrite its category.

### V8 — Admission and terminal verification

Before implementation, a separately reviewed named-provider proposal must define
the exact new selection representation and all changed protocol/record/lifecycle
discriminators. Parent, worker, frozen authority and terminal verifier must agree.
Unsupported, missing or contradictory selection prevents dispatch and cannot
fall back to v13/v14/v15 verification. Independently reconstruct submitted
semantic request, frozen treatment, trusted selection and expected bindings;
interpret admitted identity and causal provider observations; verify the required
cleanup/publication relationship and applicable seals/topology. Do not reconstruct
byte-for-byte provider-added transformations or generated content that did not
exist before dispatch. Identify relevant provider-added transformations, bound
them where admission-critical, and assess their effects on semantics/evidence.
This excludes impossible pre-dispatch reconstruction, not critical effects from
admission review.
Adversarial fixtures must include coordinated tampering and local rehashing.

### V9 — Offline coverage and historical isolation

Fake HTTP responses must include actual lazy byte streams; pre-materialized JSON
fixtures do not prove early interception. Inject exact SDK/client substitutes,
errors, time and cleanup failures. Nearly all MCL enforcement should be tested
without credentials or sockets; provider factual claims still need primary
evidence. Existing OpenAI fixtures are patterns and regression obligations,
never proof of candidate compatibility.

Preserve all existing historical meanings and emission. Do not generalize
`execution_profile_for_kind`, extract a generic provider framework, or route a
new provider through the existing OpenAI identity/lifecycle builder.

## 7. Neutral failure mapping obligations

The neutral category names below are established repository vocabulary (R3).
Mappings are proposed; **LIKELY** means the documented signal gives a credible
mapping, not that the adapter exists. **UNKNOWN** entries need evidence before
complete qualification. Cleanup and normalization are also lifecycle obligations
and must not be disguised as interchangeable provider errors.

| Observation | Anthropic evidence / proposed mapping | Meta evidence / proposed mapping |
| --- | --- | --- |
| Explicit refusal | A17/A9: **LIKELY** `policy_refusal`, including Sonnet 5 HTTP-200 `stop_reason: "refusal"`; status alone cannot authorize success | **UNKNOWN** authoritative refusal signal; do not infer refusal from prose alone |
| Malformed JSON/envelope, invalid content blocks | **LIKELY** `malformed_provider_protocol` under closed extractor | Same **LIKELY** local rule; actual provider extensions need enumeration |
| Truncated/incomplete generation | A9 `max_tokens` or context-exceeded: **LIKELY** `incomplete_provider_result`; paused/tool turns remain non-success | M2 `length`: **LIKELY** `incomplete_provider_result`; other incomplete signals **UNKNOWN** |
| Rate limit versus quota | A14 monthly-cap `error.details.error_code=enforced_spend_limit_reached`: **LIKELY** `quota_exhausted`; ordinary rate signal: **LIKELY** `rate_limit`. User-set spend limits may instead be 400 with documented message prefixes; bounded recognition needs review/testing. | M7 429: **LIKELY** rate category for documented rate signal; separate quota signal **UNKNOWN** |
| Authentication/configuration | A8 401: **LIKELY** `authentication_configuration` | M7 401: **LIKELY** same; local config rejection must precede dispatch |
| Permission/model/invalid request | A8 supports generic **LIKELY** permission/invalid-request mapping from actual error evidence. Exact model-cause discriminator is **UNKNOWN** (U11); do not infer retirement/access/invalid-ID causes from 400/403/404 alone | M7 400/404 support invalid request/not-found observations; exact permission/model distinction **UNKNOWN** |
| Provider failure | A8 500/529: **LIKELY** `provider_overload_internal` | M7 5xx: **LIKELY** provider error, exact subtype **UNKNOWN** |
| Timeout/connectivity | SDK/HTTPX exception taxonomy: **LIKELY** `transport_provider_timeout` / `transport_connectivity`; distinguish parent deadline/infrastructure facts | Same client-side feasibility; provider-side timeout vocabulary **UNKNOWN** |
| Unknown provider error | **LIKELY** `unknown_sanitized_failure`, retaining bounded available facts | Same; must not falsely call ambiguous quota a rate limit |
| Extraction/normalization failure after return | **LIKELY** closed protocol/sanitized outcome as appropriate; earlier return survives | Same causal obligation |
| Required cleanup failure | **LIKELY** publication veto and conservative infrastructure/lifecycle outcome; no invented cleanup provider category | Same; veto pending success and failure alike |

Provider instructions to continue, retry or fall back are not MCL authority.
Successful worker closure cannot convert any of these failures into success.

## 8. Comparative assessment and selection threshold

Ratings describe inspected evidence and proposed feasibility, not runtime
conformance. Both candidates receive the same accepted MCL constraints.

| Criterion | Anthropic tuple | Meta tuple |
| --- | --- | --- |
| Decision 0006 compliance | Unknown: critical gaps remain | Unknown: identity and closure gaps |
| Decision 0007 compatibility | Likely acceptable explicit separate branch | Likely acceptable explicit separate branch |
| Observed identity | Strong documentary basis; exact extraction proof pending | Unknown provenance and snapshot semantics |
| One-request enforceability | Strong client controls; service unknown | Strong client controls; service unknown |
| Retry/fallback control | Client retries controllable; service unknown | Same; cookbook helpers explicitly unsuitable |
| Deterministic reconstruction | Likely feasible; Sonnet 5 exact treatment and client serialization unknown | Weaker evidence: role/default/parameter differences |
| Capability closure | Unknown storage/service/schema closure; explicit thinking-off candidate, sampling/prefill restrictions | Weak: tool-choice difference and automatic cache |
| Transport/materialization bounds | Likely feasible; full proof outstanding | Same mechanisms, independent endpoint proof needed |
| Cleanup observability | Likely feasible client ownership; remote limits explicit | Same; no Meta-specific proof |
| Neutral failures | Documented monthly quota split; exact extraction/mapping tests pending | Incomplete authoritative error/finish reference |
| Offline testability | Strong seams, exact dependency not executed | Strong installed-client seams, service unverified |
| Terminal verification | Likely feasible after gaps close | Unknown critical identity/closure inputs |
| Dependency complexity | Additional SDK; 0.84.0 is an unqualified research pin with request-type retrieval gaps | Existing client package; endpoint compatibility unknown |
| Historical isolation | Required separate branch | Required separate branch despite shared SDK |
| Implementation surface | Moderate inference; distributed admission gates remain | At least comparable; wire compatibility saves no admission gates |
| Generic-refactoring risk | Contained by explicit branch | Elevated temptation to reuse OpenAI semantics; prohibited |
| Future local/open-weight support | No class-wide cloud assumption needed | Compatibility does not define future identity policy |
| Canary before implementation | Not justified as next step; documentary gaps first | Not justified; one call cannot resolve multiple gaps |
| Availability durability | Sonnet 5 preferred over 4.6/Haiku on documented retirement lower bounds; no perpetual availability claim | Model lifecycle/snapshot durability unknown |

### Six-part threshold result

Gate tokens: **MET** means the stated criterion is evidenced within its precise
scope; **NOT MET** means insufficient or conflicting evidence, including unresolved
critical UNKNOWNs. A narrow negative finding is not a positive qualification.
Both detailed candidates have the following result:

| Criterion | Status | Reason / limit |
| --- | --- | --- |
| 1. Exact provider/API/model/deployment/client boundary identified | **NOT MET** | Targets named, but exact qualified dependency/deployment boundary incomplete; Meta model-version guarantees unresolved. |
| 2. Critical behaviors have established support | **NOT MET** | Service/capability/request evidence incomplete. |
| 3. No architecture-invalidating UNKNOWN remains | **NOT MET** | Blocking items remain in Section 10 under the Chair's semantic boundary. |
| 4. Remaining LIKELY claims are bounded implementation obligations | **NOT MET** | Outstanding facts include service semantics, not only offline implementation proofs. Hosted residual uncertainty must be considered separately, not hidden in LIKELY. |
| 5. No DISQUALIFYING property remains in proposed candidate path | **NOT MET** | No irreparable provider-wide conflict established, but incomplete closure prevents certifying absence in either proposed path. Stock vLLM label-only identity and unchanged multi-call recipes are separately incompatible. |
| 6. Residual live questions explicitly identified | **MET — DISCLOSURE ONLY** | U8/U10 and the residual table identify limits; no claim of endpoint compatibility or accepted residual risk. This criterion does not cure criteria 1–5. |

Thus neither is **QUALIFIED FOR NAMED-PROVIDER PROPOSAL**. The bounded result is
valuable: it identifies a better-evidenced investigation lead and concrete
reasons that OpenAI-compatible/Muse and stock local naming cannot shortcut
admission. It does not claim exhaustive market coverage.

## 9. Likely future source/test surface — not authorized changes

Both candidates need the distributed surfaces below. This is an impact map,
not the exact change list required by the later named-provider proposal.

| Surface | Future responsibility |
| --- | --- |
| New provider-specific module(s), names not allocated | Closed treatment, pure request builder, bounded extraction/error mapping, owned client/transport boundary |
| `protocol.py`, `adapters.py`, `worker.py`, `executor.py` | Trusted versioned admission and worker launch/collection; registry-only activation forbidden |
| `runner.py`, `attempt_lifecycle.py` or separately proposed lifecycle path | Frozen selection, zero retries, permission/observations/cleanup/publication relationship |
| `artifacts.py`, `invocation.py` | New-path persistence and independent terminal reconstruction without historical fallback |
| `security.py` and provider credential boundary, if necessary | Narrow secret handoff and closed non-secret treatment; no credential work now |
| Dependency declaration, only if separately approved | Anthropic SDK/dependency pin or verified reuse of installed client for Meta; no install implied |
| New candidate-specific offline tests | V1–V9, all A/B/C roles, all terminal classes and failure categories |
| Existing regression references | `test_execution_profile.py`, `test_provider_identity_policy.py`, `test_provider_treatment_config.py`, `test_live_contract.py`, `test_attempt_lifecycle_dispatch.py`, `test_attempt_lifecycle_terminal.py`, `test_retry_policy.py`, `test_executor_response_bounds.py`, `test_openai_adapter_transport.py`, `test_openai_response_guard.py` |

A later proposal must narrow this map to exact source/test paths and justify
each change. New code must not globally restamp existing run emission or change
historical reconstruction through a repurposed profile lookup. Retained `runs/`
evidence and the known legacy no-output-directory test conflict remain untouched;
no whole-suite pass is claimed here.

## 10. Blocking UNKNOWNs, proof obligations and residual uncertainty

### Admission-critical and compatibility evidence gaps

U1–U5, the incomplete failure semantics in U6/U11, and missing foundational
source/transport evidence in U7 can invalidate the proposed path and remain
blocking. Once documentary boundaries are established, concrete implementation
proofs (V1–V9: serialization, counting, bounds, normalization and cleanup) are
implementation-verifiable **LIKELY** obligations, not proof of hosted internals.
U8/U10 distinguish unobserved compatibility/availability from those structural
gaps. Ultimate retirement dates need not be predictable; model unavailability
must remain a conservatively handled failure.


| Gap | Applies to | Evidence needed / resolution boundary |
| --- | --- | --- |
| U1: service one-execution boundary | Both detailed candidates; DeepSeek screen | Adequate authoritative support for the exact semantic service boundary under the Chair ruling, including no unadmitted alternate-model routing, semantic redispatch, delegation or same-model replay. Client counts and silence alone are insufficient; proof of every numerical internal is not required. U1 remains blocking for both assessed candidates. |
| U2: identity provenance/stability | Meta; Gemini/DeepSeek screens | Official response-field semantics, exact wire-token equality and alias/snapshot rules. For Anthropic, verify bounded extraction and reject mismatches; its documentary basis is stronger. |
| U3: storage/capability closure | Both; DeepSeek cache screen | Exact defaults, disable mechanisms and feature scope for caches/retention/background/state. Anthropic native-format schema caching is a treatment-dependent consequence of the prefill/format choice (Section 4); Meta automatic prompt caching also needs closure. No inferred exception to Decision 0006. |
| U4: no-tools/default execution | Meta, plus service-level part for Anthropic | Meta needs proof that omitted/empty tools closes server capabilities despite rejecting `tool_choice="none"`. Excluding agent wrappers is necessary but insufficient. |
| U5: exact request/output semantics | Both; Sonnet 5 primary and 4.6 comparison | Prove Sonnet 5's closed treatment satisfies the intended experiment without dropping frozen settings; exact schema, defaults, prepared fields, token/bounds assumptions and independent reconstruction. Thinking disablement, effort levels/default and sampling/prefill restrictions are documented. The effort × disabled-thinking × format cross-product and exact admitted default semantics still require proof. Determine whether 4.6 offers a material compatible-treatment advantage. Meta input-overflow/total-cap gaps remain. |
| U6: incomplete provider failure evidence | Meta; candidate-client proof remains for Anthropic | Meta needs distinguishing quota/rate and refusal/incomplete signals. Anthropic monthly-cap code is established (A14); pinned-client extraction and user-set-limit recognition are bounded verification obligations, not an absent-code claim. |
| U7: full bounds/dependency proof | Both; explicit Sonnet 5 SDK reassessment | Resolve missing 0.84.0 request-type/disabled-type source and coherent package provenance, then exact Sonnet 5 serialization/parser/runtime compatibility. Complete header/body/decompression and owned-resource close-once/EOF/reaping proof. Remote cancellation is treated separately below; it is not client cleanup proof. Later offline fault/boundary tests require separate authorization. Do not relabel Haiku evidence or infer an upgrade is sufficient. |
| U8: live compatibility | Both | Exact response identity/shape, encoding and supported closed request on actual endpoint remain unobserved. Resolve structural gaps first; later separately authorized compatibility check if necessary. |
| U9: reproducible Meta reference access / model identity provenance | Meta | Wire identity remains **UNRECONCILED**: Astra observed muse-spark-1.3; independent review observed muse-spark-1.1 at the same moving-main URLs. Section 2 records the final timestamped retrievals; no immutable revision establishes continuity or replacement. Obtain immutable recipe/model provenance and accessible authoritative API reference. Login-gated pages were not inspected. No credentials authorized. |
| U10: lifecycle and continued availability | Anthropic model comparison; Meta lifecycle remains unknown | Final retirement dates and Amy's account access are unknown. Recheck official lifecycle status/lower bounds before a named proposal; do not treat a lower bound as a shutdown date or a pinned ID as perpetual availability. No account/credential lookup now. |
| U11: model-unavailability discriminator | Anthropic direct Messages | **UNKNOWN:** distinguishing retired, account-inaccessible, unsupported, malformed/invalid model ID and generic missing resource. A16 establishes failure after retirement; A8 gives generic 400 invalid_request_error, 403 permission_error and 404 not_found_error, not guaranteed model-cause mappings. Preserve actual status/type and bounded observations without inventing cause. |

U11 verification: exercise ambiguous error bodies under each documented generic
status/type, without inferring retirement from status alone. Preserve the
applicable neutral failure based on supported evidence; otherwise retain a
conservative sanitized failure. No diagnostic provider request, retry, alternate
model or successor substitution may follow ambiguity. Absence of exact cause
need not force a fabricated discriminator: the later proposal must prove its
conservative mapping loses no available material observation.

### Hosted-service residual uncertainty — not accepted risk

| Residual domain | Classification / limits | Required treatment at selection gate |
| --- | --- | --- |
| Ordinary opaque inference mechanics | Potentially irreducible residual uncertainty under Section 1. No client can enumerate all internal computation/scheduling. | Residual classification applies only when client behavior is bounded, semantic service boundary adequately supported, no affirmative incompatible behavior known, and uncertainty concerns ordinary internals. Current U1 cannot be moved here merely because it is hard to prove. |
| Remote cancellation after disconnect | Client close, EOF and worker reaping cannot establish remote termination. This may remain irreducible hosted-service uncertainty rather than an eventually closable client test. | Identify non-observation explicitly; do not attest remote cancellation or safe redispatch. If evidence indicates a new semantic execution, or the proposed admission requires unproved remote cessation, that issue is blocking rather than residual. |
| Serving infrastructure changes around a pinned model | Provider-observed identity is not a frozen service implementation (A1). Ordinary implementation variation may remain residual. | Review its effect on semantic request, capabilities, authority and result path. Known fallback/replay or an unknown critical semantic change cannot be waived as ordinary implementation. |

No hosted residual risk is accepted by this dossier. The selection gate must
consider its scope and evidence explicitly. **Architecture-invalidating UNKNOWNs
remain blocking.** The Chair's ruling resolves the interpretation question,
not provider-specific factual gaps. It grants no admission or implementation.

**Recommended next decision:** review this dossier, then authorize a narrowly
bounded documentary gap-closure checkpoint focused on Sonnet 5 U1/U3/U5/U7,
with Sonnet 4.6 comparison only where it materially reduces treatment complexity,
if Amy wishes to continue with the strongest inspected lead. That is an evidence
priority recommendation, not provider selection. A different candidate may be
investigated instead; this dossier supplies no basis for claiming it inferior.

No provider must be contacted in this checkpoint. Any future request for a
provider clarification is an external message requiring separate approval.
If admission-critical public evidence remains unavailable, retain blocking
UNKNOWN and stop. Ordinary opaque residuals follow the separate rule above;
do not require impossible proof or turn a testing limitation into compatibility.

## 11. Future canary disposition

**None proposed for execution or approval at this checkpoint.** There is no
single narrow empirical unknown separating either tuple from qualification.
Identity provenance, hidden execution and storage/default semantics cannot be
established by one matching response. Running the cookbook would also incur
unapproved setup/ping/retry/tool calls.

After structural gaps close, a compatibility canary might be appropriate. Before
seeking authorization, its separate specification must fix provider, endpoint,
exact model, reviewed command/tool, one-call ceiling, input/output token limits
including reasoning, hard cost ceiling, secret handoff without disclosure,
evidence destination, required observations, success/failure criteria and stop
conditions. It must prohibit retries/fallback, establish offline call counting
and cleanup first, and stop on ambiguous dispatch, identity, encoding or cleanup.
No concrete command, cost assumption or evidence path is allocated here because
there is no ready canary to authorize. This paragraph is a readiness checklist,
not an executable or partially authorized canary specification.

## 12. Mechanical handoff and review boundary

- Baseline: branch `m1-live-adapter-dev`, HEAD
  `e6eb6650e3e6b5ba72f6823758f97e9c5ae13ec7`, accepted decision hashes in Section 1.
- Current tranche: P3-A, exactly this documentation artifact and Amy-authorized
  bounded F1–F15 revision incorporating the Human Chair ruling; no provider admitted. Sonnet 5 is an investigation
  target; Sonnet 4.6 is not an automatic replacement. Haiku is historical comparison.
- Amy reviews the exact document bytes and evidence verdict. Acceptance does not
  choose a provider, allocate versions, authorize dependencies or authorize code.
- Astra may perform further document authorship only within Amy's explicit
  authorization. No P4 work or silent expansion follows this dossier.
- Sol receives implementation only after a separately reviewed and approved
  named-provider proposal meeting Decisions 0006/0007, including exact source/test
  scope, version selection, evidence, bounds, failure mapping and verification.
- No credentials, local/remote inference, provider calls, installs, agents or
  subagents. No staging/commit/push or other Git mutation without Amy's specific
  authorization. Public research does not authorize external messages.
- Stop on baseline discrepancy, unexpected project changes, inaccessible evidence
  requiring authentication, new protected action, or any need to change accepted
  identity/admission semantics. Preserve state; do not repair it.
- Completion verification: full readback; only this new project path; unchanged
  index/tracked paths and canonical HEAD; both decision hashes rechecked; dossier
  SHA-256 reported in the delivery message. The dossier does not contain its own
  self-referential hash.

### F1–F15 incorporation record

| Finding | Incorporated correction / retained boundary |
| --- | --- |
| F1 | Exact-URL/timestamp/token observations and retained package warning in Section 2; conflicting 1.3/1.1 wire identity explicitly UNRECONCILED in the Meta tuple and U9. No continuity or replacement inferred. |
| F2 | Effort/default/format analysis, SDK xhigh typing gap and no silent omission in Section 4. |
| F3 | Explicit U11 model-error discriminator gap; conservative mapping without extra calls. |
| F4 | Controlling Chair ruling in Section 1; semantic service gap retained, same-model replay prohibited. |
| F5 | Gemini effort-bound minimal screen, DeepSeek screened deferral and Meta assessed deferral distinguished. |
| F6 | Sonnet 4.6 comparison-only label; not a qualification target at this checkpoint. |
| F7 | Superseded untracked hash is session provenance, not repository-reconstructible history; future retention needs authorization. |
| F8 | SDK release/model release chronology and Python metadata versus actual validation distinguished. |
| F9 | Explicit status on all six gate criteria; disclosure alone grants no qualification. |
| F10 | Dated approximate token delta and published 128k maximum; no inherited MCL ceilings/conversions. |
| F11 | Prefill restriction → native format option → schema cache → unresolved storage closure traced. |
| F12 | Blocking UNKNOWN, implementation-verifiable LIKELY and conditional hosted residuals separated; no risk acceptance implied. |
| F13 | Configured-label circularity and provider-observed trust basis explained; no commercial cryptographic presumption. |
| F14 | Normative successor rule in Section 1, shorter enforcement references elsewhere. |
| F15 | V8 reconstructs submitted semantics and evidence relations, not pre-dispatch nonexistent provider content; admission-critical transformations still assessed. |

P3-A has not been accepted by this revision. No P4 work begins.

**STOP FOR AMY REVIEW.**
