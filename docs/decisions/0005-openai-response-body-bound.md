# Decision 0005 — OpenAI Response Body Bound

## Status

Accepted for F6b Checkpoint 1

## Decision

Model Council Lab admits at most 8,000,000 actual HTTP response-body bytes from
an OpenAI Responses request into SDK parsing. Exactly 8,000,000 bytes is
allowed. A response is rejected when the next complete source chunk would
cross that boundary. The guard does not yield a prefix of that chunk, request
another chunk, drain the response, accumulate the whole body, parse it, or
truncate it.

The production HTTP client sends `Accept-Encoding: identity`. A response may
omit `Content-Encoding` or provide exactly one value that becomes `identity`
after stripping whitespace and normalizing case. Empty values, duplicate
fields, comma-separated lists, gzip, deflate, Brotli, Zstandard, and unknown
encodings are rejected. Compression is rejected because a bound on encoded
wire bytes would not bound the decoded bytes admitted to SDK parsing. F6b does
not add a decompression bound or a compression fallback.

`Content-Length` is neither trusted nor authoritative. The guard counts every
complete byte chunk delivered by the HTTP response stream, including fields
that MCL later discards. Headers and HTTP transfer framing are outside the
count. This makes the actual body authoritative for missing, understated, and
overstated `Content-Length` values.

## Early interception

The OpenAI `DefaultHttpxClient` has a synchronous HTTPX response hook. HTTPX
calls that hook before it reads or decodes the response body. The hook first
checks `Content-Encoding`, then replaces the synchronous response stream with
an `httpx.SyncByteStream` wrapper. The wrapper passes source chunks through the
bounded iterator and forwards close at most once. It marks itself closed before
calling the source close operation, propagates stream errors, and does not
drain a rejected body.

Custom and test responses created with an already-buffered `content=` or
`json=` body have materialized before the response hook receives them. The hook
checks their existing body length without copying it. That behavior provides
overflow detection coverage only; it is not evidence of early interception.
Streamed `httpx.Response(..., stream=...)` fixtures exercise the production
interception point.

Guard rejection maps to the existing malformed-provider-protocol result only
when the guard exception is the directly raised exception or the exact
immediate cause of an SDK wrapper. The mapping does not traverse deeper cause
graphs or retain status, request IDs, body data, request data, credentials, or
other provider-controlled fields.

## Production client ownership

The production default factory now returns a private ownership carrier instead
of a raw OpenAI SDK client. The carrier holds one SDK client, has a fixed
non-sensitive representation, transfers ownership once, cannot be reused, is
not an SDK proxy, and has no destructor or garbage-collection cleanup. It is
consumed inside the provider-local transport and never crosses the worker
protocol.

Objects returned by ordinary injected factories remain borrowed. This includes
SDK clients, dictionaries, test doubles, objects with or without a `close`
attribute, and raw clients returned by a patched default factory. The transport
does not infer ownership from factory selection, object shape, SDK identity,
global state, or runtime flags. Only the exact private carrier communicates
ownership.

Production construction transfers ownership in this order:

```text
bounded HTTP-client builder
→ default factory owns HTTP client
→ OpenAI construction succeeds
→ SDK client owns HTTP cleanup
→ ownership carrier returned
→ transport consumes carrier
→ transport owns SDK-client close
```

If OpenAI construction fails after HTTP-client acquisition, the factory tries
to close the HTTP client once. If carrier handoff fails after SDK construction,
it tries to close the SDK client once and does not separately close the HTTP
client. Construction and cleanup failures still expose only the fixed client
initialization failure. Construction-time `KeyboardInterrupt` and `SystemExit`
are replaced with fresh control exceptions after the applicable one-time
cleanup attempt.

## Cleanup and lifecycle ordering

After ownership transfer, the transport detaches its stored ownership and
attempts SDK-client close exactly once. It does not retry, call an HTTP-client
fallback, register a global client, or rely on garbage collection or process
exit. Cleanup retains only a fixed status: success, ordinary failure,
`KeyboardInterrupt`, or `SystemExit`. It does not retain or stringify the
cleanup exception, traceback, client, bound close method, request, or response.

A successful close preserves the pending transport result. An ordinary close
failure discards any pending success or normalized provider failure and raises
the fixed infrastructure error `openai client cleanup failed`. A cleanup-time
control exception similarly discards the pending result and raises a fresh
control exception. If another exception is already escaping, that original
exception remains authoritative regardless of cleanup behavior.

The lifecycle still records `sdk_return_observed` or
`sdk_exception_observed` immediately after the SDK call and before extraction,
normalization, or cleanup. Cleanup occurs after extraction or exception
normalization has discarded raw SDK references. Only a transport result that
survives successful close can reach the existing `outcome_observed` path.
Therefore cleanup failure creates no outcome observation, successful stage
seal, downstream stage, final candidate, or evaluation. Existing closure
semantics remain unchanged: a normally returned worker error envelope can
produce terminal `infrastructure_failure`, closure reason `returned`, absent
outcome, and `indeterminate` retry safety. The word `returned` does not attest
successful client cleanup.

Owned-client close consumes the same absolute parent deadline as the rest of
the attempt. F6b adds no cleanup-specific timeout, reset, grace period, thread,
retry, or process. If close blocks until that deadline, existing F6a worker
termination may end the attempt. Such evidence does not establish successful
cleanup, result publication, or provider outcome, and forced process
termination does not guarantee that cleanup completed.

## Limits and compatibility

This checkpoint bounds HTTP response-body bytes admitted to SDK parsing. It
does not establish a total-process RSS bound, bounded decompression support, or
guaranteed cleanup after forced termination. Existing extraction, token,
provider-call, retry, request JSON, timeout, `stream=False`, SDK
`max_retries=0`, protocol v15, and lifecycle contracts remain in force.

The default factory's private return type changes from a raw SDK client to the
ownership carrier. Injected-factory behavior remains opaque and unchanged.
Offline tests verify OpenAI 2.54.0 and HTTPX 0.28.1 behavior with
`httpx.MockTransport`. Compatibility of `Accept-Encoding: identity` with the
real OpenAI provider is not verified in this checkpoint because no provider
call or live canary is authorized.
