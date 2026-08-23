# Decision 0004 — M1 Adapter Trust Model

## Status

Accepted by Human Chair

## Decision

For M1, adapter implementations are trusted, project-controlled harness code. Model-generated outputs are untrusted.

Project-controlled adapter implementations are reviewed components of the harness. M1 does not support arbitrary third-party or model-supplied Python adapters.

The following are untrusted inputs and must be handled by the harness accordingly:

- model output and structured model responses
- tool requests
- model-generated content and other model-produced structured data

The harness retains authority over experiment configuration, model identity, resource limits, evaluator configuration, permitted context, filesystem and artifact destinations, and stage transitions.

The subprocess boundary provides invocation-protocol isolation and direct-worker timeout enforcement. It is not claimed to be an OS sandbox against malicious project-controlled Python. Same-user hostile-code containment and external cryptographic notarization are outside M1 scope.

Future support for genuinely untrusted adapter implementations requires a separately designed isolation boundary.

This decision clarifies implementation trust boundaries. It does not modify the A/B/C/D experimental design of [Decision 0002](0002-mvp-experiment-design.md) or the pilot parameters of [Decision 0003](0003-m1-pilot-parameters.md).
