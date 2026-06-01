# chio-cohere-tools-adapter Architecture

## Ownership Boundary

`chio-cohere-tools-adapter` owns the Cohere `/v2/chat` translation boundary. It accepts native Cohere chat and stream payloads, routes outbound requests through the adapter transport, lifts Cohere `tool_calls` blocks into Chio `ToolInvocation` values, gates streaming `tool-call-end` frames before bytes are forwarded, and lowers kernel verdicts plus tool results back into Cohere `tool` role messages.

The crate does not own kernel policy evaluation, receipt signing, canonical JSON primitives, HTTP client internals, or provider-wide streaming parsers. Those stay in `chio-tool-call-fabric`, `chio-core`, and `chio-provider-adapter-core`.

## Internal Surfaces

- `src/lib.rs` owns public configuration, adapter construction, provider identity, non-streaming lift, verdict lowering, and provenance stamping.
- `src/transport.rs` owns real and mock Cohere `/v2/chat` transport behavior, including the pinned transport API version and HTTP error taxonomy mapping.
- `src/streaming.rs` owns deterministic SSE parsing and gating for Cohere `tool-call-end` frames.
- `src/native.rs` owns the Cohere wire shapes that are stable enough to expose to tests and downstream adapter callers.
- `tests/live_transport.rs` verifies the real HTTP transport shape with a local mock server and no live Cohere dependency.
- `tests/error_taxonomy_doctest.rs` keeps README error taxonomy documentation aligned with adapter-visible failures.

## Current Risk

`CohereAdapterConfig::new` constructs configs pinned to `transport::COHERE_API_VERSION`, but the config is public, serializable, and cloneable. A config loaded from disk or mutated by a caller can carry a stale or future `api_version`. If runtime paths trust that drifted value, the adapter can stamp incorrect provenance and can reach the outbound transport before detecting that the local adapter contract no longer matches the configured Cohere surface.

## Required Invariant

Every runtime path that sends native requests, gates provider output, stamps provenance, or lowers tool results must fail closed unless `config.api_version == COHERE_API_VERSION`. Public construction stays compatible: `CohereAdapter::new` remains infallible, but operational paths reject drift before any outbound request or provenance-bearing conversion.

## Verification Contract

Regression tests should prove that a drifted API version:

- rejects `chat` before the mock transport records a send,
- rejects `chat_stream` before the mock transport records a send,
- rejects direct non-streaming lift before provenance stamping,
- rejects direct lowering before producing a native tool message.

The crate must remain hermetic: no test requires a live Cohere API key or network outside local mock servers.
