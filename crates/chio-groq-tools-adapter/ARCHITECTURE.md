# chio-groq-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Groq's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, pinned endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Groq content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain Points

- `GroqAdapterConfig::new` pins `api_version` to `GROQ_API_VERSION`, but the public serializable config can be loaded from disk or mutated with a stale API version before it reaches `GroqAdapter::new`.
- Runtime paths currently trust `config.api_version` when stamping provenance and exposing provider metadata, even though the transport path always sends the pinned `x-groq-api-version` header.
- A drifted config can therefore send an upstream request before the mismatch is detected, gate streamed output with stale provenance, or lower a tool result under a local contract that no longer matches the transport pin.
- `response.rs` now owns OpenAI-compatible response-envelope classification and shared `tool_calls` decoding; that trust boundary should stay internal and should not be weakened by moving parsing back into `lib.rs`.

## Constraints

- Preserve public API compatibility for `GroqAdapter`, `GroqAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not touch fixture corpus or generated artifacts in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Groq fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Groq fixture path for cross-provider verdict equality, not on private parsing helpers.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder; moving it requires updating only the internal module import.

## Planned Improvement

Add an adapter-local API-pin guard that fails closed unless `config.api_version == GROQ_API_VERSION`, then invoke it before outbound transport, direct batch lift, direct stream gating, provenance stamping, and tool-result lowering. This is architectural because it tightens the adapter's runtime contract across every trust-boundary entrypoint while preserving the public construction API and the existing internal response module boundary.
