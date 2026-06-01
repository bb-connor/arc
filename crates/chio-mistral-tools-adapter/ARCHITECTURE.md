# chio-mistral-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Mistral's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Mistral content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain Points

- `MistralAdapterConfig::new` pins `api_version` to `MISTRAL_API_VERSION`, but the public serializable config can be deserialized or mutated with a stale API version before it reaches `MistralAdapter::new`.
- Runtime paths currently trust `config.api_version` when stamping provenance and exposing provider metadata, even though the transport path always sends the pinned `x-mistral-api-version` header.
- A drifted config can therefore send an upstream request before mismatch detection, gate streamed output with stale provenance, or lower a tool result under a local contract that no longer matches the transport pin.
- `response.rs` now owns Mistral response-envelope classification and shared OpenAI-compatible `tool_calls` decoding; that trust boundary should stay internal and should not move back into the public adapter surface.

## Constraints

- Preserve public API compatibility for `MistralAdapter`, `MistralAdapterConfig`, transport constructors, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for decoded `function.arguments`.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not edit generated artifacts or fixture corpora in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Mistral fixture behavior and API-version pins.
- Cross-provider equality checks depend on the captured Mistral fixture path for canonical invocation bytes.
- `streaming.rs` depends on the OpenAI-compatible `tool_calls` decoder; moving it requires updating only the internal module import.

## Planned Improvement

Add an adapter-local API-pin guard that fails closed unless `config.api_version == MISTRAL_API_VERSION`, then invoke it before outbound transport, direct batch lift, direct stream gating, provenance stamping, and tool-result lowering. This is architectural because it tightens the adapter's runtime contract across every trust-boundary entrypoint while preserving the public construction API and the existing internal response module boundary.
