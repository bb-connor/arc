# chio-gemini-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns outbound HTTP wiring for Gemini `generateContent` and `streamGenerateContent`, including query-parameter API-key auth and the `v1beta` path pin.
- `native.rs` owns the public Gemini content-part shapes used by callers and tests.
- `streaming.rs` owns buffered SSE frame mediation for `streamGenerateContent` and gates `functionCall` frames before forwarding bytes.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain points

- `GeminiAdapterConfig::new` pins `api_version` to `GEMINI_API_VERSION`, but the public serializable config can be loaded from disk or mutated with a stale API version before it reaches `GeminiAdapter::new`.
- Runtime paths currently trust `config.api_version` when stamping provenance and exposing provider metadata, even though the transport path always posts to the pinned `v1beta` endpoint.
- A drifted config can therefore send an upstream request before the mismatch is detected, gate streamed output with stale provenance, or lower a tool result under a local contract that no longer matches the transport pin.
- `response.rs` now owns Gemini response-envelope classification and `functionCall` extraction; that trust boundary should stay internal and should not be weakened by moving parsing back into `lib.rs`.

## Constraints

- Preserve public API compatibility for `GeminiAdapter`, `GeminiAdapterConfig`, `Transport`, `FunctionCallPart`, and `FunctionResponsePart`.
- Preserve canonical JSON byte stability for lifted tool arguments.
- Preserve fail-closed behavior for malformed upstream payloads, invalid tool arguments, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `v1beta`.
- Do not touch fixture corpus or generated artifacts in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Gemini fixture behavior and API-version pins.
- `examples/cross-provider-policy` depends on the captured Gemini fixture path for cross-provider verdict equality, not on private response parsing helpers.
- No downstream crate should depend on private `lib.rs` parsing helpers.

## Planned improvement

Add an adapter-local API-pin guard that fails closed unless `config.api_version == GEMINI_API_VERSION`, then invoke it before outbound transport, direct batch lift, direct stream gating, provenance stamping, and tool-result lowering. This is architectural because it tightens the adapter's runtime contract across every trust-boundary entrypoint while preserving the public construction API and the internal response module boundary.
