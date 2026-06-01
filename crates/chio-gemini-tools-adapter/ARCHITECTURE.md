# chio-gemini-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns outbound HTTP wiring for Gemini `generateContent` and `streamGenerateContent`, including query-parameter API-key auth and the `v1beta` path pin.
- `native.rs` owns the public Gemini content-part shapes used by callers and tests.
- `streaming.rs` owns buffered SSE frame mediation for `streamGenerateContent` and gates `functionCall` frames before forwarding bytes.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain points

- `lib.rs` currently mixes adapter orchestration, Gemini response-envelope parsing, native `functionCall` extraction, validation, and function-response lowering. That keeps the public adapter surface and the provider response trust boundary in one large file.
- The README taxonomy documents Gemini safety blocks as `ProviderError::ContentPolicy`, but the batch lift path does not classify a `promptFeedback.blockReason` response before the no-tool-call path reports it as malformed.
- Existing branch-local hardening already made malformed wrapper fields fail closed and split lower-response helpers, so the next slice should not be another small helper extraction.

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

Move Gemini response-envelope classification and `functionCall` extraction into an internal response module, and classify `promptFeedback.blockReason` safety blocks as `ProviderError::ContentPolicy` before the adapter reaches the generic malformed/no-tool path. This is architectural because it creates a distinct native-response trust boundary, aligns implementation with the documented error taxonomy, and keeps public adapter APIs stable.
