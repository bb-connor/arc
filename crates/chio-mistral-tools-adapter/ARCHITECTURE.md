# chio-mistral-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Mistral's OpenAI-compatible `chat/completions` endpoint, including Bearer auth, endpoint constants, and the `2025-04` API-version header.
- `native.rs` owns the adapter's normalized Mistral content shapes: decoded function calls and gated function responses.
- `streaming.rs` owns buffered SSE mediation for OpenAI-compatible `chat.completion.chunk` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for providers that cannot expose runtime model bytes.

## Pain Points

- `lib.rs` still mixes adapter orchestration, native response-envelope parsing, OpenAI-compatible `tool_calls` extraction, validation, and lower-response helpers.
- The README taxonomy documents Mistral safety blocks as `ProviderError::ContentPolicy`, but the batch lift path reaches the generic no-tool-call malformed branch for `finish_reason: content_filter`.
- `openai_tool_call_to_function_call` is shared by batch and streaming paths but lives beside the public adapter surface, making the native response trust boundary harder to audit.

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

Move Mistral response-envelope classification and OpenAI-compatible `tool_calls` decoding into an internal response module, then classify `finish_reason: content_filter` envelopes as `ProviderError::ContentPolicy` before reaching the generic malformed/no-tool path. This is architectural because it creates a single native-response trust boundary shared by batch and streaming paths, aligns code with the documented error taxonomy, and keeps public APIs stable.
