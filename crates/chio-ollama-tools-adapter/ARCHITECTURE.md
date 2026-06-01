# chio-ollama-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Ollama's `/api/chat` endpoint, including localhost defaults, optional gateway bearer auth, and the `2025-04` API-version pin.
- `native.rs` owns the adapter's normalized Ollama content shapes: decoded tool calls and lowered tool-result messages.
- `streaming.rs` owns buffered NDJSON mediation for streaming `/api/chat` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit adapter-handle unavailable path plus a separate loaded-weights wrapper for callers that can provide local model bytes.

## Pain Points

- `lib.rs` still mixes adapter orchestration, native response-envelope parsing, `tool_calls` extraction, validation, and lower-response helpers.
- The README taxonomy documents model refusals as `ProviderError::ContentPolicy`, but the batch lift path reaches the generic no-tool-call malformed branch for `policy: refusal`.
- Streaming NDJSON parses tool-call entries separately from the batch path, so the native response boundary is duplicated across modules.

## Constraints

- Preserve public API compatibility for `OllamaAdapter`, `OllamaAdapterConfig`, transport constructors, loaded-weights helpers, `ToolCallPart`, `ToolCallFunction`, and `ToolResultMessage`.
- Preserve canonical JSON byte stability for decoded `tool_calls[].function.arguments` and lowered tool-result messages.
- Preserve fail-closed behavior for malformed upstream payloads, invalid arguments, transport failures, bad lower-response bytes, and streaming verdict failures.
- Preserve the pinned upstream API version `2025-04`.
- Do not edit generated artifacts or fixture corpora in this slice.

## Dependents

- `crates/chio-provider-conformance` depends on Ollama fixture behavior and API-version pins.
- `tests/localhost_replay.rs` depends on the recorded Ollama fixture and the shared mock transport path.
- Cross-provider equality checks depend on the captured Ollama fixture path for canonical invocation bytes.
- `streaming.rs` depends on the same tool-call entry decoder as batch response parsing.

## Planned Improvement

Move Ollama response-envelope classification and `tool_calls` decoding into an internal response module, then classify `policy: refusal` envelopes as `ProviderError::ContentPolicy` before reaching generic malformed/no-tool handling or forwarding stream frames. This is architectural because it creates a single native-response trust boundary shared by batch and streaming paths, aligns code with the documented error taxonomy, and keeps public APIs stable.
