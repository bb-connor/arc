# chio-ollama-tools-adapter architecture note

## Boundaries

- `lib.rs` owns the public adapter handle, configuration, provider identity, lift/lower entrypoints, and the `Provider` implementation.
- `transport.rs` owns the shared HTTP transport wiring for Ollama's `/api/chat` endpoint, including localhost defaults, optional gateway bearer auth, and the `2025-04` API-version pin.
- `native.rs` owns the adapter's normalized Ollama content shapes: decoded tool calls and lowered tool-result messages.
- `streaming.rs` owns buffered NDJSON mediation for streaming `/api/chat` frames and gates streamed `tool_calls` before release.
- `loaded_weights.rs` owns the explicit adapter-handle unavailable path plus a separate loaded-weights wrapper for callers that can provide local model bytes.

## Pain Points

- `OllamaAdapterConfig.api_version` is public and serializable, so persisted or hand-built configs can drift away from the crate pin even though the transport, README, and fixtures define a single supported API snapshot.
- `api_version()` and provenance stamps currently trust the mutable config field directly, which can make a stale local config look like an accepted upstream contract.
- Outbound calls, captured batch lifting, streamed gating, direct tool-call lifting, and lower-response helpers share the same trust boundary but do not currently enforce the pin before doing work.

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
- `streaming.rs` and direct native lifting depend on the same config pin as outbound transport because both stamp provider provenance.

## Planned Improvement

Add an adapter-local API-version guard that accepts only `OLLAMA_API_VERSION` before any outbound transport, captured lift, streaming evaluation, direct provenance stamp, or lower-response operation. This is architectural because it turns the upstream contract pin from documentation and fixture metadata into an enforced boundary across every public mediation path while keeping the public config shape stable.
