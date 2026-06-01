# chio-provider-adapter-core Architecture

## Boundaries

- `lib.rs` is the public adapter-core facade. It exposes provider identity, loaded-weights helpers, streaming gate helpers, deny-reason text, and SSE parsing types.
- `http.rs` owns shared provider HTTP transport, mock transport, auth configuration, status classification, and NDJSON parsing.
- Provider adapters depend on this crate for fail-closed stream parsing, common HTTP error taxonomy, and test transport seams.

## Pain Points

- The public facade currently carries the whole SSE parser implementation, which mixes provider identity helpers with a byte-stream parser used by multiple adapters.
- `SseFrame::raw` is documented as original bytes retained for exact forwarding, but the parser rebuilds raw frames from normalized text lines. CRLF-delimited upstream streams therefore lose byte fidelity.
- SSE parsing is a provider trust boundary. A parser that advertises byte-exact forwarding but silently rewrites line endings is too easy for adapters to misuse.

## Constraints

- Preserve public API compatibility for `SseFrame`, `SseParseOptions`, `UnknownSseFieldPolicy`, and `parse_sse_frames`.
- Preserve fail-closed parsing for invalid UTF-8, malformed JSON data, unknown-field rejection, event/type mismatch, and missing event names under cross-check mode.
- Preserve done-sentinel semantics: terminator frames expose `done = true`, `data = None`, and retain the original bytes for forwarding.
- Do not change provider adapters unless the public compatibility tests prove a dependent regression.

## Affected Dependents

- `chio-openai`, `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`, and `chio-gemini-tools-adapter` call the shared SSE parser.
- Provider replay and conformance tests rely on the shared `ProviderError` taxonomy and byte-stable stream gating behavior.

## Planned Improvement

Move SSE parsing behind an internal `sse` module while keeping the existing public exports. The parser will retain each frame's exact original raw bytes, including provider CRLF delimiters, while preserving the current fail-closed validation behavior.
