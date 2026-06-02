# chio-provider-adapter-core Architecture

## Boundaries

- `lib.rs` is the public adapter-core facade. It exposes provider identity, loaded-weights helpers, streaming gate helpers, deny-reason text, and SSE parsing types.
- `http.rs` owns shared provider HTTP transport, mock transport, auth configuration, status classification, and NDJSON parsing.
- Provider adapters depend on this crate for fail-closed stream parsing, common HTTP error taxonomy, and test transport seams.

## Pain Points

- The public facade now keeps SSE parsing behind an internal `sse` module while preserving public re-exports and CRLF byte fidelity for `SseFrame::raw`.
- `HttpTransportConfig::base_url` is public and caller supplied. Today `HttpTransport::new` accepts blank strings, surrounding whitespace, unsupported schemes, URL userinfo, query strings, and fragments, deferring most failures until a request is sent.
- Provider adapters inject auth through `AuthScheme` and provider-specific headers. Allowing credentials or query material in `base_url` creates a second ambient authority path and makes request-target construction harder to audit.

## Constraints

- Preserve public API compatibility for `SseFrame`, `SseParseOptions`, `UnknownSseFieldPolicy`, and `parse_sse_frames`.
- Preserve fail-closed parsing for invalid UTF-8, malformed JSON data, unknown-field rejection, event/type mismatch, and missing event names under cross-check mode.
- Preserve done-sentinel semantics: terminator frames expose `done = true`, `data = None`, and retain the original bytes for forwarding.
- Preserve public API compatibility for `HttpTransportConfig`, `HttpTransportError`, `ProviderHttpTransport`, `MockHttpTransport`, and status/transport error mapping.
- Keep provider secrets flowing through `AuthScheme`, never through URL userinfo or opaque base URL query strings.
- Do not change provider adapters unless the public compatibility tests prove a dependent regression.

## Affected Dependents

- `chio-openai`, `chio-groq-tools-adapter`, `chio-mistral-tools-adapter`, `chio-cohere-tools-adapter`, and `chio-gemini-tools-adapter` call the shared SSE parser.
- Provider replay and conformance tests rely on the shared `ProviderError` taxonomy and byte-stable stream gating behavior.

## Planned Improvement

Validate the configured HTTP base URL when constructing `HttpTransport`: reject empty or padded values, non-HTTP(S) schemes, embedded userinfo, query strings, and fragments before any request can be built. This is architectural because it tightens the shared outbound trust boundary for every provider adapter while preserving the existing config and transport trait surface.
