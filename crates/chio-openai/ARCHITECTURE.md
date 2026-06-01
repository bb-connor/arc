# chio-openai Architecture Note

## Boundaries

- `src/lib.rs` owns the stable default surface: Chat Completions and Responses
  API tool-call extraction, manifest conversion, and direct kernel execution.
- `src/adapter.rs` is feature gated behind `provider-adapter` and owns
  Responses API lift/lower into `chio-tool-call-fabric` shapes.
- `src/streaming.rs` is feature gated behind `provider-adapter` and owns SSE
  frame buffering, event ordering, tool-call argument assembly, and verdict
  release.
- `src/transport.rs` is feature gated behind `provider-adapter` and owns the
  outbound `/v1/responses` and `/v1/chat/completions` HTTP boundary over the
  shared `chio-provider-adapter-core` transport.

## Pain Points

- The default extraction helpers and the provider-adapter lift path share
  OpenAI tool-call validation, but the large `src/lib.rs` file still carries
  much of the stable public surface. Changing that shape would be high-risk
  API work, so this slice does not move those public types.
- The transport boundary documents fail-closed status classification, but the
  injected transport seam can return an `HttpResponse` carrying a non-2xx
  status. `send_responses` and `send_chat_completions` currently parse those
  bytes before checking the status, which can downgrade a provider rate limit
  or upstream failure into `Malformed`.
- Streaming uses the shared transport's `post_sse` surface, which already
  fails real non-2xx responses as transport errors. The status gap is limited
  to buffered JSON responses that are returned as `HttpResponse` values.

## Security And API Constraints

- Keep the default feature build free of `chio-tool-call-fabric` and
  `chio-provider-adapter-core`.
- Preserve existing public exports and the pinned Responses API version
  `responses.2026-04-25`.
- Preserve canonical JSON bytes for successful tool-call invocations.
- Preserve fail-closed behavior: upstream status errors must map to concrete
  `ProviderError` classes before any body is interpreted as a tool response.
- Do not introduce live-network dependencies into tests.

## Affected Dependents

- `crates/chio-provider-conformance` consumes the OpenAI provider-adapter
  behavior through replay fixtures.
- Downstream callers that inject `MockHttpTransport` or another custom
  `ProviderHttpTransport` depend on `OpenAiTransport` enforcing the same
  status taxonomy as the real reqwest-backed transport.

## Planned Improvement

Normalize every buffered JSON `HttpResponse` status inside `OpenAiTransport`
before parsing or lifting the body. This makes injected transports obey the
same fail-closed taxonomy as real OpenAI HTTP responses and keeps the README
error table truthful for both `/v1/responses` and `/v1/chat/completions`.
