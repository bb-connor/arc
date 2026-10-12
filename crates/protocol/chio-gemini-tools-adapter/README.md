# chio-gemini-tools-adapter

Converts Gemini generateContent function calls into Chio tool invocations and
converts evaluator verdicts and tool results back to provider-native messages.
It sits between provider traffic and the tool-call fabric; the host supplies
kernel evaluation and actual tool dispatch. The API identifier is `v1beta`.

## Usage

Project a captured tool call offline. The example uses default dependencies
and a mock transport; it makes no network request.

```rust
use chio_gemini_tools_adapter::{GeminiAdapter, GeminiAdapterConfig, transport::MockTransport};
use chio_tool_call_fabric::ProviderRequest;
use std::sync::Arc;

let config = GeminiAdapterConfig::new("local", "Example", "1", "00", "example");
let adapter = GeminiAdapter::new(config, Arc::new(MockTransport::new()));
let response = br#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"weather","args":{}}}]}}]}"#;
let calls = adapter.lift_batch(ProviderRequest(response.to_vec()))?;
assert_eq!(calls[0].tool_name, "weather");
assert_eq!(calls[0].arguments, b"{}");
assert!(calls[0].bridge_security.is_none());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`lift_batch` validates native tool-call fields and canonicalizes argument
objects before returning invocations. Shared original JSON readers reject
duplicate keys and enforce byte bounds before typed projection.
`lower_function_response` applies allow-verdict redactions or emits a denial result.

The basic constructor produces projections without manifest authority.
new_with_registry binds the admitted manifest and tool security sidecars.
Streaming evaluation requires these registry coordinates before invoking the evaluator.

## Error taxonomy

Batch conversion validates selected tool calls; transport classification uses
status or typed transport errors. Stream gates validate framing and lifecycle
and propagate evaluator failures. SSE wrappers below describe event/data pairs.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Trigger |
| -------------------- | ---------------------------- | ------- | ------- |
| `ProviderError::RateLimited` | `{"status":429,"body":{"error":{"code":429,"message":"Resource has been exhausted (e.g. check quota).","status":"RESOURCE_EXHAUSTED"}}}` | `GeminiAdapter::generate_content` / `http::map_http_status` | HTTP 429; retry_after_ms is 0 and Retry-After is not parsed. |
| `ProviderError::ContentPolicy` | `{"promptFeedback":{"blockReason":"SAFETY","safetyRatings":[]}}` | `response::classify_content_policy` | Batch candidate finishReason=SAFETY or nonempty promptFeedback.blockReason rejects before extraction; HTTP 403 also maps here. |
| `ProviderError::BadToolArgs` | `{"candidates":[{"content":{"parts":[{"functionCall":{"name":"get_weather","args":"not-an-object"}}]}}]}` | `GeminiAdapter::lift_batch` / `validate_function_call` | A selected native tool call has nonobject arguments; rejected requests can also map here through HTTP status. |
| `ProviderError::Upstream5xx` | `{"status":503,"body":{"error":{"code":503,"message":"The service is currently unavailable.","status":"UNAVAILABLE"}}}` | `GeminiAdapter::generate_content` / `http::map_http_status` | HTTP 5xx maps to Upstream5xx with the observed status. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://generativelanguage.googleapis.com","timeout_ms":60000}` | `http::map_transport_error` | HttpTransportError::Timeout becomes TransportTimeout with the configured timeout in ms. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"gemini","event":"functionCall","observed_ms":300,"budget_ms":250}` | `GeminiAdapter::gate_sse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"candidates":[{"content":{"parts":[{"text":"no tool call here"}]}}]}` | `GeminiAdapter::lift_batch` and `gate_sse_stream` | Batch lift_batch finds no functionCall, or the SSE candidate lifecycle is invalid. |
| `ProviderError::UntrustedInput` | `{"event":"message","data":"not-json"}` | `parse_sse_frames` / `input::json_bounded` | Representative SSE event/data contains non-JSON data; original ambiguous or oversized JSON also rejects. |
<!-- error-taxonomy:end -->

## Status

Implemented native conversion and buffered stream gating, with local unit,
fixture, and mock-transport coverage. These checks cover adapter behavior;
external provider availability and deployment acceptance require operator evidence.
`LoadedWeights` reports unavailable model bytes.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Provider adapter core](../chio-provider-adapter-core/README.md)
- [Provider replay tests](../chio-provider-conformance/README.md)
- [License](../../../LICENSE)
