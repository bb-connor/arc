# chio-cohere-tools-adapter

Converts Cohere v2 chat tool calls into Chio tool invocations and
converts evaluator verdicts and tool results back to provider-native messages.
It sits between provider traffic and the tool-call fabric; the host supplies
kernel evaluation and actual tool dispatch. The API identifier is `2025-04`.

## Usage

Project a captured tool call offline. The example uses default dependencies
and a mock transport; it makes no network request.

```rust
use chio_cohere_tools_adapter::{CohereAdapter, CohereAdapterConfig, transport::MockTransport};
use chio_tool_call_fabric::ProviderRequest;
use std::sync::Arc;

let config = CohereAdapterConfig::new("local", "Example", "1", "00", "example");
let adapter = CohereAdapter::new(config, Arc::new(MockTransport::new()));
let response = br#"{"message":{"tool_calls":[{"id":"call-1","type":"function","function":{"name":"weather","arguments":"{}"}}]}}"#;
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
`lower_tool_message` applies allow-verdict redactions or emits a denial result.

The basic constructor produces projections without manifest authority.
new_with_registry binds the admitted manifest and tool security sidecars.
Streaming evaluation requires these registry coordinates before invoking the evaluator.

## Error taxonomy

Batch conversion validates selected tool calls; transport classification uses
status or typed transport errors. Stream gates validate framing and lifecycle
and propagate evaluator failures. SSE wrappers below describe event/data pairs.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | Source | Trigger |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status":429,"body":{"message":"rate limit exceeded"}}` | `CohereAdapter::chat` / `http::map_http_status` | HTTP 429; retry_after_ms is 0 and Retry-After is not parsed. |
| `ProviderError::ContentPolicy` | `{"status":403,"body":{"message":"forbidden"}}` | `CohereAdapter::chat` / `http::map_http_status` | HTTP 403 maps to ContentPolicy; response-body error codes do not override status. |
| `ProviderError::BadToolArgs` | `{"message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"[]"}}]}}` | `CohereAdapter::lift_batch` / `input::arguments` | message.tool_calls[].function.arguments decodes to []; input::arguments requires an object. |
| `ProviderError::Upstream5xx` | `{"status":503,"body":{"message":"service unavailable"}}` | `CohereAdapter::chat` / `http::map_http_status` | HTTP 5xx maps to Upstream5xx with the observed status. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","elapsed_ms":5000}` | `http::map_transport_error` | HttpTransportError::Timeout becomes TransportTimeout with the configured timeout in ms. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms":300,"budget_ms":250}` | `CohereAdapter::gate_sse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"event":"tool-call-end","data":{}}` | `CohereAdapter::gate_sse_stream` lifecycle validation | Representative SSE event/data: tool-call-end has no tool_call. |
| `ProviderError::UntrustedInput` | `{"event":"message","data":"not-json"}` | `parse_sse_frames` / `input::json_bounded` | Representative SSE event/data contains non-JSON data; original ambiguous or oversized JSON also rejects. |
<!-- error-taxonomy:end -->

A successful finish_reason=ERROR_TOXIC body without tool calls reaches
`lift_batch`'s empty-call rejection as Malformed. No native refusal classifier
is installed for that field.

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
