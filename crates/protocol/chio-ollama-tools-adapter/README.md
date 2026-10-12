# chio-ollama-tools-adapter

Converts Ollama local chat tool calls into Chio tool invocations and
converts evaluator verdicts and tool results back to provider-native messages.
It sits between provider traffic and the tool-call fabric; the host supplies
kernel evaluation and actual tool dispatch. The API identifier is `2025-04`.

## Usage

Project a captured tool call offline. The example uses default dependencies
and a mock transport; it makes no network request.

```rust
use chio_ollama_tools_adapter::{OllamaAdapter, OllamaAdapterConfig, transport::MockTransport};
use chio_tool_call_fabric::ProviderRequest;
use std::sync::Arc;

let config = OllamaAdapterConfig::new("local", "Example", "1", "00", "example");
let adapter = OllamaAdapter::new(config, Arc::new(MockTransport::new("mock://ollama")));
let response = br#"{"message":{"tool_calls":[{"function":{"name":"weather","arguments":{}}}]}}"#;
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
and propagate evaluator failures. Stream input consists of NDJSON records.

<!-- error-taxonomy:start -->
| ProviderError class | Native envelope (inline JSON) | Raised by | Notes |
|---|---|---|---|
| `ProviderError::RateLimited` | `{"status":429,"body":{"error":"rate limit reached"}}` | `OllamaAdapter::chat` / `http::map_http_status` | HTTP 429; retry_after_ms is 0 and Retry-After is not parsed. |
| `ProviderError::ContentPolicy` | `{"status":200,"body":{"done_reason":"stop","policy":"refusal"}}` | `response::classify_content_policy` | Batch top-level policy=refusal (trimmed, case-insensitive) rejects before extraction; HTTP 403 also maps here. |
| `ProviderError::BadToolArgs` | `{"message":{"role":"assistant","tool_calls":[{"function":{"name":"get_weather","arguments":"not-an-object"}}]}}` | `OllamaAdapter::lift_batch` / `validate_tool_call` | A selected native tool call has nonobject arguments; rejected requests can also map here through HTTP status. |
| `ProviderError::Upstream5xx` | `{"status":503,"body":{"error":"model not loaded"}}` | `OllamaAdapter::chat` / `http::map_http_status` | HTTP 5xx maps to Upstream5xx with the observed status. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","elapsed_ms":5000}` | `http::map_transport_error` | HttpTransportError::Timeout becomes TransportTimeout with the configured timeout in ms. |
| `ProviderError::VerdictBudgetExceeded` | `{"observed_ms":300,"budget_ms":250}` | `OllamaAdapter::gate_sse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"message":{"role":"assistant","content":""}}` | `OllamaAdapter::lift_batch` and `gate_sse_stream` | Batch response has no message.tool_calls; NDJSON without terminal done also rejects. |
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
