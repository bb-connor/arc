# chio-anthropic-tools-adapter

Converts Anthropic Messages content blocks into Chio tool invocations and
converts evaluator verdicts and tool results back to provider-native messages.
It sits between provider traffic and the tool-call fabric; the host supplies
kernel evaluation and actual tool dispatch. The API identifier is `2023-06-01`.

## Usage

Lower an already supplied verdict and result offline. This example uses
default features and a mock transport; it does not issue an authorization receipt.

```rust
use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig, MockTransport};
use chio_tool_call_fabric::{ToolResult, VerdictResult, ReceiptId};
use std::sync::Arc;

let config = AnthropicAdapterConfig::new("local", "Example", "1", "00", "workspace");
let adapter = AnthropicAdapter::new(config, Arc::new(MockTransport::new()));
let verdict = VerdictResult::Allow {
    receipt_id: ReceiptId("example-receipt".into()), redactions: vec![],
};
let block = adapter.lower_tool_result_block(
    "call-1", verdict, ToolResult(br#"{"ok":true}"#.to_vec()),
)?;
assert_eq!(block.tool_use_id, "call-1");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
|---|---|---|
| `computer-use` | Off | Enables hosted server-tool variants and the beta header; an explicit manifest allowlist is also required. |

No feature is enabled by default.

## Guarantees

`lift_batch` validates native tool-call fields and canonicalizes argument
objects before returning invocations. Shared original JSON readers reject
duplicate keys and enforce byte bounds before typed projection.
`lower_tool_result_block` applies allow-verdict redactions or emits a denial result.

AnthropicAdapter::new and new_with_manifest do not install registry authority.
Tool lifting requires new_with_registry, including for ordinary custom tools.

## Error taxonomy

Batch conversion validates selected tool calls; transport classification uses
status or typed transport errors. Stream gates validate framing and lifecycle
and propagate evaluator failures. SSE wrappers below describe event/data pairs.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"type":"error","error":{"type":"rate_limit_error","message":"rate limit reached"},"request_id":"req_rate"}}` | `AnthropicAdapter::send_messages` / `http::map_http_status` | HTTP 429; retry_after_ms is 0 and Retry-After is not parsed. |
| `ProviderError::ContentPolicy` | `{"status":403,"body":{"error":{"type":"permission_error","message":"forbidden"}}}` | `AnthropicAdapter::send_messages` / `http::map_http_status` | HTTP 403 maps to ContentPolicy; response-body error codes do not override status. |
| `ProviderError::BadToolArgs` | `{"type":"tool_use","id":"toolu_bad_args","name":"get_weather","input":"not an object"}` | `AnthropicAdapter::lift_batch` / `validate_tool_use_block` | A selected native tool call has nonobject arguments; rejected requests can also map here through HTTP status. |
| `ProviderError::Upstream5xx` | `{"status":529,"body":{"type":"error","error":{"type":"overloaded_error","message":"overloaded"},"request_id":"req_overloaded"}}` | `AnthropicAdapter::send_messages` / `http::map_http_status` | HTTP 5xx maps to Upstream5xx with the observed status. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.anthropic.com/v1/messages","elapsed_ms":30000}` | `http::map_transport_error` | HttpTransportError::Timeout becomes TransportTimeout with the configured timeout in ms. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"anthropic","event":"content_block_start","observed_ms":300,"budget_ms":250}` | `AnthropicAdapter::gate_sse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"event":"content_block_delta","data":{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}}` | `AnthropicAdapter::gate_sse_stream` lifecycle validation | Representative SSE event/data: content_block_delta arrives without an active block. |
| `ProviderError::UntrustedInput` | `{"event":"message","data":"not-json"}` | `parse_sse_frames` / `input::json_bounded` | Representative SSE event/data contains non-JSON data; original ambiguous or oversized JSON also rejects. |
<!-- error-taxonomy:end -->

A successful stop_reason=refusal body without tool calls reaches
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
