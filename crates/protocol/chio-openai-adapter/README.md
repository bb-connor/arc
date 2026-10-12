# chio-openai-adapter

Exposes Chio manifest tools as OpenAI function definitions and routes tool calls
through cross-protocol planning and the Chio kernel. The optional native provider
surface converts Responses API traffic into tool-call fabric invocations and
provides outbound HTTP transport and buffered SSE gating.

## Usage

Extract a Responses API call offline using the default public surface.
The returned call still requires capability-bound kernel execution.

```rust
use chio_openai::ChioOpenAiAdapter;
use serde_json::json;

let response = json!({"output": [{
    "type": "function_call", "call_id": "call-1",
    "name": "weather", "arguments": "{\"city\":\"Boston\"}"
}]});
let calls = ChioOpenAiAdapter::extract_responses_api_calls(&response)?;
assert_eq!(calls[0].id, "call-1");
assert_eq!(calls[0].function.name, "weather");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
|---|---|---|
| `default` | Yes | Empty feature set; manifest export and kernel execution remain available. |
| `provider-adapter` | Off | Adds fabric lift/lower, provider HTTP transport, and Responses SSE gating. |

## Guarantees

`ChioOpenAiAdapter::new` validates its combined manifest, rejects an empty tool
set, and rejects tools requiring declared flows on this constructor path.
Duplicate function names retain the first manifest binding.
`execute_tool_call` binds host execution context and routes admission through
the kernel. Invalid input can reject before an authorization receipt exists.
The provider surface can project without sidecars; callers must bind registry
admission before using those projections for authoritative execution.

## Error taxonomy

The provider-adapter surface classifies HTTP status before parsing response
bodies. Batch call extraction, SSE lifecycle validation, and evaluator callbacks
have separate rejection paths. SSE wrappers describe event/data pairs.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"status":429,"headers":{"retry-after-ms":"1000"},"body":{"error":{"type":"rate_limit_exceeded","message":"Rate limit reached","code":"rate_limit_exceeded","param":null},"request_id":"req_openai_rate"}}` | `OpenAiTransport::send_responses` / `http::map_http_status` | HTTP 429; retry_after_ms is 0 and Retry-After is not parsed. |
| `ProviderError::ContentPolicy` | `{"status":403,"body":{"error":{"type":"invalid_request_error","message":"Request rejected by content policy","code":"content_policy_violation","param":null},"request_id":"req_openai_policy"}}` | `OpenAiTransport::send_responses` / `http::map_http_status` | HTTP 403 maps to ContentPolicy; response-body error codes do not override status. |
| `ProviderError::BadToolArgs` | `{"status":400,"body":{"error":{"code":"content_policy_violation"}}}` | `OpenAiTransport::send_responses` / `http::map_http_status` | HTTP 400 maps to BadToolArgs even when the body names content_policy_violation. |
| `ProviderError::UntrustedInput` | `{"type":"function_call","call_id":"call_bad_args","name":"get_weather","arguments":"{not json"}` | `OpenAiAdapter::lift_batch` / `input::arguments` | A selected function_call has invalid JSON argument text; original duplicate or oversized JSON also rejects. |
| `ProviderError::Upstream5xx` | `{"status":500,"body":{"error":{"type":"server_error","message":"Internal server error","code":"server_error","param":null},"request_id":"req_openai_500"}}` | `OpenAiTransport::send_responses` / `http::map_http_status` | HTTP 5xx maps to Upstream5xx with the observed status. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","endpoint":"https://api.openai.com/v1/responses","elapsed_ms":30000}` | `http::map_transport_error` | HttpTransportError::Timeout becomes TransportTimeout with the configured timeout in ms. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"openai","event":"response.output_item.done","observed_ms":300,"budget_ms":250}` | `OpenAiAdapter::gate_sse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"event":"response.function_call_arguments.delta","data":{"type":"response.function_call_arguments.delta","output_index":0,"call_id":"call_orphan","delta":"{}"}}` | `OpenAiAdapter::gate_sse_stream` lifecycle validation | Representative SSE event/data: argument delta arrives without an active output item. |
<!-- error-taxonomy:end -->

## Status

Implemented manifest export, kernel routing, provider projection, and buffered
stream handling with local unit, fixture, and HTTP mock coverage. The native
Responses snapshot identifier is `2026-04-25`. Local evidence covers these code
paths; external provider reliability and deployment acceptance remain operational concerns.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol capability contract](../../../spec/PROTOCOL.md#5-capability-contract)
- [Cross-protocol routing](../chio-cross-protocol/README.md)
- [Provider core](../chio-provider-adapter-core/README.md)
- [License](../../../LICENSE)
