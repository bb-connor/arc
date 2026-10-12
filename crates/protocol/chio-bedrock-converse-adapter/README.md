# chio-bedrock-converse-adapter

Converts Bedrock Converse tool-use content into Chio tool invocations and
converts evaluator verdicts and tool results back to provider-native messages.
It sits between provider traffic and the tool-call fabric; the host supplies
kernel evaluation and actual tool dispatch. The API identifier is `bedrock.converse.v1`.

## Usage

Project a captured response offline with a mock transport. The example uses
no optional features and supplies an illustrative, unauthenticated caller label.

```rust
use chio_bedrock_converse_adapter::{BedrockAdapter, BedrockAdapterConfig, MockTransport};
use chio_tool_call_fabric::ProviderRequest;
use std::sync::Arc;

let config = BedrockAdapterConfig::new(
    "local", "Example", "1", "00", "arn:aws:iam::123456789012:user/example",
    "123456789012",
);
let adapter = BedrockAdapter::new(config, Arc::new(MockTransport::new()))?;
let calls = adapter.lift_batch(ProviderRequest(br#"{"output":{"message":{"content":[{"toolUse":{"toolUseId":"call-1","name":"weather","input":{}}}]}}}"#.to_vec()))?;
assert_eq!(calls[0].tool_name, "weather");
assert!(calls[0].bridge_security.is_none());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`lift_batch` validates native tool-call fields and canonicalizes argument
objects before returning invocations. Shared original JSON readers reject
duplicate keys and enforce byte bounds before typed projection.
`lower_tool_result` applies allow-verdict redactions or emits a denial result.

The basic constructor projects provider traffic without manifest authority.
Use a registry constructor before evaluation and signed IAM construction
when caller identity must come from authenticated mapping data.

## Error taxonomy

Batch conversion validates selected tool calls; transport classification uses
status or typed transport errors. Stream gates validate framing and lifecycle
and propagate evaluator failures. Stream examples use captured single-event-key
JSON records.

<!-- error-taxonomy:start -->
| ProviderError class | Native or boundary envelope | Source | Adapter-visible behavior |
| ------------------- | --------------------------- | ------ | ------------------------ |
| `ProviderError::RateLimited` | `{"operation":"Converse","status":429,"headers":{"x-amzn-errortype":"ThrottlingException"},"body":{"message":"Rate exceeded"},"retry_after_ms":1000}` | `BedrockAdapter::converse` / `map_transport_error` (SDK) | SDK ThrottlingException maps to RateLimited with retry_after_ms=1000. |
| `ProviderError::BadToolArgs` | `{"toolUse":{"toolUseId":"tooluse_bad_args","name":"get_weather","input":"not an object"}}` | `BedrockAdapter::lift_batch` / `validate_tool_use` | Selected toolUse.input is a nonobject; validate_tool_use rejects it before invocation construction. |
| `ProviderError::Upstream5xx` | `{"operation":"Converse","status":500,"headers":{"x-amzn-errortype":"InternalServerException"},"body":{"message":"Internal failure"}}` | `BedrockAdapter::converse` / `map_transport_error` (SDK) | SDK InternalServerException maps to status 500; ServiceUnavailableException maps to 503. |
| `ProviderError::TransportTimeout` | `{"transport":"timeout","provider":"bedrock","operation":"Converse","elapsed_ms":30000}` | `BedrockAdapter::converse` / `map_transport_error` | Explicit transport timeout preserves ms; SDK ModelTimeoutException and TimeoutError use ms=0. |
| `ProviderError::VerdictBudgetExceeded` | `{"provider":"bedrock","event":"contentBlockStart","observed_ms":300,"budget_ms":250}` | `BedrockAdapter::gate_converse_stream` evaluator callback | The evaluator returns VerdictBudgetExceeded; the gate propagates it. No gate-owned 250 ms timer is installed. |
| `ProviderError::Malformed` | `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"toolUse":{"input":"{}"}}}}` | `BedrockAdapter::gate_converse_stream` lifecycle validation | A captured contentBlockDelta has no active block; captured stream exception records also reject as Malformed. |
<!-- error-taxonomy:end -->

Native guardrail-only Converse responses with no toolUse return Malformed;
there is no native ContentPolicy mapping. Captured ConverseStream exception
records use the single-event-key shape, such as `{ "throttlingException": {} }`,
and reject as Malformed. SDK Converse failures use the transport rows above.

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
