# chio-provider-adapter-core

Shared provider-adapter primitives for HTTP transport, bounded original JSON,
SSE framing, response envelopes, and OpenAI-compatible tool-call assembly.
Provider-specific adapters supply endpoint details, identity projection,
manifest admission, and evaluator callbacks.

## Usage

Parse one SSE frame offline and preserve its original bytes for forwarding.
The parser validates framing and JSON; it does not evaluate a tool call.

```rust
use chio_provider_adapter_core::{parse_sse_frames, SseParseOptions};

let raw = b"event: message\ndata: {\"ok\":true}\n\n";
let frames = parse_sse_frames(raw, SseParseOptions::rejecting_unknown("Example"))?;
assert_eq!(frames.len(), 1);
assert_eq!(frames[0].event.as_deref(), Some("message"));
assert_eq!(frames[0].raw, raw);
# Ok::<(), Box<dyn std::error::Error>>(())
```

No optional Cargo features are declared. The example uses existing dependencies
and makes no network request.

## Guarantees

`input::json_bounded` validates original bytes before typed decoding.
`input::arguments` requires an object and enforces a 1 MiB argument bound.
`parse_sse_frames` preserves original frame bytes and applies stream quotas.
`SseParseOptions` selects unknown-field handling, terminators, and event/type checks.
`ensure_streaming_allow_no_redactions` rejects denial and stream redactions.

## Status

Implemented shared support for native provider adapters, with unit tests and
local HTTP mock coverage. `GatedStream::new` stores caller-supplied vectors;
its constructor does not independently verify their correspondence.
Provider authentication, kernel admission, and tool execution belong to callers.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol serialization](../../../spec/PROTOCOL.md#4-serialization-and-identity)
- [Tool-call fabric](../chio-tool-call-fabric/README.md)
- [Provider replay harness](../chio-provider-conformance/README.md)
- [License](../../../LICENSE)
