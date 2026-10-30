# chio-ag-ui-proxy

Evaluates agent-to-UI events against capability scope and signs event receipts. It provides transport metadata and counters for SSE and WebSocket embeddings.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use chio_ag_ui_proxy::{AgUiProxy, AgUiProxyConfig};
use chio_core::crypto::Keypair;

let proxy = AgUiProxy::try_new(AgUiProxyConfig::default(), Keypair::generate())?;
assert!(!proxy.config().allow_display_without_capability);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`AgUiProxy::evaluate` validates event identity fields, derives classification, blocks mismatches, and signs a receipt before updating transport counters. Capability-bearing events use `verify_capability_full` and event-bound scope matching.

The host delivers an event only when the returned ProxyDecision is Forward.
Transport counters update after the decision receipt has been built.

## Status

Implemented in-memory evaluator and signed receipt API. `Transport` records metadata and counts; hosts implement SSE/WebSocket I/O. `max_events_per_second` is configuration metadata without a rate-limit check in `evaluate`.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-acp-proxy](../chio-acp-proxy/README.md)

## License

See the workspace [license](../../../LICENSE).
