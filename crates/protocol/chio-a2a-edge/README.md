# chio-a2a-edge

Exposes admitted Chio tools as A2A skills, builds an Agent Card, and dispatches calls through the kernel and cross-protocol orchestrator.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use chio_a2a_edge::{A2aEdgeConfig, ChioA2aEdge};
use chio_manifest::VerifiedManifestRegistry;

let registry = VerifiedManifestRegistry::default();
let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), &registry)?;
assert!(edge.skill_ids().is_empty());
assert!(edge.agent_card().capabilities.streaming);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; telemetry integration is disabled. |
| `otel` | No | Enables the OTel module and kernel/MCP-edge telemetry features. |

## Guarantees

`ChioA2aEdge::new` requires a `VerifiedManifestRegistry` and validates Agent Card configuration. `handle_jsonrpc` validates original JSON bytes with a 1 MiB limit before dispatch. Kernel execution supplies capability enforcement and receipts.

Use the request-ID entrypoints for request-bound authorization artifacts.
Deferred task queries and cancellation retain host-authenticated owner checks.

## Status

Implemented library entrypoints cover blocking sends and deferred task execution. Streaming creates a task; `task/get` resolves it and `task/cancel` can cancel pending work. The embedding host supplies authenticated execution context and HTTP routing.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#11-a2a-adapter-contract)
- [chio-a2a-adapter](../chio-a2a-adapter/README.md)

## License

See the workspace [license](../../../LICENSE).
