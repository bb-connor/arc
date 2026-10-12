# chio-acp-edge

Publishes admitted Chio tools as ACP capabilities and handles permission previews, blocking invocations, and deferred invocation tasks.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use chio_acp_edge::{AcpEdgeConfig, ChioAcpEdge};
use chio_manifest::VerifiedManifestRegistry;

let registry = VerifiedManifestRegistry::default();
let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), &registry)?;
assert!(edge.capabilities().is_empty());
assert!(edge.capability_ids().is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; fuzz instrumentation is disabled. |
| `fuzz` | No | Adds arbitrary and exposes the fuzz entrypoint module. |

## Guarantees

`ChioAcpEdge::new` validates peer features and admitted manifests. `handle_jsonrpc` validates original JSON bytes with an 8 MiB limit. `invoke` dispatches through the kernel; permission preview has a separate evaluation path.

Permission preview and tool invocation have separate evaluation paths.
Request-ID entrypoints bind request-specific authorization before dispatch.

## Status

Implemented library supports `tool/invoke`, `tool/stream`, `tool/cancel`, and `tool/resume`. The host authenticates callers, supplies execution contexts, and registers bound tool servers. Deferred tasks live in memory.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-acp-proxy](../chio-acp-proxy/README.md)

## License

See the workspace [license](../../../LICENSE).
