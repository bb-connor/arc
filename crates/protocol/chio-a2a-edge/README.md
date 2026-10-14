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
assert!(!edge.agent_card().capabilities.streaming);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; telemetry integration is disabled. |
| `otel` | No | Enables the OTel module and kernel/MCP-edge telemetry features. |

## Guarantees

`ChioA2aEdge::new` requires a `VerifiedManifestRegistry` and validates Agent Card configuration. `handle_jsonrpc` validates original JSON bytes with a 1 MiB limit before dispatch. Kernel execution supplies capability enforcement and receipts.

The edge serves A2A v1.0.0 `SendMessage`, `GetTask` and `CancelTask`; other methods return `-32601`. `message.messageId` is the kernel request ID. The host-authenticated execution context supplies authority; message metadata never does. Task lookups return the same `-32001` for absent and inaccessible tasks.

## Status

`SendMessage` blocks until the kernel returns a result, with omitted or `false` `configuration.returnImmediately`; `true` returns `-32004` before task creation. Approval-blocked work returns `TASK_STATE_INPUT_REQUIRED`. The owner resumes it with `SendMessage`, the original `messageId` and the returned `taskId`; the tool, arguments, capability and intent stay fixed and only the signed approval artifacts change. `GetTask` observes a task without executing it, and `CancelTask` cancels work awaiting approval.

The Agent Card advertises `text/plain` and `application/json` and does not advertise streaming. Multi-turn contexts, history, file parts and message extensions are refused. The embedding host supplies authentication, HTTP routing, TLS and protocol-version header enforcement.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#11-a2a-adapter-contract)
- [chio-a2a-adapter](../chio-a2a-adapter/README.md)

## License

See the workspace [license](../../../LICENSE).
