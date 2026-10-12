# chio-acp-proxy

Intercepts ACP JSON-RPC messages between an editor and agent, applies file and terminal guards, and records tool-call audit entries with optional kernel attestation.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use chio_acp_proxy::{AcpProxyConfig, MessageInterceptor};

let config = AcpProxyConfig::new("unused-agent", "");
let interceptor = MessageInterceptor::new(config);
assert!(!interceptor.has_capability_checker());
assert!(!interceptor.has_receipt_signer());
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; OTel integration is disabled. |
| `otel` | No | Enables the OTel module and kernel telemetry feature. |

## Guarantees

`AcpMessage::decode` validates original bytes before interception. `FsGuard` rejects empty, relative, traversing, and out-of-prefix paths. `TerminalGuard` applies an explicit command allowlist. `MessageInterceptor::with_kernel` installs optional capability checking and receipt signing.

The relay forwards Forward and ForwardWithReceipt values to the destination;
a Block value is an error response for the sender.

## Status

Standalone `AcpProxy::start` uses local guards and unsigned audit entries. Capability enforcement and signed receipts require injected checker and signer components. Callers drive receive, intercept, and send operations.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-acp-edge](../chio-acp-edge/README.md)

## License

See the workspace [license](../../../LICENSE).
