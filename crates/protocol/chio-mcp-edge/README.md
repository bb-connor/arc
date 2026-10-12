# chio-mcp-edge

Exposes Chio kernel sessions through MCP JSON-RPC and supplies shared MCP
transport contracts. `ChioMcpEdge` owns initialization, discovery, request
routing, nested callbacks, tasks, and result projection for one edge session.

## Usage

Decode peer bytes before passing a message to `ChioMcpEdge::handle_jsonrpc`.
The decoder accepts ordinary producer decimals and rejects duplicate members.

```rust
use chio_mcp_edge::decode_mcp_request;

let request = decode_mcp_request(
    br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#,
    4096,
)?;
assert_eq!(request["method"], "ping");
assert!(decode_mcp_request(br#"{"id":1,"id":2}"#, 4096).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Build `ChioMcpEdge` with a kernel, subject, capabilities, and manifests.
`new_with_manifest_registry` retains verified publisher metadata. Hosts provide
stdio or HTTP transport ownership and register the kernel's tool servers.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `otel` | Off | Exposes the `otel` module and enables `chio-kernel/otel`. |
| `fuzz` | Off | Exposes fuzz entrypoints and enables `arbitrary`. |

There is no declared default feature set.

## Guarantees

- `decode_mcp_request` bounds input and validates the original invocation-proof
  slice with signed JSON decoding before projecting the unsigned envelope.
  Cryptographic proof verification occurs during kernel evaluation.
- `ChioMcpEdge::new` validates manifests, rejects duplicate exposed tool names,
  and compiles input validators. Registry constructors use admitted manifests.
- `execute_bridge_mcp_tool_call_async` checks peer capabilities before invoking
  kernel evaluation and projecting the resulting receipt and decision.
- `ingress::IngressBudget` accounts retained wire bytes, JSON nodes, and text;
  transport loops reserve capacity before retaining decoded messages.

## Status

Implements MCP protocol version `2025-11-25`, initialization state, tools,
resources, prompts, completions, logging, tasks, and negotiated nested flows.
Unit and loopback tests cover dispatch and refusal boundaries. Callers own
transport authentication and durable kernel-store configuration.

## Related

- [Architecture](ARCHITECTURE.md)
- [MCP compatibility](../../../spec/PROTOCOL.md#82-mcp-compatibility)
- [MCP adapter](../chio-mcp-adapter/README.md)
- [License](../../../LICENSE)
