# chio-mcp-adapter

Wraps an MCP server as a Chio `ToolServerConnection`. The adapter translates
MCP discovery and results; the kernel owns capability checks, guards, and
receipt signing when the connection is registered and dispatched through it.

## Usage

Construct an adapter with a caller-provided transport. This example stays in
memory and exercises the same invocation mapping as a wrapped server.

```rust
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig};
use chio_mcp_adapter::edge::{AdapterError, McpTransport, McpToolInfo, McpToolResult};
use serde_json::{json, Value};

struct Echo;
impl McpTransport for Echo {
    fn list_tools(&self) -> Result<Vec<McpToolInfo>, AdapterError> {
        Ok(vec![])
    }
    fn call_tool(&self, _: &str, arguments: Value) -> Result<McpToolResult, AdapterError> {
        Ok(McpToolResult {
            content: vec![], structured_content: Some(arguments), is_error: Some(false),
        })
    }
}
let adapter = McpAdapter::new(McpAdapterConfig {
    server_id: "echo".into(), server_name: "Echo".into(),
    server_version: "1".into(), public_key: "00".repeat(32),
}, Box::new(Echo));
let result = adapter.invoke("echo", json!({"message": "hello"}))?;
assert_eq!(result["structuredContent"]["message"], "hello");
# Ok::<(), AdapterError>(())
```

Use `server::AdaptedMcpServer::new_with_manifest_registry` to retain admitted
publisher metadata after matching fresh discovery. Native subprocess creation
requires `transport::CageRequiredLaunch` and performs initialization immediately.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `fuzz` | Off | Exposes fuzz entrypoints and enables `arbitrary`. |

There is no declared default feature set.

## Guarantees

- `generate_manifest` requires object schemas and validates the generated manifest.
  Missing, malformed, or conflicting safety hints classify tools as side-effecting.
- `verify_discovered_manifest_surface` checks discovery-visible fields against
  admitted metadata. Signature admission belongs to `VerifiedManifestRegistry`.
- `McpAdapter::from_command_with_timeouts` rejects mismatched launch server IDs
  and requires fully enforced native evidence plus a persisted enforcement receipt.
- `McpAdapter::invoke` delegates to the transport; authorization requires kernel
  dispatch through `AdaptedMcpServer`. Custom transports own their I/O guarantees.

## Status

Implements stdio transport, discovery, resources, prompts, completions, nested
callbacks, result mapping, and kernel connection adapters. Unit and loopback
integration tests exercise these paths. Deployment custody and transport setup
remain the host's responsibility; this crate is unpublished in the workspace.

## Related

- [Architecture](ARCHITECTURE.md)
- [MCP compatibility](../../../spec/PROTOCOL.md#82-mcp-compatibility)
- [MCP edge](../chio-mcp-edge/README.md)
- [License](../../../LICENSE)
