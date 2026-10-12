# chio-openapi-mcp-bridge

Generates Chio tool manifests and HTTP route bindings from OpenAPI, then
projects registry-bound tools into MCP discovery. Borrowed and owned
`ToolServerConnection` adapters let a host register the bridge with a kernel.

## Usage

Parse and inspect a bridge without making an HTTP request.

```rust
use chio_openapi_mcp_bridge::{BridgeConfig, OpenApiMcpBridge};

let spec = r#"{
  "openapi":"3.0.3", "info":{"title":"Echo","version":"1"},
  "paths":{"/echo":{"get":{"operationId":"echo",
    "responses":{"200":{"description":"OK"}}}}}
}"#;
let bridge = OpenApiMcpBridge::from_spec(spec, BridgeConfig {
    server_id: "echo-api".into(), server_name: "Echo API".into(),
    server_version: "1".into(),
    public_key: chio_core::crypto::Keypair::from_seed(&[7; 32]).public_key().to_hex(),
    base_url: "https://api.example.com".into(), egress_contract: None,
})?;
assert!(!bridge.tool_names().is_empty());
assert!(bridge.mcp_tools_list().is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `registry_bound_mcp_tools` with the admitted generated manifest. Live
invocation needs a caller-supplied `HttpDispatcher` and `HttpEgressContract`.
The dispatcher must return raw observed response bytes and avoid redirects.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | On | Empty; enables no optional functionality. |
| `fuzz` | Off | Exposes fuzz entrypoints and enables `arbitrary`. |

## Guarantees

- `from_parsed_spec` rejects an empty tool surface and validates the manifest.
- `mcp_tools_list` refuses plain export. `registry_bound_mcp_tools` requires
  canonical manifest equality and exact effective-egress security bindings.
- `invoke_tool` rejects missing dispatchers/contracts, checks URL and DNS before
  dispatch, rejects returned 3xx statuses, and checks observed response bytes.
  Response limits are checked after the dispatcher returns the body.
- Kernel registration and evaluation supply capability checks and signed receipts.
  Direct `invoke_tool` calls perform bridge checks and HTTP dispatch only.

## Status

Implements manifest generation, route expansion, MCP projection, and kernel
connection wrappers. Tests cover registry binding, egress refusal, argument
routing, and kernel admission before dispatch. The caller owns the actual HTTP
transport and its raw byte accounting; this crate supplies no HTTP client.

## Related

- [Architecture](ARCHITECTURE.md)
- [OpenAPI manifests](../../../spec/PROTOCOL.md#71-openapi-derived-manifests)
- [MCP edge](../chio-mcp-edge/README.md)
- [License](../../../LICENSE)
