# chio-mcp-edge

`chio-mcp-edge` hosts a Chio-governed kernel as an MCP (Model Context
Protocol) server. `ChioMcpEdge` implements the MCP JSON-RPC method surface
over stdio or an in-process channel and dispatches every call through
`chio_kernel::ChioKernel`, so capability checks, guard evaluation, and receipt
signing stay in the kernel rather than the edge.

The crate also owns the wire contracts shared with `chio-mcp-adapter`:
`McpTransport`, `McpToolInfo`, `McpToolResult`, `McpServerCapabilities`, and
`AdapterError`. `chio-mcp-adapter` implements `McpTransport` to adapt an
existing upstream MCP server into a governed Chio tool server. This crate does
the reverse: it hosts Chio's own tools as an MCP server.

## Responsibilities

- Implement the MCP JSON-RPC 2.0 method surface: `initialize`, `tools/list`,
  `tools/call`, `tasks/*`, `resources/*`, `prompts/*`, `completion/complete`,
  `logging/setLevel`, and the `notifications/initialized` /
  `notifications/roots/list_changed` / `notifications/cancelled` handshake.
- Project validated `chio_manifest::ToolManifest`s into MCP tool listings,
  translating side-effect and latency hints into MCP annotations.
- Run the MCP task lifecycle: bounded, TTL-limited deferred tasks with
  background pumping, cancellation, and status notifications.
- Mediate server-to-client nested flows (sampling, roots, elicitation) over
  both a blocking reader/writer transport and a channel-based transport, with
  a cancellation side channel independent of the main JSON-RPC dispatcher.
- Project kernel tool-call responses into MCP results, including collapsed or
  chunk-streamed output, and record `chio_receipt_write_total` metrics at the
  kernel boundary.
- Provide `McpTargetExecutor`, the default MCP-target executor for
  `chio-cross-protocol` cross-protocol tool-call bridging.

## Public API

- `ChioMcpEdge`, `McpEdgeConfig`, `McpExposedTool` - the hosting runtime, its
  configuration, and the tool shape it advertises over MCP.
- Entry points: `ChioMcpEdge::{new, handle_jsonrpc, serve_stdio,
  serve_message_channels, drain_runtime_notifications, restore_ready_session,
  attach_upstream_transport}`.
- Host-driven hooks: `notify_resource_updated`, `notify_resources_list_changed`,
  `notify_tools_list_changed`, `notify_prompts_list_changed`,
  `notify_elicitation_completed`, and `create_message` (sampling within an
  existing operation context, over a reader/writer transport).
- `McpTransport`, `McpToolInfo`, `McpToolResult`, `McpServerCapabilities`,
  `AdapterError` - shared MCP wire contracts, implemented by
  `chio-mcp-adapter`.
- `execute_bridge_mcp_tool_call`, `execute_bridge_mcp_tool_call_async`,
  `BridgeMcpToolCall`, `BridgeMcpToolCallRequest`, `McpTargetExecutor` -
  bridge-only tool-call execution that projects a kernel response into an MCP
  result without running the JSON-RPC loop.
- `metrics::{receipt_write_total, render_mcp_edge_metrics_prometheus,
  CHIO_RECEIPT_WRITE_TOTAL, RECEIPT_WRITE_OUTCOME_*}` - receipt-write counters
  and Prometheus exposition.

## Usage

```rust
use chio_mcp_edge::{ChioMcpEdge, McpEdgeConfig};
use serde_json::json;

// kernel, agent_id, capabilities, and manifests are built the usual way
// with chio-kernel, chio-core, and chio-manifest.
let mut edge = ChioMcpEdge::new(McpEdgeConfig::default(), kernel, agent_id, capabilities, manifests)?;

edge.handle_jsonrpc(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }));
edge.handle_jsonrpc(json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} }));
let response = edge.handle_jsonrpc(json!({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": { "name": "echo_json", "arguments": { "city": "Boston" } }
}));
```

Use `serve_stdio` or `serve_message_channels` instead of `handle_jsonrpc` to
run a full inbound loop (background tasks, deferred nested-flow messages,
queued notifications) over stdio or an in-process channel.

## Opt-in execution receipts

A `tools/call` request can set `_meta.chioIncludeReceipt: true` together with a
fresh `_meta.chioRequestId`. The resulting MCP tool result includes:

```json
{
  "_meta": {
    "chioReceipt": {
      "version": 1,
      "receipt": "the complete signed ChioReceipt object",
      "output_kind": "value",
      "output": "the exact kernel output value before MCP projection"
    }
  }
}
```

The strings above stand for JSON values, not serialized JSON strings. The actual
receipt object uses the existing Chio receipt schema. For complete value results,
`receipt.content_hash` is SHA-256 over the RFC 8785 canonical encoding of `output`.
A completed denial without output uses `output_kind: "none"` and `output: null`.
The signed `metadata.receipt_context.request_id` binds the caller's request ID.
Clients must check the operator-pinned signer, receipt integrity, mediation, tool
and server, exact arguments, request ID, and output hash. MCP's separately rendered
`content` and `structuredContent` are not the canonical output commitment.

The edge overwrites upstream `_meta.chioReceipt` with its own envelope and preserves
other valid metadata. The envelope is additive and absent unless requested; a
non-boolean request flag is a JSON-RPC invalid-params error. The export is available
on the direct JSON-RPC, stdio, and channel session paths. It does not change the
bridge-only executor API. Streaming output uses `output_kind: "stream"` without a
complete `output`; clients must support the stream commitment or reject it.
Cancellation and pre-evaluation protocol failures may return errors without an
exported receipt. Verification clients must fail closed when evidence is missing
and must not automatically retry an uncertain external effect.

See the [Python MCP verifier](../../../sdks/python/chio-py/README.md) and the
[LangChain example](../../../examples/langchain-kernel/README.md) for a complete
value-result client. Receipt export includes argument and output data; the operator
must account for this when selecting tools and configuring data guards.

## Feature flags

| Flag | Effect |
|------|--------|
| `otel` | Enables `otel`, MCP-flavored GenAI tool-call span helpers built on `chio-kernel/otel`. |
| `fuzz` | Exposes `fuzz`, the libFuzzer entry point for the stdio decode-then-`handle_jsonrpc` dispatch pipeline. Off by default; pulls in `arbitrary`. Enabled only by the standalone `fuzz` workspace. |

## Testing

`cargo test -p chio-mcp-edge`

## See also

- `chio-mcp-adapter` - adapts an existing upstream MCP server into a governed
  Chio tool server, implementing this crate's `McpTransport` contract.
- `chio-kernel` - the governed runtime this edge hosts and dispatches into.
- `chio-manifest` - tool manifest types and validation this crate projects
  into MCP tool listings.
- `chio-a2a-edge`, `chio-acp-edge` - route cross-protocol tool calls into MCP
  targets through `McpTargetExecutor`.
- `chio-openapi-mcp-bridge` - projects OpenAPI operations into this crate's
  `McpToolInfo`.
