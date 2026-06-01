# chio-mcp-edge architecture note

## Boundaries

- `lib.rs` owns the public crate surface, shared MCP data contracts, metrics exports, and optional fuzz/otel feature gates.
- `runtime.rs` owns the `ChioMcpEdge` state machine, session lifecycle, task orchestration, kernel dispatch, runtime event forwarding, and inbound loop control.
- `runtime/protocol.rs` owns JSON-RPC envelope parsing, response and notification shaping, task/result metadata, pagination, cancellation matching, capability selection, and wire helpers.
- `runtime/nested_flow.rs` owns server-to-client nested-flow client implementations for sampling, roots, elicitation, progress, and cancellation mediation.
- `metrics.rs` owns MCP edge receipt-write counters and Prometheus rendering through the workspace metrics registry.

## Pain Points

- `runtime/protocol.rs` still mixes JSON-RPC wire shaping with Chio-manifest to MCP-tool discovery projection.
- `ChioMcpEdge::new` builds exposed tool bindings inline, so duplicate-name checks and projection rules sit in the runtime constructor rather than a focused discovery boundary.
- MCP `tools/list` schemas are protocol-facing JSON Schema objects, but the edge currently forwards arbitrary manifest `input_schema` and `output_schema` values without checking shape.
- This makes malformed manifest metadata visible to MCP clients even though ready-state methods and session traffic otherwise fail closed.

## Constraints

- Preserve public API compatibility for `ChioMcpEdge`, `McpEdgeConfig`, `McpExposedTool`, bridge execution helpers, shared transport contracts, metrics exports, and feature-gated fuzz/otel modules.
- Preserve exact-match MCP protocol negotiation, ready-state gating, JSON-RPC error codes, task ownership metadata, cancellation behavior, URL elicitation handling, progress notifications, and receipt-write metrics semantics.
- Preserve canonical tool-call authorization through the kernel and do not bypass capability, guard, receipt, session, budget, revocation, approval, or runtime-assurance paths.
- Preserve MCP wire compatibility for `initialize`, `tools/list`, `tools/call`, resources, prompts, completion, logging, tasks, and notification replay.
- Keep this slice scoped to `chio-mcp-edge` unless dependent tests prove a transitive change is required.

## Dependents

- `chio-mcp-adapter`, `chio-mcp-remote`, `chio-hosted-mcp`, and `examples/hello-mcp` construct or re-export `ChioMcpEdge`.
- `spec/WIRE_PROTOCOL.md` defines ready-state and hosted MCP version-negotiation behavior.
- `spec/schemas/chio-wire/v1/jsonrpc` and `spec/schemas/chio-http/v1/stream-frame.schema.json` mirror the JSON-RPC and stream notification shapes emitted by this crate.
- `docs/architecture/CHIO_RUNTIME_BOUNDARIES.md` records the current `runtime.rs` versus `runtime/protocol.rs` ownership split.
- `docs/protocols/EDGE-CRATE-SYMMETRY.md` treats `manifest_tool_to_mcp_tool` as the reference outward-edge discovery projection.

## Planned Improvement

Move Chio-manifest to MCP-tool discovery projection into an internal discovery module, then validate that exposed `inputSchema` and `outputSchema` values are JSON objects before the edge starts. This is architectural because it creates one auditable discovery trust boundary, keeps the runtime constructor focused on state assembly, and prevents malformed signed manifest metadata from becoming MCP client-facing tool schema.
