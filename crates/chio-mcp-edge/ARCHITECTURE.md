# chio-mcp-edge architecture note

## Boundaries

- `lib.rs` owns the public crate surface, shared MCP data contracts, metrics exports, and optional fuzz/otel feature gates.
- `runtime.rs` owns the `ChioMcpEdge` state machine, session lifecycle, task orchestration, kernel dispatch, runtime event forwarding, and inbound loop control.
- `runtime/protocol.rs` owns JSON-RPC envelope parsing, response and notification shaping, task/result metadata, pagination, cancellation matching, capability selection, and wire helpers.
- `runtime/nested_flow.rs` owns server-to-client nested-flow client implementations for sampling, roots, elicitation, progress, and cancellation mediation.
- `metrics.rs` owns MCP edge receipt-write counters and Prometheus rendering through the workspace metrics registry.

## Pain Points

- `runtime/discovery.rs` owns Chio-manifest to MCP-tool projection, but it only validates projection-local schema object shape and duplicate exposed tool names.
- `ChioMcpEdge::new` can still accept manifests that fail the canonical `chio_manifest::validate_manifest` envelope checks, including unsupported schema versions, invalid embedded public keys, empty tool lists, invalid tool names, and duplicate server-tool allowlist entries.
- This leaves discovery with two trust boundaries: manifest envelope validation in signer/loader paths, and partial projection validation at the MCP edge.
- MCP clients should never see tools derived from a manifest envelope the workspace manifest validator would reject.

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

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before discovery projection or exposed-name indexing, while keeping cross-manifest duplicate exposed-name checks in `runtime/discovery.rs`. This is architectural because it makes manifest validation the single canonical envelope gate and leaves the MCP discovery module responsible only for outward projection and cross-manifest exposure rules.
