# chio-acp-edge

Edge crate that projects Chio tool manifests outward as ACP (Agent Client
Protocol) capabilities, so ACP-compatible editors and IDEs can discover and
invoke Chio tools over ACP-shaped permission and invocation surfaces.
Kernel-backed entry points route through `chio-cross-protocol`'s orchestrator
and emit signed Chio receipts. Every invocation uses kernel admission.

This is the opposite direction from `chio-acp-proxy`, which proxies a
third-party ACP agent and enforces Chio checks on its calls; `chio-acp-edge`
instead exposes Chio's own tools as an ACP server.

## Responsibilities

- Map `ToolManifest`/`ToolDefinition` into ACP capability advertisements,
  inferring an `AcpCategory` from the tool name and evaluating `BridgeFidelity`
  per tool.
- Withhold capabilities that cannot be honestly projected onto ACP: browser
  automation, generic side-effectful tools, `x-chio-publish=false`, and tool
  names that collide across manifests.
- Serve `session/request_permission` as a kernel-backed permission preview
  that never consumes the DPoP nonce a later `tool/invoke` will spend.
- Dispatch `tool/invoke` (blocking) and the deferred `tool/stream` /
  `tool/cancel` / `tool/resume` triad through the Chio kernel, attaching
  signed receipt metadata to every outcome, including denials.
- Bound and TTL-prune retained deferred tasks so a resumed or cancelled task
  replays its stored terminal result instead of re-executing the kernel
  request.
- Record receipt-write outcomes via `chio-edge-metrics` and render them as
  Prometheus text.

## Public API

- `ChioAcpEdge::new(AcpEdgeConfig, &VerifiedManifestRegistry) -> Result<Self, AcpEdgeError>`
  and `capabilities` / `capability` / `capability_ids` / `bridge_fidelity` for
  discovery.
- `evaluate_permission` / `evaluate_permission_with_kernel` for permission
  preview.
- `invoke` / `invoke_with_mcp_target` for kernel-backed blocking invocation.
- `handle_jsonrpc(bytes, kernel, execution) -> Result<AcpJsonRpcResponse, AcpEdgeError>` - the
  JSON-RPC entry point for `session/list_capabilities`,
  `session/request_permission`, `tool/invoke`, `tool/stream`, `tool/cancel`,
  `tool/resume`.
- Wire types: `AcpEdgeConfig`, `AcpEdgeError`, `AcpCapability`, `AcpCategory`,
  `PermissionRequest`, `PermissionDecision`, `AcpInvocationResult`,
  `AcpInvocationTask`, `AcpTaskStatus`, `AcpJsonRpcResponse`,
  `AcpKernelExecutionContext`.
- `metrics::{render_acp_edge_metrics_prometheus, receipt_write_total,
  receipt_write_outcome_for_verdict, CHIO_RECEIPT_WRITE_TOTAL,
  RECEIPT_WRITE_OUTCOME_*}`.

## Feature flags

| Flag | Effect |
|------|--------|
| `fuzz` | Exposes `fuzz::fuzz_acp_envelope_decode`, the libFuzzer entry point over the original-byte `handle_jsonrpc` boundary. Off by default; pulls in `arbitrary`. Enabled only by the standalone `chio-fuzz` workspace. |

## Testing

`cargo test -p chio-acp-edge`

## See also

- `chio-acp-proxy` - the other ACP integration: a stdio subprocess proxy in
  front of a third-party ACP agent, not a projection of Chio tools as ACP
  capabilities.
- `chio-cross-protocol` - supplies `CapabilityBridge`, `CrossProtocolOrchestrator`,
  `BridgeFidelity`, and the target registry this crate implements against;
  shared with `chio-a2a-edge`.
- `chio-kernel` - the execution and DPoP-preview authority behind every
  kernel-backed entry point.
- `chio-mcp-edge` - supplies `McpTargetExecutor`, one of the two non-native
  target executors for multi-hop ACP routing.
