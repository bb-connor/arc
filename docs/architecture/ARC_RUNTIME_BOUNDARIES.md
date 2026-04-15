# ARC Runtime Boundaries

This document records the ownership seams introduced in phase `180` so later
runtime work has a stable place to land and the largest entrypoints do not
quietly collapse back into monolithic shells.

## Ownership Map

| Surface | Runtime shell responsibility | Extracted boundary |
| --- | --- | --- |
| `crates/arc-cli/src/remote_mcp.rs` | hosted MCP session lifecycle, auth, edge routing, and transport orchestration | `crates/arc-cli/src/remote_mcp/admin.rs` owns remote admin routes, admin-only storage access, and session trust control handlers |
| `crates/arc-cli/src/trust_control.rs` | trust-service routing, issuance, registry operations, remote client entrypoints, and cluster coordination | `crates/arc-cli/src/trust_control/health.rs` owns health-report composition and cluster health projection; `crates/arc-cli/src/federation_policy.rs` owns the bounded federation-policy model; `crates/arc-cli/src/scim_lifecycle.rs` owns the bounded SCIM lifecycle model |
| `crates/arc-mcp-edge/src/runtime.rs` | `ArcMcpEdge` state machine, task orchestration, runtime event forwarding, and inbound loop control | `crates/arc-mcp-edge/src/runtime/protocol.rs` owns JSON-RPC shaping, task/result metadata, transport glue, pagination, and capability selection helpers |
| `crates/arc-kernel/src/lib.rs` | kernel policy flow, dispatch, receipt persistence, checkpoint triggering, and public crate surface | `crates/arc-kernel/src/receipt_support.rs` owns receipt hashing and metadata helpers; `crates/arc-kernel/src/request_matching.rs` owns session request tracking plus capability and constraint matching |

## Layering Rules

- `arc-cli` stays a shell. `crates/arc-cli/src/main.rs` re-exports runtime
  surfaces from `arc-hosted-mcp` and `arc-control-plane` instead of inlining
  additional giant modules.
- `arc-hosted-mcp` remains the owner of the remote MCP HTTP edge via
  `#[path = "../../arc-cli/src/remote_mcp.rs"]`.
- `arc-control-plane` remains the owner of the trust-control service via
  `#[path = "../../arc-cli/src/trust_control.rs"]`.
- `arc-mcp-edge` keeps protocol glue separate from the runtime loop so JSON-RPC
  behavior can change without widening the edge state machine.
- `arc-kernel` keeps receipt construction and request matching separate from
  the main kernel flow so policy and dispatch changes do not hide low-level
  security drift.

## Regression Guard

`crates/arc-control-plane/tests/runtime_boundaries.rs` is the source-shape
guard for this boundary. It verifies:

- the extracted ownership files exist
- the main CLI entrypoint still re-exports hosted/control-plane crates
- the runtime shells stay below the line-count ceilings captured in phase `180`
- this document remains present as the human-readable ownership map
