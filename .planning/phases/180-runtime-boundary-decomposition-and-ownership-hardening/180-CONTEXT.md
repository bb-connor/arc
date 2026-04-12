# Phase 180: Runtime Boundary Decomposition and Ownership Hardening - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Split the oversized runtime entrypoints into named ownership seams after
`v2.42` stabilized the release truth, planning state, and assurance surfaces.

</domain>

<decisions>
## Implementation Decisions

### Extract Along Real Crate Ownership
- keep `remote_mcp.rs` owned through `arc-hosted-mcp`
- keep `trust_control.rs` owned through `arc-control-plane`
- avoid moving runtime shells into `arc-cli/src/main.rs`

### Separate Runtime Flow From Support Glue
- keep `ArcMcpEdge` state and loops in `runtime.rs`, move JSON-RPC and task
  shaping helpers to `runtime/protocol.rs`
- keep `ArcKernel` flow in `lib.rs`, move receipt support and request matching
  helpers to focused support files

### Guard The Shape
- add a source-shape regression test for re-export boundaries, extracted files,
  and file-size ceilings
- document the ownership map so later work lands in the right module first

</decisions>

<code_context>
## Existing Runtime Seams

- `crates/arc-cli/src/remote_mcp.rs` mixed session lifecycle, auth, admin
  endpoints, and storage access in one shell
- `crates/arc-cli/src/trust_control.rs` mixed service routing and health
  composition inside the same giant file
- `crates/arc-mcp-edge/src/runtime.rs` mixed the `ArcMcpEdge` runtime loop with
  JSON-RPC/result/task helper glue
- `crates/arc-kernel/src/lib.rs` mixed kernel flow with receipt-building and
  request-matching support logic

</code_context>

<deferred>
## Deferred Ideas

- deeper trust-control decomposition beyond health remains possible if later
  phases need to split client/store/report families further

</deferred>
