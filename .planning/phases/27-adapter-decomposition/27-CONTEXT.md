---
phase: 27
slug: adapter-decomposition
status: in_progress
created: 2026-03-25
---

# Phase 27 Context

## Objective

Split the adapter layer at the real transport/runtime seams so MCP edge
runtime behavior stops living inside `arc-mcp-adapter` and the A2A adapter no
longer concentrates most of its behavior in one giant source file.

## Current Reality

- `crates/arc-mcp-adapter/src/edge.rs` is 7,462 LOC and mixes edge-session
  runtime, JSON-RPC handling, pagination, nested flow orchestration, task
  tracking, and test coverage in one file
- the MCP edge runtime only depends on `arc-mcp-adapter` for shared MCP
  transport types: `AdapterError`, `McpTransport`, `McpToolInfo`,
  `McpToolResult`, and `McpServerCapabilities`
- `crates/arc-a2a-adapter/src/lib.rs` is 8,064 LOC and currently holds config,
  auth, transport, discovery, task-registry, mapping, invocation, and tests in
  one file
- current consumers mostly import MCP edge types through top-level
  `arc-mcp-adapter` reexports, so a compatibility facade can keep API churn
  low while moving ownership

## Constraints

- Phase 27 should avoid a new dependency cycle between `arc-mcp-adapter` and
  the new MCP edge crate
- runtime behavior must stay stable enough for existing CLI and hosted-MCP
  integration tests to remain the regression safety net
- file movement is valuable, but public API stability matters more than perfect
  final internal naming on the first extraction

## Strategy

- create a new `arc-mcp-edge` crate that owns the shared MCP transport types
  plus the edge runtime itself
- make `arc-mcp-adapter` depend on `arc-mcp-edge` and reexport the edge
  types so existing callers do not need to change
- split `arc-a2a-adapter/src/lib.rs` into concern-based source files while
  preserving the current root-level behavior surface
- verify with targeted MCP and A2A regression tests before advancing to Phase
  28
