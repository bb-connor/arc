---
phase: 397-protocol-to-protocol-fabric-runtime
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 397 Summary

## Outcome

ARC now has a real protocol-to-protocol execution seam instead of an
edge-to-native-only orchestrator.

- Added `TargetProtocolExecutor`, `CrossProtocolTargetRequest`, and
  `CrossProtocolTargetExecution` to `arc-cross-protocol`.
- `CrossProtocolOrchestrator` now dispatches registered non-native target
  protocols and records projected protocol results/notifications alongside ARC
  receipt lineage.
- `arc-mcp-edge` now exports `McpTargetExecutor` and
  `execute_bridge_mcp_tool_call(...)` as the first authoritative non-native
  target execution path.
- `arc-acp-edge` now proves an authoritative ACP -> MCP bridge path through
  `invoke_with_mcp_target(...)`, preserving ARC receipt metadata while
  returning MCP-shaped projected results.

## Requirements Closed

- `FABRIC-01`
- `FABRIC-02`
- `FABRIC-03`
