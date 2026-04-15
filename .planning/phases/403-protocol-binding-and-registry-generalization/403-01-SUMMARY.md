# Phase 403 Summary

Phase 403 closed the remaining bounded-fabric routing gap from the post-v3.14
review.

## What Shipped

- shared `x-arc-target-protocol` metadata now drives authoritative target
  selection through `arc-cross-protocol`
- A2A and ACP authoritative bindings now carry resolved target protocol state
  instead of hardcoding `DiscoveryProtocol::Native`
- the shared orchestrator path now selects registered target executors for
  supported non-native bindings such as MCP, rather than relying on bespoke
  ACP-only helpers
- the bridge design docs now distinguish the shipped bounded protocol-aware
  fabric from the still-future universal multi-hop fabric cleanly

## Requirements Closed

- `FABRIC2-01`
- `FABRIC2-02`
- `FABRIC2-03`
