---
phase: 397-protocol-to-protocol-fabric-runtime
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 397 Context

## Problem

`CrossProtocolOrchestrator` was real, but authoritative edge execution still
collapsed to `DiscoveryProtocol::Native`. That left the fabric story short of
the v3.14 requirement: ARC needed at least one truthful non-native target path
with preserved attenuation, trace lineage, and receipt metadata.

## Scope

- add a target-protocol executor seam to `arc-cross-protocol`
- prove authoritative non-native execution on one bridge path
- keep bridge lineage, fidelity, and receipt metadata intact

## Non-Goals

- full multi-hop dynamic bridge routing
- new protocol families beyond the existing MCP/A2A/ACP surface
