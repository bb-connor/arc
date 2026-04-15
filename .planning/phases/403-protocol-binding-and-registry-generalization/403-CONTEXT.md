---
phase: 403
milestone: v3.15
title: Protocol-Aware Bridge Binding and Registry Generalization
status: complete locally 2026-04-14
created: 2026-04-14
---

# Context

`v3.14` proved that ARC can execute a real non-native protocol hop, but the
authoritative edge code still chooses `DiscoveryProtocol::Native` by default
unless a bespoke helper overrides it. The latest review called that out as the
remaining structural fabric gap:

- `arc-a2a-edge` still hardcodes `DiscoveryProtocol::Native` on its default
  authoritative send path.
- `arc-acp-edge` has a specific ACP -> MCP helper, but its default invoke path
  still hardcodes `Native`.
- `CROSS-PROTOCOL-BRIDGING.md` acknowledges the shipped substrate but still
  needs to explain the new intermediate state cleanly enough: shipped
  protocol-aware substrate vs future multi-hop universal fabric.

The phase goal is to make authoritative edge bindings select target protocol
from shared bridge metadata instead of edge-local defaults, and to route
non-native execution through the existing executor-registry seam rather than
one-off helpers.

# Requirements

- `FABRIC2-01`
- `FABRIC2-02`
- `FABRIC2-03`

# Notes

- Prefer the existing `x-arc-*` metadata pattern over a breaking manifest
  format change.
- The shipped result only needs to generalize routing truthfully for the
  currently supported executor set; it does not need to claim a complete
  universal multi-hop registry.
