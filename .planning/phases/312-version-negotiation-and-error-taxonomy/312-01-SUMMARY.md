---
phase: 312
plan: 01
created: 2026-04-13
status: complete
---

# Summary 312-01

Phase `312` turns hosted versioning from an implied contract into an explicit
negotiation rule.

- `spec/versions/arc-protocol-negotiation.v1.json` now records the exact
  exchange format for the hosted MCP edge, the out-of-band exact-match rule
  for native ARC, and the path-prefix versioning rule for trust-control.
- `crates/arc-mcp-edge/src/runtime.rs` now inspects
  `initialize.params.protocolVersion` and rejects incompatible values instead
  of silently ignoring them.
- Successful initialize responses now expose one explicit ARC negotiation block
  under `capabilities.experimental.arcProtocol`, including the supported set,
  selected version, compatibility rule, downgrade behavior, and error-registry
  reference.

The current shipped behavior is intentionally narrow: the hosted edge supports
one MCP protocol version (`2025-11-25`) and therefore has no downgrade path.
Mismatch is rejected explicitly rather than downgraded implicitly.
