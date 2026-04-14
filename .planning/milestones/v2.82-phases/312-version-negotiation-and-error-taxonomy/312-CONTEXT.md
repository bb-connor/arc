---
phase: 312-version-negotiation-and-error-taxonomy
milestone: v2.82
created: 2026-04-13
status: complete
---

# Phase 312 Context

## Goal

Define the shipped version-negotiation contract and publish a machine-readable
error taxonomy with numeric codes, categories, transience, and retry guidance.

## Current Reality

- Phase `311` defined the transport surfaces, but version compatibility is only
  partially enforced in code.
- The hosted MCP edge advertises `protocolVersion` during `initialize` and
  checks `MCP-Protocol-Version` on an established session, but
  `initialize.params.protocolVersion` is not negotiated explicitly today.
- Error communication is fragmented:
  - native ARC uses stable snake_case `ToolCallError` discriminators
  - hosted MCP uses JSON-RPC numeric codes with string messages
  - trust-control returns JSON bodies shaped as `{ "error": "..." }`
  - OAuth subflows use OAuth-style string error codes

## Boundaries

- Keep the negotiation contract honest about the shipped implementation:
  current hosted MCP support is a single-version exact-match negotiation, not a
  multi-version downgrade matrix.
- Publish one machine-readable registry that covers the categories named by the
  roadmap even if some surfaces still expose category-specific subprofiles.
- Avoid broad trust-control endpoint rewrites; prefer targeted artifacts and
  selective runtime hooks that add machine-readable data where the implementation
  already has structured error carriers.

## Key Risks

- If the spec claims downgrade behavior the server does not implement, phase
  `312` regresses protocol truthfulness.
- If the error taxonomy is only prose, downstream SDKs and future conformance
  work still have no stable machine-readable registry to consume.
- If the runtime only advertises a version but never rejects incompatible
  initialize requests, the negotiation section remains aspirational.

## Decision

Anchor the phase around three concrete deliverables:

1. a version-negotiation artifact that documents the exact hosted MCP exchange
   format and the current single-version compatibility rule
2. a numeric error registry JSON artifact with category and retry metadata
3. a small hosted-edge implementation update that rejects incompatible
   `initialize.params.protocolVersion` requests with structured machine-readable
   error data
