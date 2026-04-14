---
phase: 311-wire-protocol-specification
milestone: v2.82
created: 2026-04-13
status: complete
---

# Phase 311 Context

## Goal

Publish a normative ARC wire-protocol specification that is complete enough
for an engineer outside this codebase to implement the shipped transport and
understand how it composes with the hosted MCP edge and trust-control
capability lifecycle.

## Current Reality

- `spec/PROTOCOL.md` is a broad shipped-repository profile, not a focused wire
  specification. It names the native wire and hosted HTTP edge, but it does
  not define framing, recovery behavior, or lifecycle flows tightly enough for
  independent implementation.
- The native ARC transport is already stable in code:
  `crates/arc-core-types/src/message.rs` defines the message catalog and
  `crates/arc-kernel/src/transport.rs` defines framing as
  `[4-byte big-endian length][canonical JSON bytes]` with a `16 MiB` limit.
- Session initialization, receipt lookup, issuance, federated delegation, and
  revocation live on adjacent surfaces rather than inside the native framed
  transport:
  - hosted MCP edge: `crates/arc-cli/src/remote_mcp/http_service.rs`
  - trust-control: `crates/arc-cli/src/trust_control/http_handlers_a.rs`
    and `service_types.rs`

## Boundaries

- Be explicit about the shipped surface split instead of pretending the native
  length-prefixed transport already covers hosted initialization or
  trust-control issuance.
- Keep the normative message schemas scoped to the typed native ARC message
  families that the Rust implementation serializes directly today.
- Preserve unrelated dirty planning and runtime work already in the worktree.

## Key Risks

- If the new spec blurs the native framed lane and the hosted MCP lane, phase
  `311` will produce documentation that is easier to read but technically
  false.
- If the checked-in schemas are not exercised against actual Rust
  serialization, they become aspirational artifacts rather than conformance
  material.
- If the diagrams talk about issuance, delegation, or revocation without
  naming the real HTTP endpoints and state transitions, an external engineer
  still cannot reconstruct the shipped protocol flow.

## Decision

Split the deliverable into one focused normative spec plus versioned native
message schemas. The spec will define three cooperating surfaces:

1. the native ARC framed transport for direct agent-to-kernel messages
2. the hosted MCP-compatible HTTP session transport used by `arc mcp serve-http`
3. the trust-control HTTP APIs that issue capabilities, return receipts, and
   record revocations

The validation harness will serialize live `AgentMessage`, `KernelMessage`,
`ToolCallResult`, and `ToolCallError` values from Rust and validate them
against the checked-in schemas.
