---
phase: 311-wire-protocol-specification
created: 2026-04-13
status: complete
---

# Phase 311 Validation

## Required Evidence

- A focused normative spec exists for the shipped ARC wire surface and defines:
  - native framing and recovery behavior
  - the native message catalog and field expectations
  - the hosted MCP initialization/session contract
  - trust-control issuance, receipt query, delegation, and revocation flows
- The spec contains sequence diagrams for:
  - initialization
  - capability issuance
  - tool invocation with receipt
  - delegation
  - revocation
  - error handling
- Versioned JSON Schema files exist for every native ARC message variant and
  the nested `ToolCallResult` and `ToolCallError` variants.
- A test serializes live Rust message values and validates them against those
  schemas.

## Verification Commands

- `cargo test -p arc-core-types wire_protocol_`
- `git diff --check -- spec/PROTOCOL.md spec/WIRE_PROTOCOL.md spec/schemas/arc-wire/v1 crates/arc-core-types/Cargo.toml crates/arc-core-types/tests/wire_protocol_schema.rs .planning/phases/311-wire-protocol-specification`

## Regression Focus

- native framing details match the implementation in `arc-kernel`
- hosted initialization semantics match the remote MCP HTTP service
- delegation and revocation diagrams name the actual trust-control endpoints
- schema files accept the real serialized message shapes emitted by Rust
