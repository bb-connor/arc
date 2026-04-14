---
phase: 311
status: passed
completed: 2026-04-13
---

# Phase 311 Verification

## Outcome

Phase `311` passed. ARC now has a normative wire-spec document for the shipped
transport surfaces, versioned native message schemas, and a live Rust
serialization test that proves those schemas match the implementation.

## Automated Verification

- `cargo test -p arc-core-types wire_protocol_`
- `git diff --check -- spec/PROTOCOL.md spec/WIRE_PROTOCOL.md spec/schemas/arc-wire/v1 crates/arc-core-types/Cargo.toml crates/arc-core-types/tests/wire_protocol_schema.rs .planning/phases/311-wire-protocol-specification`

## Evidence

- `spec/WIRE_PROTOCOL.md` defines:
  - native framing and recovery behavior
  - the full native message catalog
  - hosted MCP initialization and session headers
  - trust-control issuance, delegation, receipt query, and revocation paths
- `spec/schemas/arc-wire/v1/` contains the checked-in schema set for all
  shipped native message variants and nested result/error variants.
- The Rust validation test passed after compiling the new `jsonschema`
  dependency and validating live serialized values against those files.

## Requirement Closure

- `SPEC-01`: the native framed wire is now specified normatively, including
  byte order, maximum size, and recovery behavior.
- `SPEC-02`: versioned JSON Schema files exist for every shipped native
  message variant.
- `SPEC-03`: the spec includes sequence diagrams for initialization, issuance,
  tool invocation with receipt, delegation, revocation, and error handling.
- `SPEC-04`: the spec separates native ARC, hosted MCP, and trust-control
  responsibilities clearly enough for independent implementation.
