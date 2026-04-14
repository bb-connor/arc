---
phase: 312-version-negotiation-and-error-taxonomy
created: 2026-04-13
status: complete
---

# Phase 312 Validation

## Required Evidence

- A machine-readable version-negotiation artifact exists and defines:
  - exchange format
  - compatibility determination
  - downgrade behavior
  - connection rejection behavior
- A machine-readable numeric error registry exists and each entry records:
  - category
  - transient/permanent status
  - retry guidance
- The hosted MCP runtime rejects unsupported `initialize.params.protocolVersion`
  requests with structured machine-readable error data.
- Tests cover:
  - hosted initialize version mismatch rejection
  - registry uniqueness/shape guarantees

## Verification Commands

- `cargo test -p arc-mcp-edge initialize_unsupported_protocol_version_rejected`
- `cargo test -p arc-core-types protocol_error_registry_`
- `git diff --check -- spec/WIRE_PROTOCOL.md spec/errors spec/versions crates/arc-mcp-edge/src/runtime.rs crates/arc-mcp-edge/src/runtime/runtime_tests.rs crates/arc-core-types/tests/protocol_error_registry.rs .planning/phases/312-version-negotiation-and-error-taxonomy`

## Regression Focus

- existing initialize success path still returns the current protocol version
- version mismatch rejection includes stable numeric ARC error metadata
- registry codes remain unique and category-complete
