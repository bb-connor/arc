---
phase: 312
status: passed
completed: 2026-04-13
---

# Phase 312 Verification

## Outcome

Phase `312` passed. ARC now has an explicit version-negotiation artifact, a
numeric machine-readable error registry with retry guidance, and hosted-edge
runtime enforcement for incompatible initialize protocol versions.

## Automated Verification

- `cargo test -p arc-mcp-edge initialize_unsupported_protocol_version_rejected`
- `cargo test -p arc-core-types protocol_error_registry_`
- `git diff --check -- spec/WIRE_PROTOCOL.md spec/errors spec/versions crates/arc-mcp-edge/src/runtime.rs crates/arc-mcp-edge/src/runtime/runtime_tests.rs crates/arc-core-types/tests/protocol_error_registry.rs .planning/phases/312-version-negotiation-and-error-taxonomy`

## Evidence

- `spec/versions/arc-protocol-negotiation.v1.json` defines the hosted exchange
  fields, native compatibility rule, downgrade behavior, and rejection path.
- `spec/errors/arc-error-registry.v1.json` defines stable numeric ARC error
  codes with categories, transient flags, and retry semantics.
- The hosted edge now rejects unsupported initialize protocol versions with
  JSON-RPC `-32600` plus structured ARC error metadata in `error.data.arcError`.

## Requirement Closure

- `SPEC-05`: version exchange format, compatibility determination, downgrade
  behavior, and rejection behavior are now defined both normatively and in a
  machine-readable artifact.
- `SPEC-06`: numeric ARC error codes are now categorized across protocol,
  auth, capability, guard, budget, tool, and internal lanes.
- `SPEC-07`: every published registry entry now carries explicit retry
  guidance and transient/permanent classification.
