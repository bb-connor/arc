---
phase: 25-cli-thinning-and-service-boundary-extraction
plan: 02
subsystem: control-plane
tags:
  - architecture
  - control-plane
  - v2.4
requires:
  - 01
provides:
  - Extracted trust-control service and shared runtime helpers
key-files:
  created:
    - crates/pact-control-plane/Cargo.toml
    - crates/pact-control-plane/src/lib.rs
  modified:
    - Cargo.toml
    - crates/pact-cli/Cargo.toml
    - crates/pact-cli/src/main.rs
    - crates/pact-cli/src/trust_control.rs
    - crates/pact-cli/src/certify.rs
    - crates/pact-cli/src/evidence_export.rs
    - crates/pact-cli/src/issuance.rs
    - crates/pact-cli/src/reputation.rs
requirements-completed:
  - ARCH-01
  - ARCH-02
completed: 2026-03-25
---

# Phase 25 Plan 02 Summary

The trust-control surface now lives behind a real crate boundary instead of
being compiled only as part of `pact-cli`.

## Accomplishments

- added `pact-control-plane` as a workspace member and moved trust-control
  ownership, shared helper functions, and related admin/runtime modules behind
  that crate boundary
- switched the CLI to reexport `pact_control_plane::CliError` and shared helper
  functions instead of carrying duplicate copies inside `main.rs`
- widened the actual public control-plane API types needed by provider admin,
  certification, evidence, and reputation flows so cross-crate callers compile
  cleanly

## Verification

- `cargo check -p pact-control-plane`
- `cargo test -p pact-cli --test provider_admin --test certify -- --nocapture`
