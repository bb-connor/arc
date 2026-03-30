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
    - crates/arc-control-plane/Cargo.toml
    - crates/arc-control-plane/src/lib.rs
  modified:
    - Cargo.toml
    - crates/arc-cli/Cargo.toml
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/certify.rs
    - crates/arc-cli/src/evidence_export.rs
    - crates/arc-cli/src/issuance.rs
    - crates/arc-cli/src/reputation.rs
requirements-completed:
  - ARCH-01
  - ARCH-02
completed: 2026-03-25
---

# Phase 25 Plan 02 Summary

The trust-control surface now lives behind a real crate boundary instead of
being compiled only as part of `arc-cli`.

## Accomplishments

- added `arc-control-plane` as a workspace member and moved trust-control
  ownership, shared helper functions, and related admin/runtime modules behind
  that crate boundary
- switched the CLI to reexport `arc_control_plane::CliError` and shared helper
  functions instead of carrying duplicate copies inside `main.rs`
- widened the actual public control-plane API types needed by provider admin,
  certification, evidence, and reputation flows so cross-crate callers compile
  cleanly

## Verification

- `cargo check -p arc-control-plane`
- `cargo test -p arc-cli --test provider_admin --test certify -- --nocapture`
