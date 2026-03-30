---
phase: 21-release-hygiene-and-codebase-structure
plan: 03
subsystem: cli-structure
tags:
  - refactor
  - cli
  - regression
requires:
  - 21-01
  - 21-02
provides:
  - A dedicated admin module and a cleaner targeted lint/regression gate
key-files:
  created:
    - crates/arc-cli/src/admin.rs
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/evidence_export.rs
    - crates/arc-cli/src/issuance.rs
    - crates/arc-cli/src/remote_mcp.rs
    - crates/arc-cli/src/trust_control.rs
requirements-completed:
  - PROD-08
completed: 2026-03-25
---

# Phase 21 Plan 03 Summary

`arc-cli` now has a clearer control-plane admin boundary and a cleaner targeted
validation lane.

## Accomplishments

- extracted 510 lines of trust/provider/certification/federation admin handling
  into `crates/arc-cli/src/admin.rs`
- reduced `crates/arc-cli/src/main.rs` from 4,690 lines to 4,190 lines without
  changing the command surface
- fixed the narrow clippy issues exposed by the targeted Phase 21 validation
  pass

## Verification

- `cargo clippy -p arc-cli -- -D warnings`
- `cargo test -p arc-cli --test provider_admin -- --nocapture`
- `cargo test -p arc-cli --test certify -- --nocapture`
- `cargo test -p arc-cli --test federated_issue -- --nocapture`
- `cargo test -p arc-cli --test evidence_export -- --nocapture`
- `cargo test -p arc-cli --test reputation_issuance -- --nocapture`
