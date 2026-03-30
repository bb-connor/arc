---
phase: 16-cross-org-shared-evidence-analytics
plan: 01
subsystem: shared-evidence
tags:
  - federation
  - analytics
  - trust-control
requires: []
provides:
  - Shared-evidence reference queries exist in kernel, trust-control, and CLI
key-files:
  created:
    - .planning/phases/16-cross-org-shared-evidence-analytics/16-01-SUMMARY.md
  modified:
    - crates/arc-kernel/src/operator_report.rs
    - crates/arc-kernel/src/lib.rs
    - crates/arc-kernel/src/receipt_store.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/main.rs
requirements-completed:
  - XORG-01
completed: 2026-03-24
---

# Phase 16 Plan 01 Summary

Shared remote evidence is now a first-class query surface instead of an
internal-only federated issuance substrate.

## Accomplishments

- Added shared-evidence query/report types in `arc-kernel`
- Added `GET /v1/federation/evidence-shares`
- Added `arc trust evidence-share list`
- Kept imported-share data isolated from native local receipt tables

## Verification

- `cargo test -p arc-cli --test receipt_query -- --nocapture`
