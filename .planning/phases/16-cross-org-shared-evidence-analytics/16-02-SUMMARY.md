---
phase: 16-cross-org-shared-evidence-analytics
plan: 02
subsystem: operator-reporting
tags:
  - federation
  - provenance
  - reputation
requires:
  - 16-01
provides:
  - Operator report and reputation comparison carry shared-evidence provenance
key-files:
  created:
    - .planning/phases/16-cross-org-shared-evidence-analytics/16-02-SUMMARY.md
  modified:
    - crates/pact-kernel/src/receipt_store.rs
    - crates/pact-cli/src/trust_control.rs
    - crates/pact-cli/src/reputation.rs
requirements-completed:
  - FED-03
  - XORG-02
completed: 2026-03-24
---

# Phase 16 Plan 02 Summary

Cross-org downstream activity is now reported with explicit upstream remote
share provenance.

## Accomplishments

- Embedded `sharedEvidence` in operator reports
- Embedded the same shared-evidence payload in portable reputation comparison
- Surfaced `localAnchorCapabilityId`, per-reference local receipt counts, and
  remote share metadata for downstream provenance

## Verification

- `cargo test -p pact-cli --test receipt_query -- --nocapture`
