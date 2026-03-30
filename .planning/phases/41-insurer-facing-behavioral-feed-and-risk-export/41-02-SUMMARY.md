---
phase: 41-insurer-facing-behavioral-feed-and-risk-export
plan: 02
subsystem: behavioral-feed-surfaces
tags:
  - risk
  - trust-control
  - cli
requires:
  - 41-01
provides:
  - Local and trust-control behavioral-feed export surfaces
  - Receipt-store behavioral-feed rollups derived from canonical receipt truth
  - Signed exports that incorporate local reputation and governed-action data
key-files:
  modified:
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/reputation.rs
    - crates/arc-store-sqlite/src/receipt_store.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/tests/receipt_query.rs
requirements-completed:
  - RISK-01
completed: 2026-03-26
---

# Phase 41 Plan 02 Summary

Phase 41-02 implemented the shipped behavioral-feed export surfaces.

## Accomplishments

- added `arc trust behavioral-feed export` plus
  `GET /v1/reports/behavioral-feed`
- derived feed content from canonical receipt analytics, compliance/export
  scope, settlement reconciliation, governed metadata, shared evidence, and a
  compact subject reputation summary
- signed exports with the configured authority seed or authority database so
  remote and local exports share one verification contract
- added receipt-store rollups for governed-action and settlement-state feed
  summaries plus stable receipt detail rows

## Verification

- `cargo test -p arc-cli --test receipt_query`
