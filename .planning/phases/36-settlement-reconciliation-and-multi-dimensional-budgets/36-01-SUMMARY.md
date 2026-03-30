---
phase: 36-settlement-reconciliation-and-multi-dimensional-budgets
plan: 01
subsystem: settlement-reconciliation
tags:
  - settlements
  - operator-reporting
  - trust-control
requires: []
provides:
  - Receipt-level settlement backlog reporting for pending and failed settlements
  - Sidecar reconciliation actions keyed by `receipt_id` without receipt mutation
key-files:
  modified:
    - crates/arc-kernel/src/operator_report.rs
    - crates/arc-store-sqlite/src/receipt_store.rs
    - crates/arc-cli/src/trust_control.rs
requirements-completed:
  - ECON-04
completed: 2026-03-26
---

# Phase 36 Plan 01 Summary

Phase 36-01 added the operator-side reconciliation surface without weakening
receipt truth.

## Accomplishments

- added typed settlement reconciliation report/state models plus a bounded
  settlement backlog query surface on the operator report contract
- added a SQLite sidecar reconciliation table keyed by `receipt_id`, with
  upsert and backlog query helpers that join signed receipt settlement data
  without rewriting receipts
- exposed `GET /v1/reports/settlements` and `POST /v1/settlements/reconcile`,
  and embedded the same reconciliation report inside the composite operator
  report

## Verification

- `cargo test -p arc-cli --test receipt_query`
