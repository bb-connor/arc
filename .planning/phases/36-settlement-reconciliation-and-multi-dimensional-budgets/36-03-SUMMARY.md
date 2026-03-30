---
phase: 36-settlement-reconciliation-and-multi-dimensional-budgets
plan: 03
subsystem: operator-surfaces
tags:
  - tests
  - docs
  - trust-control
requires:
  - 36-01
  - 36-02
provides:
  - Regression coverage for settlement reconciliation endpoints and operator-report composition
  - Updated protocol and operator docs for sidecar reconciliation plus budget dimensions
key-files:
  modified:
    - crates/arc-cli/tests/receipt_query.rs
    - docs/AGENT_ECONOMY.md
    - spec/PROTOCOL.md
requirements-completed:
  - ECON-04
  - ECON-05
completed: 2026-03-26
---

# Phase 36 Plan 03 Summary

Phase 36-03 closed the loop by proving the new operator surfaces and documenting
their contract.

## Accomplishments

- added trust-control regression coverage for the dedicated settlement backlog
  report, reconciliation update endpoint, and composite operator report summary
- documented that settlement reconciliation is mutable sidecar state, separate
  from signed receipt `financial.settlement_status`
- documented invocation-plus-money utilization profiles as the shipped
  multi-dimensional budget surface

## Verification

- `cargo test -p arc-cli --test receipt_query`
- `rg -n "reconciliation|budget dimension|invocation" docs/AGENT_ECONOMY.md spec/PROTOCOL.md`
