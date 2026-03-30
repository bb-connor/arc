---
phase: 36-settlement-reconciliation-and-multi-dimensional-budgets
plan: 02
subsystem: budget-dimensions
tags:
  - budgets
  - operator-reporting
  - policy
requires:
  - 36-01
provides:
  - Explicit invocation and money budget-dimension profiles on utilization rows
  - Operator-visible non-monetary budget reporting that composes with money
key-files:
  modified:
    - crates/arc-kernel/src/operator_report.rs
    - crates/arc-cli/src/trust_control.rs
requirements-completed:
  - ECON-05
completed: 2026-03-26
---

# Phase 36 Plan 02 Summary

Phase 36-02 promoted invocation limits from incidental counters to a
first-class budget dimension.

## Accomplishments

- added `BudgetDimensionUsage` and `BudgetDimensionProfile` so operator
  responses can describe invocation and monetary limits with a consistent
  `used`/`limit`/`remaining`/`utilization` model
- kept the existing raw invocation and money fields for compatibility while
  adding explicit `dimensions.invocations` and `dimensions.money` profiles to
  each utilization row
- preserved the existing composed near-limit and exhausted semantics so the new
  non-monetary dimension augments rather than replaces monetary enforcement

## Verification

- `cargo test -p arc-cli --test receipt_query`
