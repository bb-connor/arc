---
phase: 08-core-enforcement
plan: 01
subsystem: kernel
tags: [monetary, budget, receipt, enforcement, sqlite, rust]

requires:
  - phase: 07-schema-monetary-foundation
    provides: MonetaryAmount type and ToolGrant monetary fields (max_cost_per_invocation, max_total_cost)

provides:
  - FinancialReceiptMetadata struct in pact-core with all required fields
  - BudgetStore.try_charge_cost trait method (per-invocation + total cost enforcement)
  - SqliteBudgetStore.try_charge_cost (IMMEDIATE transaction, atomic)
  - InMemoryBudgetStore.try_charge_cost (HashMap-based, mirrors SQLite semantics)
  - BudgetUsageRecord.total_cost_charged field
  - ToolInvocationCost struct on ToolServerConnection trait
  - invoke_with_cost default trait method (delegates to invoke, returns None cost)
  - HA overrun bound documentation and named test

affects:
  - 08-02 (monetary enforcement wiring in kernel dispatch path)
  - 08-03 (receipt metadata population for monetary grants)
  - 08-04 (HA replication of budget records)

tech-stack:
  added: []
  patterns:
    - IMMEDIATE SQLite transaction for atomic read-check-write budget enforcement
    - LWW (last-write-wins) replication conflict resolution using MAX() on total_cost_charged
    - HA overrun bound documented as max_cost_per_invocation x node_count

key-files:
  created: []
  modified:
    - crates/pact-core/src/receipt.rs
    - crates/pact-core/src/lib.rs
    - crates/pact-kernel/src/budget_store.rs
    - crates/pact-kernel/src/lib.rs

key-decisions:
  - "FinancialReceiptMetadata uses settlement_status as a String (not enum) to allow extension without schema migration"
  - "try_charge_cost performs invocation_count + total_cost_charged checks in a single IMMEDIATE transaction for atomicity"
  - "HA overrun bound documented inline: worst-case overrun = max_cost_per_invocation x node_count; named test concurrent_charge_overrun_bound"
  - "invoke_with_cost default method returns None cost; servers reporting actual costs override the method"
  - "upsert_usage conflict resolution for total_cost_charged uses MAX() when seqs are equal, seq-winner value when seq strictly exceeds current"

patterns-established:
  - "Monetary enforcement follows fail-closed pattern: any limit violation rolls back and returns false"
  - "Budget schema migrations use ensure_*_column helpers (same pattern as ensure_budget_seq_column)"

requirements-completed: [SCHEMA-04, SCHEMA-05, SCHEMA-06]

duration: 7min
completed: 2026-03-22
---

# Phase 08 Plan 01: Monetary Budget Enforcement Foundation Summary

**FinancialReceiptMetadata struct, BudgetStore.try_charge_cost with atomic per-invocation and total-cost enforcement, ToolInvocationCost on ToolServerConnection, and HA overrun bound documentation**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-22T15:13:28Z
- **Completed:** 2026-03-22T15:20:43Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added `FinancialReceiptMetadata` to pact-core with all required audit fields (grant_index, cost_charged, currency, budget_remaining, budget_total, delegation_depth, root_budget_holder, settlement_status, and optional payment_reference, cost_breakdown, attempted_cost)
- Extended `BudgetStore` trait with `try_charge_cost` and implemented it for both `SqliteBudgetStore` (IMMEDIATE transaction) and `InMemoryBudgetStore`; also added `total_cost_charged` to `BudgetUsageRecord` with LWW MAX conflict resolution in `upsert_usage`
- Added `ToolInvocationCost` struct and `invoke_with_cost` default method to `ToolServerConnection`; existing servers get None-cost default without breaking changes

## Task Commits

1. **Task 1: FinancialReceiptMetadata + BudgetStore try_charge_cost** - `e4c7664` (feat)
2. **Task 2: ToolInvocationCost + invoke_with_cost** - `0c17471` (feat)

## Files Created/Modified

- `crates/pact-core/src/receipt.rs` - Added FinancialReceiptMetadata struct + 3 tests
- `crates/pact-core/src/lib.rs` - Re-exported FinancialReceiptMetadata
- `crates/pact-kernel/src/budget_store.rs` - Added total_cost_charged field, try_charge_cost trait method and both implementations, ensure_total_cost_charged_column, updated upsert_usage/list_usages/list_usages_after, 11 new tests
- `crates/pact-kernel/src/lib.rs` - Added ToolInvocationCost struct, invoke_with_cost default method, 2 tests

## Decisions Made

- `FinancialReceiptMetadata.settlement_status` is a `String` not an enum, allowing extension without code changes
- `try_charge_cost` performs read + all three checks + write in one IMMEDIATE SQLite transaction; any check failure rolls back atomically
- HA overrun bound documented in code comment and in `concurrent_charge_overrun_bound` test: worst case = `max_cost_per_invocation * node_count`
- `invoke_with_cost` returns `None` by default; only servers that track monetary costs need to override it
- `upsert_usage` conflict resolution: higher-seq record wins; when seqs are equal, MAX() preserves the highest total_cost_charged

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- `FinancialReceiptMetadata` and `try_charge_cost` are in place for Phase 08-02 to wire monetary enforcement into the kernel dispatch path
- `ToolInvocationCost` and `invoke_with_cost` are ready for Phase 08-02 to use actual reported costs in budget calculations
- HA overrun bound is documented, satisfying the STATE.md blocker for Phase 8

---
*Phase: 08-core-enforcement*
*Completed: 2026-03-22*
