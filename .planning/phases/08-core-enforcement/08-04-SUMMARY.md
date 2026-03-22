---
phase: 08-core-enforcement
plan: 04
subsystem: kernel
tags: [monetary, enforcement, merkle, checkpoint, velocity, kernel, integration]

requires:
  - phase: 08-core-enforcement
    plan: 01
    provides: FinancialReceiptMetadata, BudgetStore.try_charge_cost, ToolInvocationCost
  - phase: 08-core-enforcement
    plan: 02
    provides: build_checkpoint, SqliteReceiptStore.append_pact_receipt_returning_seq, store_checkpoint, receipts_canonical_bytes_range
  - phase: 08-core-enforcement
    plan: 03
    provides: VelocityGuard, matched_grant_index on GuardContext

provides:
  - Monetary budget enforcement in evaluate_tool_call (try_charge_cost call in budget check path)
  - FinancialReceiptMetadata on allow receipts (cost_charged, settlement_status=authorized)
  - FinancialReceiptMetadata on deny receipts (attempted_cost, settlement_status=not_applicable)
  - invoke_with_cost dispatch for monetary grants (actual cost recorded vs worst-case debit)
  - matched_grant_index populated in GuardContext before guards run
  - Merkle checkpoint triggering in record_pact_receipt (every checkpoint_batch_size receipts)
  - checkpoint_batch_size field in KernelConfig and PactKernel
  - DEFAULT_CHECKPOINT_BATCH_SIZE=100 constant
  - as_any_mut() on ReceiptStore trait for SqliteReceiptStore downcast
  - BudgetChargeResult private struct for carrying monetary charge info through the pipeline
  - dispatch_tool_call_with_cost helper (replaces old dispatch_tool_call)
  - build_monetary_deny_response helper for budget exhaustion denials with financial metadata
  - finalize_tool_output_with_cost helper for allow receipts with financial metadata
  - build_allow_response_with_metadata for merging extra metadata into allow receipts

affects:
  - pact-cli (KernelConfig now requires checkpoint_batch_size)
  - pact-mcp-adapter (KernelConfig update in edge.rs tests)
  - pact-guards/tests/integration.rs (KernelConfig update)
  - tests/e2e/tests/full_flow.rs (KernelConfig update)

tech-stack:
  added: []
  patterns:
    - Downcast via as_any_mut() + downcast_mut::<SqliteReceiptStore>() for checkpoint triggering without trait bloat
    - BudgetChargeResult private struct threads monetary info from budget check to receipt building
    - Worst-case pre-execution debit: kernel charges max_cost_per_invocation upfront; actual cost from invoke_with_cost determines settlement_status
    - Checkpoint trigger: (seq - last_checkpoint_seq) >= checkpoint_batch_size in record_pact_receipt

key-files:
  created: []
  modified:
    - crates/pact-kernel/src/lib.rs
    - crates/pact-kernel/src/receipt_store.rs
    - crates/pact-kernel/Cargo.toml
    - crates/pact-cli/src/main.rs
    - crates/pact-mcp-adapter/src/edge.rs
    - crates/pact-guards/tests/integration.rs
    - tests/e2e/tests/full_flow.rs

key-decisions:
  - "BudgetChargeResult is a private struct (not part of any public API); it threads budget charge info from check_and_increment_budget through to receipt metadata construction"
  - "Downcast via ReceiptStore.as_any_mut() avoids adding checkpoint methods to the minimal ReceiptStore trait; only SqliteReceiptStore gets real checkpoint behavior"
  - "Pre-execution worst-case debit: kernel charges max_cost_per_invocation upfront via try_charge_cost; if server reports lower actual cost, cost_charged reflects actual; if higher, settlement_status=failed"
  - "dispatch_tool_call removed (dead code); dispatch_tool_call_with_cost covers both monetary and non-monetary paths"
  - "check_and_increment_budget returns (usize, Option<BudgetChargeResult>) -- backward compatible since existing callers that only care about Ok/Err still work"

requirements-completed: [SCHEMA-04, SCHEMA-05, SCHEMA-06, SEC-01, SEC-02, SEC-05]

duration: 21min
completed: 2026-03-22
---

# Phase 08 Plan 04: Kernel Enforcement Integration Summary

Monetary enforcement, Merkle checkpointing, and velocity guard integration wired into the pact-kernel evaluate_tool_call pipeline with 9 new integration tests.

## Performance

- **Duration:** 21 min
- **Started:** 2026-03-22T15:24:47Z
- **Completed:** 2026-03-22T15:45:56Z
- **Tasks:** 1
- **Files modified:** 7

## Accomplishments

- Wired `try_charge_cost` into `check_and_increment_budget`: monetary grants now use atomic read-check-write budget enforcement; non-monetary grants continue using `try_increment`
- `check_and_increment_budget` now returns `(matched_grant_index, Option<BudgetChargeResult>)`, enabling both guard context population and financial metadata construction from a single call
- `matched_grant_index` is populated in `GuardContext` before guards run (both `evaluate_tool_call_with_session_roots` and nested flow path)
- `dispatch_tool_call_with_cost` calls `invoke_with_cost` for monetary grants; servers that report actual costs have those costs recorded in `FinancialReceiptMetadata.cost_charged`
- `build_monetary_deny_response` produces deny receipts with `FinancialReceiptMetadata` under `"financial"` key (`settlement_status="not_applicable"`, `attempted_cost` set)
- `finalize_tool_output_with_cost` produces allow receipts with `FinancialReceiptMetadata` under `"financial"` key (`settlement_status="authorized"` or `"failed"` if server overran cap)
- `record_pact_receipt` triggers Merkle checkpoints by downcasting to `SqliteReceiptStore` when `(seq - last_checkpoint_seq) >= checkpoint_batch_size`
- Added `as_any_mut()` to `ReceiptStore` trait (default `None`); `SqliteReceiptStore` overrides with `Some(self)`
- Added `checkpoint_batch_size` field to `KernelConfig` and `PactKernel`, with `DEFAULT_CHECKPOINT_BATCH_SIZE=100` constant

## Task Commits

1. **Task 1: Wire monetary enforcement, Merkle checkpointing, and velocity guard into kernel pipeline** - `083e888` (feat)

## Files Created/Modified

- `crates/pact-kernel/src/lib.rs` - BudgetChargeResult struct, updated check_and_increment_budget, updated run_guards signature, updated PactKernel struct (3 checkpoint fields), updated KernelConfig (checkpoint_batch_size), updated PactKernel::new, updated evaluate_tool_call_with_session_roots and nested flow path, added dispatch_tool_call_with_cost, build_monetary_deny_response, finalize_tool_output_with_cost, build_allow_response_with_metadata, record_pact_receipt with checkpoint triggering, maybe_trigger_checkpoint; 9 new integration tests; removed dead dispatch_tool_call
- `crates/pact-kernel/src/receipt_store.rs` - Added as_any_mut() to ReceiptStore trait; SqliteReceiptStore overrides it
- `crates/pact-kernel/Cargo.toml` - No new production deps (dev-dep add/remove cycle, net unchanged)
- `crates/pact-cli/src/main.rs` - Added checkpoint_batch_size to KernelConfig literal
- `crates/pact-mcp-adapter/src/edge.rs` - Added checkpoint_batch_size to 3 KernelConfig literals in test helpers
- `crates/pact-guards/tests/integration.rs` - Added checkpoint_batch_size to KernelConfig literal
- `tests/e2e/tests/full_flow.rs` - Added checkpoint_batch_size to 3 KernelConfig literals

## Decisions Made

- `BudgetChargeResult` is a private struct (not part of any public API); it threads budget charge info from `check_and_increment_budget` through to receipt metadata construction
- Downcast via `ReceiptStore.as_any_mut()` avoids adding checkpoint methods to the minimal `ReceiptStore` trait; only `SqliteReceiptStore` gets real checkpoint behavior; non-SQLite stores silently skip checkpointing
- Pre-execution worst-case debit: kernel charges `max_cost_per_invocation` upfront via `try_charge_cost`; if server reports lower actual cost, `cost_charged` reflects actual; if higher, `settlement_status="failed"`
- `dispatch_tool_call` removed as dead code; `dispatch_tool_call_with_cost` covers both monetary and non-monetary paths
- `check_and_increment_budget` returns `(usize, Option<BudgetChargeResult>)` -- backward compatible since both eval paths simply pattern-match on Ok/Err

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] KernelConfig struct extension required updating 6+ call sites**
- **Found during:** Task 1 (build check after adding checkpoint_batch_size field)
- **Issue:** Adding `checkpoint_batch_size` to `KernelConfig` broke all existing struct initializers in pact-cli, pact-mcp-adapter, pact-guards tests, and e2e tests
- **Fix:** Added `checkpoint_batch_size: pact_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE` to all 7 external KernelConfig initializers
- **Files modified:** crates/pact-cli/src/main.rs, crates/pact-mcp-adapter/src/edge.rs (3 sites), crates/pact-guards/tests/integration.rs, tests/e2e/tests/full_flow.rs (3 sites)
- **Commit:** 083e888

**2. [Rule 1 - Bug] VelocityGuard test would create circular dependency**
- **Found during:** Task 1 (attempting to add pact-guards as dev-dependency of pact-kernel)
- **Issue:** pact-guards depends on pact-kernel for the Guard trait, so adding pact-guards as dev-dep creates a cycle
- **Fix:** Implemented an equivalent counting rate-limit guard inline in the test (CountingRateLimitGuard), testing the same kernel behavior (guard denial produces signed receipt) without the circular dep
- **Files modified:** crates/pact-kernel/src/lib.rs
- **Commit:** 083e888

## Self-Check: PASSED

- FOUND: crates/pact-kernel/src/lib.rs
- FOUND: crates/pact-kernel/src/receipt_store.rs
- FOUND: commit 083e888

## Next Phase Readiness

- Full enforcement pipeline is in place: monetary budget checks, financial receipt metadata, Merkle checkpoints, velocity-compatible guard context
- Requirements SCHEMA-04, SCHEMA-05, SCHEMA-06, SEC-01, SEC-02, SEC-05 satisfied
- Phase 09 compliance documents can reference these passing test artifacts

---
*Phase: 08-core-enforcement*
*Completed: 2026-03-22*
