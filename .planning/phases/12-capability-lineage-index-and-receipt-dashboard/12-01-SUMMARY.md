---
phase: 12-capability-lineage-index-and-receipt-dashboard
plan: 01
subsystem: database
tags: [sqlite, rusqlite, capability-tokens, delegation-chain, recursive-cte, arc-kernel]

requires:
  - phase: 08-core-enforcement
    provides: SqliteReceiptStore with connection, receipt tables, and WAL SQLite setup
  - phase: 07-schema-compatibility
    provides: CapabilityToken struct with id, issuer, subject, scope, issued_at, expires_at

provides:
  - capability_lineage SQLite table co-located with arc_tool_receipts for efficient JOINs
  - CapabilitySnapshot struct (serializable, cloneable capability point-in-time record)
  - record_capability_snapshot -- idempotent INSERT OR IGNORE with depth computation
  - get_lineage -- O(1) lookup by capability_id primary key
  - get_delegation_chain -- WITH RECURSIVE CTE walk, root-first, max-depth guard (level < 20)
  - list_capabilities_for_subject -- indexed scan by subject_key, newest-first

affects:
  - 12-02-receipt-dashboard (dashboard queries capability_lineage for JOIN display)
  - future compliance and audit phases

tech-stack:
  added: []
  patterns:
    - "snapshot_from_row helper function eliminates duplicate row-mapping closures across query methods"
    - "pub(crate) connection field allows sibling modules to implement methods on SqliteReceiptStore without accessor indirection"
    - "INSERT OR IGNORE for idempotent first-writer-wins snapshot semantics"
    - "WITH RECURSIVE CTE with level < 20 guard for safe delegation chain traversal"

key-files:
  created:
    - crates/arc-kernel/src/capability_lineage.rs
  modified:
    - crates/arc-kernel/src/receipt_store.rs
    - crates/arc-kernel/src/lib.rs

key-decisions:
  - "pub(crate) on SqliteReceiptStore.connection field allows capability_lineage.rs to implement methods without a separate accessor; same pattern used by budget_store and checkpoint"
  - "snapshot_from_row free function (not closure) eliminates type annotation boilerplate and ensures consistent column ordering across all query sites"
  - "delegation_depth queried from parent at insert time (not computed at query time) -- depth is stable and avoids recursive computation on every read"
  - "ORDER BY level DESC in WITH RECURSIVE CTE produces root-first ordering because root is discovered at the highest recursion level"

patterns-established:
  - "snapshot_from_row: shared row-to-struct extractor for consistent column-index mapping"
  - "INSERT OR IGNORE idempotency: capability snapshots are immutable once recorded; re-inserts are silently dropped"

requirements-completed: [PROD-02]

duration: 4min
completed: 2026-03-22
---

# Phase 12 Plan 01: Capability Lineage Table and Store Summary

**SQLite capability_lineage table with WITH RECURSIVE delegation chain walk, idempotent snapshot recording, and subject_key index -- co-located with arc_tool_receipts for efficient JOINs**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-22T00:13:23Z
- **Completed:** 2026-03-22T00:17:15Z
- **Tasks:** 1
- **Files modified:** 3

## Accomplishments

- Created `capability_lineage` table with subject_key, issued_at, and parent_capability_id indexes alongside existing receipt tables in the same SQLite WAL database
- Implemented `record_capability_snapshot` with INSERT OR IGNORE idempotency and automatic delegation depth computation from parent row
- Implemented `get_delegation_chain` using WITH RECURSIVE CTE with a level < 20 depth guard and root-first ORDER BY level DESC
- Implemented `list_capabilities_for_subject` with indexed scan on subject_key, newest-first ordering
- 9 unit tests pass covering all acceptance criteria: persistence, idempotency, JSON round-trip, missing lookup, 3-level chain walk, root-only chain, depth guard (25-entry chain capped at 21), table existence, and index existence via PRAGMA index_list

## Task Commits

1. **Task 1: Create capability_lineage table DDL and capability_lineage.rs module** - `7432195` (feat)

## Files Created/Modified

- `crates/arc-kernel/src/capability_lineage.rs` - CapabilitySnapshot struct, CapabilityLineageError, and impl SqliteReceiptStore methods for record/get/chain/list operations with 9 unit tests
- `crates/arc-kernel/src/receipt_store.rs` - capability_lineage table DDL and indexes added to execute_batch in SqliteReceiptStore::open; connection field promoted to pub(crate)
- `crates/arc-kernel/src/lib.rs` - pub mod capability_lineage declaration, re-exports of CapabilitySnapshot and CapabilityLineageError

## Decisions Made

- `pub(crate)` on `SqliteReceiptStore.connection` allows capability_lineage.rs to implement methods without a separate accessor -- consistent with how budget_store and checkpoint access the connection
- `snapshot_from_row` as a free function (not closure) eliminates type annotation boilerplate and ensures consistent column ordering across all query sites
- Delegation depth is queried from the parent row at insert time rather than computed lazily at query time -- depth is stable and avoids recursive computation on every read
- ORDER BY level DESC in the WITH RECURSIVE CTE produces root-first ordering because the root is discovered at the highest recursion level (deepest ancestor = most iterations = highest level)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed module-level doc comment style causing clippy failure**
- **Found during:** Task 1 (after clippy run)
- **Issue:** Used `///` (item doc comment) at the top of the module file with a blank line after it, triggering `empty_line_after_doc_comments`
- **Fix:** Changed `///` to `//!` (inner doc comment) for the module preamble
- **Files modified:** crates/arc-kernel/src/capability_lineage.rs
- **Verification:** `cargo clippy -p arc-kernel -- -D warnings` passes
- **Committed in:** 7432195 (Task 1 commit)

**2. [Rule 3 - Blocking] Fixed type inference errors in rusqlite row closures**
- **Found during:** Task 1 (first compile attempt)
- **Issue:** Rust could not infer types for tuple destructuring patterns from rusqlite query_map closures when using complex tuple return types
- **Fix:** Extracted `snapshot_from_row` helper function with explicit `&Row<'_>` parameter type, replacing all inline closure tuple patterns
- **Files modified:** crates/arc-kernel/src/capability_lineage.rs
- **Verification:** All 9 tests compile and pass
- **Committed in:** 7432195 (Task 1 commit)

**3. [Rule 1 - Bug] Fixed Operation::Execute -> Operation::Invoke**
- **Found during:** Task 1 (first compile attempt)
- **Issue:** Test helper used `Operation::Execute` which does not exist in the enum (correct variant is `Operation::Invoke`)
- **Fix:** Changed to `Operation::Invoke`
- **Files modified:** crates/arc-kernel/src/capability_lineage.rs (test module)
- **Verification:** Compiles and tests pass
- **Committed in:** 7432195 (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (1 clippy doc style, 1 blocking type inference, 1 wrong enum variant)
**Impact on plan:** All auto-fixes required for compilation and correctness. No scope creep.

## Issues Encountered

None beyond the auto-fixed compile errors above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- capability_lineage table is ready for JOIN queries from the receipt dashboard (Phase 12 Plan 02)
- record_capability_snapshot can be called from the kernel at token issuance time in future integration work
- All 148 arc-kernel tests pass, no regressions

## Self-Check: PASSED

- FOUND: crates/arc-kernel/src/capability_lineage.rs
- FOUND: crates/arc-kernel/src/receipt_store.rs (modified)
- FOUND: crates/arc-kernel/src/lib.rs (modified)
- FOUND: .planning/phases/12-capability-lineage-index-and-receipt-dashboard/12-01-SUMMARY.md
- FOUND commit 7432195: feat(12-01): add capability_lineage table and CapabilityLineageStore

---
*Phase: 12-capability-lineage-index-and-receipt-dashboard*
*Completed: 2026-03-22*
