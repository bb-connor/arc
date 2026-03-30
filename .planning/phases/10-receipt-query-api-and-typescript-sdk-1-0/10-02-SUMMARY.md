---
phase: 10-receipt-query-api-and-typescript-sdk-1-0
plan: 02
subsystem: http-api
tags: [axum, receipt-query, cli, json-lines, pagination, cursor, integration-test]

# Dependency graph
requires:
  - phase: 10-01
    provides: ReceiptQuery, ReceiptQueryResult, query_receipts on SqliteReceiptStore
provides:
  - GET /v1/receipts/query HTTP endpoint with filtering, pagination, auth enforcement
  - ReceiptQueryHttpQuery (HTTP query params struct, camelCase)
  - ReceiptQueryResponse (totalCount, nextCursor, receipts)
  - TrustControlClient.query_receipts() for remote CLI mode
  - arc receipt list CLI subcommand with JSON Lines output
  - 5 integration tests proving end-to-end filtering, pagination, auth
affects: [dashboard consumers, SIEM, CLI operators, TypeScript SDK consumers]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ReceiptQueryHttpQuery -> ReceiptQuery mapping: field-by-field conversion before calling store.query_receipts"
    - "JSON Lines output to stdout, pagination metadata (next_cursor, total_count) to stderr"
    - "Integration tests insert receipts directly into SQLite before spawning trust service"
    - "ArcReceipt serializes with snake_case field names (no rename_all camelCase)"

key-files:
  modified:
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/main.rs
  created:
    - crates/arc-cli/tests/receipt_query.rs

key-decisions:
  - "Receipts in ReceiptQueryResponse are serialized from stored.receipt (ArcReceipt), not StoredToolReceipt -- StoredToolReceipt does not implement Serialize"
  - "Integration test field access uses snake_case (capability_id, not capabilityId) -- ArcReceipt has no rename_all annotation"
  - "cmd_receipt_list uses fully-qualified arc_kernel:: paths to avoid polluting main.rs imports"
  - "Pagination metadata (next_cursor, total_count) written to stderr so stdout remains machine-parseable JSON Lines"

requirements-completed: [PROD-01]

# Metrics
duration: 4min
completed: 2026-03-23
---

# Phase 10 Plan 02: Receipt Query HTTP Endpoint and CLI Subcommand Summary

**GET /v1/receipts/query HTTP endpoint and `arc receipt list` CLI subcommand delivering programmatic and terminal-based receipt access, completing PROD-01**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-23T00:34:18Z
- **Completed:** 2026-03-23T00:38:xx
- **Tasks:** 3
- **Files modified:** 2 (trust_control.rs, main.rs); 1 created (receipt_query.rs test)

## Accomplishments

- Implemented `GET /v1/receipts/query` HTTP endpoint on the trust-control axum server with auth enforcement, all 8 filter dimensions, cursor pagination, and `ReceiptQueryResponse` (totalCount, nextCursor, receipts in camelCase)
- Added `TrustControlClient.query_receipts()` for remote CLI mode using existing `get_json_with_query` pattern
- Implemented `arc receipt list` CLI subcommand with 10 flags (--capability, --tool-server, --tool-name, --outcome, --since, --until, --min-cost, --max-cost, --limit, --cursor)
- CLI routes through `TrustControlClient` when `--control-url` is set, otherwise opens `SqliteReceiptStore` directly
- Output format: JSON Lines (one receipt per line) to stdout, pagination metadata to stderr
- 5 integration tests covering no-filters, capability filter, cursor pagination (non-overlapping pages), total_count independence from limit, and 401 auth enforcement

## Task Commits

1. **Task 1: HTTP endpoint and TrustControlClient.query_receipts** - `5cb175e` (feat)
2. **Task 2: arc receipt list CLI subcommand** - `9121bfe` (feat)
3. **Task 3: Integration tests for receipt query endpoint** - `f148c68` (test)

## Files Created/Modified

- `crates/arc-cli/src/trust_control.rs` - Added `RECEIPT_QUERY_PATH`, `ReceiptQueryHttpQuery`, `ReceiptQueryResponse`, `handle_query_receipts` handler, route wiring, `TrustControlClient.query_receipts()`, `ReceiptQuery` import
- `crates/arc-cli/src/main.rs` - Added `Receipt` variant to `Commands`, `ReceiptCommands` enum with `List` variant, `cmd_receipt_list` function, match arm in main dispatch
- `crates/arc-cli/tests/receipt_query.rs` - 5 integration tests with test setup helper that spawns trust service

## Decisions Made

- `StoredToolReceipt` does not implement `Serialize` so the handler maps via `stored.receipt` (`ArcReceipt`) to get serializable values -- the seq cursor information is carried in `ReceiptQueryResponse.next_cursor` instead
- `ArcReceipt` serializes with Rust field names (snake_case) -- integration tests access `capability_id` not `capabilityId`. The `ReceiptQueryResponse` wrapper uses camelCase for its own fields as required by the HTTP API design
- `cmd_receipt_list` uses fully-qualified `arc_kernel::SqliteReceiptStore` and `arc_kernel::ReceiptQuery` paths to avoid adding new imports to main.rs
- The `#[allow(clippy::too_many_arguments)]` is already set globally on main.rs for all cmd_ functions

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] StoredToolReceipt does not implement Serialize**
- **Found during:** Task 1 (build failure)
- **Issue:** `result.receipts.into_iter().map(serde_json::to_value)` fails because `StoredToolReceipt` derives only `Debug, Clone`
- **Fix:** Changed mapping to `|stored| serde_json::to_value(stored.receipt)` to serialize the inner `ArcReceipt` which is `Serialize`
- **Files modified:** crates/arc-cli/src/trust_control.rs
- **Committed in:** 5cb175e (Task 1 commit)

**2. [Rule 1 - Bug] Integration test used camelCase field name for receipt body**
- **Found during:** Task 3 (test failure: `test_receipt_query_filter_capability`)
- **Issue:** Test asserted `receipt["capabilityId"]` but `ArcReceipt` serializes as `receipt["capability_id"]` (no `rename_all` annotation)
- **Fix:** Changed assertion to use `receipt["capability_id"]`
- **Files modified:** crates/arc-cli/tests/receipt_query.rs
- **Committed in:** f148c68 (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (both compilation/test failures from incorrect assumptions about type derives and serialization naming)
**Impact on plan:** Both fixes required before tests passed. No scope creep.

## Issues Encountered

- None beyond the two auto-fixed issues above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `GET /v1/receipts/query` is live and tested
- `arc receipt list` CLI is usable immediately
- `TrustControlClient.query_receipts()` is available for any SDK or tooling that wraps the CLI
- PROD-01 requirement (receipt query API) is complete

## Self-Check: PASSED

- receipt_query.rs test file: FOUND
- 10-02-SUMMARY.md: FOUND (this file)
- commit 5cb175e (Task 1): FOUND
- commit 9121bfe (Task 2): FOUND
- commit f148c68 (Task 3): FOUND

---
*Phase: 10-receipt-query-api-and-typescript-sdk-1-0*
*Completed: 2026-03-23*
