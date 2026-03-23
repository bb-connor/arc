---
phase: 12-capability-lineage-index-and-receipt-dashboard
plan: 02
subsystem: database,http-api
tags: [sqlite, rusqlite, receipt-query, capability-lineage, axum, left-join, tdd]

requires:
  - phase: 12-01
    provides: capability_lineage table, CapabilitySnapshot struct, get_lineage/get_delegation_chain methods on SqliteReceiptStore

provides:
  - agent_subject: Option<String> filter on ReceiptQuery (capability_lineage LEFT JOIN, not log replay)
  - GET /v1/lineage/:capability_id -- returns CapabilitySnapshot by ID or 404
  - GET /v1/lineage/:capability_id/chain -- returns root-first delegation chain array
  - GET /v1/agents/:subject_key/receipts -- convenience receipt query by agent subject key
  - agentSubject query param on GET /v1/receipts/query

affects:
  - 12-03-receipt-dashboard (dashboard can use agentSubject param and lineage endpoints)
  - pact receipt list CLI (agent_subject: None preserves existing behavior)

tech-stack:
  added:
    - tower-http 0.6 (features = ["fs"]) added to pact-cli Cargo.toml (needed for Plan 12-04 SPA serving)
  patterns:
    - "LEFT JOIN capability_lineage ON capability_id in query_receipts_impl -- agent filter without log replay"
    - "?9 IS NULL OR cl.subject_key = ?9 guard -- NULL-safe filter that is no-op when agent_subject is None"
    - "AxumPath alias to avoid conflict with std::path::Path in axum handler signatures"
    - "AgentReceiptsHttpQuery delegates to same query_receipts kernel call -- no duplicate logic"

key-files:
  created: []
  modified:
    - crates/pact-kernel/src/receipt_query.rs
    - crates/pact-kernel/src/receipt_store.rs
    - crates/pact-cli/src/trust_control.rs
    - crates/pact-cli/src/main.rs
    - crates/pact-cli/Cargo.toml

key-decisions:
  - "agent_subject placed as ?9 parameter; cursor moved to ?10 and limit to ?11 -- keeps parameter numbering sequential and readable"
  - "LEFT JOIN (not INNER JOIN) preserves all receipts when agent_subject is None -- no rows filtered out on unfiltered queries"
  - "AgentReceiptsHttpQuery is a minimal struct (cursor + limit only) -- subject_key comes from path, not query string"
  - "CapabilitySnapshot/CapabilityLineageError imports removed from trust_control.rs since Rust infers the type via get_lineage return value and errors are converted to strings"

requirements-completed: [PROD-03]

duration: 7min
completed: 2026-03-23
---

# Phase 12 Plan 02: Agent-Centric Receipt Query and Lineage HTTP Endpoints Summary

**Agent-centric receipt queries via LEFT JOIN capability_lineage (no log replay) and three new lineage HTTP endpoints added to trust-control service**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-23T02:20:33Z
- **Completed:** 2026-03-23T02:27:06Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added `agent_subject: Option<String>` field to `ReceiptQuery` with doc comment explaining the JOIN-based resolution strategy
- Modified `query_receipts_impl` in receipt_store.rs to LEFT JOIN capability_lineage and add `?9 IS NULL OR cl.subject_key = ?9` filter to both data and count SQL queries; parameter renumbering: cursor is now ?10, limit is ?11
- Added 5 new agent_subject tests (TDD): filter, none-returns-all, no-match, outcome-intersection, cursor pagination -- all pass
- Added `agentSubject` field to `ReceiptQueryHttpQuery` (camelCase via serde rename_all), wired through `handle_query_receipts`
- Implemented `handle_get_lineage` returning 200 JSON CapabilitySnapshot or 404 with message
- Implemented `handle_get_delegation_chain` returning 200 JSON array (root-first, from get_delegation_chain CTE)
- Implemented `handle_agent_receipts` (GET /v1/agents/:subject_key/receipts) as a convenience wrapper delegating to query_receipts
- Added `AgentReceiptsHttpQuery` struct for path-based agent receipt queries
- Registered all three new routes in serve_async router before `.with_state(state)`
- Added `tower-http = { version = "0.6", features = ["fs"] }` to pact-cli Cargo.toml for Plan 12-04
- All 23 receipt_query tests pass (18 existing + 5 new); cargo build and clippy pass

## Task Commits

1. **Task 1 RED: Failing agent_subject tests** - `bc372b1` (test)
2. **Task 1 GREEN: Add agent_subject to ReceiptQuery with LEFT JOIN** - `c44fe94` (feat)
3. **Task 2: Lineage HTTP endpoints and agentSubject query param** - `3778e7b` (feat)

## Files Created/Modified

- `crates/pact-kernel/src/receipt_query.rs` - Added `agent_subject: Option<String>` field to ReceiptQuery; 5 new test functions added
- `crates/pact-kernel/src/receipt_store.rs` - query_receipts_impl updated with LEFT JOIN capability_lineage and agent_subject filter; parameters renumbered (?9 agent_sub, ?10 cursor, ?11 limit)
- `crates/pact-cli/src/trust_control.rs` - AxumPath import, 3 new route constants, agentSubject field on ReceiptQueryHttpQuery, AgentReceiptsHttpQuery struct, 3 new handler functions, routes registered in serve_async
- `crates/pact-cli/src/main.rs` - agent_subject: None added to both ReceiptQueryHttpQuery and ReceiptQuery struct initializers in receipt list command
- `crates/pact-cli/Cargo.toml` - tower-http 0.6 with fs feature added

## Decisions Made

- Parameter ?9 is agent_subject; cursor moved to ?10 and limit to ?11 -- sequential numbering is more maintainable than inserting at a non-contiguous position
- LEFT JOIN (not INNER JOIN) is critical for backwards compatibility: when agent_subject is None, the ?9 IS NULL guard passes all rows regardless of whether cl.subject_key is NULL (no lineage entry) or a real key
- `AgentReceiptsHttpQuery` is a minimal struct -- subject_key comes from the path segment, so only cursor/limit are needed as query parameters
- Rust infers `CapabilitySnapshot` type from `get_lineage` return value without explicit import in trust_control.rs; errors are converted via `.to_string()` so `CapabilityLineageError` import is also unnecessary

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed missing agent_subject field in main.rs struct initializers**
- **Found during:** Task 2 (first cargo build)
- **Issue:** Adding `agent_subject` to `ReceiptQuery` and `ReceiptQueryHttpQuery` made two non-exhaustive struct initializers in main.rs fail to compile
- **Fix:** Added `agent_subject: None` to both struct initializers in the receipt list CLI command path
- **Files modified:** crates/pact-cli/src/main.rs
- **Verification:** cargo build passes
- **Committed in:** 3778e7b (Task 2 commit)

**2. [Rule 1 - Bug] Removed unused CapabilityLineageError and CapabilitySnapshot imports**
- **Found during:** Task 2 (first cargo build warning)
- **Issue:** Imported `CapabilityLineageError` and `CapabilitySnapshot` explicitly but Rust infers both via type context; `unused_imports` warning triggered
- **Fix:** Removed both explicit imports from the pact_kernel use statement in trust_control.rs
- **Files modified:** crates/pact-cli/src/trust_control.rs
- **Verification:** cargo clippy -D warnings passes
- **Committed in:** 3778e7b (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 struct initializer exhaustiveness, 1 unnecessary import)
**Impact on plan:** Both required for compilation. No scope creep.

## Issues Encountered

Pre-existing test `mcp_serve_http_control_service_centralizes_receipts_revocations_and_authority` fails with "trust control service did not become ready" -- this is a timing/flakiness issue unrelated to capability lineage or receipt query changes. The test file (mcp_serve_http.rs) is untracked and was failing before these changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `/v1/receipts/query?agentSubject=<hex>` filters receipts by agent subject key via JOIN
- `/v1/lineage/:capability_id` and `/v1/lineage/:capability_id/chain` are live
- `/v1/agents/:subject_key/receipts` convenience endpoint is live
- All endpoints protected by Bearer auth (validate_service_auth)
- `tower-http` dependency pre-staged for Plan 12-04 SPA file serving

## Self-Check: PASSED

- FOUND: crates/pact-kernel/src/receipt_query.rs (agent_subject field + 5 new tests)
- FOUND: crates/pact-kernel/src/receipt_store.rs (LEFT JOIN capability_lineage)
- FOUND: crates/pact-cli/src/trust_control.rs (handle_get_lineage, handle_get_delegation_chain, handle_agent_receipts)
- FOUND commit bc372b1: test(12-02): add failing tests for agent_subject filter
- FOUND commit c44fe94: feat(12-02): add agent_subject filter to ReceiptQuery with LEFT JOIN capability_lineage
- FOUND commit 3778e7b: feat(12-02): add lineage HTTP endpoints and agentSubject query param to trust-control

---
*Phase: 12-capability-lineage-index-and-receipt-dashboard*
*Completed: 2026-03-23*
