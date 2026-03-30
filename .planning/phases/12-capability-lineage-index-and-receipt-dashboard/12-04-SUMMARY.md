---
phase: 12-capability-lineage-index-and-receipt-dashboard
plan: "04"
subsystem: http-api,ui,testing
tags: [axum, tower-http, spa, servedur, react, integration-tests, lineage]

requires:
  - phase: 12-02
    provides: lineage HTTP handlers (handle_get_lineage, handle_get_delegation_chain, handle_agent_receipts) and router with all API routes
  - phase: 12-03
    provides: React SPA built to crates/arc-cli/dashboard/dist/ with index.html entry point

provides:
  - tower_http::ServeDir nest_service wiring that serves dashboard dist/ as SPA catch-all after all API routes
  - Graceful degradation when dashboard/dist/index.html is absent (API-only mode with warn! log)
  - 8 new integration tests covering: lineage GET, delegation chain root-first ordering, 404, auth enforcement, agentSubject HTTP filter, agent receipts endpoint, API priority over SPA catch-all

affects:
  - Stakeholders using the dashboard URL (PROD-05 completed -- non-engineer can open http://host:port/?token=X)
  - CI pipelines that run arc-cli tests (tests now cover all lineage and agent endpoints)

tech-stack:
  added: []
  patterns:
    - "nest_service('/') registered LAST in the axum router -- all API routes take precedence over the SPA catch-all"
    - "Conditional SPA serving: dashboard_dir.join('index.html').exists() guards nest_service to allow API-only mode without build dependency"
    - "prepopulate_lineage test helper opens SqliteReceiptStore directly before spawning service -- same pattern as existing receipt_query tests"

key-files:
  created: []
  modified:
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/tests/receipt_query.rs

key-decisions:
  - "Conditional nest_service: only wire SPA if dashboard/dist/index.html exists -- CI and API-only deployments start without requiring a frontend build"
  - "warn! log when dashboard is absent so operators know to run 'npm run build' -- fail-open with clear signal"
  - "Route constant syntax fixed from :param to {param} for axum 0.8 compatibility (pre-existing bug introduced in 12-02, blocking all integration tests)"

patterns-established:
  - "SPA catch-all pattern: API routes registered before nest_service('/') guarantees JSON routes win over HTML fallback"

requirements-completed: [PROD-04, PROD-05]

duration: 6min
completed: "2026-03-23"
---

# Phase 12 Plan 04: ServeDir SPA Wiring and Lineage Integration Tests Summary

**tower_http ServeDir wired as axum catch-all after all API routes, with 8 new integration tests proving lineage endpoints, agent subject filter, and SPA route priority all work correctly**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-23T02:30:00Z
- **Completed:** 2026-03-23T02:36:23Z
- **Tasks:** 1 (Task 2 is a human-verify checkpoint)
- **Files modified:** 2

## Accomplishments

- Added `tower_http::services::{ServeDir, ServeFile}` import to trust_control.rs
- Added `DASHBOARD_DIST_DIR = "dashboard/dist"` constant
- Wired conditional `nest_service("/", spa_service)` at the end of `serve_async`, after all API routes; graceful degradation with `warn!` when dist/index.html is absent
- Fixed pre-existing axum 0.8 route syntax bug: route constants `LINEAGE_PATH`, `LINEAGE_CHAIN_PATH`, `AGENT_RECEIPTS_PATH` updated from `:param` to `{param}` -- the binary was panicking at startup before this fix
- Added 8 new integration tests to `receipt_query.rs`: lineage GET snapshot, delegation chain (3-level root-first), 404, auth enforcement, agentSubject filter via HTTP, agent receipts endpoint, API-priority-over-SPA
- All 12 receipt_query integration tests pass

## Task Commits

1. **Task 1: Wire ServeDir into axum router and add integration tests** - `e0c8027` (feat)

## Files Created/Modified

- `crates/arc-cli/src/trust_control.rs` - Added ServeDir/ServeFile import, DASHBOARD_DIST_DIR constant, conditional nest_service wiring, axum 0.8 route syntax fix
- `crates/arc-cli/tests/receipt_query.rs` - Added CapabilityToken imports, make_capability_token and prepopulate_lineage helpers, 8 new integration test functions

## Decisions Made

- Conditional SPA wiring (check for dist/index.html before registering nest_service) ensures the trust-control server starts without requiring a frontend build in CI or API-only deployments
- warn! log when dashboard is absent gives operators clear signal to run `npm run build` -- the alternative of panicking at startup would break API-only use cases
- Route constant fix is non-negotiable for axum 0.8 -- the binary panics at router initialization with colon-style route parameters

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed axum 0.8 route parameter syntax in LINEAGE_PATH, LINEAGE_CHAIN_PATH, AGENT_RECEIPTS_PATH**
- **Found during:** Task 1 (integration test execution -- binary panicked at startup)
- **Issue:** Routes used `:capability_id` / `:subject_key` syntax from axum 0.7. axum 0.8 requires `{capture}` syntax. The binary panicked with "Path segments must not start with ':'. For capture groups, use '{capture}'." -- all integration tests failed because the service never became ready.
- **Fix:** Changed all three route constants to use `{param}` syntax: `/v1/lineage/{capability_id}`, `/v1/lineage/{capability_id}/chain`, `/v1/agents/{subject_key}/receipts`
- **Files modified:** crates/arc-cli/src/trust_control.rs
- **Verification:** Binary starts cleanly, health endpoint responds, all 12 integration tests pass
- **Committed in:** e0c8027 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking bug -- axum 0.8 route syntax)
**Impact on plan:** The route syntax fix was required for the binary to start at all. This was a latent bug from plan 12-02 that only manifested during integration testing in plan 12-04. No scope creep.

## Issues Encountered

The axum 0.8 route syntax bug was introduced in 12-02 but not caught because the existing receipt_query tests at that time did not exercise the lineage or agent-receipts routes. The 12-04 integration tests exposed the panic immediately on first test run.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `cargo build -p arc-cli` produces a binary that serves the SPA at root when `dashboard/dist/index.html` exists
- API routes continue to function correctly alongside SPA serving
- Task 2 (human-verify checkpoint) requires: build dashboard with `npm run build`, start trust service, open browser to verify dashboard renders and filters work
- All 12 receipt_query integration tests pass; no regressions

## Self-Check: PASSED

- FOUND: crates/arc-cli/src/trust_control.rs (ServeDir import, DASHBOARD_DIST_DIR, conditional nest_service)
- FOUND: crates/arc-cli/tests/receipt_query.rs (8 new test functions)
- FOUND commit e0c8027: feat(12-04): wire ServeDir SPA into axum router and add lineage integration tests

---
*Phase: 12-capability-lineage-index-and-receipt-dashboard*
*Completed: 2026-03-23*
