---
phase: 12-capability-lineage-index-and-receipt-dashboard
verified: 2026-03-22T08:00:00Z
status: human_needed
score: 11/12 must-haves verified
human_verification:
  - test: "Open dashboard in browser and filter receipts without CLI"
    expected: "Dashboard loads at http://host:port/?token=X, filter sidebar is visible, receipt table renders, filters by agent/tool/outcome/time update the table, receipt row click opens delegation chain panel"
    why_human: "PROD-05 non-engineer usability requires visual browser verification; automated tests confirm the SPA builds and is served but cannot evaluate UX quality or end-to-end rendering in a browser"
---

# Phase 12: Capability Lineage Index and Receipt Dashboard Verification Report

**Phase Goal:** Operators and compliance officers can answer "what did agent X do?" through a web dashboard backed by a persistent capability lineage index.

**Verified:** 2026-03-22T08:00:00Z
**Status:** human_needed
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Capability snapshots are persisted at issuance time with subject, issuer, grants, and delegation metadata | VERIFIED | `capability_lineage.rs` implements `record_capability_snapshot` using `INSERT OR IGNORE`; 9 unit tests pass confirming persistence of all fields |
| 2 | Snapshots are keyed by `capability_id` and idempotent on re-insert | VERIFIED | `INSERT OR IGNORE INTO capability_lineage` in `record_capability_snapshot`; test `record_capability_snapshot_is_idempotent` confirms single row after two inserts |
| 3 | Delegation chain is tracked via `parent_capability_id` foreign key | VERIFIED | Schema DDL in `receipt_store.rs` declares `parent_capability_id TEXT REFERENCES capability_lineage(capability_id)`; `get_delegation_chain` WITH RECURSIVE CTE walks it; 3-level chain test passes |
| 4 | `capability_lineage` table co-located with `pact_tool_receipts` in same SQLite file | VERIFIED | DDL added to `SqliteReceiptStore::open`'s `execute_batch`; `capability_lineage_table_created_by_open` test confirms table exists after open |
| 5 | Agent-centric receipt queries resolve through capability lineage index via JOIN without replaying issuance logs | VERIFIED | `query_receipts_impl` uses `LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id` with `?9 IS NULL OR cl.subject_key = ?9`; 5 unit tests and HTTP integration test `test_agent_subject_filter_via_http` pass |
| 6 | `GET /v1/lineage/:capability_id` returns the capability snapshot for a given ID | VERIFIED | `handle_get_lineage` registered at `LINEAGE_PATH = "/v1/lineage/{capability_id}"` in axum router; integration test `test_lineage_get_capability_snapshot` confirms 200 with matching fields |
| 7 | `GET /v1/lineage/:capability_id/chain` returns the full delegation chain root-first | VERIFIED | `handle_get_delegation_chain` registered at `LINEAGE_CHAIN_PATH`; integration test `test_lineage_get_delegation_chain` confirms 3-level root-first array |
| 8 | `GET /v1/receipts/query?agentSubject=<hex>` filters receipts by agent subject key | VERIFIED | `ReceiptQueryHttpQuery` has `agent_subject: Option<String>` (serde camelCase); passed to kernel `ReceiptQuery.agent_subject` in `handle_query_receipts` |
| 9 | Dashboard SPA (React 18, Vite 6, TanStack Table 8, Recharts 2) builds and serves | VERIFIED | `dist/index.html` exists; `npm run build` produced 618kB JS bundle; package.json pins react@18.3.1, vite@6.0.0, @tanstack/react-table@8.21.3, recharts@2.15.0 |
| 10 | Dashboard SPA is served by axum via `tower_http::ServeDir` at the root path after API routes | VERIFIED | `ServeDir` and `ServeFile` imported; `nest_service("/", spa_service)` registered LAST in `serve_async`; conditional on `dist/index.html` existing; integration test `test_api_routes_not_shadowed_by_spa` passes |
| 11 | Delegation chain is inspectable in the detail panel | VERIFIED | `DelegationChain.tsx` calls `fetchDelegationChain` from `api.ts`; imported and rendered in `ReceiptTable.tsx` detail panel on row click |
| 12 | Non-engineer stakeholder can open dashboard URL and filter receipts without CLI access | NEEDS HUMAN | SPA builds, is served, and API routes work -- but actual browser rendering and filter UX must be verified by a human |

**Score:** 11/12 truths verified (1 requires human testing)

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/pact-kernel/src/capability_lineage.rs` | CapabilityLineageStore with `record_capability_snapshot`, `get_lineage`, `get_delegation_chain` | VERIFIED | 536 lines (min 100); all four methods implemented on `SqliteReceiptStore`; 9 tests |
| `crates/pact-kernel/src/receipt_store.rs` | `capability_lineage` table in `SqliteReceiptStore::open` | VERIFIED | DDL with 4 columns and 3 indexes present in `execute_batch`; contains "capability_lineage" |
| `crates/pact-kernel/src/lib.rs` | Re-export of `capability_lineage` module | VERIFIED | `pub mod capability_lineage;` and `pub use capability_lineage::{CapabilityLineageError, CapabilitySnapshot};` present |
| `crates/pact-kernel/src/receipt_query.rs` | `ReceiptQuery.agent_subject` field | VERIFIED | `pub agent_subject: Option<String>` with doc comment about JOIN-based resolution; 5 new tests |
| `crates/pact-cli/src/trust_control.rs` | Lineage API endpoints and `agent_subject` query param on receipt query | VERIFIED | `handle_get_lineage`, `handle_get_delegation_chain`, `handle_agent_receipts` all present; `agentSubject` in `ReceiptQueryHttpQuery`; `ServeDir` nest_service wiring present |
| `crates/pact-cli/tests/receipt_query.rs` | Integration tests for lineage endpoints and agent query | VERIFIED | 8 new integration tests covering lineage GET, chain, 404, auth, agentSubject filter, agent receipts endpoint, SPA priority |
| `crates/pact-cli/dashboard/package.json` | React 18 + Vite 6 + TanStack Table 8 + Recharts 2 | VERIFIED | react@^18.3.1, vite@^6.0.0, @tanstack/react-table@^8.21.3, recharts@^2.15.0 all present |
| `crates/pact-cli/dashboard/src/components/ReceiptTable.tsx` | TanStack Table 8 with server-side pagination | VERIFIED | 338 lines (min 60); `useReactTable`, `manualPagination: true`, `fetchReceipts` call present |
| `crates/pact-cli/dashboard/src/components/FilterSidebar.tsx` | Filter controls for agent, tool, outcome, time range | VERIFIED | 135 lines (min 40); 6 controlled inputs for agentSubject, toolServer, toolName, outcome, since, until |
| `crates/pact-cli/dashboard/src/components/DelegationChain.tsx` | Expandable delegation tree component | VERIFIED | 152 lines (min 30); calls `fetchDelegationChain` on mount; expand/collapse via ChevronDown/Right |
| `crates/pact-cli/dashboard/src/components/BudgetSparkline.tsx` | Recharts 2 area chart for cost over time | VERIFIED | 53 lines (min 20); imports `AreaChart`, `ResponsiveContainer` from recharts |
| `crates/pact-cli/dashboard/src/api.ts` | Typed fetch wrappers for receipt query, lineage, agents | VERIFIED | 134 lines (min 30); `fetchReceipts`, `fetchLineage`, `fetchDelegationChain`, `fetchAgentReceipts`, `fetchAgentCostSeries` all present |
| `crates/pact-cli/dashboard/dist/index.html` | Built SPA assets | VERIFIED | `dist/index.html` exists alongside `dist/assets/index-*.js` and `dist/assets/index-*.css` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `capability_lineage.rs` | `receipt_store.rs` (capability_lineage table) | Methods on `SqliteReceiptStore` use `self.connection` to query table | WIRED | `capability_lineage` appears in both table DDL and all query methods |
| `receipt_store.rs` | `capability_lineage` table | `LEFT JOIN capability_lineage` in `query_receipts_impl` | WIRED | Pattern "LEFT JOIN capability_lineage" confirmed at lines 659 and 679 |
| `trust_control.rs` | `receipt_store.rs` (lineage methods) | `handle_get_lineage` calls `get_lineage`; `handle_query_receipts` passes `agent_subject` | WIRED | Pattern "agent_subject|get_lineage|get_delegation_chain" confirmed |
| `trust_control.rs` | `dashboard/dist/` | `ServeDir::new` pointing to "dashboard/dist" | WIRED | `DASHBOARD_DIST_DIR = "dashboard/dist"`, conditional `nest_service("/", spa_service)` at lines 570-573 |
| `App.tsx` | `ReceiptTable.tsx` | Imports and renders with `filters` state | WIRED | `import { ReceiptTable }` and `<ReceiptTable filters={filters} />` in App.tsx |
| `ReceiptTable.tsx` | `api.ts` | Calls `fetchReceipts` to load TanStack Table data | WIRED | `import { fetchReceipts, fetchAgentCostSeries }` and `fetchReceipts(filters, cursor, 50)` in useEffect |
| `api.ts` | `/v1/receipts/query` | `fetch()` with Bearer auth header | WIRED | `apiFetch(\`/v1/receipts/query${query}\`)` in `fetchReceipts` |
| `DelegationChain.tsx` | `api.ts` (`fetchDelegationChain`) | Imported and called on mount | WIRED | `import { fetchDelegationChain }` and `fetchDelegationChain(capabilityId)` in useEffect |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| PROD-02 | 12-01-PLAN.md | Capability lineage index persists capability snapshots keyed by capability_id with subject, issuer, grants, and delegation metadata | SATISFIED | `capability_lineage.rs` with `record_capability_snapshot`, table DDL, 9 unit tests; all fields stored and retrievable |
| PROD-03 | 12-02-PLAN.md | Agent-centric receipt queries resolve through capability lineage index without replaying issuance logs | SATISFIED | `LEFT JOIN capability_lineage` in `query_receipts_impl` with `?9 IS NULL OR cl.subject_key = ?9`; 5 unit tests + HTTP integration test confirm correct filtering |
| PROD-04 | 12-03-PLAN.md, 12-04-PLAN.md | Web-based receipt dashboard renders receipts filterable by agent/tool/outcome/time with delegation chain inspection | SATISFIED (automated) | SPA builds with all four components; dist/index.html exists; `test_api_routes_not_shadowed_by_spa` passes; delegation chain renders in detail panel |
| PROD-05 | 12-03-PLAN.md, 12-04-PLAN.md | Non-engineer stakeholders can answer "what did agent X do?" via dashboard without CLI access | NEEDS HUMAN | Token sourced from URL param `?token=`; SPA served at root; automated checks pass; browser UX verification required |

**Orphaned requirements check:** REQUIREMENTS.md maps PROD-02, PROD-03, PROD-04, PROD-05 exclusively to Phase 12. All four are claimed by plans in this phase. No orphaned requirements.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `crates/pact-cli/src/trust_control.rs` | 1039 | `// Remote monetary cost charging is not yet implemented.` returns `Ok(true)` | Info | Pre-existing in remote budget stub; unrelated to Phase 12 scope; not a Phase 12 regression |
| `dashboard/src/components/BudgetSparkline.tsx` | 26 | "No cost data" placeholder text | Info | Legitimate empty-state message, not a code stub; component renders real Recharts AreaChart when data present |
| `dashboard/src/components/FilterSidebar.tsx` | 67-89 | HTML `placeholder` attributes on inputs | Info | Standard HTML form placeholders for UX guidance; not code stubs |

No blockers or warnings found. All detected patterns are informational and expected.

---

### Human Verification Required

#### 1. End-to-end Dashboard UX (PROD-05)

**Test:**
1. Build the dashboard: `cd crates/pact-cli/dashboard && npm run build`
2. Start the trust service: `cargo run -p pact-cli -- --receipt-db /tmp/pact-verify.sqlite3 --revocation-db /tmp/pact-revoke.sqlite3 --authority-db /tmp/pact-auth.sqlite3 --budget-db /tmp/pact-budget.sqlite3 trust serve --listen 127.0.0.1:8080 --service-token test-token-123`
3. Open browser to: `http://127.0.0.1:8080/?token=test-token-123`

**Expected:**
- Dashboard loads with "PACT Receipt Dashboard" header
- Filter sidebar is visible on the left with agent/tool/outcome/time controls
- Receipt table shows "No receipts found" (empty database) or real receipts
- Selecting "Allow" in outcome dropdown filters the table
- Clicking a receipt row opens a detail panel
- Detail panel shows capability ID and delegation chain

**Why human:** Browser rendering, layout correctness, interactive filter behavior, and overall usability for a non-engineer stakeholder cannot be verified programmatically. The automated tests confirm the server responds with 200 and the build produces assets, but not that the UI is functional and comprehensible.

---

### Test Results Summary

| Test Suite | Command | Result |
|------------|---------|--------|
| capability_lineage unit tests | `cargo test -p pact-kernel -- capability_lineage` | 9/9 passed |
| receipt_query unit tests (incl. agent_subject) | `cargo test -p pact-kernel -- receipt_query` | 23/23 passed |
| pact-cli build | `cargo build -p pact-cli` | success |
| receipt_query integration tests | `cargo test -p pact-cli --test receipt_query` | 12/12 passed |
| dashboard dist/ | presence of `dist/index.html` | EXISTS |

---

### Gaps Summary

No gaps blocking automated goal achievement. The single remaining item (PROD-05 stakeholder UX) is designated human verification because it requires browser interaction and usability judgment that cannot be automated. All Rust unit tests, integration tests, and the TypeScript build pass cleanly. The capability lineage index, agent-centric query API, HTTP endpoints, and dashboard SPA are all substantive and fully wired.

---

_Verified: 2026-03-22T08:00:00Z_
_Verifier: Claude (gsd-verifier)_
