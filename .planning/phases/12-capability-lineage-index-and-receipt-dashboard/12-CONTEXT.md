# Phase 12: Capability Lineage Index and Receipt Dashboard - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Capability lineage index in arc-kernel persisting capability snapshots at issuance time with delegation chain tracking, agent-centric receipt queries via JOIN extension, and a React 18 + Vite 6 receipt dashboard SPA served by axum via tower_http::ServeDir. Non-engineer stakeholders can filter receipts by agent/tool/outcome/time and inspect delegation chains and budget views.

</domain>

<decisions>
## Implementation Decisions

### Capability Lineage Index Design
- Index stored in SQLite table in arc-kernel alongside receipt store -- co-located for efficient joins
- Capability snapshots persisted at issuance time (when kernel creates a new capability)
- Keyed by capability_id with subject, issuer, grants, and delegation metadata
- Agent-centric queries via JOIN capability_lineage ON capability_id extending existing receipt_query.rs with agent filter
- Delegation chain tracked via parent_capability_id foreign key enabling recursive chain walks

### Receipt Dashboard Stack
- React 18 + Vite 6 for the SPA
- TanStack Table 8 for headless, type-safe data tables with pagination/sorting
- Recharts 2 for budget/cost visualization charts
- Served via axum tower_http::ServeDir from dist/ directory -- no separate web server

### Dashboard UX
- Default view: receipt list with filters sidebar (agent, tool, outcome, time range)
- Delegation chain: expandable tree in receipt detail panel (click to expand parent chain)
- Budget view: per-agent cost summary with sparkline chart showing spend over time
- Authentication: same Bearer token as trust-control API -- reuse existing auth

### Claude's Discretion
- capability_lineage SQLite table schema details beyond core columns
- React component structure and file organization
- TanStack Table column definitions and sorting defaults
- Recharts sparkline configuration and styling
- Dashboard CSS/styling approach
- Vite build configuration details

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc-kernel/src/receipt_query.rs` -- ReceiptQuery, query_receipts for receipt filtering and pagination
- `arc-kernel/src/receipt_store.rs` -- SqliteReceiptStore, receipt persistence, seq-based cursors
- `arc-cli/src/trust_control.rs` -- axum HTTP server, existing trust-control endpoints, Bearer auth
- `arc-core/src/capability.rs` -- CapabilityToken, ToolGrant, ArcScope for capability snapshots

### Established Patterns
- SQLite stores with WAL mode, SYNCHRONOUS=FULL
- axum handlers with JSON responses and Bearer auth extractors
- receipt_query.rs cursor-based pagination with ReceiptQueryResult

### Integration Points
- capability_lineage table created alongside existing receipt and budget tables in kernel
- Agent-centric query extends ReceiptQuery struct with optional agent_subject filter
- Dashboard SPA builds to dist/ and is served by axum ServeDir alongside API routes
- Dashboard calls GET /v1/receipts/query (Phase 10) and new lineage/agent endpoints

</code_context>

<specifics>
## Specific Ideas

- ROADMAP specifies React 18 / Vite 6 / TanStack Table 8 / Recharts 2 stack
- Success criterion 3: "non-engineer stakeholder" must be able to use dashboard without CLI access
- Success criterion 4: delegation chain inspection and budget views for monetary grants
- Phase 10's receipt query API is the data source for the dashboard

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
