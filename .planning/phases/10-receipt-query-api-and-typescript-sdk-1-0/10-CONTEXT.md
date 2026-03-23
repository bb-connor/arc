# Phase 10: Receipt Query API and TypeScript SDK 1.0 - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Receipt query API in pact-kernel with cursor-based pagination and multi-filter support, exposed via CLI subcommand and HTTP endpoint. TypeScript SDK hardened to 1.0 with typed errors, DPoP proof generation helpers, and ReceiptQueryClient. No new enforcement logic or protocol changes -- product surface and developer experience.

</domain>

<decisions>
## Implementation Decisions

### Receipt Query API Design
- Cursor-based pagination using receipt seq (receipt_store already uses seq for delta queries); response includes next_cursor
- Budget impact filtering via min_cost and max_cost as separate optional params (range queries)
- Flat list response with total_count and next_cursor -- grouping deferred to Phase 12 dashboard
- Query module lives in receipt_query.rs in pact-kernel, co-located with receipt_store for direct SQLite access
- Filter parameters: capability_id, tool_server, tool_name, time_range (since/until), outcome, min_cost, max_cost

### CLI Receipt List UX
- Default output format: JSON lines (one receipt per line) -- pipeable, machine-readable
- Auto-paginate with --limit (default 50) and --cursor for manual cursor-walking
- Filter flags map 1:1 to query API: --capability, --tool, --since, --until, --outcome, --min-cost, --max-cost
- HTTP API endpoint: GET /v1/receipts/query on existing trust-control axum server (versioned path)

### TypeScript SDK 1.0 Scope
- Typed error classes extending PactError base: DpopSignError, QueryError, TransportError with error codes
- Explicit signDpopProof(params) function returning signed proof object -- not auto-middleware
- ReceiptQueryClient class included in SDK for querying receipts via HTTP API
- npm package name: @pact-protocol/sdk
- SDK version bumped from 0.1.0 to 1.0.0 with semantic versioning

### Claude's Discretion
- Internal receipt_query.rs struct layout and SQL query construction
- CLI help text and flag descriptions
- TypeScript SDK internal module organization
- ReceiptQueryClient pagination helper implementation details
- Error code numbering and message formatting

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `pact-kernel/src/receipt_store.rs` -- SqliteReceiptStore with list_tool_receipts (5-filter query), list_tool_receipts_after_seq (cursor-based), seq-based pagination
- `pact-cli/src/trust_control.rs` -- Existing axum HTTP endpoints for trust-control operations
- `pact-cli/src/main.rs` -- CLI subcommand routing with clap
- `packages/sdk/pact-ts/` -- Existing TS SDK at v0.1.0 with auth/, client/, session/, transport/ modules
- `pact-kernel/src/dpop.rs` -- DpopProofBody, DpopProof::sign for TS SDK to mirror

### Established Patterns
- SQLite queries use parameterized WHERE with IS NULL OR pattern for optional filters
- CLI uses clap derive macros for subcommand definitions
- Trust-control HTTP handlers use axum extractors and JSON responses
- TS SDK uses TypeScript with standard module exports from index.ts

### Integration Points
- receipt_query.rs builds on top of SqliteReceiptStore's existing list_tool_receipts method
- CLI receipt list subcommand calls receipt_query through the same kernel instance used by other CLI commands
- HTTP GET /receipts endpoint added to trust-control's axum router
- TS SDK DPoP helpers must produce proofs compatible with pact-kernel's verify_dpop_proof

</code_context>

<specifics>
## Specific Ideas

- The existing list_tool_receipts in receipt_store.rs already supports 5 filters -- receipt_query.rs extends this with budget impact and cursor pagination
- TS SDK DPoP proof generation must match the exact DpopProofBody schema from pact-kernel/src/dpop.rs (canonical JSON + Ed25519)
- Phase 12 (dashboard) will consume the receipt query API -- keep the API stable and well-documented
- SIEM exporters (Phase 11) use cursor-pull against the same receipt store -- align cursor semantics

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
