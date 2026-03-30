---
phase: 10-receipt-query-api-and-typescript-sdk-1-0
verified: 2026-03-22T12:00:00Z
status: passed
score: 11/11 must-haves verified
re_verification: false
---

# Phase 10: Receipt Query API and TypeScript SDK 1.0 -- Verification Report

**Phase Goal:** Receipts are queryable through a stable API and the TypeScript SDK is published at 1.0 with DPoP proof generation helpers.
**Verified:** 2026-03-22
**Status:** passed
**Re-verification:** No -- initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | query_receipts filters by capability_id, tool_server, tool_name, outcome, time range, and budget impact | VERIFIED | `receipt_store.rs:615` -- `query_receipts_impl` uses parameterized SQL with IS NULL OR pattern for all 8 dimensions; 18 unit tests cover each dimension individually and in combination |
| 2 | query_receipts returns cursor-paginated results using seq-based exclusive cursor | VERIFIED | SQL clause `AND (?9 IS NULL OR seq > ?9) ORDER BY seq ASC LIMIT ?10`; `test_query_cursor_pagination_pages` traverses 7 receipts without duplicates |
| 3 | min_cost/max_cost filters only match receipts with financial metadata (NULL json_extract excluded) | VERIFIED | SQL uses `CAST(json_extract(raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7`; NULL cast from non-financial receipts fails the inequality, naturally excluding them; `test_query_filter_cost_range_min` and `test_query_filter_cost_range_max` confirm |
| 4 | total_count reflects the full filtered set without LIMIT | VERIFIED | Separate COUNT(*) query in `receipt_store.rs` uses same WHERE filters but no cursor clause; `test_query_total_count` inserts 10 receipts, fetches limit=3, asserts total_count==10 |
| 5 | next_cursor is Some(last_seq) when results.len() == limit, None otherwise | VERIFIED | `receipt_store.rs:724` -- `if receipts.len() == limit { receipts.last().map(|r| r.seq) } else { None }`; `test_query_next_cursor_some_when_more` and `test_query_next_cursor_none_when_last_page` confirm |
| 6 | GET /v1/receipts/query returns filtered, paginated receipt results over HTTP | VERIFIED | `trust_control.rs:1403` -- `handle_query_receipts` handler; route wired at line 543: `.route(RECEIPT_QUERY_PATH, get(handle_query_receipts))`; 5 integration tests in `crates/arc-cli/tests/receipt_query.rs` all pass |
| 7 | arc receipt list CLI subcommand outputs JSON Lines (one receipt per line) to stdout | VERIFIED | `main.rs:1428` -- `cmd_receipt_list` uses `println!("{}", serde_json::to_string(...))` per receipt; `ReceiptCommands::List` variant defined at line 332 |
| 8 | CLI filter flags map 1:1 to query API and routes through TrustControlClient when --control-url is set | VERIFIED | `main.rs:1443-1464` branches on `control_url`; builds `ReceiptQueryHttpQuery` and calls `client.query_receipts(&query)` in remote mode; builds `arc_kernel::ReceiptQuery` and calls `store.query_receipts` in direct mode |
| 9 | SDK package is named @arc-protocol/sdk at version 1.0.0 with private:true removed | VERIFIED | `package.json` confirms: `"name": "@arc-protocol/sdk"`, `"version": "1.0.0"`, no `"private"` field; confirmed by 3 passing package smoke tests |
| 10 | signDpopProof produces canonical JSON DPoP proofs matching arc-kernel DpopProofBody schema exactly | VERIFIED | `dpop.ts` exports `DPOP_SCHEMA = "arc.dpop_proof.v1"`, `DpopProofBody` interface with snake_case fields matching Rust struct; `canonicalizeJson(body)` ensures RFC 8785 alphabetical ordering; 13 DPoP tests pass including cross-language signature verification |
| 11 | ReceiptQueryClient.query() and .paginate() fetch receipts from GET /v1/receipts/query with typed params | VERIFIED | `receipt_query_client.ts` -- `query()` constructs URL with camelCase params, passes Bearer auth header, throws `QueryError` on non-200 and `TransportError` on network failure; `paginate()` is an async generator following `nextCursor`; 9 ReceiptQueryClient tests pass |

**Score:** 11/11 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/arc-kernel/src/receipt_query.rs` | ReceiptQuery struct, ReceiptQueryResult struct, query_receipts method on SqliteReceiptStore | VERIFIED | File exists (619 lines), exports `ReceiptQuery`, `ReceiptQueryResult`, `MAX_QUERY_LIMIT`; `impl SqliteReceiptStore { pub fn query_receipts }` delegates to `query_receipts_impl` in receipt_store.rs |
| `crates/arc-kernel/src/lib.rs` | pub mod receipt_query and re-exports | VERIFIED | Line 28: `pub mod receipt_query;`; Line 72: `pub use receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};` |
| `crates/arc-cli/src/trust_control.rs` | GET /v1/receipts/query endpoint, ReceiptQueryHttpQuery, ReceiptQueryResponse, TrustControlClient.query_receipts | VERIFIED | `RECEIPT_QUERY_PATH` constant at line 50; `ReceiptQueryHttpQuery` struct at line 221; `ReceiptQueryResponse` at line 247; `handle_query_receipts` handler at line 1403; route wired at line 543; `TrustControlClient.query_receipts` at line 677 |
| `crates/arc-cli/src/main.rs` | Receipt subcommand with List variant and filter args | VERIFIED | `Commands::Receipt` at line 140; `ReceiptCommands::List` with all 10 flags (--capability, --tool-server, --tool-name, --outcome, --since, --until, --min-cost, --max-cost, --limit, --cursor) at line 332; dispatch and `cmd_receipt_list` at line 1428 |
| `crates/arc-cli/tests/receipt_query.rs` | Integration tests for receipt query HTTP endpoint | VERIFIED | File exists (389 lines); 5 tests: no_filters, filter_capability, cursor_pagination, total_count, requires_auth -- all pass |
| `packages/sdk/arc-ts/src/errors.ts` | ArcError base class, DpopSignError, QueryError, TransportError | VERIFIED | All 4 classes present with correct codes and `instanceof ArcError` chain; `QueryError` carries optional `status: number` |
| `packages/sdk/arc-ts/src/dpop.ts` | signDpopProof function, DpopProofBody interface, DpopProof interface | VERIFIED | `DPOP_SCHEMA`, `DpopProofBody`, `DpopProof`, `SignDpopProofParams`, `signDpopProof` all exported; imports from `./invariants/crypto.ts` and `./invariants/json.ts` |
| `packages/sdk/arc-ts/src/receipt_query_client.ts` | ReceiptQueryClient class with query() and paginate() methods | VERIFIED | `ReceiptQueryClient`, `ReceiptQueryParams`, `ReceiptQueryResponse` exported; query() and paginate() implemented |
| `packages/sdk/arc-ts/package.json` | Package config at @arc-protocol/sdk 1.0.0 with build script | VERIFIED | `"name": "@arc-protocol/sdk"`, `"version": "1.0.0"`, `"build": "tsc"`, no private field |
| `packages/sdk/arc-ts/tsconfig.json` | TypeScript compilation config targeting dist/ with declarations | VERIFIED | `"outDir": "./dist"`, `"declaration": true`, `"declarationMap": true`, `"sourceMap": true` |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `crates/arc-kernel/src/receipt_query.rs` | `crates/arc-kernel/src/receipt_store.rs` | `self.query_receipts_impl(query)` on SqliteReceiptStore | WIRED | `query_receipts` at line 53 calls `self.query_receipts_impl(query)`; `query_receipts_impl` is `pub(crate)` in `receipt_store.rs` at line 615 |
| `crates/arc-cli/src/trust_control.rs` | `crates/arc-kernel/src/receipt_query.rs` | `store.query_receipts(&kernel_query)` | WIRED | `ReceiptQuery` imported from `arc_kernel` at line 21; called at line 1427: `store.query_receipts(&kernel_query)` |
| `crates/arc-cli/src/main.rs` | `crates/arc-cli/src/trust_control.rs` | `ReceiptCommands::List` dispatch through `cmd_receipt_list` | WIRED | Dispatch at line 548; `cmd_receipt_list` at line 1428 calls `trust_control::build_client`, `trust_control::ReceiptQueryHttpQuery`, and `client.query_receipts` |
| `packages/sdk/arc-ts/src/dpop.ts` | `packages/sdk/arc-ts/src/invariants/crypto.ts` | `signEd25519Message, sha256Hex` imports | WIRED | Line 4: `import { signEd25519Message, sha256Hex } from "./invariants/crypto.ts";` |
| `packages/sdk/arc-ts/src/dpop.ts` | `packages/sdk/arc-ts/src/invariants/json.ts` | `canonicalizeJson` import | WIRED | Line 5: `import { canonicalizeJson } from "./invariants/json.ts";` |
| `packages/sdk/arc-ts/src/receipt_query_client.ts` | `GET /v1/receipts/query` (API contract) | URL construction in `query()` | WIRED | Line 35: `new URL(\`${this.baseUrl}/v1/receipts/query\`)`; matches Rust constant `RECEIPT_QUERY_PATH = "/v1/receipts/query"` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| PROD-01 | 10-01, 10-02 | Receipt query API supports filtering by capability, tool, time range, outcome, and budget impact | SATISFIED | `query_receipts` in arc-kernel with 8 filter dimensions; GET /v1/receipts/query HTTP endpoint; `arc receipt list` CLI subcommand; 18 unit tests + 5 integration tests pass |
| PROD-06 | 10-03 | TypeScript SDK 1.0 with DPoP proof generation helpers | SATISFIED | `@arc-protocol/sdk@1.0.0` with `signDpopProof`, typed error hierarchy, `ReceiptQueryClient`; 40 SDK tests pass; package confirmed publishable |

Both requirements mapped to Phase 10 in REQUIREMENTS.md traceability table are fully satisfied. No orphaned requirements found for this phase.

---

## Anti-Patterns Found

No anti-patterns detected in phase artifacts:

- No TODO/FIXME/PLACEHOLDER comments in modified files
- No empty implementations or stub returns
- No console.log-only handlers
- Clippy passes clean on arc-kernel and arc-cli with `-D warnings`
- No `unwrap_used` or `expect_used` outside `#[cfg(test)]` blocks

---

## Human Verification Required

None. All phase goals are verified programmatically through tests:

- All 18 arc-kernel unit tests pass (`cargo test -p arc-kernel receipt_query`)
- All 5 arc-cli integration tests pass (`cargo test -p arc-cli --test receipt_query`)
- All 40 TypeScript SDK tests pass (errors, dpop, receipt_query_client, package smoke)
- Clippy clean on all modified crates

The only post-phase step that requires human action is the actual `npm publish` for `@arc-protocol/sdk@1.0.0` (requires npm org credentials for the `@arc-protocol` scope). This is an operational step explicitly deferred per plan decision, not a gap in goal achievement.

---

## Summary

Phase 10 fully achieves its goal. The receipt query engine is implemented at three layers:

1. **Data layer** (`arc-kernel`): `ReceiptQuery` with 8 filter dimensions, cursor pagination, separate `COUNT(*)` for total_count, and `MAX_QUERY_LIMIT=200`. 18 unit tests cover all filter combinations.

2. **API and CLI layer** (`arc-cli`): GET `/v1/receipts/query` HTTP endpoint with auth enforcement, `arc receipt list` subcommand with 10 flags, JSON Lines stdout output. 5 integration tests prove end-to-end filtering, pagination, and 401 enforcement.

3. **TypeScript SDK** (`@arc-protocol/sdk@1.0.0`): Typed error hierarchy (ArcError, DpopSignError, QueryError, TransportError), `signDpopProof` producing RFC 8785 canonical JSON proofs compatible with arc-kernel, `ReceiptQueryClient.query()` and `.paginate()`, tsconfig outputting to `dist/` with `.d.ts` declarations.

PROD-01 and PROD-06 are both fully satisfied.

---

_Verified: 2026-03-22_
_Verifier: Claude (gsd-verifier)_
