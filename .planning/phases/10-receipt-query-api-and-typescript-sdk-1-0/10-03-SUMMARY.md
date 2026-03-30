---
phase: 10-receipt-query-api-and-typescript-sdk-1-0
plan: "03"
subsystem: sdk
tags: [typescript, dpop, ed25519, canonical-json, receipt-query, npm]

# Dependency graph
requires:
  - phase: 09-receipt-archive-and-compliance-docs
    provides: receipt store and DPoP kernel implementation that SDK wraps
  - phase: 10-receipt-query-api-and-typescript-sdk-1-0
    plan: "01"
    provides: receipt query HTTP endpoint GET /v1/receipts/query
provides:
  - "@arc-protocol/sdk 1.0.0 with typed error hierarchy, DPoP proof generation, and ReceiptQueryClient"
  - "ArcError base class with DpopSignError, QueryError (with HTTP status), TransportError subclasses"
  - "signDpopProof function producing RFC 8785 canonical JSON proofs compatible with arc-kernel verify_dpop_proof"
  - "ReceiptQueryClient.query() and .paginate() for typed receipt querying"
  - "npm-publishable package (dry-run confirmed): @arc-protocol/sdk@1.0.0"
affects:
  - consumers of @arc-protocol/sdk
  - any TypeScript code using DPoP proofs with arc-kernel

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "TDD red-green cycle: write failing tests, implement minimally, verify green, commit"
    - "Snake_case field names in DpopProofBody matching Rust/serde serialization exactly"
    - "RFC 8785 alphabetical canonical JSON ensures TS signatures verify in Rust"
    - "Mock fetch injection pattern for ReceiptQueryClient testing without live server"
    - "ArcError SDK layer distinct from ArcInvariantError invariant layer"

key-files:
  created:
    - packages/sdk/arc-ts/src/errors.ts
    - packages/sdk/arc-ts/src/dpop.ts
    - packages/sdk/arc-ts/src/receipt_query_client.ts
    - packages/sdk/arc-ts/test/dpop.test.ts
    - packages/sdk/arc-ts/test/receipt_query_client.test.ts
  modified:
    - packages/sdk/arc-ts/src/index.ts
    - packages/sdk/arc-ts/package.json
    - packages/sdk/arc-ts/tsconfig.json
    - packages/sdk/arc-ts/test/errors.test.ts

key-decisions:
  - "DpopProofBody fields use snake_case (not camelCase) to match Rust serde serialization for cross-language verifiability"
  - "ArcError (SDK layer) is separate from ArcInvariantError (invariant layer) -- different error hierarchies for different abstraction levels"
  - "QueryError accepts optional status parameter as second constructor arg (not in ErrorOptions) for typed HTTP status access"
  - "package.json smoke tests use readFile+JSON.parse instead of createRequire to avoid ESM/CJS module path resolution issues"
  - "tsconfig.json updated from noEmit:true to outDir:dist with declaration:true, retaining strict and exactOptionalPropertyTypes"

patterns-established:
  - "Error hierarchy pattern: ArcError base with typed subclasses carrying semantic codes"
  - "DPoP proof pattern: canonicalizeJson body then signEd25519Message for cross-language compatibility"
  - "paginate() async generator terminates on missing/null nextCursor"

requirements-completed: [PROD-06]

# Metrics
duration: 3min
completed: 2026-03-23
---

# Phase 10 Plan 03: TypeScript SDK 1.0 -- Typed Errors, DPoP Proofs, and ReceiptQueryClient Summary

**@arc-protocol/sdk@1.0.0 with typed error hierarchy (ArcError/DpopSignError/QueryError/TransportError), RFC 8785 DPoP proof generation compatible with arc-kernel verify_dpop_proof, and ReceiptQueryClient with cursor-based pagination**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-23T00:25:07Z
- **Completed:** 2026-03-23T00:28:39Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Typed error hierarchy: ArcError base class with DpopSignError (dpop_sign_error), QueryError (query_error + HTTP status), TransportError (transport_error) -- all instanceof ArcError
- signDpopProof function producing DPoP proofs with RFC 8785 canonical JSON body, Ed25519 signature over canonical body, matching arc-kernel DpopProofBody schema exactly (snake_case fields, alphabetical canonical order)
- ReceiptQueryClient.query() fetching GET /v1/receipts/query with Authorization Bearer header, typed params, typed response; throws QueryError on non-2xx, TransportError on network failure
- ReceiptQueryClient.paginate() async generator following nextCursor across pages until exhausted
- Package renamed @arc/sdk -> @arc-protocol/sdk at 1.0.0 with private:true removed; npm publish --dry-run confirmed publishable
- tsconfig.json updated to emit dist/ with .d.ts declarations and source maps
- 55 total SDK tests pass (26 new: 13 error hierarchy + 13 DPoP + 14 ReceiptQueryClient + 2 package smoke)

## Task Commits

1. **Task 1: Add typed error hierarchy and DPoP proof generation** - `5f2a542` (feat)
2. **Task 2: Add ReceiptQueryClient, build pipeline, and package rename to 1.0.0** - `418bd56` (feat)

## Files Created/Modified

- `packages/sdk/arc-ts/src/errors.ts` - ArcError base, DpopSignError, QueryError, TransportError
- `packages/sdk/arc-ts/src/dpop.ts` - signDpopProof, DpopProofBody, DpopProof, DPOP_SCHEMA
- `packages/sdk/arc-ts/src/receipt_query_client.ts` - ReceiptQueryClient with query() and paginate()
- `packages/sdk/arc-ts/src/index.ts` - Added exports for errors, dpop, receipt_query_client
- `packages/sdk/arc-ts/package.json` - Renamed to @arc-protocol/sdk 1.0.0, removed private, added build script
- `packages/sdk/arc-ts/tsconfig.json` - Updated for dist/ output with declaration + sourceMap
- `packages/sdk/arc-ts/test/errors.test.ts` - Extended with ArcError hierarchy tests
- `packages/sdk/arc-ts/test/dpop.test.ts` - New: DPoP proof generation + cross-language verification tests
- `packages/sdk/arc-ts/test/receipt_query_client.test.ts` - New: ReceiptQueryClient + package smoke tests

## Decisions Made

- DpopProofBody fields use snake_case matching Rust serde to ensure TypeScript signatures verify in Rust via verifyEd25519Signature over canonical JSON
- ArcError (SDK layer) is a distinct hierarchy from ArcInvariantError (invariant layer) -- different abstraction levels, don't mix
- QueryError puts HTTP status as second constructor positional arg, not in ErrorOptions, for typed access as err.status
- Package smoke tests use readFile+JSON.parse instead of createRequire to avoid ESM/CJS resolver incompatibility in Node 25
- tsconfig.json preserves exactOptionalPropertyTypes and noUncheckedIndexedAccess from previous config while adding build output settings

## Deviations from Plan

None -- plan executed exactly as written (one minor auto-fix: package.json smoke test approach changed from createRequire to readFile to fix Node 25 module resolution, classified as Rule 1 bug fix in test code).

## Issues Encountered

Package.json smoke tests initially used `createRequire(testDir)` to load package.json, but Node 25's module resolver couldn't find `../package.json` relative to a directory path. Fixed by switching to `readFile` + `JSON.parse`, which works reliably in ESM context.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- @arc-protocol/sdk@1.0.0 is ready for npm publish (requires npm org credentials for @arc-protocol scope)
- PROD-06 requirement fulfilled
- All 55 SDK tests pass
- ReceiptQueryClient ready for integration with deployed arc-kernel HTTP server
