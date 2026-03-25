# Phase 16 Research

**Date:** 2026-03-24
**Status:** Complete

## Findings

1. `SqliteReceiptStore` already persisted imported share manifests, imported
   tool receipts, imported lineage snapshots, and local-to-remote bridge edges.
2. `get_combined_delegation_chain` already stitched native local lineage and
   imported parent lineage together truthfully.
3. Operator report and reputation comparison were the missing surfaces: both
   already had stable contracts and simply needed a shared-evidence section
   built from the imported-share index.
4. The dashboard did not need a new client-side provenance engine; the correct
   architecture was to extend the trust-control API contracts and render the
   server-side truth directly.

## Chosen Approach

- Build one shared-evidence report type in `pact-kernel`
- Reuse it in:
  - `GET /v1/federation/evidence-shares`
  - `GET /v1/reports/operator`
  - `POST /v1/reputation/compare/{subject_key}`
- Add one CLI wrapper and dashboard rendering over the same JSON contract

## Rejected Alternatives

- Joining imported foreign receipts directly into local receipt analytics:
  rejected because it would blur provenance and violate the import isolation
  decision already established in earlier federation work.
- Recomputing remote-reference attribution in the dashboard:
  rejected because it would duplicate server logic and risk drift between CLI,
  API, and UI surfaces.
