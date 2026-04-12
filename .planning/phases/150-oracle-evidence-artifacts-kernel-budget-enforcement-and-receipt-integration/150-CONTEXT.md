# Phase 150 Context

## Goal

Use the new `arc-link` runtime inside the kernel so cross-currency reported
tool cost can be reconciled into grant currency with explicit oracle evidence
instead of the old "warn and keep mismatch" behavior.

## Constraints

- ARC receipts must remain canonical immutable receipts rather than mutable
  oracle-ledger records.
- Cross-currency reconciliation has to fit the current synchronous kernel API.
- Failure must remain conservative: if conversion cannot be justified, ARC
  keeps the provisional charge and records the failure explicitly instead of
  silently widening spend.

## Selected Approach

- add an optional `price_oracle` seam to `ArcKernel`
- synchronously bridge to the async oracle only at the narrow reconciliation
  point
- convert reported cost into grant currency when the oracle succeeds
- attach `financial.oracle_evidence` plus receipt-side conversion details
- mark settlement failed and preserve the provisional charge when conversion
  cannot be justified
