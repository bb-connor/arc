# Summary 46-03

Closed the phase with docs and regression coverage for adapter ingestion,
replay, and missing-evidence handling.

## Delivered

- updated `spec/PROTOCOL.md` to document the mutable metered-evidence sidecar
  boundary
- updated `docs/TOOL_PRICING_GUIDE.md` to explain the quote / financial /
  external-evidence split
- added integration coverage in `crates/arc-cli/tests/receipt_query.rs` for:
  - metered evidence attachment
  - replay rejection across receipts
  - non-metered receipt rejection
  - operator report and behavioral-feed visibility
  - proof that signed receipt query results still carry `usageEvidence: null`

## Notes

- replay and wrong-surface attachment both fail closed with conflict responses
- the behavioral feed exposes mutable metered reconciliation next to, not
  inside, the signed governed block
