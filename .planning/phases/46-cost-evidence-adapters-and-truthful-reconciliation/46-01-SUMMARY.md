# Summary 46-01

Added the phase 46 metered-evidence adapter contract and durable persistence.

## Delivered

- introduced typed metered-billing reconciliation and evidence records in
  `crates/arc-kernel/src/operator_report.rs`
- added replay-safe mutable SQLite sidecar persistence keyed by `receipt_id`
  and `(adapter_kind, evidence_id)` in
  `crates/arc-store-sqlite/src/receipt_store.rs`
- added fail-closed validation so evidence cannot attach to receipts that lack
  governed metered-billing context

## Notes

- signed receipt JSON remains immutable
- external evidence is durable, queryable, and operator-reconcilable without
  becoming receipt truth
