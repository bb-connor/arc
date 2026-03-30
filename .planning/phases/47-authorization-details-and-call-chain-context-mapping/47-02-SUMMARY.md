# Summary 47-02

Implemented local and remote authorization-context reporting surfaces.

## Delivered

- added a durable derived authorization-context query in
  `crates/arc-store-sqlite/src/receipt_store.rs`
- exposed `/v1/reports/authorization-context` plus composite operator-report
  inclusion in `crates/arc-cli/src/trust_control.rs`
- added `arc trust authorization-context list` in `crates/arc-cli/src/main.rs`
  for local SQLite or remote trust-control usage

## Notes

- report rows are derived from canonical governed receipt metadata
- commerce, metered-billing, approval, runtime-assurance, and call-chain scope
  remain separated but legible in one export
