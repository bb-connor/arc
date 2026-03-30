# Summary 46-02

Implemented the trust-control and reporting surfaces for truthful metered-cost
reconciliation.

## Delivered

- added `/v1/reports/metered-billing` and
  `/v1/metered-billing/reconcile` trust-control endpoints in
  `crates/arc-cli/src/trust_control.rs`
- extended composite operator reporting with
  `metered_billing_reconciliation`
- extended behavioral-feed exports with metered-billing reconciliation
  summaries and per-receipt mutable sidecar state that stays separate from
  signed governed metadata

## Notes

- report rows show quote, financial, and adapter evidence side by side
- operator reconciliation state can suppress action-required rows without
  rewriting the signed receipt body
