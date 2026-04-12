# Phase 115-01 Summary

Phase `115-01` is complete.

ARC now defines explicit liability claim payout instruction and payout receipt
artifacts over adjudicated claim truth and capital-execution truth. The
implementation adds:

- `LiabilityClaimPayoutInstructionArtifact` and
  `LiabilityClaimPayoutReceiptArtifact` in `crates/arc-core/src/market.rs`
- durable payout-instruction and payout-receipt persistence in
  `crates/arc-store-sqlite/src/receipt_store.rs`
- trust-control issuance endpoints and CLI surfaces in
  `crates/arc-cli/src/trust_control.rs` and `crates/arc-cli/src/main.rs`

The payout lane is intentionally narrow:

- payout instructions require a payable adjudication outcome
- payout instructions require one unreconciled `transfer_funds`
  `facility_commitment` capital instruction with matching subject and amount
- payout receipts are separate artifacts rather than mutating claim or capital
  truth

This closes the artifact-definition portion of phase `115`.
