# Phase 414 Context: Partner-Visible Receipt and Settlement Contracts

## Why This Phase Exists

ARC already has governed receipts, checkpoints, inclusion proofs, settlement
artifacts, market artifacts, credit artifacts, and underwriting artifacts. But
being comptroller-capable is not enough. For the market thesis, those outputs
must become explicit partner-facing contract surfaces that third parties can
consume for billing, settlement, dispute, audit, and reconciliation.

Phase `414` converts ARC evidence and economic artifacts into partner-visible
contracts rather than repo-local data models.

## Required Outcomes

1. Define the partner-consumable contract package for receipts, checkpoints,
   inclusion proofs, reconciliation, and settlement.
2. Define how market, underwriting, and credit artifacts participate in
   partner-facing economic workflows.
3. Make governed receipt-bearing paths clearly authoritative and degraded
   passthrough paths clearly non-authoritative for partner workflows.

## Existing Assets

- `crates/arc-http-core/src/receipt.rs`
- `crates/arc-kernel/src/checkpoint.rs`
- `crates/arc-market/src/lib.rs`
- `crates/arc-open-market/src/lib.rs`
- `crates/arc-credit/src/lib.rs`
- `crates/arc-underwriting/src/lib.rs`
- `crates/arc-settle/src`
- multi-language SDK passthrough metadata (`allow_without_receipt`)

## Gaps To Close

- partner contract packaging is still implicit and scattered
- settlement and reconciliation evidence is not yet framed as the primary
  partner contract surface
- degraded compatibility paths are honest, but not yet fully integrated into
  the partner-authority story

## Requirements Mapped

- `PARTNER4-01`
- `PARTNER4-02`
- `PARTNER4-03`

## Exit Criteria

This phase is complete only when an external partner can understand which ARC
artifacts they consume, what they mean, and which flows are authoritative
without reading the crate internals.
