# Phase 86 Verification

status: passed

## Result

Phase 86 is complete. ARC now fails delegated and autonomous governed
execution closed unless the request carries explicit autonomy context, a valid
active delegation bond, matching call-chain scope, supported reserve posture,
and sufficient runtime assurance.

## Commands

- `cargo test -p arc-core constraint_serde_roundtrip -- --nocapture`
- `cargo test -p arc-core governed_transaction_receipt_metadata_serde_roundtrip -- --nocapture`
- `cargo test -p arc-kernel autonomy -- --nocapture`
- `cargo test -p arc-kernel weak_runtime_assurance -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture`
- `git diff --check`

## Notes

- runtime autonomy gating resolves delegation bonds through the configured
  receipt store and therefore denies fail closed when no receipt store is
  available
- phase `86` stops at reserve-backed autonomy gating; loss, recovery,
  delinquency, and reserve-release lifecycle state remain in phases `87` and
  `88`
