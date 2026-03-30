# Phase 85 Verification

status: passed

## Result

Phase 85 is complete. ARC now ships one signed bond, reserve-lock, and
collateral-state contract over canonical exposure and active facility truth,
with explicit `lock`, `hold`, `release`, and `impair` posture plus fail-closed
mixed-currency reserve accounting.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-core credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_bond -- --nocapture`
- `git diff --check`

## Notes

- bond disposition now uses the full-set underwriting settlement summary for
  pending and failed posture, so reserve state reflects the newest unresolved
  receipts even when the general paged exposure selection is oldest-first
- this phase stops at signed reserve and collateral truth; delegation-bond
  gating, slashing, and loss-lifecycle execution remain in phases `86` and
  `87`
