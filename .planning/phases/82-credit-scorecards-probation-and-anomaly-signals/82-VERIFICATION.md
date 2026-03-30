# Phase 82 Verification

status: passed

## Result

Phase 82 is complete. ARC now ships a signed, subject-scoped credit-scorecard
surface that combines canonical exposure-ledger truth with the existing local
reputation inspection, then exposes explicit confidence, probation, and
anomaly posture with evidence references.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-core credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query credit_scorecard -- --nocapture`
- `git diff --check`

## Notes

- the scorecard is intentionally narrower than facility issuance or capital
  allocation policy
- sparse history remains low-confidence and probationary rather than silently
  scoring as mature credit
