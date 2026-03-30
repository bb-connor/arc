# Phase 87 Verification

status: passed

## Result

Phase 87 is complete. ARC now records delinquency, recovery, reserve-release,
and write-off as immutable signed bond-loss lifecycle artifacts, with
delinquency derived from recent failed-loss evidence rather than from a
truncated exposure page.

## Commands

- `cargo test -p arc-cli --test receipt_query credit_loss_lifecycle -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_bond_report_impairs_and_fails_closed_on_mixed_currency -- --nocapture`
- `git diff --check`

## Notes

- lifecycle persistence updates current bond projection without mutating the
  previously signed bond or receipt bodies
- reserve release remains bounded: ARC requires cleared delinquency and no
  remaining unbooked outstanding exposure before releasing reserve state
