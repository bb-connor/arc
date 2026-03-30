# Phase 84 Verification

status: passed

## Result

Phase 84 is complete. ARC now qualifies the `v2.18` credit layer with
deterministic backtests and one signed provider-facing risk package that ties
exposure, scorecard, facility posture, runtime assurance, certification, and
recent-loss history back to canonical ARC evidence.

## Commands

- `cargo test -p arc-core credit -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_credit_backtest_report_surfaces_drift_and_failure_modes -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_provider_risk_package_export_surfaces -- --exact --nocapture`
- `cargo fmt --all`
- `git diff --check`

## Notes

- provider risk packages are now recent-loss aware even when the general
  exposure ledger page is truncated, because recent-loss rows are queried from
  newest matching loss evidence directly
- `v2.18` remains intentionally bounded to capital review and facility policy;
  reserve locks, bond execution, and liability-market clearing move to `v2.19`
  and `v2.20`
