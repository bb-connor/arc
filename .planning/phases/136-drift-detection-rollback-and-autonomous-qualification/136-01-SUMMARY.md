# Summary 136-01

Defined drift detection and rollback-control surfaces for bounded autonomous
insurance automation.

## Delivered

- added rollback plans, drift signals, drift reports, and validation in
  `crates/arc-core/src/autonomy.rs`
- published `docs/standards/ARC_AUTONOMOUS_DRIFT_REPORT_EXAMPLE.json`

## Result

Critical automation drift now engages one explicit fail-safe path instead of
becoming an undocumented operational exception.
