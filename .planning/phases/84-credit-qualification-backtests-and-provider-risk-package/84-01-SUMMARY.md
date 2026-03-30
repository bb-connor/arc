# Summary 84-01

Added deterministic historical backtests for ARC's credit layer.

## Delivered

- defined a typed credit-backtest report with bounded replay-window and
  reason-code semantics
- implemented subject-scoped replay over exposure, scorecard, and facility
  policy so drift and failure modes are explicit
- covered stale evidence, mixed-currency books, utilization overage, missing
  runtime assurance, and settlement-backlog drift in regression tests
