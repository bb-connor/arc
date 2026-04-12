# Summary 110-02

Implemented instruction issuance, validation, and reconciliation handling in
`crates/arc-cli/src/trust_control.rs` and the CLI surface in
`crates/arc-cli/src/main.rs`.

Implemented:

- signed issuance at `POST /v1/capital/instructions/issue`
- CLI issuance via `arc trust capital-instruction issue`
- explicit authority-chain validation over owner approval, custody-provider
  execution, approval time, and expiry
- explicit execution-window validation plus separate intended versus
  reconciled execution state
- fail-closed rejection for stale authority, missing custodian approval,
  contradictory windows, mixed-currency or overstated amounts, action/source
  mismatches, and observed execution that does not match the intended amount

The handler preserves bounded HTTP failures instead of degrading negative
paths into generic server errors, so remote issuance remains fail closed and
operator-readable.
