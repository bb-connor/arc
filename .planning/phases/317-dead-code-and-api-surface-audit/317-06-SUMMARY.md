# Summary 317-06

Phase `317` then took a focused `arc-cli` trust-command signature-cleanup wave.

The implemented refactor updated:

- `crates/arc-cli/src/cli/trust_commands.rs`
- `crates/arc-cli/src/cli/dispatch.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave6 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave6 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates/arc-cli/src/cli/trust_commands.rs`
- `git diff --check -- crates/arc-cli/src/cli/trust_commands.rs crates/arc-cli/src/cli/dispatch.rs`

This wave removed twelve non-test `#[allow(clippy::too_many_arguments)]`
sites by introducing typed argument and backend structs for these trust-command
paths:

- `cmd_trust_credit_loss_lifecycle_list`
- `cmd_trust_credit_backtest_export`
- `cmd_trust_provider_risk_package_export`
- `cmd_trust_liability_market_list`
- `cmd_trust_liability_claims_list`
- `cmd_trust_underwriting_input_export`
- `cmd_trust_underwriting_decision_evaluate`
- `cmd_trust_underwriting_decision_simulate`
- `cmd_trust_underwriting_decision_issue`
- `cmd_trust_underwriting_decision_list`
- `cmd_trust_underwriting_appeal_resolve`
- `cmd_receipt_list`

The dispatch layer now constructs explicit typed inputs instead of sending long
positional argument lists into `trust_commands.rs`, and that file no longer
contains any `too_many_arguments` suppressions.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `51`
- remaining highest concentrations: `crates/arc-cli/src/cli/runtime.rs` (`15`),
  `crates/arc-cli/src/trust_control/capital_and_liability.rs` (`5`),
  `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`5`),
  `crates/arc-cli/src/passport.rs` (`4`), `crates/arc-mcp-edge/src/runtime.rs`
  (`4`), and `crates/arc-appraisal/src/lib.rs` (`4`)
