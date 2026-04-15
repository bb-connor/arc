# Summary 317-10

Phase `317` then took a trust-control stale-suppression cleanup wave.

The implemented cleanup updated:

- `crates/arc-cli/src/trust_control/capital_and_liability.rs`
- `crates/arc-cli/src/trust_control/credit_and_loss.rs`

Verification that passed during this wave:

- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave10 cargo check -p arc-cli`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-cli/src/trust_control/capital_and_liability.rs crates/arc-cli/src/trust_control/credit_and_loss.rs`

This wave removed seven non-test `#[allow(clippy::too_many_arguments)]` sites
that had become stale after earlier refactors:

- `build_credit_bond_report`
- `build_credit_backtest_report`
- `build_signed_credit_provider_risk_package`
- `build_credit_backtest_report_from_store`
- `build_credit_provider_risk_package_from_store`
- `build_credit_facility_report_from_store`
- `build_credit_bond_report_from_store`

Those functions are now at or below the default Clippy threshold, so the
suppression layer was dead inventory rather than an active exemption.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `29`
- remaining highest concentrations: `crates/arc-appraisal/src/lib.rs` (`4`),
  `crates/arc-mcp-edge/src/runtime.rs` (`4`), `crates/arc-cli/src/passport.rs`
  (`4`), `crates/arc-mercury/src/commands/shared.rs` (`3`), and
  `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`2`)
