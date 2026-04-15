# Summary 317-08

Phase `317` then took another focused `arc-cli` runtime export signature-cleanup
wave.

The implemented refactor updated:

- `crates/arc-cli/src/cli/runtime.rs`
- `crates/arc-cli/src/cli/dispatch.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave8 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `rg -n '^\s*#\[allow\(clippy::too_many_arguments\)\]' crates/arc-cli/src/cli/runtime.rs`
- `git diff --check -- crates/arc-cli/src/cli/runtime.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-cli/tests/capability_lineage.rs`

This wave removed four non-test `#[allow(clippy::too_many_arguments)]` sites:

- `cmd_trust_behavioral_feed_export`
- `cmd_trust_exposure_ledger_export`
- `cmd_trust_credit_scorecard_export`
- `cmd_trust_capital_book_export`

Those runtime export paths now use typed query/export input structs plus the
shared signed-query backend instead of long positional signatures, and the
dispatch layer constructs those typed inputs directly.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `43`
- remaining highest concentrations: `crates/arc-cli/src/cli/runtime.rs` (`7`),
  `crates/arc-cli/src/trust_control/capital_and_liability.rs` (`5`),
  `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`5`),
  `crates/arc-cli/src/passport.rs` (`4`), `crates/arc-mcp-edge/src/runtime.rs`
  (`4`), and `crates/arc-appraisal/src/lib.rs` (`4`)
