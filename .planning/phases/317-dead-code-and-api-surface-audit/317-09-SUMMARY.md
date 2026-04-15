# Summary 317-09

Phase `317` then took another focused `arc-cli` runtime signature-cleanup wave.

The implemented refactor updated:

- `crates/arc-cli/src/cli/runtime.rs`
- `crates/arc-cli/src/cli/dispatch.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave9 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave9 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `rg -n '^\s*#\[allow\(clippy::too_many_arguments\)\]' crates/arc-cli/src/cli/runtime.rs`
- `git diff --check -- crates/arc-cli/src/cli/runtime.rs crates/arc-cli/src/cli/dispatch.rs`

This wave removed seven non-test `#[allow(clippy::too_many_arguments)]` sites:

- `cmd_trust_capital_allocation_issue`
- `cmd_trust_credit_facility_evaluate`
- `cmd_trust_credit_facility_issue`
- `cmd_trust_credit_facility_list`
- `cmd_trust_credit_bond_evaluate`
- `cmd_trust_credit_bond_issue`
- `cmd_trust_credit_bond_list`

Those runtime issuance and list paths now use typed query/input structs plus
the shared `QueryBackend` / `SignedQueryBackend` helpers instead of long
positional signatures, and the dispatch layer constructs those typed inputs
directly.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `36`
- `crates/arc-cli/src/cli/runtime.rs`: `0`
- remaining highest concentrations: `crates/arc-cli/src/trust_control/credit_and_loss.rs`
  (`5`), `crates/arc-cli/src/trust_control/capital_and_liability.rs` (`5`),
  `crates/arc-appraisal/src/lib.rs` (`4`), `crates/arc-mcp-edge/src/runtime.rs`
  (`4`), `crates/arc-cli/src/passport.rs` (`4`), and
  `crates/arc-mercury/src/commands/shared.rs` (`3`)
