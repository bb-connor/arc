# Summary 317-11

Phase `317` then took a focused `arc-mercury` helper-signature cleanup wave.

The implemented refactor updated:

- `crates/arc-mercury/src/commands/shared.rs`
- `crates/arc-mercury/src/commands/core_cli.rs`
- `crates/arc-mercury/src/commands/assurance_release.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave11 cargo check -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave11 cargo test -p arc-mercury --test cli`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-mercury/src/commands/shared.rs crates/arc-mercury/src/commands/core_cli.rs crates/arc-mercury/src/commands/assurance_release.rs`

This wave removed three non-test `#[allow(clippy::too_many_arguments)]` sites:

- `build_assurance_package`
- `build_governance_review_package`
- `build_assurance_review_package`

Those builder helpers now take typed input structs instead of long positional
signatures, and the `arc-mercury` command paths construct those typed inputs at
their local call sites.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `26`
- remaining highest concentrations: `crates/arc-appraisal/src/lib.rs` (`4`),
  `crates/arc-mcp-edge/src/runtime.rs` (`4`), `crates/arc-cli/src/passport.rs`
  (`4`), and `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`2`)
