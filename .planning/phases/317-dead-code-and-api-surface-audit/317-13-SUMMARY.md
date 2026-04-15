# Summary 317-13

Phase `317` then took the next bounded `arc-cli` passport command-wrapper
cleanup wave.

The implemented refactor updated:

- `crates/arc-cli/src/passport.rs`
- `crates/arc-cli/src/cli/dispatch.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave13 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave13 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-cli/src/passport.rs crates/arc-cli/src/cli/dispatch.rs`

This wave removed four non-test `#[allow(clippy::too_many_arguments)]` sites:

- `cmd_passport_policy_create`
- `cmd_passport_challenge_create`
- `cmd_passport_oid4vp_request_create`
- `cmd_passport_oid4vp_respond`

Those passport command wrappers now take typed input structs, and the dispatch
layer constructs those typed inputs directly.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `18`
- remaining highest concentrations: `crates/arc-mcp-edge/src/runtime.rs` (`4`)
  and `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`2`)
