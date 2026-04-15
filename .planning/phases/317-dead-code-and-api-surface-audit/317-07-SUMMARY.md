# Summary 317-07

Phase `317` then took a follow-on `arc-cli` runtime reporting cleanup wave.

The implemented refactor updated:

- `crates/arc-cli/src/cli/runtime.rs`
- `crates/arc-cli/src/cli/dispatch.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave6 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave6 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `rg -n '^\s*#\[allow\(clippy::too_many_arguments\)\]' crates/arc-cli/src/cli/runtime.rs`
- `git diff --check -- crates/arc-cli/src/cli/trust_commands.rs crates/arc-cli/src/cli/runtime.rs crates/arc-cli/src/cli/dispatch.rs`

This wave removed four non-test `#[allow(clippy::too_many_arguments)]` sites:

- `cmd_trust_evidence_share_list`
- `cmd_trust_authorization_context_metadata`
- `cmd_trust_authorization_context_list`
- `cmd_trust_authorization_context_review_pack`

The `authorization_context_metadata` suppression was stale and could be removed
directly, while the evidence-share and authorization-context list/review-pack
paths now use typed query inputs plus the shared backend struct instead of long
positional signatures.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `47`
- remaining highest concentrations: `crates/arc-cli/src/cli/runtime.rs` (`11`),
  `crates/arc-cli/src/trust_control/capital_and_liability.rs` (`5`),
  `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`5`),
  `crates/arc-mcp-edge/src/runtime.rs` (`4`), `crates/arc-cli/src/passport.rs`
  (`4`), and `crates/arc-appraisal/src/lib.rs` (`4`)
