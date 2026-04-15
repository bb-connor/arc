# Summary 317-12

Phase `317` then took a focused `arc-appraisal` attestation-surface cleanup
wave.

The implemented refactor updated:

- `crates/arc-appraisal/src/lib.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-appraisal`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave12 cargo test -p arc-appraisal --lib`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**' | wc -l`
- `git diff --check -- crates/arc-appraisal/src/lib.rs`

This wave removed four non-test `#[allow(clippy::too_many_arguments)]` sites:

- `create_signed_runtime_attestation_verifier_descriptor`
- `create_signed_runtime_attestation_reference_value_set`
- `create_signed_runtime_attestation_trust_bundle`
- `RuntimeAttestationAppraisal::artifact`

Those public attestation constructors and the internal artifact builder now use
typed argument structs instead of long positional signatures.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `22`
- remaining highest concentrations: `crates/arc-mcp-edge/src/runtime.rs` (`4`),
  `crates/arc-cli/src/passport.rs` (`4`), and
  `crates/arc-cli/src/trust_control/credit_and_loss.rs` (`2`)
