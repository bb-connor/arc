# Summary 317-17

Phase `317` then took the remaining `arc-credentials` singleton cleanup wave.

The implemented refactor updated:

- `crates/arc-credentials/src/cross_issuer.rs`
- `crates/arc-credentials/src/challenge.rs`
- `crates/arc-credentials/src/portable_reputation.rs`
- `crates/arc-credentials/src/oid4vci.rs`
- `crates/arc-credentials/src/tests.rs`
- `crates/arc-cli/src/trust_control/http_handlers_a.rs`
- `crates/arc-cli/src/passport.rs`
- `crates/arc-cli/src/trust_control/service_runtime.rs`
- `crates/arc-cli/tests/certify.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-credentials -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave17-cred cargo test -p arc-credentials --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave17-cred-integration cargo test -p arc-credentials --test integration_smoke`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave17-cli cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave17-cli-tests cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave17-certify cargo test -p arc-cli --test certify --no-run`
- `git diff --check -- crates/arc-credentials/src/cross_issuer.rs crates/arc-credentials/src/challenge.rs crates/arc-credentials/src/portable_reputation.rs crates/arc-credentials/src/oid4vci.rs crates/arc-credentials/src/tests.rs crates/arc-cli/src/trust_control/http_handlers_a.rs crates/arc-cli/src/passport.rs crates/arc-cli/src/trust_control/service_runtime.rs crates/arc-cli/tests/certify.rs`

This wave removed four non-test `#[allow(clippy::too_many_arguments)]` sites:

- `create_signed_cross_issuer_migration`
- `create_passport_presentation_challenge_with_reference`
- `build_portable_reputation_summary_artifact`
- `new_portable_compact`

Those boundaries now take typed input structs or request contexts instead of
long positional argument lists, and the workspace non-test
`#[allow(clippy::too_many_arguments)]` inventory dropped from `8` to `4`.
