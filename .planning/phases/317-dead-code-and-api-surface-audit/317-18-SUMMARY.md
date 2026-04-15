# Summary 317-18

Phase `317` then cleared the last four cross-crate singleton
`too_many_arguments` suppressions.

The implemented refactor updated:

- `crates/arc-kernel/src/kernel/responses.rs`
- `crates/arc-kernel/src/kernel/mod.rs`
- `crates/arc-store-sqlite/src/receipt_store/support.rs`
- `crates/arc-store-sqlite/src/receipt_store/reports.rs`
- `crates/arc-mercury-core/src/proof_package.rs`
- `crates/arc-mercury-core/src/pilot.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-kernel -p arc-store-sqlite -p arc-mercury-core`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave18-kernel cargo test -p arc-kernel --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave18-store cargo test -p arc-store-sqlite --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave18-mercury cargo test -p arc-mercury-core --lib`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**'`
- `git diff --check -- crates/arc-kernel/src/kernel/responses.rs crates/arc-kernel/src/kernel/mod.rs crates/arc-store-sqlite/src/receipt_store/support.rs crates/arc-store-sqlite/src/receipt_store/reports.rs crates/arc-mercury-core/src/proof_package.rs crates/arc-mercury-core/src/pilot.rs crates/arc-credentials/src/cross_issuer.rs crates/arc-credentials/src/challenge.rs crates/arc-credentials/src/portable_reputation.rs crates/arc-credentials/src/oid4vci.rs crates/arc-credentials/src/tests.rs crates/arc-cli/src/trust_control/http_handlers_a.rs crates/arc-cli/src/passport.rs crates/arc-cli/src/trust_control/service_runtime.rs crates/arc-cli/tests/certify.rs`

This wave removed the final four non-test
`#[allow(clippy::too_many_arguments)]` sites:

- `finalize_tool_output_with_cost`
- `derive_authorization_sender_constraint`
- `MercuryInquiryPackage::build`
- `build_step`

Those boundaries now take typed context/request structs instead of long
positional signatures, and the live non-test
`#[allow(clippy::too_many_arguments)]` inventory is now `0`.

Phase `317` is still open only because the crate-root wildcard compatibility
facade audit remains in `arc-core-types` and `arc-core`.
