# Summary 317-16

Phase `317` then took the remaining same-crate `arc-cli` singleton cleanup
wave across the evidence-export and remote-session boundaries.

The implemented refactor updated:

- `crates/arc-cli/src/evidence_export.rs`
- `crates/arc-cli/src/cli/dispatch.rs`
- `crates/arc-cli/src/remote_mcp/session_core.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave16 cargo check -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave16 cargo test -p arc-cli --test evidence_export evidence_export_with_signed_federation_policy_roundtrips -- --exact`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave16 cargo test -p arc-cli cli_entrypoint_tests --bin arc`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**'`
- `git diff --check -- crates/arc-cli/src/evidence_export.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-cli/src/remote_mcp/session_core.rs`

This wave removed two non-test `#[allow(clippy::too_many_arguments)]` sites:

- `cmd_evidence_federation_policy_create`
- `RemoteSession::new`

Both boundaries now take typed input structs instead of long positional
argument lists, and the workspace non-test
`#[allow(clippy::too_many_arguments)]` inventory dropped from `10` to `8`.
