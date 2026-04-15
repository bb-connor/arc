# Summary 317-04

Phase `317` then took a bounded API-surface cleanup wave across the local
reputation lane and the hosted-MCP compatibility facade.

The implemented refactor and cleanup updated:

- `crates/arc-reputation/src/model.rs`
- `crates/arc-reputation/src/tests.rs`
- `crates/arc-cli/src/issuance.rs`
- `crates/arc-cli/src/reputation.rs`
- `crates/arc-cli/src/cli/dispatch.rs`
- `crates/arc-hosted-mcp/src/lib.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-reputation -p arc-cli -p arc-hosted-mcp`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave4 cargo test -p arc-reputation capability_lineage_record_parses_scope_json --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave4 cargo check -p arc-cli -p arc-hosted-mcp`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**'`
- `rg -n 'pub use .*\\*|pub use .*::\\*' crates/*/src/lib.rs crates/*/src/*.rs`
- `git diff --check -- crates/arc-reputation/src/model.rs crates/arc-reputation/src/tests.rs crates/arc-cli/src/issuance.rs crates/arc-cli/src/reputation.rs crates/arc-cli/src/cli/dispatch.rs crates/arc-hosted-mcp/src/lib.rs`

This wave removed three constructor-style `#[allow(clippy::too_many_arguments)]`
sites by introducing typed inputs for:

- `CapabilityLineageRecord::from_scope_json`
- `cmd_reputation_local`
- `cmd_reputation_compare`

The CLI dispatch path now constructs those request structs explicitly, so the
reputation command boundary stays readable without long positional signatures.

The `arc-hosted-mcp` facade also no longer nests wildcard re-export modules for
`enterprise_federation`, `policy`, and `trust_control`; it now re-exports the
public `arc_control_plane` modules directly.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `67`
- remaining wildcard re-export surfaces: `arc-core-types::*` plus the
  compatibility facade modules under `arc-core/src/*.rs`
