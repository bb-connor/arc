# Summary 317-03

Phase `317` then took a combined signature-refactor and dependency-audit wave
across the public discovery helpers, the hosted remote-MCP ownership lane, and
the workspace Cargo manifests.

The implemented refactor and cleanup updated:

- `crates/arc-credentials/src/discovery.rs`
- `crates/arc-cli/src/remote_mcp/oauth.rs`
- `crates/arc-cli/src/remote_mcp/tests.rs`
- `crates/arc-cli/src/trust_control/config_and_public.rs`
- `crates/arc-hosted-mcp/src/lib.rs`
- `crates/arc-acp-proxy/Cargo.toml`
- `crates/arc-ag-ui-proxy/Cargo.toml`
- `crates/arc-api-protect/Cargo.toml`
- `crates/arc-config/Cargo.toml`
- `crates/arc-http-core/Cargo.toml`
- `crates/arc-metering/Cargo.toml`
- `crates/arc-openapi/Cargo.toml`
- `crates/arc-policy/Cargo.toml`
- `crates/arc-tower/Cargo.toml`
- `crates/arc-workflow/Cargo.toml`

Verification that passed during this wave:

- `rustfmt --edition 2021 crates/arc-credentials/src/discovery.rs crates/arc-cli/src/remote_mcp/oauth.rs crates/arc-cli/src/remote_mcp/tests.rs crates/arc-cli/src/trust_control/config_and_public.rs crates/arc-hosted-mcp/src/lib.rs`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-next cargo test -p arc-credentials discovery_tests --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-check cargo check -p arc-credentials -p arc-cli -p arc-hosted-mcp`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-hosted cargo test -p arc-hosted-mcp introspection_bearer_verifier`
- `cargo udeps -V`
- `CARGO_TARGET_DIR=/tmp/arc-udeps-workspace cargo +nightly-aarch64-apple-darwin udeps --workspace --all-targets`
- `git diff --check -- crates/arc-credentials/src/discovery.rs crates/arc-cli/src/remote_mcp/oauth.rs crates/arc-cli/src/remote_mcp/tests.rs crates/arc-cli/src/trust_control/config_and_public.rs crates/arc-hosted-mcp/src/lib.rs crates/arc-acp-proxy/Cargo.toml crates/arc-ag-ui-proxy/Cargo.toml crates/arc-api-protect/Cargo.toml crates/arc-config/Cargo.toml crates/arc-http-core/Cargo.toml crates/arc-metering/Cargo.toml crates/arc-openapi/Cargo.toml crates/arc-policy/Cargo.toml crates/arc-tower/Cargo.toml crates/arc-workflow/Cargo.toml`

This wave removed the discovery and remote-MCP constructor-style
`#[allow(clippy::too_many_arguments)]` sites by introducing typed inputs for:

- `create_signed_public_issuer_discovery`
- `create_signed_public_verifier_discovery`
- `create_signed_public_discovery_transparency`
- `issue_token_response`
- `sign_access_token`
- `session_auth_context_from_introspection`

The downstream trust-control builders now construct those typed inputs
explicitly, and the `arc-hosted-mcp` crate root now exports only
`serve_http` and `RemoteServeHttpConfig` from `remote_mcp_impl` instead of a
wildcard surface.

The dependency-audit lane is now operational locally. After installing
`cargo-udeps` and running the first nightly workspace pass, this wave removed
the reported dead dependencies from ten crates:

- `arc-acp-proxy`
- `arc-ag-ui-proxy`
- `arc-api-protect`
- `arc-config`
- `arc-http-core`
- `arc-metering`
- `arc-openapi`
- `arc-policy`
- `arc-tower`
- `arc-workflow`

The follow-up nightly audit completed with `All deps seem to have been used.`,
so the phase's `udeps` gate is now satisfied on this machine.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `70`
- remaining crate-root wildcard re-export surfaces: `arc-core-types::*` module
  facades plus the nested `arc-hosted-mcp::{enterprise_federation,policy,trust_control}`
  facades
