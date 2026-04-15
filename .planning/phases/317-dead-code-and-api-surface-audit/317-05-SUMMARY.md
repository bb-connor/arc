# Summary 317-05

Phase `317` then took another bounded signature-cleanup wave across the HTTP
evaluator helpers, session-auth construction, and workflow step recording.

The implemented refactor updated:

- `crates/arc-api-protect/src/evaluator.rs`
- `crates/arc-tower/src/evaluator.rs`
- `crates/arc-core-types/src/session.rs`
- `crates/arc-cli/src/remote_mcp/oauth.rs`
- `crates/arc-workflow/src/authority.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-api-protect -p arc-tower -p arc-core-types -p arc-workflow -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave5-api cargo test -p arc-api-protect --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave5-tower cargo test -p arc-tower --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave5-core cargo test -p arc-core-types oauth_session_auth_context_roundtrips_with_federated_claims --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave5-workflow cargo test -p arc-workflow --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase317-wave5-cli cargo check -p arc-cli`
- `rg -n '#\[allow\(clippy::too_many_arguments\)\]' crates --glob '!**/tests/**'`
- `rg -n 'pub use .*\\*|pub use .*::\\*' crates/*/src/lib.rs crates/*/src/*.rs`
- `git diff --check -- crates/arc-api-protect/src/evaluator.rs crates/arc-tower/src/evaluator.rs crates/arc-core-types/src/session.rs crates/arc-cli/src/remote_mcp/oauth.rs crates/arc-workflow/src/authority.rs`

This wave removed four constructor-style `#[allow(clippy::too_many_arguments)]`
sites by introducing typed input structs for:

- `RequestEvaluator::build_result`
- `ArcEvaluator::build_result`
- `SessionAuthContext::streamable_http_oauth_bearer_with_claims`
- `WorkflowAuthority::record_step`

The downstream `arc-cli` remote-MCP OAuth path now builds the session-auth
input explicitly, and the workflow tests now record step outcomes through the
typed input struct instead of long positional argument lists.

Current inventory after this wave:

- non-test `#[allow(clippy::too_many_arguments)]` sites still present across the
  workspace: `63`
- remaining wildcard re-export surfaces: `arc-core-types::*` plus the
  compatibility facade modules under `arc-core/src/*.rs`
