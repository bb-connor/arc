# Summary 317-01

Phase `317` started with the non-test `dead_code` inventory so the workspace
stops carrying unexplained suppressions.

The implemented cleanup updated explicit justification comments in:

- `crates/arc-acp-edge/src/lib.rs`
- `crates/arc-acp-proxy/src/kernel_signer.rs`
- `crates/arc-acp-proxy/src/kernel_checker.rs`
- `crates/arc-anchor/src/evm.rs`
- `crates/arc-cli/src/policy.rs`
- `crates/arc-cli/src/remote_mcp/session_core.rs`
- `crates/arc-cli/src/trust_control/service_runtime.rs`
- `crates/arc-cli/src/trust_control/service_types.rs`
- `crates/arc-link/src/chainlink_disabled.rs`
- `crates/arc-mcp-edge/src/runtime.rs`
- `crates/arc-mcp-edge/src/runtime/nested_flow.rs`
- `crates/arc-settle/src/evm.rs`

Verification that passed during this wave:

- `rustfmt --edition 2021 crates/arc-acp-edge/src/lib.rs crates/arc-acp-proxy/src/kernel_signer.rs crates/arc-acp-proxy/src/kernel_checker.rs crates/arc-anchor/src/evm.rs crates/arc-mcp-edge/src/runtime/nested_flow.rs crates/arc-mcp-edge/src/runtime.rs crates/arc-settle/src/evm.rs crates/arc-link/src/chainlink_disabled.rs crates/arc-cli/src/policy.rs crates/arc-cli/src/trust_control/service_runtime.rs crates/arc-cli/src/trust_control/service_types.rs crates/arc-cli/src/remote_mcp/session_core.rs`
- `cargo check -p arc-acp-edge -p arc-acp-proxy -p arc-anchor -p arc-link -p arc-mcp-edge -p arc-settle -p arc-cli`
- `git diff --check -- .planning/phases/316-coverage-push-and-store-hardening .planning/phases/317-dead-code-and-api-surface-audit crates/arc-acp-edge/src/lib.rs crates/arc-acp-proxy/src/kernel_signer.rs crates/arc-acp-proxy/src/kernel_checker.rs crates/arc-anchor/src/evm.rs crates/arc-mcp-edge/src/runtime/nested_flow.rs crates/arc-mcp-edge/src/runtime.rs crates/arc-settle/src/evm.rs crates/arc-link/src/chainlink_disabled.rs crates/arc-cli/src/policy.rs crates/arc-cli/src/trust_control/service_runtime.rs crates/arc-cli/src/trust_control/service_types.rs crates/arc-cli/src/remote_mcp/session_core.rs`

Current inventory after the audit:

- non-test `#[allow(dead_code)]` sites still present across the workspace:
  `23`

This wave does not remove every remaining `dead_code` suppression. Its purpose
is narrower and phase-aligned: every current non-test suppression in the
audited slice now carries an explicit comment explaining why the code must stay
for compatibility, transport, or feature-gated behavior.
