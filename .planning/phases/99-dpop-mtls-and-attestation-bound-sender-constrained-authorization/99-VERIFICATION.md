# Phase 99 Verification

Phase 99 is complete.

## What Landed

- sender-constrained hosted-authorization request parsing, authorization-code
  persistence, token `cnf` projection, and runtime enforcement in
  `crates/arc-cli/src/remote_mcp.rs`
- expanded ARC OAuth sender-proof discovery constants in
  `crates/arc-kernel/src/operator_report.rs`
- sender-constrained integration coverage in
  `crates/arc-cli/tests/mcp_auth_server.rs`
- protocol, profile, interop-guide, and qualification-boundary updates in
  `spec/PROTOCOL.md`,
  `docs/standards/ARC_OAUTH_AUTHORIZATION_PROFILE.md`,
  `docs/CREDENTIAL_INTEROP_GUIDE.md`,
  `docs/AGENT_PASSPORT_GUIDE.md`, and
  `docs/release/QUALIFICATION.md`

## Validation

Passed:

- `cargo fmt --all`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture --test-threads=1`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_dpop_sender_constraint_across_token_and_mcp_runtime -- --exact --nocapture --test-threads=1`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_enforces_mtls_and_attestation_bound_sender_constraint -- --exact --nocapture --test-threads=1`
- `CARGO_INCREMENTAL=0 cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_rejects_attestation_bound_sender_without_dpop_or_mtls -- --exact --nocapture --test-threads=1`

## Outcome

ARC now exposes one bounded sender-constrained hosted-authorization contract
over DPoP, mTLS thumbprint binding, and one attestation-confirmation profile.
Phase 100 is the remaining `v2.22` closeout step.
