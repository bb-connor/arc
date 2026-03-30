# Phase 76 Verification

status: passed

## Result

Phase 76 is complete. ARC's enterprise-IAM profile now has conformance
evidence, fail-closed qualification, and release-boundary proof strong enough
to treat `v2.16` as locally closed.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_arc_oauth_profile_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_incomplete_runtime_assurance_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_delegated_call_chain_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 77`
- `git diff --check`

## Notes

- `v2.16` is closed locally; `v2.17` is now the next executable milestone
