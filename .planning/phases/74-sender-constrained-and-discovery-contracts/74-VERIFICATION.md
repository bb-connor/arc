# Phase 74 Verification

status: passed

## Result

Phase 74 is complete. ARC's authorization-context report now carries explicit
sender-constraint truth derived from capability lineage, the hosted edge
publishes the same ARC authorization profile through `.well-known` discovery
documents, and the new sender/discovery mismatch paths fail closed.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_invalid_arc_oauth_profile_projection -- --exact --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_sender_binding_material -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_rejects_jwt_with_wrong_audience -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_serves_oauth_authorization_server_metadata_for_local_issuer -- --exact --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --exact --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 75`
- `git diff --check`

## Notes

- ARC's sender-constrained IAM profile is now explicit, but reviewer packs,
  metadata packaging, and milestone closeout still belong to phases 75 and 76
