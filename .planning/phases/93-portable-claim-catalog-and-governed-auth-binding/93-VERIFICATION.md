# Phase 93 Verification

Phase 93 is complete locally.

## What Changed

- Added the shared standards contract in `crates/arc-core/src/standards.rs`
- Wired the portable claim catalog and identity binding into
  `arc-credentials`
- Wired governed auth binding and issuer-binding semantics into the hosted
  ARC OAuth profile and SQLite authorization-context projection
- Updated standards-facing docs for portable credentials and hosted auth

## Validation

Passed:

- `cargo fmt --all`
- `cargo test -p arc-credentials oid4vci_metadata_with_signing_key_advertises_portable_projection -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_and_cli -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_metadata_and_review_pack_surfaces -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_authorization_context_report_rejects_missing_issuer_binding_material -- --nocapture`
- `cargo test -p arc-cli --test mcp_auth_server mcp_serve_http_local_auth_server_supports_auth_code_and_token_exchange -- --nocapture`

## Outcome

Phase 93 now gives ARC one explicit portable claim catalog, one explicit
portable identity-binding model, and one explicit governed-auth binding model
shared across portable credential metadata and hosted auth metadata.
