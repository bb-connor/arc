# Phase 64 Verification

## Result

Phase 64 is complete. ARC now has explicit qualification evidence, release
boundary language, and milestone audit closure for the standards-native
portable credential format and lifecycle lane.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-credentials oid4vci -- --nocapture`
- `cargo test -p arc-credentials portable_sd_jwt -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_local_with_published_status_attaches_portable_lifecycle_reference -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `git diff --check`

## Notes

- `v2.13` closes one standards-native credential format and lifecycle lane,
  not generic OID4VP or public-wallet ecosystem coverage
- the next milestone is `v2.14`, but it is still planned-only and not yet
  activated into executable phase detail
