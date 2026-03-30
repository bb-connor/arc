# Phase 63 Verification

## Result

Phase 63 is complete. ARC now projects portable issuer metadata, type
metadata, and lifecycle truth from the existing passport status registry
without inventing a second mutable trust root.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-cli --test passport passport_issuance_local_with_published_status_attaches_portable_lifecycle_reference -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_metadata_endpoints_require_signing_key_configuration -- --nocapture`
- `git diff --check`

## Notes

- portable lifecycle remains a reference to operator truth, not a lifecycle bit
  copied into the credential
- only `active` is a healthy portable lifecycle state; `superseded`,
  `revoked`, `notFound`, malformed responses, and stale cached responses
  remain fail-closed states
