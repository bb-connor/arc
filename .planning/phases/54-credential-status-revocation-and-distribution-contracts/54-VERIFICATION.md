# Phase 54 Verification

## Result

Phase 54 is complete. ARC now projects portable passport lifecycle support
through OID4VCI-compatible issuer metadata and credential responses, exposes a
public read-only lifecycle resolve path, and fails closed when portable
lifecycle support is claimed for an unpublished or non-current passport.

## Commands

- `cargo test -p arc-credentials oid4vci -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_local_with_published_status_attaches_portable_lifecycle_reference -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_oid4vci -- --nocapture`
- `cargo test -p arc-cli --test passport passport_status_registry_supports_publish_supersede_and_revoke -- --nocapture`
- `cargo test -p arc-cli --test passport passport_lifecycle_policy_enforcement_rejects_superseded_and_revoked_passports -- --nocapture`

## Notes

- portable lifecycle distribution remains a sidecar over existing passport
  lifecycle truth; it does not mutate the signed `AgentPassport`
- public lifecycle resolution is read-only and operator-scoped; publication
  and revocation are still explicit authenticated operator actions
