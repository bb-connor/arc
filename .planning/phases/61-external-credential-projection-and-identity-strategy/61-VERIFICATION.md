# Phase 61 Verification

## Result

Phase 61 is complete. ARC now has one explicitly documented dual-path
credential boundary: the native `AgentPassport` lane remains the ARC source of
truth, and ARC can also project that truth into one bounded
`application/dc+sd-jwt` portable credential profile with issuer `JWKS` and
type metadata rooted at the same `credential_issuer`.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-credentials oid4vci -- --nocapture`
- `cargo test -p arc-credentials portable_sd_jwt_passport_projection_roundtrip_verifies -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_local_portable_offer_requires_signing_seed -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_external_http_issuance_and_verifier_roundtrip_is_interop_qualified -- --nocapture`
- `git diff --check`

## Notes

- This phase intentionally does not claim full selective-disclosure request
  semantics or verifier-side wallet transport; those remain phase 62 and
  phase 64 work.
- Current verification still emits one unrelated compile warning from
  `arc-control-plane/src/attestation.rs` for an unused `rsa::traits::PublicKeyParts`
  import. It does not affect the phase 61 implementation or tests.
