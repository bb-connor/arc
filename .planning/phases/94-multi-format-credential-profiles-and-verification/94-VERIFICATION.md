# Phase 94 Verification

Phase 94 is complete locally.

## What Changed

- added a second bounded projected portable passport profile:
  `arc_agent_passport_jwt_vc_json` with format `jwt_vc_json`
- generalized OID4VCI issuer metadata and compact-response validation across
  the SD-JWT VC and JWT VC JSON portable profiles
- exposed a second portable type-metadata endpoint at
  `/.well-known/arc-passport-jwt-vc-json`
- added fail-closed mixed-profile request rejection and documented the bounded
  multi-format profile family

## Validation

Passed:

- `cargo fmt --all`
- `cargo test -p arc-credentials portable_jwt_vc_json -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_jwt_vc_json_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_rejects_mixed_portable_profile_request -- --nocapture`

## Outcome

ARC now supports more than one standards-legible portable credential profile
over the same canonical passport truth while keeping profile negotiation,
verification, and failure modes explicit.
