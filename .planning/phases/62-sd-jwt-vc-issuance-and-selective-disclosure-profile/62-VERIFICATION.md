# Phase 62 Verification

## Result

Phase 62 is complete. ARC now ships one bounded SD-JWT VC issuance profile
over passport truth, with explicit holder binding, a documented
always-disclosed versus selectively-disclosable claim catalog, and
fail-closed validation for unsupported disclosure behavior.

## Commands

- `cargo fmt --all`
- `cargo test -p arc-credentials portable_sd_jwt -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_metadata_and_issuance_roundtrip -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_local_portable_offer_requires_signing_seed -- --nocapture`
- `git diff --check`

## Notes

- This phase still does not claim OID4VP verifier transport, same-device or
  cross-device wallet invocation, or generic SD-JWT VC interoperability
  outside ARC's documented profile.
- Portable lifecycle/status projection remains phase 63 work.
