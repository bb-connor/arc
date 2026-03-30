# Phase 65 Verification

## Result

Phase 65 is complete. ARC now ships one narrow verifier-side OID4VP transport
contract with signed `request_uri` requests, replay-safe verifier transaction
state, and fail-closed `direct_post.jwt` validation for the projected
passport lane.

## Commands

- `cargo test -p arc-credentials oid4vp -- --nocapture`
- `cargo test -p arc-cli --test passport passport_oid4vp_request_uri_and_direct_post_roundtrip_is_replay_safe -- --nocapture`

## Notes

- the phase deliberately keeps the verifier profile narrow to ARC's projected
  `application/dc+sd-jwt` passport contract
- same-device and cross-device launch artifacts were completed in phase 66,
  but phase 65 already established the canonical stored verifier transaction
  and request fetch truth they depend on

