# Phase 71 Verification

status: passed

## Result

Phase 71 is complete. ARC now supports Google Confidential VM as a third
concrete verifier bridge, applies appraisal-aware trusted-verifier policy
across Azure, AWS Nitro, and Google evidence, and carries the accepted
attestation schema plus verifier family into governed and underwriting
surfaces.

## Commands

- `cargo test -p arc-core runtime_attestation_trust_policy -- --nocapture`
- `cargo test -p arc-policy runtime_assurance_validation -- --nocapture`
- `cargo test -p arc-control-plane google_confidential_vm -- --nocapture`
- `cargo test -p arc-kernel governed_monetary_allow_rebinds_google_attestation_to_verified -- --nocapture`
- `cargo test -p arc-cli --test receipt_query --no-run`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 71`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 72`
- `git diff --check`

## Notes

- Google support is intentionally bounded to Confidential VM JWT evidence over
  metadata-resolved `JWKS`; ARC does not claim generic Google attestation
  parity beyond that lane
- milestone closure, signed appraisal export, and broader qualification
  evidence remain phase 72 work
