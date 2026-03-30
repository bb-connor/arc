# Phase 70 Verification

status: passed

## Result

Phase 70 is complete. ARC now supports AWS Nitro as a second concrete
runtime-attestation verifier family and projects verified Nitro evidence
through the same canonical appraisal contract introduced in phase 69.

## Commands

- `cargo test -p arc-control-plane aws_nitro -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init phase-op 70`
- `git diff --check`

## Notes

- Nitro validation remains intentionally conservative: ARC supports `ES384`
  `COSE_Sign1` documents, anchored certificate trust, `SHA384` PCRs,
  freshness, nonce matching, and debug-mode denial by default
- policy-wide cross-adapter rebinding and a second non-Azure verifier family
  remain phase 71 work
