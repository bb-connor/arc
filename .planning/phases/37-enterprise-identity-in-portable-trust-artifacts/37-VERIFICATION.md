---
phase: 37
slug: enterprise-identity-in-portable-trust-artifacts
status: passed
completed: 2026-03-26
---

# Phase 37 Verification

Phase 37 passed targeted verification for explicit portable enterprise identity
provenance in `v2.7`.

## Automated Verification

- `cargo test -p arc-credentials passport`
- `cargo test -p arc-cli --test passport`
- `cargo test -p arc-cli --test federated_issue`

## Result

Passed. Phase 37 now satisfies `TRUST-01`:

- portable credentials, passport bundles, and passport verification outputs can
  carry typed `enterpriseIdentityProvenance`
- passport verification fails closed when bundle-level enterprise provenance is
  tampered or no longer matches the embedded credential provenance
- verifier policy can explicitly require enterprise provenance instead of
  treating enterprise identity as implicit authority
- CLI and trust-control surfaces now show the enterprise facts used during
  portable-trust issuance and federated admission
