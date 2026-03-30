---
phase: 37-enterprise-identity-in-portable-trust-artifacts
plan: 01
subsystem: portable-provenance-model
tags:
  - passports
  - enterprise-identity
  - credentials
requires: []
provides:
  - Typed `enterpriseIdentityProvenance` on portable reputation credentials
  - Passport-level aggregate enterprise provenance with fail-closed verification
  - Verifier-policy support for explicitly requiring enterprise provenance
key-files:
  modified:
    - crates/arc-credentials/src/lib.rs
    - crates/arc-credentials/src/artifact.rs
    - crates/arc-credentials/src/passport.rs
    - crates/arc-credentials/src/challenge.rs
    - crates/arc-credentials/src/policy.rs
    - crates/arc-credentials/src/presentation.rs
requirements-completed:
  - TRUST-01
completed: 2026-03-26
---

# Phase 37 Plan 01 Summary

Phase 37-01 defined the portable-trust enterprise provenance model instead of
leaving enterprise identity trapped in session-only metadata.

## Accomplishments

- added a typed `EnterpriseIdentityProvenance` structure that mirrors the
  normalized enterprise identity facts ARC already derives at admission time
- extended reputation credentials plus passport and presentation verification
  outputs to carry that provenance explicitly
- made passport verification fail closed when the bundle-level provenance no
  longer matches the aggregate provenance embedded in the signed credentials
- added a verifier-policy requirement flag so enterprise provenance only
  becomes authoritative when a relying party opts into it explicitly

## Verification

- `cargo test -p arc-credentials passport`
