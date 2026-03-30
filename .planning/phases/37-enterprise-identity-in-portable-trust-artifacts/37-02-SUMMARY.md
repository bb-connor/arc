---
phase: 37-enterprise-identity-in-portable-trust-artifacts
plan: 02
subsystem: operator-surfaces
tags:
  - passports
  - trust-control
  - cli
requires:
  - 37-01
provides:
  - Passport CLI issuance with explicit enterprise provenance input
  - Passport verify/evaluate/challenge surfaces that expose enterprise provenance
  - Federated-issue responses that show typed enterprise provenance alongside audit data
key-files:
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/passport.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/admin.rs
    - crates/arc-cli/dashboard/src/types.ts
requirements-completed:
  - TRUST-01
completed: 2026-03-26
---

# Phase 37 Plan 02 Summary

Phase 37-02 threaded enterprise provenance through the real operator-facing
surfaces instead of stopping at the credential model.

## Accomplishments

- added `arc passport create --enterprise-identity <file>` so operators can
  intentionally project normalized enterprise context into portable passport
  artifacts
- surfaced enterprise provenance counts and provider ids on passport verify,
  evaluate, and challenge verification outputs
- extended trust-control federated issuance responses with a typed
  `enterpriseIdentityProvenance` object so operators can see the enterprise
  facts that actually participated in admission
- updated dashboard type definitions so the UI can consume the richer passport
  verification payload without ad hoc casting

## Verification

- `cargo test -p arc-cli --test passport`
- `cargo test -p arc-cli --test federated_issue`
