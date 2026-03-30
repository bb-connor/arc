---
phase: 38-passport-lifecycle-status-and-distribution
plan: 01
subsystem: passport-lifecycle-model
tags:
  - passports
  - lifecycle
  - credentials
requires: []
provides:
  - Explicit passport lifecycle states for active, superseded, revoked, and not-found resolution
  - Distribution metadata for supported lifecycle discovery and caching
  - Passport verification outputs that can carry stable passport ids and lifecycle state
key-files:
  modified:
    - crates/arc-credentials/src/lib.rs
    - crates/arc-credentials/src/passport.rs
    - crates/arc-credentials/src/challenge.rs
    - crates/arc-credentials/src/presentation.rs
    - crates/arc-cli/src/passport_verifier.rs
requirements-completed:
  - TRUST-02
  - TRUST-05
completed: 2026-03-26
---

# Phase 38 Plan 01 Summary

Phase 38-01 defined passport lifecycle as a first-class portable-trust
contract instead of leaving revocation and supersession to local operator
convention.

## Accomplishments

- added explicit lifecycle state and resolution types for `active`,
  `superseded`, `revoked`, and `notFound`
- added distribution metadata so lifecycle records can advertise supported
  resolve URLs and cache TTL guidance
- extended passport verification, presentation verification, and verifier
  policy evaluation outputs with stable `passportId` and optional lifecycle
  resolution fields
- added verifier-policy support for `requireActiveLifecycle` so fail-closed
  lifecycle enforcement is an explicit relying-party choice

## Verification

- `cargo test -p arc-credentials passport`

