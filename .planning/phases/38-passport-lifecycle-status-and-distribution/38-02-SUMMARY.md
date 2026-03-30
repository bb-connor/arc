---
phase: 38-passport-lifecycle-status-and-distribution
plan: 02
subsystem: lifecycle-management-and-enforcement
tags:
  - passports
  - trust-control
  - did
requires:
  - 38-01
provides:
  - Local and remote lifecycle publish/list/get/resolve/revoke surfaces
  - Verifier-side lifecycle enforcement across evaluate, verify, and challenge flows
  - DID service distribution for lifecycle resolution endpoints
key-files:
  modified:
    - crates/arc-cli/src/passport.rs
    - crates/arc-cli/src/passport_verifier.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/did.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-did/src/lib.rs
requirements-completed:
  - TRUST-02
completed: 2026-03-26
---

# Phase 38 Plan 02 Summary

Phase 38-02 implemented the operator and verifier surfaces needed to make
passport lifecycle state actionable instead of informational only.

## Accomplishments

- added file-backed and trust-control-backed lifecycle registry operations for
  publish, list, get, resolve, and revoke flows
- made publishing a new current passport automatically supersede the previous
  active artifact for the same subject and exact issuer set
- threaded lifecycle resolution through `passport verify`, `passport evaluate`,
  challenge verification, and federated issue handling
- made `requireActiveLifecycle` fail closed when no lifecycle source is
  configured or when the resolved state is not `active`
- added `ArcPassportStatusService` DID service entries so operators can publish
  one supported lifecycle-discovery endpoint in resolved `did:arc` documents

## Verification

- `cargo test -p arc-cli --test did`
- `cargo test -p arc-cli --test passport`

