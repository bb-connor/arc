---
phase: 17-a2a-auth-matrix-and-partner-admission-hardening
plan: 02
subsystem: partner-admission
tags:
  - a2a
  - auth
  - federation
requires:
  - 17-01
provides:
  - Fail-closed partner admission and contextual auth diagnostics
key-files:
  created:
    - .planning/phases/17-a2a-auth-matrix-and-partner-admission-hardening/17-02-SUMMARY.md
  modified:
    - crates/arc-a2a-adapter/src/lib.rs
requirements-completed:
  - A2A-02
completed: 2026-03-25
---

# Phase 17 Plan 02 Summary

Partner admission is now explicit, narrow, and fail closed at discovery time.

## Accomplishments

- added `A2aPartnerPolicy` for tenant, skill, security-scheme, and interface
  origin checks
- made interface selection and discovery reject peers that do not satisfy the
  configured policy
- improved auth-negotiation denials with partner, interface, skill, and tenant
  context

## Verification

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`
