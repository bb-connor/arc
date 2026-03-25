---
phase: 20-ecosystem-conformance-and-operator-onboarding
plan: 02
subsystem: operator-docs
tags:
  - docs
  - onboarding
  - operators
requires:
  - 20-01
provides:
  - Operator onboarding docs for shipped v2.2 surfaces
key-files:
  created:
    - .planning/phases/20-ecosystem-conformance-and-operator-onboarding/20-02-SUMMARY.md
  modified:
    - docs/A2A_ADAPTER_GUIDE.md
    - docs/PACT_CERTIFY_GUIDE.md
    - docs/CHANGELOG.md
requirements-completed:
  - ECO-02
completed: 2026-03-25
---

# Phase 20 Plan 02 Summary

Operators now have direct onboarding docs for the completed v2.2 surfaces.

## Accomplishments

- documented explicit A2A request shaping, partner admission, and task-registry
  behavior in `A2A_ADAPTER_GUIDE.md`
- documented certification verification, publish, resolve, and revoke flows in
  `PACT_CERTIFY_GUIDE.md`
- recorded the v2.2 milestone delta in `CHANGELOG.md`

## Verification

- `cargo test -p pact-cli --test provider_admin -- --nocapture`
