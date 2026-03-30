---
phase: 17-a2a-auth-matrix-and-partner-admission-hardening
plan: 03
subsystem: docs-and-tests
tags:
  - a2a
  - docs
  - tests
requires:
  - 17-01
  - 17-02
provides:
  - Regression coverage and onboarding docs for explicit auth shaping
key-files:
  created:
    - .planning/phases/17-a2a-auth-matrix-and-partner-admission-hardening/17-03-SUMMARY.md
  modified:
    - crates/arc-a2a-adapter/src/lib.rs
    - docs/A2A_ADAPTER_GUIDE.md
requirements-completed: []
completed: 2026-03-25
---

# Phase 17 Plan 03 Summary

The completed auth and partner-admission behavior is now documented and covered
by regression tests.

## Accomplishments

- added request-shaping and admission regression tests in the adapter suite
- documented explicit request headers, query params, cookies, and partner
  admission in `A2A_ADAPTER_GUIDE.md`
- kept the verification lane on the adapter's end-to-end test harness

## Verification

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`
