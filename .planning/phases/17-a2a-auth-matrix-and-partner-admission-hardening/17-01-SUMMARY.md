---
phase: 17-a2a-auth-matrix-and-partner-admission-hardening
plan: 01
subsystem: a2a-auth-config
tags:
  - a2a
  - auth
  - operator-config
requires: []
provides:
  - Explicit adapter request-shaping surfaces for provider-specific A2A auth
key-files:
  created:
    - .planning/phases/17-a2a-auth-matrix-and-partner-admission-hardening/17-01-SUMMARY.md
  modified:
    - crates/pact-a2a-adapter/src/lib.rs
requirements-completed:
  - A2A-01
completed: 2026-03-25
---

# Phase 17 Plan 01 Summary

Operator-configurable request-shaping surfaces now exist for discovery and
invocation without bespoke per-call code.

## Accomplishments

- added explicit request header, query-param, and cookie setters to
  `A2aAdapterConfig`
- applied those surfaces to both agent-card discovery and tool invocation
- kept the configured request-shaping inputs separate from negotiated auth
  schemes

## Verification

- `cargo test -p pact-a2a-adapter --lib -- --nocapture`
