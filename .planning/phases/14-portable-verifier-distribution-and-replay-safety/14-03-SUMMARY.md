---
phase: 14-portable-verifier-distribution-and-replay-safety
plan: 03
subsystem: verifier
tags:
  - passport
  - trust-control
  - remote-api
requires:
  - 14-01
  - 14-02
provides:
  - Local and remote verifier flows share one stored-policy and replay-safe contract
  - Federated issue can consume stored verifier policy references and replay-safe challenges
key-files:
  created:
    - .planning/phases/14-portable-verifier-distribution-and-replay-safety/14-03-SUMMARY.md
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/passport.rs
    - crates/arc-cli/src/reputation.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/tests/passport.rs
    - crates/arc-cli/tests/federated_issue.rs
requirements-completed:
  - VER-03
completed: 2026-03-24
---

# Phase 14 Plan 03 Summary

Verifier policy references and replay-safe challenge semantics now work across
the local CLI and trust-control surfaces.

## Accomplishments

- Added `arc passport policy create|verify|list|get|upsert|delete`
- Extended `passport challenge create|verify` with policy references,
  verifier-policy registries, and replay-safe challenge databases
- Added trust-control verifier policy CRUD plus remote challenge create/verify
  endpoints
- Reused the same policy-reference and replay-safe challenge semantics in
  `trust federated-issue`
- Surfaced `challengeId`, `policyId`, `policySource`, `policyEvaluated`, and
  `replayState` in verifier outputs

## Verification

- `cargo test -p arc-cli --test passport -- --nocapture`
- `cargo test -p arc-cli --test federated_issue -- --nocapture`
