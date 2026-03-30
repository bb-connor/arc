---
phase: 28-domain-module-cleanup-and-dependency-enforcement
plan: 01
subsystem: domain-modules
tags:
  - architecture
  - refactor
  - domain
  - v2.4
requires: []
provides:
  - Thin facade entry modules for credentials, reputation, and policy evaluation
key-files:
  created:
    - crates/arc-credentials/src/artifact.rs
    - crates/arc-credentials/src/passport.rs
    - crates/arc-credentials/src/challenge.rs
    - crates/arc-credentials/src/registry.rs
    - crates/arc-credentials/src/presentation.rs
    - crates/arc-credentials/src/policy.rs
    - crates/arc-credentials/src/tests.rs
    - crates/arc-reputation/src/model.rs
    - crates/arc-reputation/src/score.rs
    - crates/arc-reputation/src/compare.rs
    - crates/arc-reputation/src/issuance.rs
    - crates/arc-reputation/src/tests.rs
    - crates/arc-policy/src/evaluate/context.rs
    - crates/arc-policy/src/evaluate/engine.rs
    - crates/arc-policy/src/evaluate/matchers.rs
    - crates/arc-policy/src/evaluate/outcomes.rs
    - crates/arc-policy/src/evaluate/tests.rs
  modified:
    - crates/arc-credentials/src/lib.rs
    - crates/arc-reputation/src/lib.rs
    - crates/arc-policy/src/evaluate.rs
requirements-completed:
  - ARCH-08
completed: 2026-03-25
---

# Phase 28 Plan 01 Summary

## Accomplishments

- reduced `arc-credentials/src/lib.rs`, `arc-reputation/src/lib.rs`, and
  `arc-policy/src/evaluate.rs` to thin facades
- split credential behavior into artifact, passport, challenge, registry,
  presentation, policy, and test modules without changing the crate surface
- split reputation behavior into model, score, compare, issuance, and test
  modules
- moved policy evaluation internals into a dedicated `evaluate/` directory so
  the top-level entry file no longer carries the engine directly

## Verification

- `cargo check -p arc-credentials -p arc-reputation -p arc-policy`
- `wc -l crates/arc-credentials/src/lib.rs crates/arc-reputation/src/lib.rs crates/arc-policy/src/evaluate.rs`
