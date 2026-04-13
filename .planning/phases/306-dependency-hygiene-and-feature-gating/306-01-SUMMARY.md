---
phase: 306-dependency-hygiene-and-feature-gating
plan: 01
subsystem: dependency-hygiene
tags:
  - rust
  - cargo
  - sqlite
  - yaml
requires: []
provides:
  - `serde_yml`-backed YAML loading across policy-facing crates
  - unified direct `reqwest 0.13.2` usage in the workspace
  - explicit SQLite integer conversions compatible with `rusqlite 0.39`
affects:
  - phase-306-02
  - phase-307
tech-stack:
  added:
    - `serde_yml 0.0.12`
  upgraded:
    - `reqwest 0.12.x -> 0.13.2`
    - `rusqlite 0.37 -> 0.39`
key-files:
  modified:
    - Cargo.toml
    - Cargo.lock
    - crates/arc-cli/Cargo.toml
    - crates/arc-control-plane/Cargo.toml
    - crates/arc-policy/Cargo.toml
    - crates/arc-store-sqlite/src/receipt_store/bootstrap.rs
    - crates/arc-store-sqlite/src/receipt_store/evidence_retention.rs
    - crates/arc-store-sqlite/src/receipt_store/support.rs
    - crates/arc-cli/src/passport_verifier.rs
key-decisions:
  - "Upgraded `rusqlite` instead of leaving the old hashbrown split in place, then patched the narrow SQLite `u64` surface with explicit checked conversions."
  - "Enabled `reqwest`'s `form` and `query` features explicitly because 0.13 no longer exposes those helpers implicitly through the older feature mix."
  - "Removed stale direct `arc-web3` edges from `arc-kernel` and `arc-link` because the phase 303 decomposition made those paths redundant."
patterns-established:
  - "Treat SQLite INTEGER boundaries explicitly at the persistence edge rather than relying on implicit unsigned conversions."
requirements-completed:
  - DEPS-01
  - DEPS-02
duration: 49 min
completed: 2026-04-13
---

# Phase 306 Plan 01: Dependency Hygiene Summary

**Deprecated YAML parsing is gone, direct HTTP clients share one reqwest line,
and the SQLite layer now uses explicit integer conversions compatible with the
newer rusqlite stack**

## Verification

- `cargo check -p arc-kernel -p arc-policy -p arc-control-plane -p arc-cli`
- `cargo test -p arc-policy`
- `cargo test -p arc-cli runtime_hash_ignores_yaml_formatting_noise`
- `cargo test -p arc-cli yaml_tool_access_synthesizes_default_capabilities`

## Notes

- The `rusqlite` upgrade exposed a small set of implicit `u64` SQLite reads and
  writes in `arc-store-sqlite` and `passport_verifier`; those now use checked
  `i64` conversion helpers.
- All direct workspace `reqwest` consumers now share the same version and
  explicit feature surface.
