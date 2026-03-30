---
phase: 25-cli-thinning-and-service-boundary-extraction
plan: 01
subsystem: service-boundaries
tags:
  - architecture
  - refactor
  - v2.4
requires: []
provides:
  - Concrete extraction strategy that avoids an immediate crate cycle
key-files:
  created:
    - .planning/phases/25-cli-thinning-and-service-boundary-extraction/25-CONTEXT.md
    - .planning/phases/25-cli-thinning-and-service-boundary-extraction/25-RESEARCH.md
    - crates/arc-control-plane/Cargo.toml
    - crates/arc-control-plane/src/lib.rs
    - crates/arc-hosted-mcp/Cargo.toml
    - crates/arc-hosted-mcp/src/lib.rs
requirements-completed: []
completed: 2026-03-25
---

# Phase 25 Plan 01 Summary

Phase 25 no longer depends on a vague "shared support crate later" idea.

## Accomplishments

- mapped the dependency pressure between `trust_control.rs`, `remote_mcp.rs`,
  and the helper functions still living in `main.rs`
- chose compile-time ownership transfer first: new service crates own the
  boundary immediately, while path-included compatibility modules avoid a large
  unsafe file move in the same step
- defined `arc-control-plane` as the shared support boundary for CLI service
  helpers and `arc-hosted-mcp` as the hosted runtime owner layered on top of
  that boundary

## Verification

- `rg -n "arc-control-plane|arc-hosted-mcp|pub use arc_control_plane|pub use arc_hosted_mcp" Cargo.toml crates/arc-cli/Cargo.toml crates/arc-cli/src/main.rs crates/arc-control-plane/src/lib.rs crates/arc-hosted-mcp/src/lib.rs`
