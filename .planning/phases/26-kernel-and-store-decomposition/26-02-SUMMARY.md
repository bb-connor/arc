---
phase: 26-kernel-and-store-decomposition
plan: 02
subsystem: store-crate
tags:
  - architecture
  - storage
  - sqlite
  - v2.4
requires:
  - 01
provides:
  - Dedicated arc-store-sqlite crate and consumer rewiring
key-files:
  created:
    - crates/arc-store-sqlite/Cargo.toml
    - crates/arc-store-sqlite/src/lib.rs
    - crates/arc-store-sqlite/src/authority.rs
    - crates/arc-store-sqlite/src/budget_store.rs
    - crates/arc-store-sqlite/src/capability_lineage.rs
    - crates/arc-store-sqlite/src/evidence_export.rs
    - crates/arc-store-sqlite/src/receipt_query.rs
    - crates/arc-store-sqlite/src/receipt_store.rs
    - crates/arc-store-sqlite/src/revocation_store.rs
  modified:
    - Cargo.toml
    - crates/arc-cli/Cargo.toml
    - crates/arc-control-plane/Cargo.toml
    - crates/arc-hosted-mcp/Cargo.toml
    - crates/arc-kernel/Cargo.toml
    - crates/arc-kernel/src/authority.rs
    - crates/arc-kernel/src/budget_store.rs
    - crates/arc-kernel/src/capability_lineage.rs
    - crates/arc-kernel/src/evidence_export.rs
    - crates/arc-kernel/src/lib.rs
    - crates/arc-kernel/src/receipt_query.rs
    - crates/arc-kernel/src/receipt_store.rs
    - crates/arc-kernel/src/revocation_store.rs
    - crates/arc-cli/src/evidence_export.rs
    - crates/arc-cli/src/issuance.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/passport.rs
    - crates/arc-cli/src/remote_mcp.rs
    - crates/arc-cli/src/reputation.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-control-plane/src/lib.rs
requirements-completed:
  - ARCH-04
completed: 2026-03-25
---

# Phase 26 Plan 02 Summary

The concrete SQLite implementation surface now lives behind a dedicated store
crate instead of inside the kernel crate.

## Accomplishments

- added `arc-store-sqlite` as a workspace member and moved the concrete
  SQLite-backed receipt, budget, authority, lineage, revocation, query, and
  export code into it
- trimmed the corresponding `arc-kernel` modules down to contracts and data
  types so the kernel no longer carries the bulk of the storage
  implementation
- rewired `arc-cli`, `arc-control-plane`, `arc-hosted-mcp`, and kernel test
  consumers to import concrete `Sqlite*` types from `arc-store-sqlite`

## Verification

- `cargo check -p arc-store-sqlite`
- `cargo check -p arc-kernel`
- `cargo check -p arc-store-sqlite -p arc-kernel -p arc-control-plane -p arc-hosted-mcp -p arc-cli`
