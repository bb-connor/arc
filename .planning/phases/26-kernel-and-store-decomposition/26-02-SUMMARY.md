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
  - Dedicated pact-store-sqlite crate and consumer rewiring
key-files:
  created:
    - crates/pact-store-sqlite/Cargo.toml
    - crates/pact-store-sqlite/src/lib.rs
    - crates/pact-store-sqlite/src/authority.rs
    - crates/pact-store-sqlite/src/budget_store.rs
    - crates/pact-store-sqlite/src/capability_lineage.rs
    - crates/pact-store-sqlite/src/evidence_export.rs
    - crates/pact-store-sqlite/src/receipt_query.rs
    - crates/pact-store-sqlite/src/receipt_store.rs
    - crates/pact-store-sqlite/src/revocation_store.rs
  modified:
    - Cargo.toml
    - crates/pact-cli/Cargo.toml
    - crates/pact-control-plane/Cargo.toml
    - crates/pact-hosted-mcp/Cargo.toml
    - crates/pact-kernel/Cargo.toml
    - crates/pact-kernel/src/authority.rs
    - crates/pact-kernel/src/budget_store.rs
    - crates/pact-kernel/src/capability_lineage.rs
    - crates/pact-kernel/src/evidence_export.rs
    - crates/pact-kernel/src/lib.rs
    - crates/pact-kernel/src/receipt_query.rs
    - crates/pact-kernel/src/receipt_store.rs
    - crates/pact-kernel/src/revocation_store.rs
    - crates/pact-cli/src/evidence_export.rs
    - crates/pact-cli/src/issuance.rs
    - crates/pact-cli/src/main.rs
    - crates/pact-cli/src/passport.rs
    - crates/pact-cli/src/remote_mcp.rs
    - crates/pact-cli/src/reputation.rs
    - crates/pact-cli/src/trust_control.rs
    - crates/pact-control-plane/src/lib.rs
requirements-completed:
  - ARCH-04
completed: 2026-03-25
---

# Phase 26 Plan 02 Summary

The concrete SQLite implementation surface now lives behind a dedicated store
crate instead of inside the kernel crate.

## Accomplishments

- added `pact-store-sqlite` as a workspace member and moved the concrete
  SQLite-backed receipt, budget, authority, lineage, revocation, query, and
  export code into it
- trimmed the corresponding `pact-kernel` modules down to contracts and data
  types so the kernel no longer carries the bulk of the storage
  implementation
- rewired `pact-cli`, `pact-control-plane`, `pact-hosted-mcp`, and kernel test
  consumers to import concrete `Sqlite*` types from `pact-store-sqlite`

## Verification

- `cargo check -p pact-store-sqlite`
- `cargo check -p pact-kernel`
- `cargo check -p pact-store-sqlite -p pact-kernel -p pact-control-plane -p pact-hosted-mcp -p pact-cli`
