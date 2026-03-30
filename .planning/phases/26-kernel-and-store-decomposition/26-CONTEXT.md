---
phase: 26
slug: kernel-and-store-decomposition
status: in_progress
created: 2026-03-25
---

# Phase 26 Context

## Objective

Separate the trusted kernel core from SQLite-backed persistence and reporting so
the enforcement crate stops carrying the bulk of the storage implementation.

## Current Reality

- `crates/arc-kernel/src/lib.rs` is still 8,875 LOC and reexports both core
  runtime behavior and concrete SQLite-backed store types
- storage-heavy logic is concentrated in:
  - `crates/arc-kernel/src/receipt_store.rs` (3,215 LOC)
  - `crates/arc-kernel/src/receipt_query.rs` (1,574 LOC)
  - `crates/arc-kernel/src/budget_store.rs` (1,384 LOC)
  - `crates/arc-kernel/src/evidence_export.rs` (579 LOC)
  - `crates/arc-kernel/src/authority.rs` (575 LOC)
  - `crates/arc-kernel/src/revocation_store.rs` (200 LOC)
- `capability_lineage.rs`, `receipt_query.rs`, and `evidence_export.rs` all add
  `impl SqliteReceiptStore` blocks that are storage-specific even though their
  data-model types are useful as kernel contracts
- the kernel still downcasts receipt stores to `SqliteReceiptStore` during
  receipt recording and checkpointing

## Constraints

- `arc-store-sqlite` must depend on `arc-kernel` for traits/contracts, so
  `arc-kernel` cannot use a normal dependency reexport back to that crate
- Cargo does allow the reverse direction as a **dev-dependency**, which means
  kernel tests can still use `arc-store-sqlite` after the split
- behavior compatibility matters more than preserving old import paths for the
  concrete SQLite store types

## Strategy

- leave contracts and shared data models in `arc-kernel`
- move the concrete SQLite implementations plus their heavy impl blocks into a
- new `arc-store-sqlite` crate
- replace kernel downcasts with trait-level receipt/checkpoint hooks
- update workspace call sites to import concrete SQLite types from
  `arc-store-sqlite`
- split `arc-kernel/src/lib.rs` into smaller internal modules while keeping
  public kernel behavior stable
