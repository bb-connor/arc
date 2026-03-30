---
phase: 26-kernel-and-store-decomposition
plan: 01
subsystem: kernel-contracts
tags:
  - architecture
  - kernel
  - storage
  - v2.4
requires: []
provides:
  - Contract hooks for sequence-aware receipt persistence and checkpoints
key-files:
  modified:
    - .planning/phases/26-kernel-and-store-decomposition/26-CONTEXT.md
    - .planning/phases/26-kernel-and-store-decomposition/26-RESEARCH.md
    - crates/arc-kernel/src/lib.rs
    - crates/arc-kernel/src/receipt_store.rs
requirements-completed: []
completed: 2026-03-25
---

# Phase 26 Plan 01 Summary

The kernel/store boundary no longer depends on a concrete SQLite downcast.

## Accomplishments

- added `append_arc_receipt_returning_seq`,
  `receipts_canonical_bytes_range`, and `store_checkpoint` hooks to the
  `ReceiptStore` trait so sequence-aware persistence stays contract-driven
- removed the kernel’s `downcast_mut::<SqliteReceiptStore>()` dependency from
  receipt recording and checkpoint generation
- documented the chosen contract split in the phase context and research docs

## Verification

- `rg -n "append_arc_receipt_returning_seq|receipts_canonical_bytes_range|store_checkpoint|downcast_mut::<SqliteReceiptStore>" crates/arc-kernel/src/{lib.rs,receipt_store.rs}`
