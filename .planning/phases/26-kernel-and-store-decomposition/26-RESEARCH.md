---
phase: 26
slug: kernel-and-store-decomposition
status: complete
created: 2026-03-25
---

# Phase 26 Research

## Findings

1. `authority.rs`, `budget_store.rs`, `receipt_store.rs`, and
   `revocation_store.rs` mix contracts with concrete SQLite implementations.
2. `receipt_query.rs`, `capability_lineage.rs`, and `evidence_export.rs` are
   mostly contract/query types plus `impl SqliteReceiptStore` extensions.
3. `receipt_analytics.rs`, `operator_report.rs`, and `cost_attribution.rs`
   already behave like contract/data-model modules and do not need major
   extraction edits.
4. `arc-kernel` currently depends on concrete store behavior through
   `downcast_mut::<SqliteReceiptStore>()` during receipt persistence and
   checkpoint generation.
5. A clean split is feasible if `ReceiptStore` grows small capability hooks for:
   - append returning optional sequence
   - canonical byte range retrieval for checkpoints
   - checkpoint persistence

## Decision

Phase 26 will use this shape:

- `arc-kernel`
  - owns traits, errors, shared query/report/export types, in-memory stores,
    local capability authority, and the kernel core itself
  - uses trait hooks instead of concrete SQLite downcasts
- `arc-store-sqlite`
  - owns `SqliteReceiptStore`, `SqliteBudgetStore`,
    `SqliteCapabilityAuthority`, `SqliteRevocationStore`
  - owns receipt-query, analytics, cost-attribution, shared-evidence,
    capability-lineage, and evidence-export impl blocks for the SQLite receipt
    store
  - becomes a dev-dependency of `arc-kernel` so kernel tests can still cover
    storage-backed flows without reintroducing a normal crate cycle

## Verification Inputs

- `wc -l crates/arc-kernel/src/*.rs | sort -nr | head -n 20`
- `rg -n "impl SqliteReceiptStore|impl SqliteBudgetStore|impl SqliteCapabilityAuthority|impl RevocationStore for SqliteRevocationStore" crates/arc-kernel/src/*.rs`
- local Cargo cycle check confirming normal dependency one way plus reverse
  dev-dependency works for tests
