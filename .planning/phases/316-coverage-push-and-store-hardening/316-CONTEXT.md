---
phase: 316-coverage-push-and-store-hardening
milestone: v2.83
created: 2026-04-13
status: in_progress
---

# Phase 316 Context

## Goal

Raise workspace line coverage to `80%+` while hardening the SQLite receipt
store so the runtime write path is no longer tied to a single cached
connection.

## Current Reality

- The last committed coverage artifact before phase `316` reported `67.39%`
  workspace line coverage.
- `scripts/run-coverage.sh` is the canonical tarpaulin lane and falls back to
  Docker because `cargo tarpaulin` is not installed locally.
- At phase start, `SqliteReceiptStore` kept one long-lived
  `rusqlite::Connection` and all hot write paths depended on that handle.
- The active runtime write path is concentrated in:
  - `append_arc_receipt_returning_seq`
  - `append_child_receipt`
  - `record_capability_snapshot`
  - `store_checkpoint`

## Boundaries

- Do not disturb unrelated dirty-worktree changes outside the phase `316`
  write set.
- Coverage gains must come from previously weak crates or weak public surfaces,
  not from trivial assertions layered onto already-covered code.
- Avoid a full async trait rewrite unless the pooled approach proves
  insufficient; phase `316` should stay scoped to the SQLite/runtime boundary
  plus targeted test expansion.

## Key Risks

- The coverage baseline may still sit far below `80%`, which would require a
  second execution lane beyond store hardening.
- If the store only adds a pool internally but the public write surface remains
  single-threaded, the concurrency claim will be weak.
- If the coverage push targets tiny helper functions instead of large weak
  crates, the phase can look green while missing the roadmap intent.

## Decision

Split the phase into two primary lanes:

1. Convert the hot `SqliteReceiptStore` write path onto pooled SQLite
   connections and prove one store instance can accept concurrent receipt
   writes.
2. Use the tarpaulin result to target the largest remaining weak crates and
   lift workspace coverage above the `80%` requirement with meaningful tests.
