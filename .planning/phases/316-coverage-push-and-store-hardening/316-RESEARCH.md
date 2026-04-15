---
phase: 316-coverage-push-and-store-hardening
created: 2026-04-13
status: in_progress
---

# Phase 316 Research

## Sources Reviewed

- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap get-phase 316`
- `scripts/run-coverage.sh`
- `coverage/README.md`
- `coverage/summary.txt`
- `crates/arc-kernel/src/receipt_store.rs`
- `crates/arc-kernel/src/kernel/mod.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`
- `crates/arc-store-sqlite/src/receipt_store/*.rs`
- `crates/arc-store-sqlite/src/capability_lineage.rs`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/r2d2_sqlite-0.33.0/src/lib.rs`

## Findings

1. The tarpaulin lane already exists and writes HTML, JSON, LCOV, and summary
   artifacts under `coverage/`; no new coverage harness is needed for this
   phase.
2. The last stored workspace summary before phase execution was `67.39%`, so
   the roadmap target is materially above the current baseline.
3. A full `ReceiptStore` async conversion would ripple through kernel storage
   plumbing and is larger than this phase needs.
4. `r2d2_sqlite 0.33.0` is compatible with the workspace `rusqlite 0.39`
   version and supports per-connection initialization hooks for WAL and busy
   timeout setup.
5. The real runtime serialization pressure is on the receipt append /
   checkpoint / lineage write path, not on the reporting-heavy admin queries.

## Implementation Direction

- Use `r2d2_sqlite` to back `SqliteReceiptStore` with a pooled connection
  source.
- Move the runtime write path onto pooled connections while keeping the wider
  reporting/query surface behaviorally unchanged.
- Add a direct concurrent-write test against one `Arc<SqliteReceiptStore>`
  instance so the store-level concurrency claim is explicit.
- Close the remaining phase only after the final tarpaulin report identifies
  and verifies the necessary coverage gains.
