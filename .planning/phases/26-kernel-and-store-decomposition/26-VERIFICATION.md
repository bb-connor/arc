---
phase: 26
slug: kernel-and-store-decomposition
status: passed
completed: 2026-03-25
---

# Phase 26 Verification

Phase 26 passed verification for the `v2.4` kernel/store extraction. SQLite
receipt, query, authority, budget, revocation, and export implementations now
live in `crates/arc-store-sqlite`, while `arc-kernel` retains the
enforcement contracts and a smaller public facade.

## Automated Verification

- `rg -n "append_arc_receipt_returning_seq|receipts_canonical_bytes_range|store_checkpoint|downcast_mut::<SqliteReceiptStore>" crates/arc-kernel/src/{lib.rs,receipt_store.rs}`
- `cargo check -p arc-store-sqlite`
- `cargo check -p arc-kernel`
- `cargo check -p arc-store-sqlite -p arc-kernel -p arc-control-plane -p arc-hosted-mcp -p arc-cli`
- `cargo test -p arc-kernel -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture --test-threads=1`
- `wc -l crates/arc-kernel/src/lib.rs crates/arc-kernel/src/runtime.rs crates/arc-kernel/src/revocation_runtime.rs`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`

## Result

Passed. Phase 26 now satisfies `ARCH-04` and `ARCH-05`:

- `arc-store-sqlite` now owns the concrete SQLite receipt, budget, authority,
  revocation, query, lineage, analytics, operator-report, and export
  implementation surface.
- `arc-kernel` now exposes traits/contracts plus enforcement logic without
  downcasting into concrete SQLite storage.
- concrete store consumers were rewired to depend on `arc-store-sqlite`
  directly across `arc-cli`, `arc-control-plane`, `arc-hosted-mcp`, and
  kernel integration coverage.
- `crates/arc-kernel/src/lib.rs` is reduced to 8,568 lines, with runtime
  request/response and tool-server surfaces extracted into
  `crates/arc-kernel/src/runtime.rs` and revocation runtime contracts moved to
  `crates/arc-kernel/src/revocation_runtime.rs`.
- kernel unit and integration coverage remained green after the split, and the
  storage-backed CLI regressions still passed.
- `mcp_serve_http` remains sensitive to the pre-existing parallel
  `reserve_listen_addr` race in this suite; the regression passed cleanly when
  run serially with `--test-threads=1`, matching isolated reruns and manual
  startup checks.
