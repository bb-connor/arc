---
phase: 26
slug: kernel-and-store-decomposition
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 26 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `rg`, `cargo check`, targeted `cargo test`, roadmap analyzer |
| **Quick run command** | `cargo check -p pact-store-sqlite -p pact-kernel` |
| **Kernel regression command** | `cargo test -p pact-kernel -- --nocapture` |
| **Store-backed CLI regression command** | `cargo test -p pact-cli --test receipt_query -- --nocapture` |
| **Hosted runtime regression command** | `cargo test -p pact-cli --test mcp_serve_http -- --nocapture --test-threads=1` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 26-01 | ARCH-04, ARCH-05 | `rg -n "append_pact_receipt_returning_seq|receipts_canonical_bytes_range|store_checkpoint|downcast_mut::<SqliteReceiptStore>" crates/pact-kernel/src/{lib.rs,receipt_store.rs}` |
| 26-02 | ARCH-04 | `cargo check -p pact-store-sqlite`, `cargo check -p pact-kernel`, `cargo check -p pact-store-sqlite -p pact-kernel -p pact-control-plane -p pact-hosted-mcp -p pact-cli` |
| 26-03 | ARCH-04, ARCH-05 | `cargo test -p pact-kernel -- --nocapture`, `cargo test -p pact-cli --test receipt_query -- --nocapture`, `cargo test -p pact-cli --test mcp_serve_http -- --nocapture --test-threads=1`, `wc -l crates/pact-kernel/src/lib.rs crates/pact-kernel/src/runtime.rs crates/pact-kernel/src/revocation_runtime.rs` |

## Coverage Notes

- the kernel/store split is staged so contracts remain in `pact-kernel` while
  concrete SQLite implementations move into `pact-store-sqlite`
- `pact-kernel` unit tests now use local lightweight SQLite harnesses where the
  test needs current-crate trait objects, while integration tests continue to
  exercise the real extracted store crate
- `receipt_query` proves the extracted store/query/report path still works
  through trust-control
- `mcp_serve_http` proves the hosted runtime still boots and serves the
  extracted storage boundary; it is validated serially because the existing
  port-reservation helper is parallel-racy

## Sign-Off

- [x] `pact-store-sqlite` exists and compiles as a standalone workspace crate
- [x] `pact-kernel` no longer depends on a concrete SQLite downcast for
  checkpoint or sequence-aware persistence
- [x] concrete SQLite store consumers now import `pact-store-sqlite` directly
- [x] `pact-kernel/src/lib.rs` is slimmer and re-exports smaller runtime
  modules instead of owning all runtime-facing types inline
- [x] kernel and store-backed CLI regressions passed after the extraction

**Approval:** completed
