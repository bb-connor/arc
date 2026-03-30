---
phase: 26-kernel-and-store-decomposition
plan: 03
subsystem: kernel-facade
tags:
  - architecture
  - kernel
  - tests
  - v2.4
requires:
  - 02
provides:
  - Smaller kernel facade and requalified storage-backed coverage
key-files:
  created:
    - crates/arc-kernel/src/runtime.rs
    - crates/arc-kernel/src/revocation_runtime.rs
  modified:
    - crates/arc-kernel/src/lib.rs
    - crates/arc-kernel/tests/retention.rs
    - crates/arc-cli/tests/receipt_query.rs
    - crates/arc-cli/tests/mcp_serve_http.rs
requirements-completed:
  - ARCH-04
  - ARCH-05
completed: 2026-03-25
---

# Phase 26 Plan 03 Summary

The kernel facade is smaller, and the store-backed regressions were requalified
after the extraction.

## Accomplishments

- extracted runtime-facing request/response and tool-server ownership types into
  `crates/arc-kernel/src/runtime.rs`
- moved revocation runtime contracts into
  `crates/arc-kernel/src/revocation_runtime.rs`, reducing
  `crates/arc-kernel/src/lib.rs` to 8,568 lines
- requalified kernel storage behavior, `receipt_query`, and hosted MCP runtime
  flows after the store split

## Verification

- `cargo test -p arc-kernel -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture --test-threads=1`
- `wc -l crates/arc-kernel/src/lib.rs crates/arc-kernel/src/runtime.rs crates/arc-kernel/src/revocation_runtime.rs`
