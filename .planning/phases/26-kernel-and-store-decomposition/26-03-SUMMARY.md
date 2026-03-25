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
    - crates/pact-kernel/src/runtime.rs
    - crates/pact-kernel/src/revocation_runtime.rs
  modified:
    - crates/pact-kernel/src/lib.rs
    - crates/pact-kernel/tests/retention.rs
    - crates/pact-cli/tests/receipt_query.rs
    - crates/pact-cli/tests/mcp_serve_http.rs
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
  `crates/pact-kernel/src/runtime.rs`
- moved revocation runtime contracts into
  `crates/pact-kernel/src/revocation_runtime.rs`, reducing
  `crates/pact-kernel/src/lib.rs` to 8,568 lines
- requalified kernel storage behavior, `receipt_query`, and hosted MCP runtime
  flows after the store split

## Verification

- `cargo test -p pact-kernel -- --nocapture`
- `cargo test -p pact-cli --test receipt_query -- --nocapture`
- `cargo test -p pact-cli --test mcp_serve_http -- --nocapture --test-threads=1`
- `wc -l crates/pact-kernel/src/lib.rs crates/pact-kernel/src/runtime.rs crates/pact-kernel/src/revocation_runtime.rs`
