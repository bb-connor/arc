---
phase: 27
slug: adapter-decomposition
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 27 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo check`, crate tests, CLI integration tests |
| **Quick run command** | `cargo check -p arc-mcp-edge -p arc-mcp-adapter -p arc-a2a-adapter` |
| **MCP edge regression command** | `cargo test -p arc-mcp-edge -- --nocapture` |
| **A2A adapter regression command** | `cargo test -p arc-a2a-adapter -- --nocapture` |
| **Hosted runtime regression command** | `cargo test -p arc-cli --test mcp_serve_http -- --nocapture --test-threads=1` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 27-01 | ARCH-06 | `cargo check -p arc-mcp-edge -p arc-mcp-adapter` |
| 27-02 | ARCH-07 | `cargo check -p arc-a2a-adapter`, `wc -l crates/arc-a2a-adapter/src/lib.rs crates/arc-a2a-adapter/src/*.rs` |
| 27-03 | ARCH-06, ARCH-07 | `cargo test -p arc-mcp-edge -- --nocapture`, `cargo test -p arc-a2a-adapter -- --nocapture`, `cargo test -p arc-cli --test mcp_serve_http -- --nocapture --test-threads=1` |

## Coverage Notes

- `arc-mcp-edge` now owns the MCP edge runtime and its test suite directly
- `arc-mcp-adapter` remains the compatibility import surface while depending
  on the extracted edge crate
- `arc-a2a-adapter` keeps its original root-module semantics so the split does
  not force caller-visible API churn during the refactor milestone
- the hosted-MCP integration lane is still run serially because the pre-existing
  port-reservation helper is parallel-racy

## Sign-Off

- [x] `arc-mcp-edge` exists and compiles as a standalone workspace crate
- [x] `arc-mcp-adapter` now depends on and reexports the extracted MCP edge
  runtime surface
- [x] `arc-a2a-adapter/src/lib.rs` is reduced to a thin facade over multiple
  concern-based source files
- [x] MCP edge, A2A adapter, and hosted-MCP integration regressions passed

**Approval:** completed
