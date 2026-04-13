---
phase: 304
slug: mega-file-module-decomposition
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-04-13
---

# Phase 304 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust workspace compile + targeted crate tests + global file-size gate |
| **Config file** | `Cargo.toml` workspace |
| **Quick run command** | `cargo check -p arc-cli -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge` |
| **Full suite command** | `cargo check --workspace && cargo test -p arc-cli -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge --tests` |
| **Size gate command** | `find crates -name '*.rs' ! -path '*/tests/*' -print0 | xargs -0 wc -l | awk '$1 > 3000'` |
| **Estimated runtime** | ~240 seconds |

## Sampling Rate

- **After every task commit:** run the quick compile command for the touched
  crates and the size gate if a large-file split just landed
- **After every plan wave:** run the full suite command plus the size gate
- **Before milestone verification:** full suite and size gate must both be
  green
- **Max feedback latency:** 240 seconds

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 304-01 | DECOMP-05, DECOMP-07, DECOMP-09 | `cargo check -p arc-cli -p arc-control-plane -p arc-hosted-mcp -p arc-mercury` plus size gate |
| 304-02 | DECOMP-06, DECOMP-08 | `cargo check -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge -p arc-settle -p arc-wall` plus targeted tests |
| 304-03 | DECOMP-09 | `cargo check --workspace`, `cargo test -p arc-cli -p arc-kernel -p arc-store-sqlite -p arc-mcp-edge --tests`, and the global size gate |

## Coverage Notes

- The final gate is global: any remaining non-test Rust file over 3,000 lines
  fails the phase even if it was not one of the roadmap-named roots.
- Existing tests already cover the relevant CLI, kernel, MCP edge, and
  SQLite-store behavior; no new test harness is required.
- A structural phase still needs real compile/test evidence because module
  extraction can easily break visibility, imports, and internal wiring.

## Sign-Off

- [ ] `trust_control.rs`, `arc-kernel/src/lib.rs`, `arc-cli/src/main.rs`,
      `receipt_store.rs`, and `runtime.rs` are decomposed into focused module
      trees
- [ ] global non-test file-size gate is green
- [ ] workspace compile stays green after each wave
- [ ] targeted downstream tests still pass after file moves
- [ ] `nyquist_compliant: true` is set when phase execution finishes

**Approval:** pending
