---
phase: 303
slug: arc-core-crate-decomposition
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-04-13
---

# Phase 303 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust workspace compile + targeted crate tests |
| **Config file** | `Cargo.toml` workspace |
| **Quick run command** | `cargo check -p arc-core -p arc-bindings-core -p arc-manifest -p arc-wall` |
| **Full suite command** | `cargo check --workspace && cargo test -p arc-kernel -p arc-settle -p arc-store-sqlite --tests` |
| **Estimated runtime** | ~180 seconds |

## Sampling Rate

- **After every task commit:** Run the quick compile command for the shared
  substrate and narrow dependents
- **After every plan wave:** Run the full suite command
- **Before milestone verification:** Full suite must be green
- **Max feedback latency:** 180 seconds

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 303-01 | DECOMP-01 | `cargo check -p arc-core -p arc-bindings-core -p arc-manifest -p arc-wall` plus re-export/import grep checks |
| 303-02 | DECOMP-02, DECOMP-03 | `cargo check --workspace` plus targeted downstream compile/test runs for crates using extracted domain crates |
| 303-03 | DECOMP-03, DECOMP-04 | `cargo check --workspace`, targeted downstream tests, and a reproducible incremental rebuild timing comparison |

## Coverage Notes

- The compile-time proof should target a narrow consumer such as
  `arc-bindings-core`, `arc-manifest`, `arc-wall`, or `examples/hello-tool`,
  because `arc-kernel` will still depend on many extracted domains.
- Existing Rust test infrastructure is sufficient; no new framework or harness
  is required for this phase.
- Workspace compile success is itself a core artifact for this decomposition
  phase because dependency hygiene and import rewiring are the main risks.

## Sign-Off

- [ ] Shared-substrate compile checks stay green after each extraction step
- [ ] Workspace compile stays green at wave boundaries
- [ ] Targeted downstream tests cover crates using extracted domain crates
- [ ] Incremental rebuild comparison is recorded and reproducible
- [ ] `nyquist_compliant: true` is set when phase execution finishes

**Approval:** pending
