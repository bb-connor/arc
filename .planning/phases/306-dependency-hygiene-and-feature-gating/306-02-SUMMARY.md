---
phase: 306-dependency-hygiene-and-feature-gating
plan: 02
subsystem: feature-gating
tags:
  - rust
  - cargo-features
  - web3
  - build-graph
requires:
  - phase-306-01
provides:
  - explicit `web3` feature boundaries around the alloy-heavy crates
  - stubbed non-web3 `arc-link` Chainlink/sequencer path for the core build
  - clean normal `--no-default-features` workspace graph without alloy-family crates or duplicate core-path HTTP/hash crates
affects:
  - phase-307
  - phase-308
  - phase-309
tech-stack:
  patterns:
    - crate-level `#![cfg(feature = \"web3\")]` gating for whole web3-only crates
    - `cfg_attr(path = ...)` stub swapping for mixed lightweight/heavy crates
key-files:
  created:
    - crates/arc-link/src/chainlink_disabled.rs
    - crates/arc-link/src/sequencer_disabled.rs
  modified:
    - crates/arc-link/Cargo.toml
    - crates/arc-link/src/lib.rs
    - crates/arc-anchor/Cargo.toml
    - crates/arc-anchor/src/lib.rs
    - crates/arc-settle/Cargo.toml
    - crates/arc-settle/src/lib.rs
    - crates/arc-web3-bindings/Cargo.toml
    - crates/arc-web3-bindings/src/lib.rs
key-decisions:
  - "Kept `web3` enabled by default so the normal developer build preserves the existing web3 runtime behavior."
  - "Used stub modules in `arc-link` instead of disabling the whole crate, because the kernel still needs the lightweight oracle traits and conversion helpers in the core path."
  - "Validated duplicate-package cleanup against the normal `--no-default-features` graph, which is the graph this phase is explicitly trying to slim down."
patterns-established:
  - "Mixed crates can retain lightweight shared APIs in the core path by swapping heavy modules with feature-disabled stubs."
requirements-completed:
  - DEPS-03
  - DEPS-04
duration: 41 min
completed: 2026-04-13
---

# Phase 306 Plan 02: Feature Gating Summary

**The web3 stack is now an explicit feature boundary: the default build still
includes it, but the core no-default-features workspace build excludes alloy
and related EVM compile weight entirely**

## Verification

- `cargo check --no-default-features -p arc-link -p arc-anchor -p arc-settle -p arc-web3-bindings`
- `cargo build --workspace --no-default-features`
- `cargo check --workspace`
- `cargo test -p arc-link --no-default-features`
- `cargo tree -e normal -d --no-default-features`
- `cargo tree -e normal --no-default-features`

## Notes

- The default feature graph still contains alloy and its transitive
  `hashbrown 0.14.x` via the active web3 stack, which is expected.
- The core-path normal no-default-features graph is the one that now stays free
  of alloy-family crates and duplicate `reqwest`/`serde_yaml`/`hashbrown`
  headers.
