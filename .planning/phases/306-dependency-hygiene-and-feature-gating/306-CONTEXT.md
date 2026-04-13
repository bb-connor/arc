---
phase: 306-dependency-hygiene-and-feature-gating
milestone: v2.80
created: 2026-04-13
status: complete
---

# Phase 306 Context

## Goal

Remove deprecated dependencies, collapse duplicated HTTP/runtime crates where
the core path can share one version, and gate the web3/alloy stack so the core
workspace build does not pay for EVM-only dependencies.

## Current Reality

- `serde_yaml` remained in `arc-policy`, `arc-cli`, and `arc-control-plane`.
- The workspace carried both direct `reqwest 0.12.x` and transitive
  `reqwest 0.13.x` through alloy.
- `arc-link` mixed lightweight oracle traits/configuration with alloy-backed
  Chainlink/sequencer readers in the same always-on compile path.
- `arc-anchor`, `arc-settle`, and `arc-web3-bindings` were always-on workspace
  members even though their heavy dependencies are only needed for the web3
  runtime path.

## Boundaries

- Preserve default behavior for the normal workspace build.
- Keep the kernel’s lightweight `arc-link` traits and conversion helpers
  available without enabling alloy.
- Treat the normal `--no-default-features` workspace graph as the core-path
  measurement target; dev-only/test-only web3 dependencies are out of scope for
  the compile-hygiene gate.

## Key Risks

- `reqwest 0.13.x` feature names differ from `0.12.x` (`rustls`, `form`,
  `query`), so a straight version bump can silently break existing HTTP call
  sites.
- The `rusqlite` bump needed for the duplicate-graph cleanup removes implicit
  `u64` SQLite conversions, so persistence code must cast explicitly.
- `arc-anchor` and `arc-settle` are workspace members; feature gating must let
  them compile as empty crates when `web3` is disabled.

## Decision

Keep default features unchanged for the web3 path, but add explicit `web3`
features to the alloy-heavy crates and make the feature-disabled workspace
build the authoritative “core” compile path for this phase’s dependency-hygiene
checks.
