---
phase: 306-dependency-hygiene-and-feature-gating
created: 2026-04-13
status: complete
---

# Phase 306 Research

## Discovery Summary

- `serde_yaml` was referenced in:
  `arc-policy`, `arc-cli`, `arc-control-plane`, and their associated tests.
- Duplicate `reqwest` versions came from direct `0.12.x` workspace pins versus
  `0.13.2` pulled in by alloy’s HTTP transport stack.
- `arc-kernel` and `arc-link` both declared direct `arc-web3` dependencies that
  were no longer referenced in source.
- `arc-link`’s alloy usage was isolated to `chainlink.rs` and `sequencer.rs`;
  the trait/config/control/reporting layers were independent of alloy.
- `arc-anchor`, `arc-settle`, and `arc-web3-bindings` had no non-test consumers
  in the core path, so crate-level feature gating could remove them entirely
  from the feature-disabled graph.

## Dependency Graph Notes

- Updating `rusqlite` from `0.37` to `0.39` collapses the SQLite-side
  `hashbrown` split onto `hashbrown 0.16.x` via `hashlink 0.11`.
- The default web3-enabled graph still carries `hashbrown 0.14.x` via alloy’s
  `dashmap`, which is why the phase validation uses the normal
  `--no-default-features` graph as the core-path duplicate check.

## Implementation Strategy

1. Replace `serde_yaml` with `serde_yml` and update YAML-facing call sites.
2. Move `reqwest` to a shared `0.13.2` workspace dependency and add the
   explicit `form`/`query` features needed by existing call sites.
3. Upgrade `rusqlite` and patch SQLite persistence code to cast `u64` values
   explicitly.
4. Remove unused `arc-web3` edges from `arc-kernel` and `arc-link`.
5. Add explicit `web3` features to `arc-link`, `arc-anchor`, `arc-settle`, and
   `arc-web3-bindings`, with stubs or crate-level gating where needed.
