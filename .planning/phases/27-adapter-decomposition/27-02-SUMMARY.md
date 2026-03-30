---
phase: 27-adapter-decomposition
plan: 02
subsystem: a2a-adapter
tags:
  - architecture
  - refactor
  - adapters
  - v2.4
requires:
  - 27-01
provides:
  - Concern-based A2A source-file split with a thin crate facade
key-files:
  created:
    - crates/arc-a2a-adapter/src/config.rs
    - crates/arc-a2a-adapter/src/partner_policy.rs
    - crates/arc-a2a-adapter/src/invoke.rs
    - crates/arc-a2a-adapter/src/protocol.rs
    - crates/arc-a2a-adapter/src/task_registry.rs
    - crates/arc-a2a-adapter/src/mapping.rs
    - crates/arc-a2a-adapter/src/discovery.rs
    - crates/arc-a2a-adapter/src/auth.rs
    - crates/arc-a2a-adapter/src/transport.rs
    - crates/arc-a2a-adapter/src/tests.rs
  modified:
    - crates/arc-a2a-adapter/src/lib.rs
requirements-completed:
  - ARCH-07
completed: 2026-03-25
---

# Phase 27 Plan 02 Summary

## Accomplishments

- reduced `crates/arc-a2a-adapter/src/lib.rs` to a 40-line facade
- split the prior 8k-line A2A implementation into separate source files for
  config, partner policy, invocation, protocol models, task registry, mapping,
  discovery, auth, transport, and tests
- kept the crate surface stable by preserving the original root-module item
  layout through `include!`-based source partitioning

## Verification

- `cargo check -p arc-a2a-adapter`
- `wc -l crates/arc-a2a-adapter/src/lib.rs crates/arc-a2a-adapter/src/*.rs | sort -nr | head -n 12`
