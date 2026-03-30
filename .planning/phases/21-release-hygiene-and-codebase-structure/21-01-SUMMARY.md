---
phase: 21-release-hygiene-and-codebase-structure
plan: 01
subsystem: release-inventory
tags:
  - hygiene
  - structure
  - v2.3
requires: []
provides:
  - Explicit release-input debt inventory and a bounded refactor target
key-files:
  created:
    - .planning/phases/21-release-hygiene-and-codebase-structure/21-CONTEXT.md
    - .planning/phases/21-release-hygiene-and-codebase-structure/21-RESEARCH.md
requirements-completed:
  - PROD-07
  - PROD-08
completed: 2026-03-25
---

# Phase 21 Plan 01 Summary

Phase 21 now has a concrete inventory rather than a vague “clean up the repo”
goal.

## Accomplishments

- recorded the tracked Python build/cache/egg-info debt explicitly
- documented the largest structural pressure points by file size
- selected the provider/certification/federated-issue admin slice as the safest
  first extraction from `main.rs`

## Verification

- `wc -l crates/arc-cli/src/main.rs crates/arc-cli/src/admin.rs`
