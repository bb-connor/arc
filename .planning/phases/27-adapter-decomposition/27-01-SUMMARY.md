---
phase: 27-adapter-decomposition
plan: 01
subsystem: mcp-edge
tags:
  - architecture
  - refactor
  - adapters
  - v2.4
requires: []
provides:
  - Dedicated MCP edge runtime crate with compatibility reexports
key-files:
  created:
    - crates/arc-mcp-edge/Cargo.toml
    - crates/arc-mcp-edge/src/lib.rs
    - crates/arc-mcp-edge/src/runtime.rs
  modified:
    - Cargo.toml
    - crates/arc-mcp-adapter/Cargo.toml
    - crates/arc-mcp-adapter/src/lib.rs
requirements-completed:
  - ARCH-06
completed: 2026-03-25
---

# Phase 27 Plan 01 Summary

## Accomplishments

- created `arc-mcp-edge` as a new workspace crate
- moved the MCP edge runtime and shared MCP transport/error/result types into
  the new crate
- converted `arc-mcp-adapter` into a compatibility facade that reexports the
  edge surface while keeping translation, manifest adaptation, and transport
  wrappers local

## Verification

- `cargo check -p arc-mcp-edge -p arc-mcp-adapter`
