---
phase: 25-cli-thinning-and-service-boundary-extraction
plan: 03
subsystem: hosted-mcp
tags:
  - architecture
  - hosted-mcp
  - v2.4
requires:
  - 02
provides:
  - Extracted hosted MCP runtime and thinner CLI entrypoint ownership
key-files:
  created:
    - crates/arc-hosted-mcp/Cargo.toml
    - crates/arc-hosted-mcp/src/lib.rs
  modified:
    - Cargo.toml
    - crates/arc-cli/Cargo.toml
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/remote_mcp.rs
    - crates/arc-cli/src/enterprise_federation.rs
requirements-completed:
  - ARCH-01
  - ARCH-03
completed: 2026-03-25
---

# Phase 25 Plan 03 Summary

Hosted MCP runtime ownership is no longer local to the CLI crate.

## Accomplishments

- added `arc-hosted-mcp` as a workspace member and made `arc-cli` dispatch to
  that crate for hosted MCP service behavior
- centralized the shared JWT provider profile and hosted-runtime support wiring
  so `remote_mcp.rs` no longer depends on `main.rs`-local definitions
- removed duplicate runtime helper implementations from `main.rs`; the file is
  still large at 3,872 LOC, but it no longer owns the trust-control or hosted
  runtime helper stack directly

## Verification

- `cargo check -p arc-hosted-mcp`
- `cargo check -p arc-cli`
- `cargo test -p arc-cli --test mcp_serve_http --test receipt_query -- --nocapture`
