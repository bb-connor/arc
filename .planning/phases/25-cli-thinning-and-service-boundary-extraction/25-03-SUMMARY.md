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
    - crates/pact-hosted-mcp/Cargo.toml
    - crates/pact-hosted-mcp/src/lib.rs
  modified:
    - Cargo.toml
    - crates/pact-cli/Cargo.toml
    - crates/pact-cli/src/main.rs
    - crates/pact-cli/src/remote_mcp.rs
    - crates/pact-cli/src/enterprise_federation.rs
requirements-completed:
  - ARCH-01
  - ARCH-03
completed: 2026-03-25
---

# Phase 25 Plan 03 Summary

Hosted MCP runtime ownership is no longer local to the CLI crate.

## Accomplishments

- added `pact-hosted-mcp` as a workspace member and made `pact-cli` dispatch to
  that crate for hosted MCP service behavior
- centralized the shared JWT provider profile and hosted-runtime support wiring
  so `remote_mcp.rs` no longer depends on `main.rs`-local definitions
- removed duplicate runtime helper implementations from `main.rs`; the file is
  still large at 3,872 LOC, but it no longer owns the trust-control or hosted
  runtime helper stack directly

## Verification

- `cargo check -p pact-hosted-mcp`
- `cargo check -p pact-cli`
- `cargo test -p pact-cli --test mcp_serve_http --test receipt_query -- --nocapture`
