---
phase: 25
slug: cli-thinning-and-service-boundary-extraction
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 25 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo check`, targeted `cargo test`, roadmap analyzer |
| **Quick run command** | `cargo check -p arc-cli` |
| **Control-plane regression command** | `cargo test -p arc-cli --test provider_admin --test certify -- --nocapture` |
| **Hosted runtime regression command** | `cargo test -p arc-cli --test mcp_serve_http --test receipt_query -- --nocapture` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 25-01 | ARCH-01, ARCH-02, ARCH-03 | `rg -n "arc-control-plane|arc-hosted-mcp|pub use arc_control_plane|pub use arc_hosted_mcp" Cargo.toml crates/arc-cli/Cargo.toml crates/arc-cli/src/main.rs crates/arc-control-plane/src/lib.rs crates/arc-hosted-mcp/src/lib.rs` |
| 25-02 | ARCH-01, ARCH-02 | `cargo check -p arc-control-plane`, `cargo test -p arc-cli --test provider_admin --test certify -- --nocapture` |
| 25-03 | ARCH-01, ARCH-03 | `cargo check -p arc-hosted-mcp`, `cargo check -p arc-cli`, `cargo test -p arc-cli --test mcp_serve_http --test receipt_query -- --nocapture` |

## Coverage Notes

- the extraction is intentionally staged: new crates now own the service
  boundary, while path-included compatibility modules keep the semantic churn
  bounded during Phase 25
- provider admin and certification cover the trust-control client/server surface
- hosted MCP and receipt-query integration coverage prove the extracted runtime
  still serves admin, OAuth, session, and trust-backed queries end to end

## Sign-Off

- [x] `arc-control-plane` exists and compiles as a standalone workspace crate
- [x] `arc-hosted-mcp` exists and compiles as a standalone workspace crate
- [x] `arc-cli` dispatches through the extracted crates instead of owning the
  duplicated service helper stack directly
- [x] targeted trust-control and hosted runtime regressions passed

**Approval:** completed
