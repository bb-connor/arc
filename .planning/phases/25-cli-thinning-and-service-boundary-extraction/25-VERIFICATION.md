---
phase: 25
slug: cli-thinning-and-service-boundary-extraction
status: passed
completed: 2026-03-25
---

# Phase 25 Verification

Phase 25 passed targeted verification for the first architecture extraction in
`v2.4`: the CLI no longer owns trust-control and hosted MCP runtime boundaries
directly, and those surfaces now compile and test through dedicated crates.

## Automated Verification

- `cargo check -p arc-control-plane`
- `cargo check -p arc-hosted-mcp`
- `cargo check -p arc-cli`
- `cargo test -p arc-cli --test provider_admin --test certify --test mcp_serve_http --test receipt_query -- --nocapture`
- `wc -l crates/arc-cli/src/main.rs crates/arc-control-plane/src/lib.rs crates/arc-hosted-mcp/src/lib.rs`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`

## Result

Passed. Phase 25 now satisfies `ARCH-01`, `ARCH-02`, and `ARCH-03`:

- `arc-control-plane` and `arc-hosted-mcp` now exist as standalone workspace
  crates and own the extracted service/runtime boundaries
- `arc-cli` reexports the control-plane helpers, control-plane modules, and
  hosted MCP runtime instead of carrying duplicate service definitions locally
- `crates/arc-cli/src/main.rs` is reduced to 3,872 lines and no longer owns
  the trust-control or hosted-runtime helper implementation stack directly
- provider admin, certification, hosted MCP, and receipt-query integration
  coverage stayed green after the extraction
- Phase 25 deliberately preserves path-included compatibility facades inside
  the new crates; deeper native module normalization is deferred to later
  phases so the first boundary extraction stays low-risk
