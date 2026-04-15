---
phase: 391-authoritative-edge-unification
status: passed
completed: 2026-04-14
---

# Phase 391 Verification

## Runtime Verification

- `cargo test -p arc-acp-proxy -p arc-a2a-edge -p arc-acp-edge`

This verification proves:

- ACP live-path capability enforcement now routes through the orchestrated
  kernel authority path and still fails closed on malformed, expired,
  tampered, and out-of-scope tokens.
- A2A and ACP direct passthrough behavior remains available only through
  explicit compatibility wrappers.
- Compatibility and permission-preview metadata stays explicitly
  non-authoritative and non-claim-bearing.

## Patch Integrity

- `git diff --check -- crates/arc-acp-proxy/Cargo.toml crates/arc-acp-proxy/src/lib.rs crates/arc-acp-proxy/src/attestation.rs crates/arc-acp-proxy/src/receipt.rs crates/arc-acp-proxy/src/interceptor.rs crates/arc-acp-proxy/src/kernel_checker.rs crates/arc-acp-proxy/src/tests/all.rs crates/arc-a2a-edge/src/lib.rs crates/arc-acp-edge/src/lib.rs`

No whitespace or patch-application integrity issues were reported on the
touched runtime files.
