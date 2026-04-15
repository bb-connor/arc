---
phase: 391-authoritative-edge-unification
plan: 01
subsystem: authoritative-edges
tags: [acp-proxy, a2a-edge, acp-edge, compatibility, receipts]
requirements:
  completed: [AUTH-01, AUTH-02, AUTH-03]
completed: 2026-04-14
verification:
  - cargo test -p arc-acp-proxy -p arc-a2a-edge -p arc-acp-edge
  - git diff --check -- crates/arc-acp-proxy/Cargo.toml crates/arc-acp-proxy/src/lib.rs crates/arc-acp-proxy/src/attestation.rs crates/arc-acp-proxy/src/receipt.rs crates/arc-acp-proxy/src/interceptor.rs crates/arc-acp-proxy/src/kernel_checker.rs crates/arc-acp-proxy/src/tests/all.rs crates/arc-a2a-edge/src/lib.rs crates/arc-acp-edge/src/lib.rs
---

# Phase 391 Plan 01 Summary

Phase `391` is complete. ARC's authoritative A2A/ACP edge story is now
cleaner and more defensible than it was after phase `390`.

## Accomplishments

- Replaced ACP proxy live-path token-only checking with a kernel-backed
  `KernelCapabilityChecker` that routes ACP filesystem and terminal
  authorization through `CrossProtocolOrchestrator` and a guard-only authority
  server registered with the kernel.
- Preserved fail-closed behavior while upgrading ACP checks to emit real
  allow/deny ARC receipts and propagate the authorization receipt reference
  into ACP audit context.
- Quarantined direct passthrough helpers behind explicit
  `edge.compatibility()` wrappers in both `arc-a2a-edge` and `arc-acp-edge`,
  rather than leaving those methods directly on the authoritative edge types.
- Tightened non-authoritative metadata so compatibility and preview paths now
  explicitly declare `compatibilityOnly` / `previewOnly`,
  `receiptBearing: false`, and `claimEligible: false`.
- Updated crate-local tests so the new authority path and compatibility-only
  API surfaces are exercised directly.

## Verification

- `cargo test -p arc-acp-proxy -p arc-a2a-edge -p arc-acp-edge`
- `git diff --check -- crates/arc-acp-proxy/Cargo.toml crates/arc-acp-proxy/src/lib.rs crates/arc-acp-proxy/src/attestation.rs crates/arc-acp-proxy/src/receipt.rs crates/arc-acp-proxy/src/interceptor.rs crates/arc-acp-proxy/src/kernel_checker.rs crates/arc-acp-proxy/src/tests/all.rs crates/arc-a2a-edge/src/lib.rs crates/arc-acp-edge/src/lib.rs`

## Phase Status

Phase `391` is complete. The next queued closure lane is phase `392`
(`Fidelity Semantics and Publication Gating`).
