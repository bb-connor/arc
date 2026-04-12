---
phase: 169
slug: settlement-identity-truth-and-concurrency-safe-dispatch
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-02
---

# Phase 169 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Bindings lane** | `env CARGO_TARGET_DIR=target/arc-web3-bindings CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-web3-bindings -- --test-threads=1` |
| **Settlement runtime lane** | `env CARGO_TARGET_DIR=target/arc-settle-verify CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle --lib -- --test-threads=1` |
| **Devnet identity lane** | `env CARGO_TARGET_DIR=target/arc-settle-runtime CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-settle --test runtime_devnet -- --nocapture` |
| **Contract/runtime qualification** | `pnpm --dir contracts devnet:smoke` and `./scripts/qualify-web3-runtime.sh` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 169-01 | W3INT-01 | bindings lane plus contract devnet smoke |
| 169-02 | W3INT-01 | settlement runtime lane and runtime devnet identity lane |
| 169-03 | W3INT-01 | contract/runtime qualification plus `git diff --check` |

## Coverage Notes

- identity is validated from immutable contract terms and emitted events, not
  mutable runtime nonce guesses
- duplicate replay is covered in both contract and runtime qualification

## Sign-Off

- [x] escrow and bond IDs are deterministic
- [x] runtime reconciliation uses contract truth
- [x] duplicate replay fails closed

**Approval:** completed
