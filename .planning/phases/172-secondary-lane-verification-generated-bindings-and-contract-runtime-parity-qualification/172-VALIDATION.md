---
phase: 172
slug: secondary-lane-verification-generated-bindings-and-contract-runtime-parity-qualification
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-02
---

# Phase 172 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Compile lane** | `pnpm --dir contracts compile` |
| **Bindings/anchor/settle lanes** | `cargo test -p arc-web3-bindings -- --test-threads=1`, `cargo test -p arc-anchor -- --test-threads=1`, and `cargo test -p arc-settle --lib -- --test-threads=1` |
| **Parity lane** | `./scripts/check-web3-contract-parity.sh` |
| **Qualification lane** | `./scripts/qualify-web3-runtime.sh` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 172-01 | W3INT-04 | bindings/anchor/settle lanes |
| 172-02 | W3INT-05 | parity lane over contracts, bindings, runtime constants, and standards |
| 172-03 | W3INT-05 | qualification lane plus `git diff --check` |

## Coverage Notes

- Bitcoin secondary-lane proofs are checked against the ARC super-root digest
- Rust bindings are generated from compiled interface artifacts rather than
  hand-maintained ABI drift

## Sign-Off

- [x] Bitcoin secondary lanes are cryptographically verified
- [x] bindings are artifact-derived
- [x] contract/runtime parity has an explicit qualification lane

**Approval:** completed
