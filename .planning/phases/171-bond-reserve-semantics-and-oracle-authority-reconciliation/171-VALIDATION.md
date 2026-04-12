---
phase: 171
slug: bond-reserve-semantics-and-oracle-authority-reconciliation
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-02
---

# Phase 171 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Contract compile** | `pnpm --dir contracts compile` |
| **Runtime test lanes** | `cargo test -p arc-core web3 -- --test-threads=1`, `cargo test -p arc-link -- --test-threads=1`, `cargo test -p arc-settle --lib -- --test-threads=1`, `cargo test -p arc-web3-bindings -- --test-threads=1` |
| **Contract/runtime qualification** | `pnpm --dir contracts devnet:smoke` and `./scripts/qualify-web3-runtime.sh` |
| **Artifact validation** | `jq empty` on the phase `171` standards artifacts listed in `171-VERIFICATION.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 171-01 | W3INT-03 | contract compile plus bindings/runtime test lanes |
| 171-02 | W3INT-03 | qualification lane over local-devnet contract behavior |
| 171-03 | W3INT-03, W3INT-05 | artifact validation plus `git diff --check` |

## Coverage Notes

- the official FX authority remains `arc-link`; `ArcPriceResolver` is reference
  package surface rather than the authoritative off-chain runtime source

## Sign-Off

- [x] bond collateral and reserve metadata are no longer conflated
- [x] `arc-link` is the sole runtime FX authority
- [x] docs, bindings, and runtime config tell the same money-handling story

**Approval:** completed
