---
phase: 170
slug: mandatory-receipt-storage-checkpointing-and-web3-evidence-gates
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-02
---

# Phase 170 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Compile lane** | `env CARGO_TARGET_DIR=target/phase170-check CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo check -p arc-kernel -p arc-control-plane -p arc-anchor -p arc-settle -p arc-cli --tests` |
| **Evidence tests** | `env CARGO_TARGET_DIR=target/arc-cli-web3-evidence CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p arc-cli web3_evidence -- --test-threads=1` plus the matching `arc-control-plane`, `arc-kernel`, `arc-anchor`, and `arc-settle` targeted runs from `170-VERIFICATION.md` |
| **Qualification lane** | `./scripts/qualify-web3-runtime.sh` |
| **Formatting/sanity** | `cargo fmt --all --check` and `git diff --check` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 170-01 | W3INT-02 | compile lane plus CLI/control-plane/kernel evidence tests |
| 170-02 | W3INT-02 | anchor and settle targeted evidence-substrate tests |
| 170-03 | W3INT-02 | qualification lane plus formatting/sanity |

## Coverage Notes

- this phase validates fail-closed receipt storage, checkpoint issuance, and
  canonical evidence-bundle completeness across kernel and runtime surfaces

## Sign-Off

- [x] web3-enabled deployments require durable receipt storage
- [x] checkpoint issuance is mandatory when web3 lanes are enabled
- [x] incomplete evidence substrate assumptions fail closed

**Approval:** completed
