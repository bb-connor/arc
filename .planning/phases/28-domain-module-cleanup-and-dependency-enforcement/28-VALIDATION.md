---
phase: 28
slug: domain-module-cleanup-and-dependency-enforcement
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 28 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo check`, crate tests, shell guardrail checks |
| **Quick run command** | `cargo check -p arc-credentials -p arc-reputation -p arc-policy` |
| **Layering guard command** | `./scripts/check-workspace-layering.sh` |
| **Credentials regression command** | `cargo test -p arc-credentials -- --nocapture` |
| **Reputation regression command** | `cargo test -p arc-reputation -- --nocapture` |
| **Policy regression command** | `cargo test -p arc-policy -- --nocapture` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 28-01 | ARCH-08 | `cargo check -p arc-credentials -p arc-reputation -p arc-policy`, `wc -l crates/arc-credentials/src/lib.rs crates/arc-reputation/src/lib.rs crates/arc-policy/src/evaluate.rs` |
| 28-02 | ARCH-09 | `./scripts/check-workspace-layering.sh`, `rg -n "check-workspace-layering|WORKSPACE_STRUCTURE" scripts/ci-workspace.sh docs/architecture/WORKSPACE_STRUCTURE.md` |
| 28-03 | ARCH-08, ARCH-09 | `cargo test -p arc-credentials -- --nocapture`, `cargo test -p arc-reputation -- --nocapture`, `cargo test -p arc-policy -- --nocapture`, `./scripts/check-workspace-layering.sh` |

## Coverage Notes

- the module split intentionally preserved public crate surfaces so the phase
  reduces ownership radius without forcing downstream churn
- the new layering script is intentionally narrow and negative: it blocks
  domain crates from drifting back toward CLI and HTTP dependencies
- `scripts/ci-workspace.sh` is the qualification hook for the guardrail, so the
  release lane inherits the new architecture check instead of relying on manual
  memory

## Sign-Off

- [x] `arc-credentials`, `arc-reputation`, and `arc-policy` now use thin
  entry modules over named source files
- [x] workspace layering is documented and enforced by script
- [x] the domain crate test lanes passed after the split
- [x] the qualification path now includes the layering guard

**Approval:** completed
