---
phase: 20
slug: ecosystem-conformance-and-operator-onboarding
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 20 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test`, roadmap analysis |
| **Quick run command** | `cargo test -p arc-a2a-adapter --lib -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Docs and planning verification** | `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 20-01 | ECO-01 | `cargo test -p arc-a2a-adapter --lib -- --nocapture` and `cargo test -p arc-cli --test certify -- --nocapture` |
| 20-02 | ECO-02 | `cargo test -p arc-cli --test provider_admin -- --nocapture` |
| 20-03 | ECO-01, ECO-02 | `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze` |

## Coverage Notes

- A2A auth and lifecycle conformance rides the adapter end-to-end suite
- certification registry parity rides the local and remote CLI integration suite
- operator/admin regression remains covered after trust-control surface growth
- roadmap analysis verifies the milestone planning state is internally coherent

## Sign-Off

- [x] conformance lanes are automated
- [x] docs are aligned to shipped behavior
- [x] planning artifacts trace the milestone end to end
- [x] `nyquist_compliant: true` is set

**Approval:** completed
