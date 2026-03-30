---
phase: 18
slug: durable-a2a-task-lifecycle-and-federation-hardening
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 18 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` |
| **Quick run command** | `cargo test -p arc-a2a-adapter --lib -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Docs verification** | `rg -n "task registry|follow-up|durable task correlation" docs/A2A_ADAPTER_GUIDE.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 18-01 | A2A-03 | `cargo test -p arc-a2a-adapter --lib -- --nocapture` |
| 18-02 | A2A-03, A2A-04 | `cargo test -p arc-a2a-adapter --lib -- --nocapture` |
| 18-03 | A2A-04, A2A-05 | `cargo test -p arc-a2a-adapter --lib -- --nocapture` |

## Coverage Notes

- restart-safe task recovery is covered directly by the adapter task-registry
  regression
- follow-up validation covers send/get/cancel/subscribe and push-config paths
- partner isolation is enforced through stored server, interface, and binding
  checks

## Sign-Off

- [x] durable lifecycle correlation is automated
- [x] follow-up validation is fail closed
- [x] restart recovery is covered
- [x] `nyquist_compliant: true` is set

**Approval:** completed
