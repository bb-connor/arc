---
phase: 17
slug: a2a-auth-matrix-and-partner-admission-hardening
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 17 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` |
| **Quick run command** | `cargo test -p pact-a2a-adapter --lib -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Docs verification** | `rg -n "partner admission|request headers|query params|cookies" docs/A2A_ADAPTER_GUIDE.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 17-01 | A2A-01 | `cargo test -p pact-a2a-adapter --lib -- --nocapture` |
| 17-02 | A2A-02 | `cargo test -p pact-a2a-adapter --lib -- --nocapture` |
| 17-03 | A2A-01, A2A-02 | `cargo test -p pact-a2a-adapter --lib -- --nocapture` |

## Coverage Notes

- provider-specific request shaping is covered by the adapter auth surface test
- tenant-mismatch admission rejection is covered directly in the adapter suite
- kernel-mediated receipt generation still rides the same adapter regression
  coverage

## Sign-Off

- [x] operator-configurable auth surfaces are automated
- [x] partner admission is fail closed
- [x] diagnostics remain operator-visible
- [x] `nyquist_compliant: true` is set

**Approval:** completed
