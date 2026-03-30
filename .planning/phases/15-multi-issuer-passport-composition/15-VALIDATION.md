---
phase: 15
slug: multi-issuer-passport-composition
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-24
---

# Phase 15 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` |
| **Quick run command** | `cargo test -p arc-cli --test passport -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Targeted feedback loop** | 10-30 seconds after build warmup |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 15-01 | PASS-01 | `cargo test -p arc-credentials -- --nocapture` |
| 15-02 | PASS-02 | `cargo test -p arc-cli --test passport -- --nocapture` |
| 15-03 | PASS-01, PASS-02 | `cargo test -p arc-cli --test local_reputation -- --nocapture` and doc assertions |

## Coverage Notes

- Accepted multi-issuer bundle: covered in `arc-credentials`
- Rejected multi-issuer bundle: covered in `arc-credentials`
- Mixed multi-issuer bundle with one accepted and one rejected credential:
  covered in `arc-credentials` and `arc-cli` passport CLI regression
- Reputation comparison remains truthful for multi-issuer bundles: covered in
  `local_reputation`

## Sign-Off

- [x] Composition semantics are automated
- [x] Issuer-aware evaluation/reporting is automated
- [x] CLI-facing regression exists
- [x] `nyquist_compliant: true` is set

**Approval:** completed
