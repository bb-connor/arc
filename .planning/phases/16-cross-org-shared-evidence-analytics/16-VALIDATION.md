---
phase: 16
slug: cross-org-shared-evidence-analytics
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-24
---

# Phase 16 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test`, `vitest`, `vite build` |
| **Quick run command** | `cargo test -p arc-cli --test receipt_query -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **UI verification** | `npm --prefix crates/arc-cli/dashboard test -- --run` and `npm --prefix crates/arc-cli/dashboard run build` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 16-01 | XORG-01 | `cargo test -p arc-cli --test receipt_query -- --nocapture` |
| 16-02 | FED-03, XORG-02 | `cargo test -p arc-cli --test receipt_query -- --nocapture` |
| 16-03 | XORG-01, XORG-02 | `npm --prefix crates/arc-cli/dashboard test -- --run` |
| 16-04 | FED-03, XORG-01, XORG-02 | `cargo test -p arc-cli --test local_reputation -- --nocapture` and `npm --prefix crates/arc-cli/dashboard run build` |

## Coverage Notes

- Shared-evidence operator report attribution: covered in `receipt_query`
- Direct shared-evidence trust-control endpoint plus CLI: covered in
  `receipt_query`
- Reputation comparison contract with shared-evidence payload: covered in
  `local_reputation`
- Dashboard operator summary and portable comparison rendering: covered in
  `OperatorSummary.test.tsx`, `PortableReputationPanel.test.tsx`, and
  `App.test.tsx`

## Sign-Off

- [x] Shared-evidence query/reporting is automated
- [x] CLI/API/dashboard contracts are aligned
- [x] Reputation comparison surfaces downstream provenance
- [x] `nyquist_compliant: true` is set

**Approval:** completed
