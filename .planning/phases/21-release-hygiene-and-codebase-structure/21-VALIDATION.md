---
phase: 21
slug: release-hygiene-and-codebase-structure
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 21 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | shell guard, `cargo fmt`, `cargo clippy`, targeted `cargo test` |
| **Quick run command** | `./scripts/check-release-inputs.sh` |
| **Targeted lint command** | `cargo clippy -p arc-cli -- -D warnings` |
| **Targeted regression command** | `cargo test -p arc-cli --test provider_admin -- --nocapture` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 21-01 | PROD-07, PROD-08 | `wc -l crates/arc-cli/src/main.rs crates/arc-cli/src/admin.rs` |
| 21-02 | PROD-07 | `./scripts/check-release-inputs.sh` |
| 21-03 | PROD-08 | `cargo fmt --all -- --check`, `cargo clippy -p arc-cli -- -D warnings`, `cargo test -p arc-cli --test provider_admin -- --nocapture`, `cargo test -p arc-cli --test certify -- --nocapture`, `cargo test -p arc-cli --test federated_issue -- --nocapture`, `cargo test -p arc-cli --test evidence_export -- --nocapture`, `cargo test -p arc-cli --test reputation_issuance -- --nocapture` |

## Coverage Notes

- release-input hygiene is enforced by a repo-level tracked-file inventory guard
- provider admin, certification registry, and federated issuance prove the new
  admin module still behaves end to end
- evidence export and reputation issuance cover the small lint cleanup changes
  needed to make the targeted `arc-cli` gate credible

## Sign-Off

- [x] tracked generated artifacts removed from release inputs
- [x] repo-level guard prevents the artifact classes from returning silently
- [x] `main.rs` has a clearer admin module boundary
- [x] targeted lint and regression coverage passed

**Approval:** completed
