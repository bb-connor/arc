---
phase: 174
slug: live-deployment-runner-promotion-approvals-and-reproducible-rollout
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-02
---

# Phase 174 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Script sanity** | `bash -n scripts/qualify-web3-promotion.sh scripts/qualify-web3-runtime.sh scripts/stage-web3-release-artifacts.sh` |
| **Promotion lane** | `./scripts/qualify-web3-promotion.sh` |
| **Runtime/staging lanes** | `./scripts/qualify-web3-runtime.sh` and `./scripts/stage-web3-release-artifacts.sh` |
| **Artifact checks** | `jq empty` on the deployment policy/examples plus the staged manifest |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 174-01 | W3REL-02 | promotion lane over reviewed-manifest approvals |
| 174-02 | W3REL-02 | runtime/staging lanes over hosted promotion evidence |
| 174-03 | W3REL-02 | artifact checks plus `git diff --check` |

## Coverage Notes

- promotion proof binds approval, promotion, and rollback artifacts to the
  reviewed-manifest deployment lane rather than ad hoc operator judgment

## Sign-Off

- [x] deployment promotion is policy-gated and reproducible
- [x] approval and rollback artifacts are staged with hosted evidence
- [x] public docs describe the reviewed-manifest lane honestly

**Approval:** completed
