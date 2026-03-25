---
phase: 22
slug: qualification-deployment-and-upgrade-hardening
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 22 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | shell scripts, hosted workflow declarations, release docs, integration tests |
| **Quick run command** | `./scripts/check-dashboard-release.sh` |
| **Canonical release command** | `./scripts/qualify-release.sh` |
| **Operational doc verification** | `rg` against `docs/release/QUALIFICATION.md` and `docs/release/OPERATIONS_RUNBOOK.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 22-01 | PROD-09 | `rg -n "check-dashboard-release|check-pact-ts-release|check-pact-py-release|check-pact-go-release|qualify-release" docs/release/QUALIFICATION.md` |
| 22-02 | PROD-09 | `./scripts/check-dashboard-release.sh`, `./scripts/check-pact-ts-release.sh`, `./scripts/qualify-release.sh` |
| 22-03 | PROD-10 | `rg -n "backup|restore|upgrade|rollback|admin/sessions|/health" docs/release/OPERATIONS_RUNBOOK.md` |

## Coverage Notes

- the canonical release lane now proves clean source inputs, workspace
  correctness, package-release viability, live peer compatibility, and repeated
  clustered trust determinism
- the TypeScript SDK package lane proves package metadata correctness rather
  than relying on workspace-global tools
- operator procedures are documented against the same release lane and runtime
  surfaces they are expected to support

## Sign-Off

- [x] `./scripts/qualify-release.sh` is the canonical release lane
- [x] dashboard and SDK release artifacts are validated from clean installs
- [x] hosted workflows declare required runtimes explicitly
- [x] trust-control and remote MCP operator procedures are documented

**Approval:** completed
