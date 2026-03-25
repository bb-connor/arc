---
phase: 28-domain-module-cleanup-and-dependency-enforcement
plan: 02
subsystem: layering
tags:
  - architecture
  - guardrails
  - workspace
  - v2.4
requires:
  - 28-01
provides:
  - Executable workspace layering checks and documented post-v2.4 structure
key-files:
  created:
    - docs/architecture/WORKSPACE_STRUCTURE.md
    - scripts/check-workspace-layering.sh
  modified:
    - scripts/ci-workspace.sh
    - scripts/qualify-release.sh
requirements-completed:
  - ARCH-09
completed: 2026-03-25
---

# Phase 28 Plan 02 Summary

## Accomplishments

- added `scripts/check-workspace-layering.sh` to fail if core domain crates
  gain CLI or HTTP-facing dependencies
- documented the intended post-`v2.4` workspace boundary shape in
  `docs/architecture/WORKSPACE_STRUCTURE.md`
- wired the layering check into `scripts/ci-workspace.sh` so qualification runs
  the guardrail as part of the normal workspace lane

## Verification

- `./scripts/check-workspace-layering.sh`
- `rg -n "check-workspace-layering|WORKSPACE_STRUCTURE" scripts/ci-workspace.sh docs/architecture/WORKSPACE_STRUCTURE.md`
