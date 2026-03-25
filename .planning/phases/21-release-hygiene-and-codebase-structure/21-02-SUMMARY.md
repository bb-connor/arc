---
phase: 21-release-hygiene-and-codebase-structure
plan: 02
subsystem: release-inputs
tags:
  - hygiene
  - ci
  - packaging
requires:
  - 21-01
provides:
  - Source-only release inputs with a CI guard against tracked generated artifacts
key-files:
  created:
    - scripts/check-release-inputs.sh
  modified:
    - .gitignore
    - scripts/ci-workspace.sh
    - packages/sdk/pact-py/build/lib/pact/__init__.py
    - tests/conformance/fixtures/wave1/__pycache__/mock_mcp_server.cpython-314.pyc
requirements-completed:
  - PROD-07
completed: 2026-03-25
---

# Phase 21 Plan 02 Summary

The repo no longer treats generated Python/package artifacts as legitimate
release inputs.

## Accomplishments

- deleted tracked SDK build output, egg-info metadata, and Python bytecode
- added repo-level ignore rules for Python packaging/cache artifacts
- introduced `scripts/check-release-inputs.sh` and wired it into the workspace
  CI lane

## Verification

- `./scripts/check-release-inputs.sh`
