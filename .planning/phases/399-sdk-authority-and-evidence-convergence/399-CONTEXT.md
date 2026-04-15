---
phase: 399-sdk-authority-and-evidence-convergence
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 399 Context

## Problem

The representative SDKs were still inconsistent about fail-open evidence:
receipt-bearing governed decisions existed, but degraded passthrough was not
uniformly represented and some surfaces could imply a synthetic ARC receipt.

## Scope

- converge representative SDKs on explicit degraded passthrough metadata
- preserve the “no synthetic receipt” rule on fail-open
- update SDK docs/tests to reflect the shared authority/evidence contract
