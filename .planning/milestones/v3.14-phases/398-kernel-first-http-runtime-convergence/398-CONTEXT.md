---
phase: 398-kernel-first-http-runtime-convergence
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 398 Context

## Problem

The repo narrative said governed HTTP invocations flowed through one literal
kernel authority story, but `arc-api-protect` and `arc-tower` were still
authorizing/signing via local evaluator paths. The remaining gap was to make
those surfaces share one embedded kernel-backed authority path and preserve the
kernel receipt linkage in projected HTTP receipts.

## Scope

- replace local allow/deny authorization with shared `HttpAuthority`
- keep final HTTP receipt rebinding truthful
- preserve kernel decision receipt lineage in the HTTP evidence surface
