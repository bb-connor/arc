---
phase: 398-kernel-first-http-runtime-convergence
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 398 Summary

## Outcome

Governed HTTP authorization now runs through one shared embedded kernel-backed
authority path across the supported Rust HTTP surfaces.

- `arc-http-core::HttpAuthority` now projects HTTP authorization through an
  embedded `ArcKernel` path instead of a local evaluator-only allow/deny
  branch.
- Projected HTTP receipts now carry `arc_kernel_receipt_id` linkage to the
  underlying kernel decision receipt.
- `arc-api-protect` and `arc-tower` now consume that shared authority/evidence
  path while still rebinding final receipt status to the actual returned HTTP
  response.

## Requirements Closed

- `KERNEL-01`
- `KERNEL-02`
