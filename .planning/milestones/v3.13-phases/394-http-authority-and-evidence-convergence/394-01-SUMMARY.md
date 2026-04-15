---
phase: 394-http-authority-and-evidence-convergence
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 394 Summary

## Outcome

The Rust HTTP lane now tells one coherent authority and evidence story.

- `arc-http-core` now distinguishes decision-scoped and final-scoped receipt
  status metadata without breaking the signed `HttpReceipt` shape.
- `arc-api-protect` now honors OpenAPI policy overrides, strips
  `arc_capability` from forwarded query strings, forwards operator-grade
  end-to-end request headers, and persists only final receipts for live proxy
  traffic while keeping `/arc/evaluate` on decision receipts.
- `arc-tower` now separates evaluation preparation from receipt finalization so
  service-emitted receipts bind the actual returned HTTP status instead of a
  speculative evaluator-owned value.

## Requirements Closed

- `HTTP-01`
- `HTTP-02`
- `HTTP-03`
- `HTTP-04`
