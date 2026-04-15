---
phase: 399-sdk-authority-and-evidence-convergence
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 399 Summary

## Outcome

The representative SDK fleet now shares one truthful degraded-state rule:
governed evaluation yields a real ARC receipt, while fail-open/degraded
passthrough is surfaced explicitly as `allow_without_receipt` and never
presented as a synthetic ARC receipt.

- TypeScript `node-http` and `express` preserve explicit receiptless
  passthrough state.
- Go, Python, JVM, and .NET now expose the same degraded-state marker and
  regression coverage.
- SDK docs now describe the shared authority/evidence contract instead of only
  relying on the absence of receipt headers.

## Requirements Closed

- `KERNEL-03`
- `KERNEL-04`
