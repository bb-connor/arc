---
phase: 33-governed-transaction-intents-and-approval-tokens
plan: 02
subsystem: arc-kernel
tags:
  - governed-transactions
  - kernel
  - enforcement
requires:
  - 33-01
provides:
  - Governed intent and approval-token enforcement in tool-call evaluation
  - Governed metadata propagation across allow, deny, and incomplete receipts
key-files:
  modified:
    - crates/arc-kernel/src/runtime.rs
    - crates/arc-kernel/src/lib.rs
requirements-completed:
  - ECON-01
completed: 2026-03-26
---

# Phase 33 Plan 02 Summary

Phase 33-02 threaded governed transaction artifacts through the kernel runtime
and receipt pipeline.

## Accomplishments

- extended `ToolCallRequest` so callers can attach governed intent and optional
  approval evidence
- added fail-closed kernel validation for request target binding, intent amount
  ceilings, approval-token signature/time checks, and subject/request binding
- preserved governed metadata on allow, deny, cancelled, and incomplete
  receipt paths, including metered incomplete responses

## Verification

- `cargo test -p arc-kernel governed`
