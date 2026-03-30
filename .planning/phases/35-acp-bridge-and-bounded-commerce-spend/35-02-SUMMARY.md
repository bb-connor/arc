---
phase: 35-acp-bridge-and-bounded-commerce-spend
plan: 02
subsystem: kernel-governance
tags:
  - payments
  - acp
  - kernel
requires:
  - 35-01
provides:
  - Seller-scoped governed validation for commerce approvals
  - Truthful ACP allow/deny kernel coverage
key-files:
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-kernel/src/lib.rs
requirements-completed:
  - ECON-03
completed: 2026-03-26
---

# Phase 35 Plan 02 Summary

Phase 35-02 enforced seller-bound bounded spend inside the existing governed
runtime path.

## Accomplishments

- introduced the first-class `seller_exact` constraint for tool grants and
  routed it through the governed validation path instead of ordinary argument
  matching
- made governed commerce approvals fail closed unless they carry a non-empty
  seller, a shared payment token reference, and an explicit `max_amount` bound
- added end-to-end kernel tests for a successful seller-bound ACP flow and a
  truthful pre-execution denial when the governed seller does not match the
  grant seller scope

## Verification

- `cargo test -p arc-kernel acp`
- `cargo test -p arc-kernel governed_monetary`
