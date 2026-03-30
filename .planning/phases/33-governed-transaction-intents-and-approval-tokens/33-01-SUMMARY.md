---
phase: 33-governed-transaction-intents-and-approval-tokens
plan: 01
subsystem: arc-core
tags:
  - governed-transactions
  - receipts
  - policy
requires: []
provides:
  - First-class governed intent and approval-token types in arc-core
  - Typed receipt metadata for governed transaction evidence
key-files:
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/lib.rs
    - crates/arc-core/src/receipt.rs
requirements-completed:
  - ECON-01
completed: 2026-03-26
---

# Phase 33 Plan 01 Summary

Phase 33-01 established the canonical governed transaction data model in
`arc-core`.

## Accomplishments

- added `GovernedTransactionIntent`, `GovernedApprovalToken`, and supporting
  signable body/decision types
- extended `Constraint` with `GovernedIntentRequired` and
  `RequireApprovalAbove { threshold_units }`
- added typed governed receipt metadata so later runtime and operator paths can
  preserve intent and approval evidence without raw ad hoc JSON

## Verification

- `cargo test -p arc-core`
