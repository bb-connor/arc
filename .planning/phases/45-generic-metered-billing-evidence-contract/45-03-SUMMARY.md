---
phase: 45-generic-metered-billing-evidence-contract
plan: 03
subsystem: operator-docs-and-query-coverage
tags:
  - docs
  - query
  - operator
requires:
  - 45-01
  - 45-02
provides:
  - Pricing guidance that ties manifest quotes to governed metered-billing context
  - Receipt-query coverage for the metered-billing receipt contract
  - Phase verification evidence and planning-state closure for phase 45
key-files:
  modified:
    - docs/TOOL_PRICING_GUIDE.md
    - crates/arc-cli/tests/receipt_query.rs
    - .planning/phases/45-generic-metered-billing-evidence-contract/45-VERIFICATION.md
requirements-completed:
  - EEI-01
completed: 2026-03-27
---

# Phase 45 Plan 03 Summary

Phase 45-03 made the new contract legible to operators and proved it survives
storage and query surfaces instead of disappearing after receipt signing.

## Accomplishments

- documented how governed metered-billing quotes relate to manifest pricing,
  enforced budgets, and later usage evidence
- extended receipt-query coverage so operators can see metered-billing quote
  context in governed receipts
- closed the phase with explicit verification artifacts tied to the code and
  docs changes

## Verification

- `cargo test -p arc-cli --test receipt_query -- --nocapture`

