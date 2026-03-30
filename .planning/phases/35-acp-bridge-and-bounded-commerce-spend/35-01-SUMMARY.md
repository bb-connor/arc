---
phase: 35-acp-bridge-and-bounded-commerce-spend
plan: 01
subsystem: acp-adapter
tags:
  - payments
  - acp
  - governed-transactions
requires: []
provides:
  - Typed commerce approval context on governed intents, receipts, and payment requests
  - Concrete `AcpPaymentAdapter` for seller-scoped shared-payment-token authorization
key-files:
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/receipt.rs
    - crates/arc-kernel/src/payment.rs
requirements-completed: []
completed: 2026-03-26
---

# Phase 35 Plan 01 Summary

Phase 35-01 defined the typed ACP/shared-payment-token bridge contract instead
of encoding commerce approvals as opaque JSON.

## Accomplishments

- added `GovernedCommerceContext` to governed intents and
  `GovernedCommerceReceiptMetadata` to receipt-side governed metadata
- added `CommercePaymentContext` and extended `PaymentAuthorizeRequest` so
  payment rails can receive seller-scoped approval context alongside governed
  request context
- implemented `AcpPaymentAdapter` plus adapter tests for seller-scoped
  authorize payload forwarding and hold-style authorization semantics

## Verification

- `cargo test -p arc-core governed`
- `cargo test -p arc-kernel acp`
