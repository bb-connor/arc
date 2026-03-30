---
phase: 35-acp-bridge-and-bounded-commerce-spend
plan: 03
subsystem: operator-surfaces
tags:
  - receipt-query
  - acp
  - docs
requires:
  - 35-01
  - 35-02
provides:
  - Receipt-query coverage for ACP payment and commerce approval metadata
  - Protocol and operator docs for seller-scoped bounded commerce spend
key-files:
  modified:
    - crates/arc-cli/tests/receipt_query.rs
    - docs/AGENT_ECONOMY.md
    - spec/PROTOCOL.md
requirements-completed:
  - ECON-03
completed: 2026-03-26
---

# Phase 35 Plan 03 Summary

Phase 35-03 made ACP commerce approval evidence visible to operators and
aligned the written contract to the shipped behavior.

## Accomplishments

- added trust-control receipt-query coverage for ACP payment metadata and the
  governed `commerce` receipt block
- updated `docs/AGENT_ECONOMY.md` to describe the shipped
  `AcpPaymentAdapter`, typed commerce authorize request, and receipt-query
  audit path
- updated `spec/PROTOCOL.md` to document `seller_exact` plus governed
  `commerce { seller, shared_payment_token_id }` metadata

## Verification

- `cargo test -p arc-cli receipt_query`
- `rg -n "ACP|shared payment token|seller" docs/AGENT_ECONOMY.md spec/PROTOCOL.md`
