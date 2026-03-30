---
phase: 45
slug: generic-metered-billing-evidence-contract
status: passed
completed: 2026-03-27
---

# Phase 45 Verification

Phase 45 passed targeted verification for the generic metered-billing evidence
contract in `v2.9`.

## Automated Verification

- `cargo fmt --all`
- `cargo test -p arc-core`
- `cargo test -p arc-kernel governed_monetary -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`
- `cargo test -p arc-cli --test receipt_query test_receipt_query_surfaces_governed_transaction_metadata -- --nocapture`

## Result

Passed. Phase 45 now satisfies `EEI-01`:

- governed intents can carry typed, payment-rail-neutral metered-billing quote
  context
- signed governed receipts preserve quoted billing context without collapsing it
  into enforced financial truth
- kernel validation fails closed on malformed or inconsistent metered-billing
  inputs
- protocol, pricing guidance, and receipt-query coverage now describe and prove
  the contract end to end
