---
phase: 45-generic-metered-billing-evidence-contract
plan: 01
subsystem: metered-billing-contract
tags:
  - economics
  - governed-transactions
  - receipts
requires: []
provides:
  - A typed metered-billing quote and settlement-mode contract for governed requests
  - Receipt metadata that preserves quoted billing context plus a future usage-evidence hook
  - Protocol text that keeps quoted cost separate from enforced budget truth
key-files:
  modified:
    - crates/arc-core/src/capability.rs
    - crates/arc-core/src/receipt.rs
    - spec/PROTOCOL.md
requirements-completed:
  - EEI-01
completed: 2026-03-27
---

# Phase 45 Plan 01 Summary

Phase 45-01 defined metered billing as a first-class governed intent and
receipt contract instead of leaving non-rail cost evidence trapped in loose
JSON blobs or payment-rail-specific semantics.

## Accomplishments

- added explicit `MeteredSettlementMode`, `MeteredBillingQuote`, and
  `MeteredBillingContext` types so governed requests can carry payment-rail-neutral
  pre-execution quote data
- extended governed receipt metadata with a typed `metered_billing` block plus
  a future `usage_evidence` hook for later adapter work
- updated the protocol contract to explain that metered quotes are evidence and
  planning context, not the hard enforcement boundary by themselves

## Verification

- `cargo test -p arc-core`

