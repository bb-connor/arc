# Phase 115: Automatic Claims Payment and Payout Reconciliation - Context

## Goal

Implement a narrow automatic claims-payment lane with payout instructions,
payout receipts, and external reconciliation truth.

## Why This Phase Exists

Coverage binding is incomplete without a bounded payout path that can move from
claim approval into explicit payment and reconciliation artifacts.

## Scope

- payout instruction artifacts for approved claim flows
- payout receipt and reconciliation state
- authority, counterparty, and rail metadata
- fail-closed handling for stale authority, mismatch, or duplicate payout

## Out of Scope

- recovery clearing and reinsurance settlement
- open registry, trust activation, and governance-network work
- universal settlement-network claims
