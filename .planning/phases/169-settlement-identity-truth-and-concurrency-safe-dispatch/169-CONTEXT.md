# Phase 169: Settlement Identity Truth and Concurrency-Safe Dispatch - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Make escrow and bond identity deterministic, replay-safe, and recoverable
across runtime dispatch, contract execution, and receipt observation.

</domain>

<decisions>
## Implementation Decisions

### Deterministic Contract Identity
- remove nonce-derived identity from `ArcEscrow` and `ArcBondVault`
- derive `escrowId` and `vaultId` from immutable contract terms
- fail closed on duplicate replay instead of minting a fresh ID on retry

### Receipt Reconciliation
- expose `deriveEscrowId` and `deriveVaultId` through the Solidity interfaces
- retain EVM receipt logs in `arc-settle`
- finalize prepared escrow and bond artifacts against emitted contract events

### Qualification Coverage
- cover interleaving and replay behavior in Rust runtime devnet tests
- cover deterministic identity and duplicate replay in the contract devnet
  qualification harness

</decisions>

<code_context>
## Existing Code Insights

- `prepare_web3_escrow_dispatch` and `prepare_bond_lock` were predicting
  identity by static-calling mutating methods whose return values depended on
  mutable nonce state.
- `BondLocked` did not emit `vaultId`, so drift could not be reconciled from
  transaction receipts.
- the runtime and contract qualification surfaces had no interleaving or
  duplicate-replay regression coverage.

</code_context>

<deferred>
## Deferred Ideas

- mandatory receipt-store and checkpoint activation gates in phase `170`
- bond reserve/oracle semantics reconciliation in phase `171`
- proof-bundle depth and binding-generation parity in phase `172`

</deferred>
