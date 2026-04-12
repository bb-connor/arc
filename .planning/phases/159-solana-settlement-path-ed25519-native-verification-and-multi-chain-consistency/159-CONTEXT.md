# Phase 159: Solana Settlement Path, Ed25519-Native Verification, and Multi-Chain Consistency - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the bounded Solana settlement-preparation lane and prove that its Ed25519-
first semantics remain consistent with the shipped EVM settlement contract.

</domain>

<decisions>
## Implementation Decisions

### Solana Scope
- Keep Solana support bounded to local verification and canonical instruction
  preparation in this milestone.
- Reuse ARC receipt Ed25519 signatures and the existing key-binding
  certificate instead of adding a second Solana-only truth model.

### Verification
- Require the key-binding certificate to cover `settle` purpose and the target
  Solana chain scope.
- Require the receipt signing key to match the binding's ARC public key.
- Compare settlement commitments across lanes instead of claiming live
  cross-chain execution equivalence.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-core/src/receipt.rs` and `crates/arc-core/src/web3.rs` already
  carry the ARC Ed25519 receipt and binding contracts.
- `crates/arc-settle/src/lib.rs` already defines `SettlementCommitment` as the
  narrow parity contract shared by the EVM and Solana lanes.
- `docs/research/ARC_SETTLE_PROTOCOL_DECISIONS.md` explicitly recommends a
  bounded fallback strategy for EVM-side Ed25519 constraints rather than
  pretending the chains share the same native verification model.

</code_context>

<deferred>
## Deferred Ideas

- live Solana transaction broadcast
- on-chain Solana settlement program deployment
- cross-chain message transport or automated relay infrastructure

</deferred>
