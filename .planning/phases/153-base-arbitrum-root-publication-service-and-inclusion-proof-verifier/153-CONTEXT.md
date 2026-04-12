# Phase 153: Base/Arbitrum Root Publication Service and Inclusion Proof Verifier - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn the frozen anchor-proof model into a real primary EVM anchoring runtime:
prepare publication requests, check publisher authorization and sequence state,
confirm stored roots, and verify receipt inclusion against the official root
registry.

</domain>

<decisions>
## Implementation Decisions

### Primary Chain Surface
- Keep the first runtime lane Base-first with the same root-registry contract
  family already shipped in `v2.34`.
- Reuse the existing key-binding certificate and `AnchorInclusionProof`
  contract from `arc-core` instead of inventing a new anchor-specific proof.
- Add one explicit publication guard that surfaces latest checkpoint sequence
  and publisher authorization before a publish attempt.

### Verification
- Use JSON-RPC `eth_call` and generated Alloy bindings for registry reads and
  proof verification.
- Re-confirm stored root metadata after publication instead of trusting only
  the transaction hash.
- Keep replay handling fail closed: publication must not proceed when the next
  checkpoint sequence would regress or duplicate the on-chain state.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-core/src/web3.rs` already defines the canonical anchor inclusion
  proof and verification helpers.
- `contracts/src/ArcRootRegistry.sol` already enforces publisher
  authorization, monotonic checkpoint sequences, and RFC 6962 proof checks.
- `crates/arc-web3-bindings` already exposes the root-registry interface for
  runtime use.

</code_context>

<deferred>
## Deferred Ideas

- long-running publisher daemons or schedulers
- reorg indexers and live chain watchers
- batch publication orchestration across multiple checkpoints

</deferred>
