# Phase 155: Solana Anchor Publication, Proof Normalization, and Shared Proof Bundle - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add one bounded Solana memo lane and normalize the supported EVM, Bitcoin, and
Solana evidence into one shared proof-bundle contract.

</domain>

<decisions>
## Implementation Decisions

### Solana Scope
- Support the built-in Memo program only.
- Use one canonical memo payload encoding that includes checkpoint sequence,
  merkle root, and issued-at time.
- Treat imported memo records as secondary evidence linked back to the primary
  EVM proof.

### Bundle Contract
- Keep the existing `AnchorInclusionProof` as the primary proof carrier.
- Add one explicit `arc.anchor-proof-bundle.v1` wrapper instead of inventing
  separate bundle formats per lane combination.
- Reject any bundle that declares a secondary lane without the required proof
  material.

</decisions>

<code_context>
## Existing Code Insights

- the primary EVM proof and the Bitcoin secondary lane already live in
  `arc-anchor`
- `arc-core` already models the Solana-agnostic anchor proof surface
- shared-bundle verification belongs in the runtime crate because it spans
  multiple supported lanes

</code_context>

<deferred>
## Deferred Ideas

- arbitrary Solana programs beyond the Memo program
- direct Solana transaction broadcast or RPC indexing
- generic cross-chain bundle negotiation

</deferred>
