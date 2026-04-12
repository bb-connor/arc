# Phase 163: CCIP Delegation/Settlement Transport and Cross-Chain Receipt Reconciliation - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Add one bounded CCIP settlement-coordination lane that transports explicit ARC
message payloads across chains and reconciles delivery back to canonical
execution receipts.

</domain>

<decisions>
## Implementation Decisions

### Message Family
- Support one settlement-coordination payload derived from canonical web3
  execution receipts.
- Keep source and destination chains explicit and distinct.

### Reconciliation
- Treat delivery as valid only when the message id, destination chain, and
  payload hash all match.
- Make duplicate suppression and delayed delivery explicit outcomes rather than
  inferred side effects.

### Boundary
- Keep CCIP as coordination only, not as automatic fund transport.
- Keep unsupported chains and wrong payloads fail closed.

</decisions>

<code_context>
## Existing Code Insights

- `docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json` already carries
  the canonical settlement state that the CCIP payload should project.
- `arc-settle` owns the dispatch and receipt boundary, so CCIP reconciliation
  belongs inside that crate.
- The late-March research explicitly deferred arbitrary CCIP routing, so this
  phase should implement only one bounded message family.

</code_context>

<deferred>
## Deferred Ideas

- arbitrary cross-chain routing families
- live fund bridging or CCTP movement
- permissionless chain onboarding

</deferred>
