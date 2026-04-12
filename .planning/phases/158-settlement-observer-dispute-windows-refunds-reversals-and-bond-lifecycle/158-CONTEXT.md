# Phase 158: Settlement Observer, Dispute Windows, Refunds, Reversals, and Bond Lifecycle - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Observe on-chain settlement outcomes and project them back into explicit ARC
finality, recovery, and lifecycle state instead of leaving that state implicit
in receipts or local bookkeeping.

</domain>

<decisions>
## Implementation Decisions

### Observation Model
- Keep observation inside `arc-settle` as a polling-based runtime surface
  rather than building an indexer or background daemon in this milestone.
- Use the settlement amount tier policy to determine confirmation and dispute
  requirements.
- Emit explicit recovery actions for confirmation wait, dispute-window wait,
  retry, refund, reorg, expiry, or manual review.

### Receipt Projection
- Reuse the frozen `arc.web3-settlement-execution-receipt.v1` artifact for
  projected settlement truth.
- Keep reversal and failure as separate explicit receipt builders rather than
  mutating prior signed settlement state.

### Bond Lifecycle
- Read bond state directly from the official vault contract and project active,
  released, impaired, and expired status explicitly.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-settle/src/config.rs` already models the amount-tier finality
  policy that observation should consume.
- `crates/arc-settle/src/evm.rs` already exposes escrow and bond snapshot
  reads plus reversal/failure receipt helpers.
- `crates/arc-core/src/web3.rs` already defines canonical settlement lifecycle
  states that this phase must reuse.

</code_context>

<deferred>
## Deferred Ideas

- a persistent `pending_confirmations` store
- live websocket subscriptions or third-party indexers
- explicit dispute-event indexing beyond current finality and refund handling

</deferred>
