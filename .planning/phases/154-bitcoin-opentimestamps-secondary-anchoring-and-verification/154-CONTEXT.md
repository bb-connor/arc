# Phase 154: Bitcoin OpenTimestamps Secondary Anchoring and Verification - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Add the secondary Bitcoin evidence lane: aggregate contiguous ARC checkpoints
into one super-root, prepare OpenTimestamps submission state, and require
imported `.ots` payloads to match that canonical digest before ARC accepts the
lane as anchored.

</domain>

<decisions>
## Implementation Decisions

### Secondary Evidence Contract
- Keep Bitcoin explicitly secondary to the primary EVM lane.
- Aggregate contiguous checkpoints only, so one super-root always maps to a
  deterministic checkpoint range.
- Derive one SHA-256 document digest for OTS submission from the ARC
  super-root.

### Verification Boundary
- Inspect imported `.ots` payloads with a real parser instead of treating them
  as opaque base64.
- Require at least one Bitcoin attestation before ARC marks the lane anchored.
- Keep direct Bitcoin block-header validation as an operational verifier step,
  not a local milestone blocker.

</decisions>

<code_context>
## Existing Code Insights

- `arc-core::merkle::MerkleTree` already provides the super-root aggregation
  substrate.
- `crates/arc-core/src/web3.rs` already models `bitcoin_anchor` and
  `super_root_inclusion` inside the canonical anchor proof.
- the new `arc-anchor` crate already owns the EVM primary lane and can layer
  Bitcoin linkage on top of that proof family.

</code_context>

<deferred>
## Deferred Ideas

- direct calendar submission clients
- full Bitcoin header or SPV verification inside `arc-anchor`
- direct Bitcoin transaction construction

</deferred>
