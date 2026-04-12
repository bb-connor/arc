# Phase 170: Mandatory Receipt Storage, Checkpointing, and Web3 Evidence Gates - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Make durable receipt storage, checkpoint issuance, and canonical evidence
bundle integrity mandatory prerequisites for ARC's bounded web3 runtime lanes.

</domain>

<decisions>
## Implementation Decisions

### Kernel And Startup Gates
- add an explicit `require_web3_evidence` kernel-policy switch
- fail closed during activation and session or tool entry if the runtime lacks
  a durable receipt store, uses `checkpoint_batch_size = 0`, or only has an
  append-only remote receipt mirror
- treat kernel-signed checkpoint capability as a receipt-store trait contract
  rather than an ambient assumption

### Direct Runtime Parity
- add explicit evidence-substrate validation to `arc-settle` EVM and Solana
  configs so direct library callers cannot bypass kernel-side evidence policy
- require durable local receipts, kernel-signed checkpoint statements, and
  signer equality with receipt kernel keys

### Canonical Evidence Boundary
- project anchor inclusion proofs from canonical `EvidenceExportBundle`
  material instead of ad hoc stitched checkpoint fixtures
- qualify stale, missing, and uncheckpointed evidence as fail-closed cases

</decisions>

<code_context>
## Existing Code Insights

- `ArcKernel` previously treated `receipt_store` and checkpoint issuance as
  optional, even for web3-enabled deployments.
- remote trust-control receipt persistence was append-only and could not issue
  kernel-signed checkpoints that truthfully matched client receipt keys.
- `arc-settle` and runtime devnet tests were still able to construct Merkle
  release proofs without going through the canonical exported evidence bundle
  boundary.

</code_context>

<deferred>
## Deferred Ideas

- bond reserve and collateral semantics reconciliation in phase `171`
- deeper secondary-lane proof verification and generated binding parity in
  phase `172`
- hosted workflow qualification and deployment promotion in `v2.41`

</deferred>
