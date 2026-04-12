# Phase 157: Settlement Dispatch Builder and Escrow/Bond Transaction Orchestration - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn the frozen web3 settlement-dispatch contract into a real `arc-settle`
runtime that can prepare and submit bounded escrow and bond transactions over
the official contract family.

</domain>

<decisions>
## Implementation Decisions

### Runtime Shape
- Add a dedicated `crates/arc-settle/` crate instead of extending `arc-core`
  or `arc-web3-bindings`.
- Reuse the frozen `arc.web3-settlement-dispatch.v1` artifact from
  `arc-core` instead of inventing a parallel runtime-only contract.
- Keep the first real runtime lane EVM-first over the official escrow and
  bond-vault contracts already shipped in `v2.34`.

### Dispatch Mapping
- Map approved capital instructions into explicit ERC-20 approval, escrow
  create, release, refund, and bond lifecycle call builders.
- Precompute escrow and vault identifiers with `eth_call` so ARC can bind
  dispatch truth to the intended on-chain object before submission.
- Keep cross-currency conversion out of this phase; if needed later it must
  come from `arc-link`.

### Submission Safety
- Fail closed on invalid rail kind, jurisdiction mismatch, destination
  mismatch, binding mismatch, or unsafe decimal conversion before the chain
  call is ever submitted.
- Estimate gas in the runtime rather than trusting RPC defaults for complex
  contract calls.

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-core/src/web3.rs` already freezes the settlement-dispatch and
  execution-receipt artifact family this runtime must project back into.
- `contracts/src/ArcEscrow.sol` and `contracts/src/ArcBondVault.sol` already
  implement the official contract surface for escrow and bond operations.
- `crates/arc-web3-bindings/` already exposes the generated contract
  interfaces needed by a Rust settlement runtime.
- `crates/arc-anchor/` already owns the bounded root-publication lane that the
  Merkle-proof release path must consume.

</code_context>

<deferred>
## Deferred Ideas

- EIP-2612 or EIP-3009 gasless approval and transfer flows
- solver-network batching or intent routing
- event-driven indexers or long-running settlement daemons

</deferred>
