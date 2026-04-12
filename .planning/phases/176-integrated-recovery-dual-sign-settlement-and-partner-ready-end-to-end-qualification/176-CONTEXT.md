# Phase 176: Integrated Recovery, Dual-Sign Settlement, and Partner-Ready End-to-End Qualification - Context

**Gathered:** 2026-04-02
**Status:** In progress

<domain>
## Phase Boundary

Produce one generated end-to-end qualification family that proves the bounded
web3 runtime under FX-backed dual-sign settlement, timeout refund, canonical
reorg recovery, and bond impairment/expiry behavior, then stage the same
artifact family into the hosted web3 bundle for partner review.

</domain>

<decisions>
## Implementation Decisions

### Generated E2E Evidence
- add one dedicated `arc-settle` integration test that writes reviewer-facing
  JSON artifacts under `target/web3-e2e-qualification/`
- keep the existing `runtime_devnet` regression file for local lane coverage,
  but move the partner-facing proof claim onto a separate dedicated script:
  `./scripts/qualify-web3-e2e.sh`
- stage the generated summary plus per-scenario reports under
  `target/release-qualification/web3-runtime/e2e/`

### Runtime Scope
- execute a real dual-sign release on the local devnet instead of stopping at
  static validation and gas estimation
- bind the FX-sensitive receipt to explicit `arc-link` oracle evidence rather
  than a hand-authored placeholder
- exercise timeout refund, canonical drift, bond impairment, and bond expiry
  in the same generated artifact family so partner reviewers can inspect one
  bounded proof package

### Reorg Assessment
- add one receipt-based finality helper in `arc-settle` so reorg state can be
  assessed from a stored receipt after canonical drift, even when the original
  transaction is no longer the happy-path observation target

</decisions>

<code_context>
## Existing Code Insights

- `crates/arc-settle/tests/runtime_devnet.rs` already covered escrow identity,
  Merkle release, timeout refund, and dual-sign preparation, but it did not
  emit a generated reviewer bundle or carry FX evidence
- `arc-link` already exposed the runtime authority needed to mint canonical
  `arc.oracle-conversion-evidence.v1` artifacts, so the phase can reuse the
  shipped oracle boundary instead of inventing a settlement-local override
- hosted release qualification already stages runtime, ops, and promotion
  bundles, making an `e2e/` subtree the least disruptive extension point

</code_context>

<deferred>
## Deferred Ideas

- authoritative release-governance, protocol parity, and GSD truth repair now
  remain in `v2.42`
- Nyquist validation backfill for the late web3 ladder remains phase `179`

</deferred>
