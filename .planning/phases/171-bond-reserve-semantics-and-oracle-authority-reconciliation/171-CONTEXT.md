# Phase 171: Bond Reserve Semantics and Oracle Authority Reconciliation - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Reconcile ARC's bounded web3 money-handling contract so bond-vault reserve
fields, receipt-side FX evidence, settlement config, bindings, and public docs
all describe the same bounded runtime truth.

</domain>

<decisions>
## Implementation Decisions

### Bond Semantics
- narrow the on-chain bond lane honestly instead of inventing a second reserve
  ledger mid-milestone
- keep `ArcBondVault` collateral-only for locked and slashed balances
- rename the preserved bond-term fields to
  `reserveRequirementAmount` and `reserveRequirementRatioBps` so the contract,
  bindings, and runtime snapshots treat them as signed-bond metadata rather
  than spendable on-chain reserves

### Oracle Authority
- choose `arc-link` receipt evidence as the sole supported runtime FX
  authority model for official web3 lanes
- make that choice explicit in `OracleConversionEvidence` with
  `authority = arc_link_runtime_v1`
- keep `ArcPriceResolver` as an auxiliary on-chain reference reader instead of
  a competing runtime authority

### Runtime And Qualification Parity
- expose settlement-side oracle authority explicitly in `SettlementChainConfig`
- require oracle evidence on FX-sensitive web3 execution receipts unless the
  lifecycle already failed, timed out, or reorged
- extend contract qualification so local-devnet parity proves the vault stores
  reserve requirement metadata while only locking collateral

</decisions>

<code_context>
## Existing Code Insights

- `ArcBondVault` only transferred `collateralAmount`; the older
  `reserveAmount` fields affected identity derivation and stored metadata but
  did not represent a separate on-chain balance.
- kernel cross-currency charging was already authoritative through the injected
  `PriceOracle` trait, which is implemented by `arc-link`.
- docs and examples still mixed that off-chain runtime authority with the
  optional `ArcPriceResolver` contract and with reserve-backed language that
  implied more on-chain economics than the vault actually enforced.

</code_context>

<deferred>
## Deferred Ideas

- cryptographic secondary-lane verification and proof-bundle hardening in
  phase `172`
- generated binding or ABI-derived parity work in phase `172`
- hosted qualification, deployment promotion, and operator-drill closure in
  `v2.41`

</deferred>
