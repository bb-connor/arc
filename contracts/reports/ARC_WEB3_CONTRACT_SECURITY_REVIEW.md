# ARC Web3 Contract Security Review

## Scope

This review covers the official `v2.34` contract family:

- `ArcIdentityRegistry`
- `ArcRootRegistry`
- `ArcEscrow`
- `ArcBondVault`
- `ArcPriceResolver`

## Positive Findings

- Fail-closed proof semantics
  - The legacy under-specified proof entrypoints (`releaseWithProof`,
    `partialReleaseWithProof`, `releaseBond`, `impairBond`, and
    `verifyInclusion`) revert instead of guessing missing RFC6962 metadata.
- Explicit operator binding
  - Root publication and escrow creation require the registered operator
    Ed25519 key hash to match the identity registry.
- Bounded delegate publication
  - Root publication supports explicit delegate registration, bounded to three
    active delegates per operator, with immediate revocation.
- Signature scope tightening
  - `releaseWithSignature` binds `chainid`, escrow contract address, escrow id,
    receipt hash, and settled amount into the signed digest.
- No admin override on fund release
  - Escrow and bond state transitions do not expose admin-controlled release or
    slash bypasses.
- Sequencer and staleness controls
  - `ArcPriceResolver` rejects stale feed data and sequencer-down conditions.
- Explicit collateral boundary
  - `ArcBondVault` only locks `collateralAmount` on-chain. The reserve
    requirement fields preserved in bond terms are metadata for parity with
    signed ARC bond artifacts, not a second spendable balance.
- Auxiliary price-reference scope
  - `ArcPriceResolver` is an optional contract-side reference reader. Kernel
    FX charging and receipt-side oracle evidence remain authoritative only
    through `arc-link`.

## Residual Risks and Non-Goals

- No on-chain Ed25519 verification
  - Identity binding remains an off-chain registration ceremony backed by the
    registry admin and emitted proof material.
- No sanctioned-address or blacklist screening
  - The contracts do not yet integrate USDC blacklist checks or address
    screening before escrow or bond creation.
- No relayer registry
  - Escrow release is beneficiary-driven today. The research discussed
    beneficiary-or-relayer authorization, but a relayer allowlist is not part
    of this milestone's runtime surface.
- No CREATE2 deploy script yet
  - The package now ships deterministic deployment templates, but live chain
    execution still needs an operator-specific deployment runner.
- No proxy upgrade path
  - This is intentional, but it means defect remediation requires replacement
    deployments and config migration rather than in-place upgrades.

## Reviewed Invariants

- Unauthorized or revoked publishers cannot anchor roots.
- Root checkpoint sequence must increase strictly per operator.
- Escrow release cannot exceed deposited balance.
- Escrow refund cannot happen before deadline.
- Bond release and impairment require explicit detailed proof input.
- Price reads fail closed on stale or sequencer-down inputs.

## Qualification Evidence

- `contracts/reports/local-devnet-qualification.json`
- `contracts/deployments/local-devnet.json`
- `contracts/scripts/qualify-devnet.mjs`
