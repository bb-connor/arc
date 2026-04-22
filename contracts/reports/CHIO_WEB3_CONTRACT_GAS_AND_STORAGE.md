# Chio Web3 Contract Gas and Storage

## Purpose

This report captures the measured local-devnet gas profile for the official Chio
web3 contract family and summarizes the bounded storage posture that `v2.34`
claims.

Measurement source:

- `contracts/reports/local-devnet-qualification.json`
- `contracts/scripts/qualify-devnet.mjs`

## Local Devnet Gas Estimates

These values come from the Ganache qualification harness on `2026-04-01`.
They are deterministic enough for regression tracking, not a substitute for
final Base or Arbitrum mainnet budgeting.

| Operation | Measured Gas |
| --- | ---: |
| `registerOperator` | 74,658 |
| `registerDelegate` | 74,559 |
| `publishRoot` (operator) | 172,426 |
| `publishRoot` (delegate) | 157,650 |
| `registerFeed` | 123,625 |
| `getPrice` | 60,173 |
| `createEscrow` | 305,476 |
| `partialReleaseWithProofDetailed` | 103,764 |
| `releaseWithSignature` | 76,289 |
| `lockBond` | 299,787 |
| `releaseBondDetailed` | 83,260 |

## Canonical Budget Mapping

The shipped standards artifact still reports rounded chain budgets rather than
copying local-devnet numbers directly:

- `publish_root_gas`
- `dual_sign_settlement_gas`
- `merkle_settlement_gas`
- `bond_release_gas`
- `price_read_gas`

The local-devnet figures now provide the measured lower-level evidence behind
those rounded contract-package assumptions.

## Storage Posture

The package intentionally keeps storage sparse and append-only where possible:

- `ChioIdentityRegistry`
  - one admin slot
  - one operator record per registered operator
  - one entity record per registered Chio entity
- `ChioRootRegistry`
  - one immutable identity-registry pointer
  - one root entry per `(operator, checkpointSeq)`
  - one published-root membership bit per `(operator, merkleRoot)`
  - one latest-sequence slot per operator
  - one bounded delegate-expiry slot per `(operator, delegate)`
- `ChioEscrow`
  - one immutable root-registry pointer
  - one immutable identity-registry pointer
  - one escrow state record per escrow id
  - one monotonically increasing nonce
- `ChioBondVault`
  - one immutable root-registry pointer
  - one immutable identity-registry pointer
  - one bond state record per vault id
  - one monotonically increasing nonce
- `ChioPriceResolver`
  - one admin slot
  - one immutable sequencer-feed pointer
  - one price-feed record per `(base, quote)` pair

## Qualification Notes

- Proof paths remain calldata-heavy rather than storage-heavy.
- The bounded delegate model caps active delegate count at three per operator.
- No contract in the family uses upgradeable proxy storage or admin-owned
  emergency pause slots.
