# Plan 171-01 Summary

Reconciled the bond-vault surface so collateral and reserve requirements now
mean different things everywhere they appear.

## Delivered

- `contracts/src/interfaces/IArcBondVault.sol`
- `contracts/src/ArcBondVault.sol`
- `crates/arc-web3-bindings/src/interfaces.rs`
- `crates/arc-settle/src/evm.rs`
- `contracts/scripts/qualify-devnet.mjs`
- `contracts/README.md`
- `contracts/reports/ARC_WEB3_CONTRACT_SECURITY_REVIEW.md`
- `docs/standards/ARC_SETTLE_PROFILE.md`
- `docs/release/ARC_WEB3_PARTNER_PROOF.md`
- `docs/release/RELEASE_CANDIDATE.md`
- `spec/PROTOCOL.md`

## Notes

`ArcBondVault` still locks only `collateralAmount`, but the old ambiguous
reserve field names are gone. The contract and runtime now preserve signed ARC
bond reserve requirements explicitly as metadata for parity and review rather
than implying an enforced second on-chain ledger.
