# Plan 169-01 Summary

Replaced nonce-derived settlement identity with deterministic contract truth.

## Delivered

- `contracts/src/ArcEscrow.sol`
- `contracts/src/ArcBondVault.sol`
- `contracts/src/interfaces/IArcEscrow.sol`
- `contracts/src/interfaces/IArcBondVault.sol`
- `crates/arc-web3-bindings/src/interfaces.rs`
- regenerated contract artifacts under `contracts/artifacts/`

## Notes

Escrow and bond identity now derive from immutable creation terms, and the
official interfaces expose `deriveEscrowId` plus `deriveVaultId` so runtime
preflight no longer depends on mutable nonce state.
