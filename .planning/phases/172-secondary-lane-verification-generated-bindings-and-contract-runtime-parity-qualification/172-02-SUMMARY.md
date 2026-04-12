# Plan 172-02 Summary

Converted the official binding surface to derive from compiled interface
artifacts and removed the most material contract-interface drift.

## Delivered

- `contracts/src/interfaces/IArcRootRegistry.sol`
- `contracts/src/interfaces/IArcEscrow.sol`
- `contracts/src/interfaces/IArcBondVault.sol`
- `contracts/src/interfaces/IArcPriceResolver.sol`
- `contracts/src/ArcPriceResolver.sol`
- `crates/arc-web3-bindings/Cargo.toml`
- `crates/arc-web3-bindings/src/interfaces.rs`
- `crates/arc-web3-bindings/src/lib.rs`
- `crates/arc-anchor/src/evm.rs`
- `crates/arc-settle/src/evm.rs`

## Notes

`arc-web3-bindings` now derive their contract surface from the compiled
interface artifacts under `contracts/artifacts/interfaces/`. The Rust side
keeps one shared `ArcMerkleProof` adapter so runtime code stays readable while
still following the artifact-derived ABI truth.
