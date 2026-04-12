# Plan 171-03 Summary

Closed the main regression risks around the new money contract with direct
coverage in typed validation, runtime config, and the contract devnet
qualifier.

## Delivered

- `crates/arc-core/src/web3.rs`
- `crates/arc-link/src/lib.rs`
- `crates/arc-settle/src/config.rs`
- `contracts/scripts/qualify-devnet.mjs`
- `contracts/deployments/local-devnet.json`
- `contracts/reports/local-devnet-qualification.json`

## Notes

The core receipt validator now rejects successful FX-sensitive settlement
receipts that omit oracle evidence, `arc-link` tests assert the new authority
marker, settlement config tests assert the explicit authority model, and the
contract qualifier now proves bond-vault reserve requirement metadata and
collateral locking stay in parity rather than drifting.
