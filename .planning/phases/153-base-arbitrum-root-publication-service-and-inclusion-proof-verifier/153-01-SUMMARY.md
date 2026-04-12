# Plan 153-01 Summary

Implemented the primary EVM anchoring lane in the new `arc-anchor` crate with
canonical publication requests, transaction submission, and confirmation.

## Delivered

- `crates/arc-anchor/src/lib.rs`
- `crates/arc-anchor/src/evm.rs`
- `crates/arc-anchor/Cargo.toml`

## Notes

The runtime now prepares `publishRoot` calldata from canonical ARC checkpoint
state and re-checks the stored root entry on confirmation.
