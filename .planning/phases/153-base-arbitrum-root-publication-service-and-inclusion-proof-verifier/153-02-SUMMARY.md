# Plan 153-02 Summary

Bound the EVM runtime back to canonical ARC truth with projection helpers and
on-chain proof verification.

## Delivered

- `crates/arc-anchor/src/lib.rs`
- `crates/arc-anchor/src/evm.rs`

## Notes

`arc-anchor` now reuses `AnchorInclusionProof` and the registry's
`verifyInclusionDetailed` path instead of widening the proof contract.
