# Plan 159-02 Summary

Closed the Solana lane around ARC-native Ed25519 verification rather than
opaque external trust.

## Delivered

- `crates/arc-settle/src/solana.rs`

## Notes

`arc-settle` now verifies the receipt signature, key-binding certificate,
purpose, chain scope, and ARC public-key match before any Solana settlement
artifact is prepared.
