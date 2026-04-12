# Plan 154-02 Summary

Added real OTS payload inspection and ARC-side linkage from imported Bitcoin
proofs back to the super-root and checkpoint range they cover.

## Delivered

- `crates/arc-anchor/src/bitcoin.rs`
- `crates/arc-anchor/src/lib.rs`

## Notes

ARC now rejects pending-only or digest-mismatched `.ots` payloads before
attaching secondary Bitcoin evidence to a proof.
