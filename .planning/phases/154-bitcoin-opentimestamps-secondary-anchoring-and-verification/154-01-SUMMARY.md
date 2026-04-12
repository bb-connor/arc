# Plan 154-01 Summary

Implemented deterministic OTS submission preparation over contiguous ARC
checkpoints.

## Delivered

- `crates/arc-anchor/src/bitcoin.rs`
- `docs/standards/ARC_ANCHOR_OTS_SUBMISSION_EXAMPLE.json`

## Notes

The prepared submission now carries both the ARC super-root and the SHA-256
document digest expected by imported OTS proofs.
