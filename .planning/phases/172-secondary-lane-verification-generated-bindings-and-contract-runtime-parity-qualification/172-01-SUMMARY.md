# Plan 172-01 Summary

Upgraded proof-bundle validation from structural checks to cryptographic
secondary-lane verification.

## Delivered

- `crates/arc-anchor/src/bitcoin.rs`
- `crates/arc-anchor/src/bundle.rs`
- `crates/arc-anchor/src/lib.rs`
- `crates/arc-core/src/web3.rs`
- `docs/standards/ARC_ANCHOR_PROFILE.md`
- `docs/release/ARC_ANCHOR_RUNBOOK.md`
- `docs/release/ARC_WEB3_PARTNER_PROOF.md`

## Notes

Bitcoin secondary-lane validation now proves that the imported OTS proof
commits to the ARC super-root digest and attests the declared Bitcoin block.
Bundles also fail closed on undeclared secondary evidence instead of silently
accepting extra material.
