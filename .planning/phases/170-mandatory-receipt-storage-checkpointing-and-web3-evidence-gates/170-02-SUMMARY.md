# Plan 170-02 Summary

Threaded the mandatory evidence contract through anchor and settlement runtime
surfaces.

## Delivered

- `crates/arc-anchor/src/lib.rs`
- `crates/arc-settle/src/config.rs`
- `crates/arc-settle/src/solana.rs`
- `crates/arc-settle/src/lib.rs`
- `crates/arc-settle/tests/runtime_devnet.rs`

## Notes

`arc-anchor` now projects inclusion proofs from canonical evidence bundles,
and both EVM plus Solana settlement configs reject runtimes that do not have
durable receipts and kernel-signed checkpoint truth.
