# Summary 316-14

Phase `316` added a fourteenth coverage wave focused on the weak EVM runtime
surface in `arc-settle/src/evm.rs`.

The implemented coverage wave added new tests in:

- `arc-settle/src/evm.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-settle`
- `cargo test -p arc-settle`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-settle-evm-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-settle --json --summary-only --output-path /tmp/arc-phase316-settle-evm-coverage.json`
- `git diff --check -- crates/arc-settle/src/evm.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-settle` crate total: `2681/3700` -> `3135/4071` lines (`+454`,
  `77.01%`)
- `arc-settle/src/evm.rs`: isolated workspace baseline `621/1555` ->
  refreshed crate-local summary `1258/1926` lines (`+637`, `65.32%`)

This wave exercises production settlement behavior rather than only leaf
helpers: the local JSON-RPC stub now drives `eth_call`, gas estimation,
transaction submission, transaction confirmation, escrow snapshot reads, bond
snapshot reads, and fail-closed settlement prep paths.

Applying the refreshed `arc-settle` replacement delta on top of the isolated
workspace `llvm-cov` baseline and the earlier `arc-acp-proxy` plus
`arc-policy` waves moves the estimated local workspace total to
`98332/138918` (`70.78%`). Phase `316` still remains open.
