# Summary 316-12

Phase `316` added a twelfth coverage wave focused on the previously zeroed
`arc-settle` finality observation surface in `observe.rs`.

The implemented coverage wave added new tests in:

- `arc-settle/src/observe.rs`

Verification that passed during this wave:

- `cargo test -p arc-settle`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-settle-llvm cargo llvm-cov -p arc-settle --json --summary-only --output-path /tmp/arc-phase316-settle-coverage.json`
- `git diff --check -- crates/arc-settle/src/observe.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-settle` crate total: `1713/3120` -> `2681/3700` lines (`+968`, `72.46%`)
- `arc-settle/src/observe.rs`: full-workspace baseline `0/229` source lines;
  refreshed crate-local summary `778/809` lines (`96.17%`)
- `arc-settle/src/evm.rs`: `621/1555` -> `804/1555` lines (`51.70%`)

The file-local denominator for `observe.rs` grew because the new tests live in
that same module file, so the meaningful signal from this wave is the large
production-path lift: finality status transitions, RPC error handling, receipt
fetching, timed-out refund projections, partial-settlement projections, and
bond lifecycle classification are now exercised through a local JSON-RPC stub.

Applying the measured `arc-settle` replacement delta on top of the isolated
workspace `llvm-cov` baseline and the earlier `arc-acp-proxy` wave moves the
estimated local workspace total to `97461/138263` (`70.49%`). Phase `316`
still remains open.
