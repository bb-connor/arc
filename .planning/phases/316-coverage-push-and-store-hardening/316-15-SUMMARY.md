# Summary 316-15

Phase `316` added a fifteenth coverage wave that pushed deeper into the
 production settlement-construction logic in `arc-settle/src/evm.rs`.

The implemented coverage wave added new tests in:

- `arc-settle/src/evm.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-settle`
- `cargo test -p arc-settle`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-settle-evm2-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-settle --json --summary-only --output-path /tmp/arc-phase316-settle-evm2-coverage.json`
- `git diff --check -- crates/arc-settle/src/evm.rs`

Measured local coverage from the refreshed `llvm-cov` lane:

- `arc-settle` crate total: `3135/4071` -> `3971/4488` lines (`+836`,
  `88.48%`)
- `arc-settle/src/evm.rs`: `1258/1926` -> `2094/2343` lines (`+836`,
  `89.37%`)

This follow-up wave covers the real settlement preparation path rather than
only RPC wrappers: it now exercises escrow dispatch derivation, binding and
instruction rejection paths, Merkle full and partial release construction,
dual-sign release preparation, bond lock derivation, and bond release/impair
construction through signed local fixtures and the mock JSON-RPC stub.

Applying the refreshed `arc-settle` replacement delta on top of the isolated
workspace `llvm-cov` baseline and the earlier `arc-acp-proxy` plus
`arc-policy` waves moves the estimated local workspace total to
`98663/139249` (`70.85%`). Phase `316` still remains open.
