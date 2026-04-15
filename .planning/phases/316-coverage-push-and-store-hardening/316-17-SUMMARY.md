# Summary 316-17

Phase `316` added a seventeenth coverage wave focused on the weakest remaining
liability-market path in `arc-store-sqlite/src/receipt_store/liability_market.rs`
and then re-ran full-workspace `llvm-cov` to measure the real remaining gap.

The implemented coverage wave added new tests in:

- `arc-store-sqlite/src/receipt_store/tests.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-sqlite-llvm CARGO_INCREMENTAL=0 cargo llvm-cov -p arc-store-sqlite --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace2-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-coverage.json`
- `git diff --check -- crates/arc-store-sqlite/src/receipt_store/tests.rs`

Measured local coverage from the refreshed `llvm-cov` lanes:

- `arc-store-sqlite/src/receipt_store/liability_market.rs`:
  baseline `90/1103` -> refreshed crate-local `761/1103` lines (`+671`,
  `68.99%`)
- full workspace total on the current dirty tree:
  `103913/143293` lines (`72.52%`)

This wave exercises real liability-market behavior rather than helper-only
branches: provider supersession, quote issuance, placement/binding, manual
review autobind handling, unsupported-policy rejection, and stale active-quote
rejection now execute through the exported store surface with signed fixtures.

The SQLite hardening claim remains satisfied, but the refreshed workspace total
still misses the roadmap gate by roughly `7.48` percentage points, so phase
`316` remains open with gaps recorded.
