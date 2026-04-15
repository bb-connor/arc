# Summary 316-18

Phase `316` added an eighteenth coverage wave focused on the liability-claims
and underwriting-credit receipt-store paths in
`arc-store-sqlite/src/receipt_store/liability_claims.rs` and
`arc-store-sqlite/src/receipt_store/underwriting_credit.rs`, then reran both
crate-local and full-workspace `llvm-cov` lanes to measure the real impact.

The implemented coverage wave added new tests in:

- `arc-store-sqlite/src/receipt_store/tests.rs`

Verification that passed during this wave:

- `cargo fmt -p arc-store-sqlite`
- `cargo test -p arc-store-sqlite --lib liability_claim_lifecycle_persists_package_through_payout_receipt -- --nocapture`
- `cargo test -p arc-store-sqlite --lib`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-store-next cargo llvm-cov -p arc-store-sqlite --lib --json --summary-only --output-path /tmp/arc-phase316-store-sqlite-coverage-next.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --json --summary-only --output-path /tmp/arc-phase316-workspace-next-coverage.json`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace-next cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace2-next-coverage.json`
- `git diff --check -- crates/arc-store-sqlite/src/receipt_store/tests.rs`

Measured local coverage from the refreshed `llvm-cov` lanes:

- `arc-store-sqlite` overall: `5740/11437` -> `6805/11437` lines (`50.19%` ->
  `59.50%`)
- `arc-store-sqlite/src/receipt_store/liability_claims.rs`:
  `0/911` -> `364/911` lines (`39.96%`)
- `arc-store-sqlite/src/receipt_store/underwriting_credit.rs`:
  `0/879` -> `529/879` lines (`60.18%`)
- comparable filtered full-workspace total on the current dirty tree:
  `103913/143293` -> `105290/145396` lines (`72.52%` -> `72.42%`)
- separate unfiltered full-workspace rerun on the same tree:
  `111339/151079` lines (`73.70%`)

This wave exercises real lifecycle behavior rather than helper-only branches:
underwriting supersession and appeal filtering, credit-facility effective-state
selection, and a signed liability-claim chain from claim package through payout
receipt now execute through the exported store surface. The deep claim-lifecycle
test runs on an enlarged thread stack so the signed nested artifact chain does
not overflow the default test stack.

The SQLite hardening claim remains satisfied, and the store-local coverage gains
are material. The milestone blocker is still the workspace-wide coverage floor:
the apples-to-apples filtered rerun is now `72.42%`, still about `7.58`
percentage points short of the roadmap gate, so phase `316` remains open with
gaps recorded.
