# Summary 316-08

Phase `316` added an eighth coverage wave focused on `arc-policy`,
specifically the low-coverage helper and branch-heavy surfaces in
`conditions.rs`, `detection.rs`, and `receipt.rs` that still sat near-zero in
the tarpaulin baseline.

The implemented coverage wave added new tests in:

- `arc-policy/src/conditions.rs`
- `arc-policy/src/detection.rs`
- `arc-policy/src/receipt.rs`

Verification that passed during this wave:

- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy cargo test -p arc-policy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy-llvm cargo llvm-cov -p arc-policy --json --summary-only --output-path /tmp/arc-phase316-policy-coverage.json`
- `git diff --check -- crates/arc-policy/src/conditions.rs crates/arc-policy/src/detection.rs crates/arc-policy/src/receipt.rs`

Measured local file summaries from the `llvm-cov` lane:

- `arc-policy` crate total: `2495/3764` lines (`66.29%`)
- `arc-policy/src/conditions.rs`: `403/420` lines (`95.95%`)
- `arc-policy/src/detection.rs`: `529/538` lines (`98.33%`)
- `arc-policy/src/receipt.rs`: `201/201` lines (`100.00%`)

The new tests cover compound `Condition` branches (`all_of`, `any_of`, `not`,
full-day windows), timezone and context helper parsing edges, direct pattern
runner score capping, custom detector registration, category-specific
threshold checks, empty and below-threshold detection behavior, and the
receipt policy-summary and audit metadata helpers.

A clean tarpaulin rerun was attempted with a unique output directory, but it
again stalled after the compile phase and did not emit a report file. Because
phase `316`'s running workspace estimate is currently tarpaulin-based, this
wave is recorded as verified local file coverage only and is not yet folded
into the `71.34%` workspace estimate.
