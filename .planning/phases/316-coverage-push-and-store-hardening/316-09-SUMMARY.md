# Summary 316-09

Phase `316` added a ninth coverage wave focused on the remaining untested
`arc-policy` inheritance and loader surfaces in `merge.rs` and `resolve.rs`.

The implemented coverage wave added new tests in:

- `arc-policy/src/merge.rs`
- `arc-policy/src/resolve.rs`

Verification that passed during this wave:

- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy cargo test -p arc-policy`
- `CARGO_TARGET_DIR=/tmp/arc-phase316-policy-llvm cargo llvm-cov -p arc-policy --json --summary-only --output-path /tmp/arc-phase316-policy-coverage.json`
- `git diff --check -- crates/arc-policy/src/merge.rs crates/arc-policy/src/resolve.rs`

Measured local file summaries from the refreshed `llvm-cov` lane:

- `arc-policy` crate total: `3375/4287` lines (`78.73%`)
- `arc-policy/src/merge.rs`: `684/727` lines (`94.09%`)
- `arc-policy/src/resolve.rs`: `196/213` lines (`92.02%`)
- `arc-policy/src/conditions.rs`: `403/420` lines (`95.95%`)
- `arc-policy/src/detection.rs`: `529/538` lines (`98.33%`)
- `arc-policy/src/receipt.rs`: `201/201` lines (`100.00%`)

The new tests cover replace/merge/deep-merge behavior, slot-level rule
fallbacks, nested extension map/profile combination, reputation and detection
sub-structure merges, relative and absolute `extends` path resolution,
filesystem-based parent resolution, cycle detection, HTTP rejection, parse
errors, and missing-file failures.

The targeted tarpaulin lane for `arc-policy` remains unreliable: even with a
unique output directory and a clean build, it stalled after the compile phase
and emitted no report file. Because phase `316`'s workspace estimate is still
tracked against the committed tarpaulin baseline, this wave is recorded as
verified local file coverage only and is not yet folded into the `71.34%`
workspace estimate.
