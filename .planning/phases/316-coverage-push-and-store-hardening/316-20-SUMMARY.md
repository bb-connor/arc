# Summary 316-20

Phase `316` then reran the comparable filtered full-workspace `llvm-cov` lane
on the current tree so the trust-control coverage wave could be measured
against the same gate that previously reported `72.42%`.

Verification that passed during this wave:

- `CARGO_TARGET_DIR=/tmp/arc-phase316-workspace3-llvm CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --exclude arc-formal-diff-tests --exclude arc-e2e --exclude hello-tool --exclude arc-conformance --exclude arc-control-plane --exclude arc-web3-bindings --json --summary-only --output-path /tmp/arc-phase316-workspace3-next-coverage.json`

Measured comparable filtered full-workspace coverage on the current tree:

- previous comparable artifact: `105290/145396` lines (`72.42%`)
- current comparable artifact: `108092/147497` lines (`73.28%`)
- delta: `+2802` covered lines, `+2101` total counted lines, and `-701`
  uncovered lines
- remaining gap to `80%` at the current denominator: `9906` covered lines

This means the recent trust-control wave did move the gate in the right
direction. The workspace denominator still grew, but covered lines grew faster
than total counted lines in this rerun, so the net uncovered inventory
improved.

Coverage-lane diagnostic note:

- the Docker tarpaulin lane in `scripts/run-coverage.sh` still does not emit
  final HTML/JSON/LCOV artifacts reliably on this machine even after the LLVM
  profile path fix
- the comparable filtered `llvm-cov` artifact above is therefore the current
  authoritative measurement for the `72.42%` -> `73.28%` gate movement

Phase `316` remains open because `73.28%` is still materially below the `80%`
floor, but the measurement is no longer stalled or unknown.
