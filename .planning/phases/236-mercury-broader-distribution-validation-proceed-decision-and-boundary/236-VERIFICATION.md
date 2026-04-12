---
status: passed
---

# Phase 236 Verification

## Outcome

Phase `236` validated the Mercury broader-distribution package end to end and
closed the milestone with one explicit proceed decision:
`proceed_broader_distribution_only`.

## Evidence

- `crates/arc-mercury/tests/cli.rs`
- `docs/mercury/BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md`
- `docs/mercury/BROADER_DISTRIBUTION_DECISION_RECORD.md`
- `target/mercury-broader-distribution-validation-v256/validation-report.json`
- `target/mercury-broader-distribution-validation-v256/broader-distribution-decision.json`

## Validation

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core broader_distribution --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_broader_distribution_export_writes_governed_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_broader_distribution_validate_writes_validation_report_and_decision`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- broader-distribution export --output target/mercury-broader-distribution-export-v256`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- broader-distribution validate --output target/mercury-broader-distribution-validation-v256`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init milestone-op`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `git diff --check`

## Requirement Closure

`MBD-04` and `MBD-05` are now satisfied locally: the broader-distribution
bundle validates end to end, and the milestone closes with an explicit
Mercury proceed decision that preserves the ARC generic boundary.

## Next Step

No executable phases remain. The next workflow entrypoint is
`$gsd-new-milestone`.
