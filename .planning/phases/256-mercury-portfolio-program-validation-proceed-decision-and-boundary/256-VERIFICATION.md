---
status: passed
---

# Phase 256 Verification

## Outcome

Phase `256` validated one bounded Mercury portfolio-program package end to end
and closed the milestone with one explicit proceed decision.

## Evidence

- `crates/arc-mercury/tests/cli.rs`
- `docs/mercury/PORTFOLIO_PROGRAM_VALIDATION_PACKAGE.md`
- `docs/mercury/PORTFOLIO_PROGRAM_DECISION_RECORD.md`
- `target/mercury-portfolio-program-export-v261`
- `target/mercury-portfolio-program-validation-v261`
- `.planning/v2.61-MILESTONE-AUDIT.md`

## Validation

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core portfolio_program --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_portfolio_program_export_writes_program_review_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_portfolio_program_validate_writes_validation_report_and_decision`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- portfolio-program export --output target/mercury-portfolio-program-export-v261`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- portfolio-program validate --output target/mercury-portfolio-program-validation-v261`
- `rg -n '2026-04' crates/arc-mercury/src/commands.rs crates/arc-mercury/src/main.rs crates/arc-mercury-core/src/portfolio_program.rs crates/arc-mercury-core/src/lib.rs crates/arc-mercury/tests/cli.rs`

## Requirement Closure

`MPP-04` and `MPP-05` are satisfied locally: Mercury validates one bounded
portfolio-program package end to end and closes with one explicit
`proceed_portfolio_program_only` decision.

## Next Step

No active milestone remains queued locally. The next workflow entrypoint is
`$gsd-new-milestone`.
