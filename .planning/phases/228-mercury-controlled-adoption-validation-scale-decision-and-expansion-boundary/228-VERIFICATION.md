---
status: passed
---

# Phase 228 Verification

## Outcome

Phase `228` validated the Mercury controlled-adoption package end to end and
closed the milestone with one explicit scale decision:
`scale_controlled_adoption_only`.

## Evidence

- [cli.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/tests/cli.rs)
- [CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md)
- [CONTROLLED_ADOPTION_DECISION_RECORD.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md)
- [validation-report.json](/Users/connor/Medica/backbay/standalone/arc/target/mercury-controlled-adoption-validation-v254/validation-report.json)
- [expansion-decision.json](/Users/connor/Medica/backbay/standalone/arc/target/mercury-controlled-adoption-validation-v254/expansion-decision.json)

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core controlled_adoption --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_controlled_adoption_export_writes_adoption_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_controlled_adoption_validate_writes_validation_report_and_decision`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- controlled-adoption export --output target/mercury-controlled-adoption-export-v254`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- controlled-adoption validate --output target/mercury-controlled-adoption-validation-v254`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs init milestone-op`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`
- `git diff --check -- crates/arc-mercury-core/src/lib.rs crates/arc-mercury-core/src/controlled_adoption.rs crates/arc-mercury/src/main.rs crates/arc-mercury/src/commands.rs crates/arc-mercury/tests/cli.rs docs/mercury/README.md docs/mercury/GO_TO_MARKET.md docs/mercury/CONTROLLED_ADOPTION.md docs/mercury/CONTROLLED_ADOPTION_OPERATIONS.md docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md .planning/PROJECT.md .planning/MILESTONES.md .planning/REQUIREMENTS.md .planning/ROADMAP.md .planning/STATE.md`

## Requirement Closure

`MCA-04` and `MCA-05` are now satisfied locally: the controlled-adoption
bundle validates end to end, and the milestone closes with an explicit
Mercury scale decision that preserves the ARC generic boundary.

## Next Step

No executable phases remain. The next workflow entrypoint is
`$gsd-new-milestone`.
