---
status: passed
---

# Phase 240 Verification

## Outcome

Phase `240` validated the Mercury selective-account-activation package end to
end and closed the milestone with one explicit proceed decision:
`proceed_selective_account_activation_only`.

## Evidence

- `crates/arc-mercury/tests/cli.rs`
- `docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md`
- `docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md`
- `target/mercury-selective-account-activation-validation-v257/validation-report.json`
- `target/mercury-selective-account-activation-validation-v257/selective-account-activation-decision.json`

## Validation

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core selective_account_activation --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_selective_account_activation_export_writes_controlled_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_selective_account_activation_validate_writes_validation_report_and_decision`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- selective-account-activation export --output target/mercury-selective-account-activation-export-v257`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- selective-account-activation validate --output target/mercury-selective-account-activation-validation-v257`

## Requirement Closure

`MSA-04` and `MSA-05` are now satisfied locally: the selective-account-
activation bundle validates end to end, and the milestone closes with one
explicit Mercury proceed decision that preserves the ARC generic boundary.

## Next Step

No executable phases remain. The next workflow entrypoint is
`$gsd-new-milestone`.
