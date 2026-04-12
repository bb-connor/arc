---
status: passed
---

# Phase 255 Verification

## Outcome

Phase `255` published one Mercury-owned portfolio approval, one
revenue-operations-guardrails artifact, and one explicit program handoff over
the new portfolio-program package.

## Evidence

- `crates/arc-mercury/src/commands.rs`
- `docs/mercury/PORTFOLIO_PROGRAM_OPERATIONS.md`
- `docs/mercury/PORTFOLIO_PROGRAM_DECISION_RECORD.md`
- `target/mercury-portfolio-program-export-v261`

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_portfolio_program_export_writes_program_review_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v261-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- portfolio-program export --output target/mercury-portfolio-program-export-v261`

## Requirement Closure

`MPP-03` is satisfied locally: Mercury now publishes one portfolio approval,
one revenue-operations guardrail, and one program handoff model that stays
product-owned.
