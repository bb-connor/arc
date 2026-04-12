---
status: passed
---

# Phase 235 Verification

## Outcome

Phase `235` added Mercury-owned claim-governance, selective-account approval,
and distribution-handoff controls on top of the broader-distribution package
without introducing generic sales tooling or ARC-side commercial surfaces.

## Evidence

- `crates/arc-mercury/src/commands.rs`
- `docs/mercury/BROADER_DISTRIBUTION_OPERATIONS.md`
- `target/mercury-broader-distribution-export-v256/claim-governance-rules.json`
- `target/mercury-broader-distribution-export-v256/selective-account-approval.json`
- `target/mercury-broader-distribution-export-v256/distribution-handoff-brief.json`

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury --test cli mercury_broader_distribution_export_writes_governed_bundle`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- broader-distribution export --output target/mercury-broader-distribution-export-v256`

## Requirement Closure

`MBD-03` is now satisfied locally: Mercury publishes one product-owned claim-
governance, selective-account approval, and distribution-handoff model.

## Next Step

Phase `236` can now validate the whole broader-distribution lane end to end
and close the milestone with an explicit proceed or defer decision.
