---
status: passed
---

# Phase 234 Verification

## Outcome

Phase `234` defined one Mercury-specific broader-distribution profile,
package contract, and export surface rooted in the reference-distribution,
controlled-adoption, release-readiness, trust-network, assurance, proof, and
inquiry artifacts.

## Evidence

- `crates/arc-mercury-core/src/broader_distribution.rs`
- `crates/arc-mercury-core/src/lib.rs`
- `crates/arc-mercury/src/commands.rs`
- `crates/arc-mercury/src/main.rs`

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core broader_distribution --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v256-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- broader-distribution export --output target/mercury-broader-distribution-export-v256`

## Requirement Closure

`MBD-02` is now satisfied locally: Mercury defines one bounded qualification
package and governed-distribution contract rooted in the existing Mercury
evidence stack.

## Next Step

Phase `235` can now attach claim-governance, selective-account approval, and
distribution-handoff controls to the real package rather than an abstract
distribution motion.
