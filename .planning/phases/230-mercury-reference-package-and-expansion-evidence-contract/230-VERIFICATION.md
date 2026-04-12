---
status: passed
---

# Phase 230 Verification

## Outcome

Phase `230` defined one Mercury-specific reference-distribution profile,
package contract, and export surface rooted in the controlled-adoption,
release-readiness, trust-network, assurance, proof, and inquiry artifacts.

## Evidence

- `crates/arc-mercury-core/src/reference_distribution.rs`
- `crates/arc-mercury-core/src/lib.rs`
- `crates/arc-mercury/src/commands.rs`
- `crates/arc-mercury/src/main.rs`

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v255-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v255-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core reference_distribution --lib`
- `CARGO_TARGET_DIR=/tmp/arc-v255-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- reference-distribution export --output target/mercury-reference-distribution-export-v255`

## Requirement Closure

`MRE-02` is now satisfied locally: Mercury defines one bounded reference
package and expansion-evidence contract rooted in the existing Mercury
evidence stack.

## Next Step

Phase `231` can now attach claim-discipline, buyer approval, and sales-
handoff controls to the real package rather than an abstract motion.
