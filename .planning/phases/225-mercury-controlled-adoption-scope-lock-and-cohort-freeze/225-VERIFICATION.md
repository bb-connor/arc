---
status: passed
---

# Phase 225 Verification

## Outcome

Phase `225` froze one Mercury-specific controlled-adoption lane and cohort
without reopening ARC generic-boundary work.

## Evidence

- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury/src/main.rs)
- [README.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/README.md)
- [GO_TO_MARKET.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/GO_TO_MARKET.md)
- [CONTROLLED_ADOPTION.md](/Users/connor/Medica/backbay/standalone/arc/docs/mercury/CONTROLLED_ADOPTION.md)

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v254-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo run -p arc-mercury -- controlled-adoption export --output target/mercury-controlled-adoption-export-v254`

## Requirement Closure

`MCA-01` is now satisfied locally: Mercury freezes one controlled-adoption
cohort and adoption surface on its own app surface, explicitly names the
product-owned operators, and keeps ARC generic.

## Next Step

Phase `226` can now encode the adoption-evidence and renewal package contract
over the existing Mercury artifact stack.
