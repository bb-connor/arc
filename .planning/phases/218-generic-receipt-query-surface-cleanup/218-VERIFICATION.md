---
status: passed
---

# Phase 218 Verification

## Outcome

Phase `218` removed Mercury-only naming from ARC's generic receipt query,
generic CLI, and trust-control query surfaces.

## Evidence

- [receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/receipt_query.rs)
- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs)
- [trust_control.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control.rs)

## Validation

- `CARGO_TARGET_DIR=/tmp/arc-purity-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-kernel -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-purity-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_receipt_query_no_filters`

## Requirement Closure

`MAP-02` is now satisfied locally: ARC's generic receipt query and
trust-control surfaces do not name Mercury-only filters.

## Next Step

Phase `219` can now remove the remaining Mercury-only coupling from ARC's
generic SQLite receipt store.
