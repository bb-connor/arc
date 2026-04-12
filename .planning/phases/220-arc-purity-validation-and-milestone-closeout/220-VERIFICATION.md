---
status: passed
---

# Phase 220 Verification

## Outcome

Phase `220` validated the ARC purity cleanup and closed the milestone with an
explicit boundary decision.

## Evidence

- [lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-control-plane/src/lib.rs)
- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs)
- [receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-kernel/src/receipt_query.rs)
- [trust_control.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control.rs)
- [receipt_store.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-store-sqlite/src/receipt_store.rs)
- [receipt_query.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-store-sqlite/src/receipt_query.rs)

## Validation

- `rg -n --glob '!crates/arc-mercury/**' --glob '!crates/arc-mercury-core/**' --glob '!crates/arc-wall/**' --glob '!crates/arc-wall-core/**' '\bMERCURY\b|\bMercury\b|\bmercury\b|ARC-Wall|arc-wall|arc_wall' crates`
- `CARGO_TARGET_DIR=/tmp/arc-purity-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-kernel -p arc-store-sqlite -p arc-control-plane -p arc-cli`
- `CARGO_TARGET_DIR=/tmp/arc-purity-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-store-sqlite receipt_query --lib`
- `CARGO_TARGET_DIR=/tmp/arc-purity-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-cli --test receipt_query test_receipt_query_no_filters`
- `git diff --check -- crates/arc-control-plane/src/lib.rs crates/arc-cli/src/main.rs crates/arc-kernel/src/receipt_query.rs crates/arc-cli/src/trust_control.rs crates/arc-store-sqlite/Cargo.toml crates/arc-store-sqlite/src/receipt_store.rs crates/arc-store-sqlite/src/receipt_query.rs`

## Requirement Closure

`MAP-04` and `MAP-05` are now satisfied locally: the ARC purity audit is clean,
the low-memory regression suite passes, and the milestone closes with an
explicit decision to keep Mercury release work on Mercury's own app surface.

## Next Step

Phase `221` can now freeze Mercury-specific release-readiness scope without
reintroducing Mercury logic into ARC generic crates.
