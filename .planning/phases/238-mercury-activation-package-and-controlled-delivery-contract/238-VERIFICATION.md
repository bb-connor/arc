---
status: passed
---

# Phase 238 Verification

## Outcome

Phase `238` added the selective-account-activation contract family and Mercury
CLI export path for one bounded controlled-delivery bundle.

## Evidence

- `crates/arc-mercury-core/src/selective_account_activation.rs`
- `crates/arc-mercury/src/main.rs`
- `crates/arc-mercury/src/commands.rs`
- `docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION.md`

## Validation

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo check -p arc-mercury-core -p arc-mercury`
- `CARGO_TARGET_DIR=/tmp/arc-v257-target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p arc-mercury-core selective_account_activation --lib`

## Requirement Closure

`MSA-02` is satisfied locally: Mercury now defines one bounded activation
package and controlled-delivery contract rooted in the existing broader-
distribution, proof, inquiry, and reviewer artifact stack.

## Next Step

Proceed to phase `239` to publish claim containment, approval refresh, and
customer handoff.
