---
phase: 307
status: passed
completed: 2026-04-13
---

# Phase 307 Verification

## Outcome

Phase `307` passed. ARC's remaining user-facing rename drift is gone in the
roadmap-scoped files, and `arc init` now creates a standalone project that
compiles and runs a governed hello-world tool call through the real CLI.

## Automated Verification

- `cargo check -p arc-cli`
- `cargo test -p arc-cli --test init`
- `rg -n -i '\\bchio\\b' README.md docs/ crates/*/src/*.rs`
- `cargo run -p arc-cli --bin arc -- init /tmp/arc-phase307-verify`
- `ARC_BIN=/Users/connor/Medica/backbay/standalone/arc/target/debug/arc CARGO_TARGET_DIR=/tmp/arc-phase307-target cargo run --quiet --manifest-path /tmp/arc-phase307-verify/Cargo.toml --bin demo -- Ada`

## Requirement Closure

- `ONBOARD-01`: user-facing ARC naming is now consistent in the scoped docs and
  README gate.
- `ONBOARD-02`: `arc init` writes a working policy file, tool server stub,
  governed demo runner, and build instructions.
- `ONBOARD-03`: the generated project compiles and executes a governed
  hello-world tool call without manual intervention.

## Next Step

Proceed to phase `308` to turn the in-repo SDK work into publishable,
installable packages with official examples.
