---
phase: 307-identity-resolution-and-scaffolding
created: 2026-04-13
---

# Phase 307 Validation

## Required Evidence

- `README.md`, `docs/`, and `crates/*/src/*.rs` contain no remaining `CHIO`
  literals.
- `arc init` writes a project directory with a policy file, tool server stub,
  governed demo runner, and build instructions.
- The generated project compiles and its demo performs a governed hello-world
  tool call through `arc mcp serve`.

## Verification Commands

- `cargo check -p arc-cli`
- `cargo test -p arc-cli --test init`
- `rg -n -i '\\bchio\\b' README.md docs/ crates/*/src/*.rs`
- `cargo run -p arc-cli --bin arc -- init /tmp/arc-phase307-verify`
- `ARC_BIN=/Users/connor/Medica/backbay/standalone/arc/target/debug/arc CARGO_TARGET_DIR=/tmp/arc-phase307-target cargo run --quiet --manifest-path /tmp/arc-phase307-verify/Cargo.toml --bin demo -- Ada`

## Regression Focus

- CLI subcommand parsing for the new `arc init` entry point
- generated file contents and placeholder replacement
- governed MCP tool-call path used by the scaffold demo
- user-facing naming consistency in the top-level documentation set
