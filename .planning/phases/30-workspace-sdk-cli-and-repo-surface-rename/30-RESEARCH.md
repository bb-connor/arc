# Phase 30 Research

## Findings

1. Rust package rename is feasible without a full code import rewrite.
   Package names in crate `Cargo.toml` files can move to `arc-*` while internal
   dependency keys remain `arc-*` if dependents use `package = "arc-*"` in
   their dependency specs.

2. CLI compatibility is straightforward.
   `crates/arc-cli/Cargo.toml` can expose `arc` as the primary binary while
   retaining `arc` as a second binary alias pointing at the same `src/main.rs`
   entrypoint.

3. SDK package metadata is the main external churn point.
   TypeScript uses `@arc-protocol/sdk`, Python uses `arc-py`, and Go uses a
   module path under `github.com/medica/arc/...`. Phase 30 should move the
   visible package metadata first and capture any unavoidable compatibility
   limits.

4. Phase 30 should avoid doc-wide string replacement.
   README, standards, and long-form docs are Phase 32 work. This phase should
   focus on package identity and the tooling surface required to build and test.

## Recommended Execution Shape

- Plan 30-01: rename Cargo package metadata and add package aliasing in
  inter-crate dependencies
- Plan 30-02: expose `arc` as the primary binary and move SDK package metadata
  to ARC-first naming
- Plan 30-03: update repo/release metadata and smoke-check the renamed package
  surface before Phase 31
