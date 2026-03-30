---
phase: 28
slug: domain-module-cleanup-and-dependency-enforcement
status: complete
created: 2026-03-25
---

# Phase 28 Research

## Findings

1. `arc-credentials`, `arc-reputation`, and `arc-policy` are structurally
   good crate boundaries already; the debt is mostly file concentration inside
   each crate.
2. A root-facade split is again the lowest-risk option because it preserves the
   current root-module semantics while physically separating the code.
3. `arc-policy/src/evaluate.rs` is a good candidate for a nested
   `evaluate/` folder because the file already clusters into public context,
   engine flow, rule matching, and outcome helpers.
4. A simple dependency guard can inspect Cargo manifests and fail if domain
   crates depend on CLI/service crates or transport-centric libraries.
5. The release lane already has qualification scripts, so this phase only needs
   to extend them with architecture/layering checks rather than inventing a new
   pipeline.

## Decision

Phase 28 will use this shape:

- `arc-credentials`
  - `lib.rs` becomes a facade over `artifact.rs`, `passport.rs`,
    `challenge.rs`, `registry.rs`, `policy.rs`, and `presentation.rs`
- `arc-reputation`
  - `lib.rs` becomes a facade over `model.rs`, `score.rs`, `compare.rs`,
    and `issuance.rs`
- `arc-policy`
  - `evaluate.rs` becomes a thin shim over `evaluate/context.rs`,
    `evaluate/engine.rs`, `evaluate/matchers.rs`, and `evaluate/outcomes.rs`
- workspace guardrails
  - add a script that enforces domain-crate dependency layering
  - document the intended workspace shape in a short architecture note

## Verification Inputs

- `wc -l crates/arc-credentials/src/lib.rs crates/arc-reputation/src/lib.rs crates/arc-policy/src/evaluate.rs`
- `cargo check -p arc-credentials -p arc-reputation -p arc-policy`
- qualification script update to include the new layering check
