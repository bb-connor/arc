---
phase: 317-dead-code-and-api-surface-audit
milestone: v2.83
created: 2026-04-14
status: in_progress
---

# Phase 317 Context

## Goal

Remove dead code, shrink oversize function signatures, and tighten public API
visibility so the production surface is easier to maintain and reason about.

## Current Reality

- Non-test `#[allow(dead_code)]` still exists across `arc-acp-edge`,
  `arc-acp-proxy`, `arc-anchor`, `arc-cli`, `arc-link`, `arc-mcp-edge`, and
  `arc-settle`.
- Non-test `#[allow(clippy::too_many_arguments)]` remains widespread, with the
  heaviest concentration in `arc-cli` plus scattered builder/helper surfaces in
  `arc-appraisal`, `arc-anchor`, `arc-settle`, `arc-mcp-edge`,
  `arc-mercury-core`, `arc-mercury`, `arc-workflow`, and `arc-credentials`.
- Crate-root `pub use` surfaces remain broad in `arc-core`, `arc-kernel`,
  `arc-anchor`, `arc-mercury-core`, `arc-guards`, and several bridge crates.
- `cargo +nightly udeps` is not currently installed locally:
  `error: no such command: udeps`.

## Boundaries

- Stay inside the v2.83 phase scope; do not disturb the v3.x.x planning work
  another agent has already started.
- Prefer low-risk surface cleanup first: remove or justify dead code, then
  attack the smallest high-signal `too_many_arguments` and re-export issues.
- Do not break intended public APIs just to satisfy the audit mechanically.

## Key Risks

- The `too_many_arguments` inventory is large enough that phase `317` will
  likely require multiple execution waves.
- Some crate-root re-exports may be intentional compatibility shims, so the
  visibility audit needs to distinguish public API from internal leakage.
- The `udeps` gate cannot be closed until the tool is installed or an accepted
  equivalent dependency audit is defined.

## Decision

Start with the non-test `dead_code` inventory because it is the most bounded
and lowest-risk requirement slice. Close obvious dead code, add explicit
justification comments where the field/helper must remain for compatibility or
feature-gated behavior, then move on to `too_many_arguments` refactors and the
crate-root visibility audit.
