---
phase: 43-formal-proof-and-spec-runtime-closure
plan: 02
subsystem: executable-formal-alignment
tags:
  - formal
  - diff-tests
  - runtime
requires:
  - 43-01
provides:
  - A current executable reference model for the shipped `ArcScope` subset
  - Differential coverage for resource/prompt grants, DPoP, budgets, governed constraints, and runtime assurance
  - Runtime/spec consistency fixes discovered during workspace qualification
key-files:
  modified:
    - formal/diff-tests/src/spec.rs
    - formal/diff-tests/src/generators.rs
    - formal/diff-tests/tests/scope_diff.rs
    - formal/diff-tests/src/lib.rs
    - crates/arc-cli/src/enterprise_federation.rs
requirements-completed:
  - RISK-03
completed: 2026-03-27
---

# Phase 43 Plan 02 Summary

Phase 43-02 brought the executable reference model back into alignment with the
current ARC runtime surface and closed the highest-signal drift.

## Accomplishments

- expanded the formal diff-test reference model and generators to cover the
  shipped `ArcScope` subset across tool, resource, and prompt grants
- added support for monetary caps, DPoP requirements, governed-intent
  constraints, seller scoping, and minimum runtime-assurance constraints in the
  executable spec model
- extended the differential/property tests so wildcard, prefix, budget, and
  scope-attenuation behavior are checked against the implementation rather than
  described only in docs
- clarified `formal/diff-tests` as the shipped proof-style release gate while
  standalone Lean proof modules remain advisory until they are root-imported
  and `sorry`-free
- fixed certification-discovery registry URL normalization on write so stored
  and loaded federation state cannot drift during qualification

## Verification

- `cargo test --workspace`
