---
phase: 28
slug: domain-module-cleanup-and-dependency-enforcement
status: in_progress
created: 2026-03-25
---

# Phase 28 Context

## Objective

Finish `v2.4` by splitting the remaining large domain files into smaller
source units and adding lightweight guardrails so the intended dependency
direction is harder to regress.

## Current Reality

- `crates/pact-credentials/src/lib.rs` is still 1,790 LOC
- `crates/pact-reputation/src/lib.rs` is still 967 LOC
- `crates/pact-policy/src/evaluate.rs` is still 1,811 LOC
- the core architecture work from Phases 25-27 is in place, but the domain
  layer still hides too much behavior inside a few files
- there is no dedicated script that fails closed when domain crates start
  pulling CLI/service crates or transport-centric dependencies back inward

## Constraints

- public behavior and current tests matter more than a perfect final internal
  semantic layout on the first cleanup pass
- this phase should keep the domain crates pure and avoid introducing new
  runtime or CLI dependencies
- the refactor lane needs one clear qualification entrypoint or guardrail set
  that proves the layering still holds

## Strategy

- reduce the large domain files to thin facades with named source files beneath
  them
- use low-churn source partitioning where necessary to avoid destabilizing the
  existing API surface
- add one explicit layering check script plus a short architecture document
- finish with targeted domain regressions and workspace-level qualification
