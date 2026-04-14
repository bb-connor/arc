---
phase: 315-integration-test-coverage-expansion
milestone: v2.83
created: 2026-04-13
status: in_progress
---

# Phase 315 Context

## Goal

Add integration-test coverage across the remaining zero-test crates so public
API regressions are caught at crate boundaries, then deepen coverage for the
security- and protocol-facing crates called out in the roadmap.

## Current Reality

- The active roadmap still phrases phase `315` as filling "the 12 crates that
  have none", but the current worktree shows `22` workspace crates with no
  files under `tests/`.
- Many of those crates are artifact/domain crates with large public surfaces
  but no integration-test smoke lane at all.
- The crates explicitly called out by the roadmap have only unit-style
  coverage today:
  - `arc-credentials`
  - `arc-policy`
  - `arc-store-sqlite`
  - `arc-a2a-adapter`
  - `arc-mcp-adapter`
  - `arc-mcp-edge`

## Boundaries

- Do not destabilize unrelated dirty worktree changes outside the phase `315`
  write set.
- Prefer narrow public-API tests over broad fixture duplication for the
  domain/artifact crates.
- Use deeper success/failure/edge-case tests only where the roadmap requires
  meaningful behavioral coverage rather than mere smoke coverage.

## Key Risks

- If the phase only adds trivial compile checks, it will technically satisfy
  the file-count requirement without materially improving regression coverage.
- If the integration tests depend on private helpers or `src/tests.rs`
  internals, they will not actually validate the exported crate contracts.
- If the protocol-facing exchange tests are too heavy, phase `315` will turn
  into infrastructure work and stall the rest of the milestone.

## Decision

Split the phase into three execution lanes:

1. Add smoke integration tests for the zero-test artifact/domain crates using
   public constructors, schema constants, validation methods, and serde
   roundtrips.
2. Add focused public-API integration tests for `arc-credentials`,
   `arc-policy`, and `arc-store-sqlite` covering success, failure, and edge
   conditions.
3. Add one real exchange lane each for `arc-a2a-adapter`, `arc-mcp-adapter`,
   and `arc-mcp-edge` so the protocol-facing crates have integration coverage
   that exercises their exported runtime contracts.
