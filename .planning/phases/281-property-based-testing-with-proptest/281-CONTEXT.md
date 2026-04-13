# Phase 281 Context

## Goal

Add property-based test coverage to the shipped ARC crates for the exact
invariants the roadmap calls out: Ed25519 sign/verify roundtrips, monetary
budget arithmetic, and capability attenuation subset relationships.

## Existing Surface

- `formal/diff-tests` already uses `proptest`, but it is isolated from the main
  shipped crates and does not cover the three `QUAL-01` through `QUAL-03`
  requirements
- `crates/arc-core` owns the cryptographic and capability primitives:
  `crypto.rs`, `capability.rs`, and the `validate_attenuation` helpers
- `crates/arc-kernel/src/budget_store.rs` owns the bounded monetary accounting
  and fail-closed overflow/underflow behavior that `QUAL-02` actually depends on

## Important Constraint

The roadmap says "monetary arithmetic", but the real shipped arithmetic surface
is the budget store, not a generic math utility. The property tests should
target `InMemoryBudgetStore` so the suite proves exact integer accounting,
overflow denial, and underflow protection on the real kernel path.

## Requirement Mapping

- `QUAL-01`: property tests in `arc-core` for arbitrary byte payload Ed25519
  sign/verify roundtrips
- `QUAL-02`: property tests in `arc-kernel` for budget charge, reduction,
  reversal, and overflow/underflow fail-closed behavior
- `QUAL-03`: property tests in `arc-core` for attenuation-derived child scopes
  remaining valid subsets of parent scopes

## Execution Direction

- add `proptest` as an explicit dev-dependency in the crates that need it
- keep the tests crate-owned and focused:
  - `crates/arc-core/tests/` for crypto and attenuation
  - `crates/arc-kernel/tests/` for budget invariants
- use a shared `PROPTEST_CASES` env override with a `256` case default so CI
  and local runs stay deterministic and legible
