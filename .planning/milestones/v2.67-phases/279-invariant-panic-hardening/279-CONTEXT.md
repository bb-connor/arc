# Phase 279 Context

## Goal

Remove the remaining literal `panic!` macros from `arc-kernel/src` now that the
audit has proven they are all test-only invariant assertions.

## Audit Carry-Forward

- production `arc-kernel` code is already free of literal panic macros
- all 22 literal `panic!` sites live in `#[cfg(test)]` modules inside
  `crates/arc-kernel/src/transport.rs`, `payment.rs`, and `lib.rs`

The value of phase 279 is source hygiene:

- future panic scans should only flag real regressions
- the milestone promise "no panic! macro remains in arc-kernel source" should
  become true without pretending these test assertions were production DoS
  vectors

## Execution Direction

- replace each literal `panic!` assertion with explicit `assert!`,
  `matches!`, or `Option`-based extraction
- keep test intent unchanged; only the assertion style should change
- verify `rg -n "panic!\\(" crates/arc-kernel/src` returns no results
