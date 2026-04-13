# Phase 277 Context

## Goal

Inventory the real `arc-kernel` panic surface, classify each literal `panic!`
site, and capture roadmap drift before any hardening work starts.

## Audit Finding

The roadmap premise is stale in one important way:

- all 22 literal `panic!` macros in `crates/arc-kernel/src` are inside
  `#[cfg(test)]` modules
- the production code paths in `crates/arc-kernel/src/*` contain no literal
  `panic!`, `unwrap()`, `expect()`, `unreachable!`, or `todo!` before the test
  modules begin

That means phase 277 is not discovering live production DoS vectors from
literal `panic!` calls. It is documenting a test-only panic surface and
establishing that the real external-input hardening work must focus on
transport and protocol error handling instead.

## Code Surface

- `crates/arc-kernel/src/transport.rs` owns length-prefixed canonical JSON
  framing and `AgentMessage` deserialization
- `crates/arc-kernel/src/lib.rs` owns session-operation routing, fail-closed
  policy evaluation, and typed `KernelError` results
- `crates/arc-kernel/src/payment.rs` contains payment-adapter tests with one
  remaining literal `panic!` assertion

## Baseline Evidence

- `rg -n "panic!\\(" crates/arc-kernel/src crates/arc-kernel/tests -g '!target'`
  returns exactly 22 hits, all in `src/*` test modules
- a full pre-test-module scan across every file in `crates/arc-kernel/src`
  returns zero production `panic!`, `unwrap()`, `expect()`, `unreachable!`, or
  `todo!` calls

## Requirement Mapping

- `HARDEN-01`: satisfied only by publishing the full 22-site audit with
  classification and rationale
- downstream phases must target the actual fail-closed boundary that exists
  today:
  transport framing, canonical JSON deserialization, and source hygiene inside
  `arc-kernel/src`

## Execution Direction

- publish a dedicated audit artifact listing all 22 literal `panic!` sites
- classify every site as invariant-violation vs input-dependent and tag it as
  `convert` or `harden`
- explicitly record that zero production literal panic sites were found, so
  phase 278 should focus on real structured error behavior instead of fictional
  panic conversions
