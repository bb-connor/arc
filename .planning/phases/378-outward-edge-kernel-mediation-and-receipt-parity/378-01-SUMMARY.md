---
phase: 378
plan: 01
title: Explicit Kernel-Backed Edge Execution Paths
created: 2026-04-14
status: completed
---

# Plan 378-01 Summary

Phase `378` closed the most direct outward-edge credibility gap: `arc-a2a-edge`
and `arc-acp-edge` now expose explicit kernel-backed execution APIs that emit
signed receipt metadata, and the remaining direct passthrough helpers are
documented as bounded compatibility paths rather than the default trust story.

## What Landed

- `arc-a2a-edge` now exposes kernel-backed send and JSON-RPC helpers that
  convert `SendMessage` requests into `ToolCallRequest` values and return
  receipt-bearing task responses.
- `arc-acp-edge` now exposes kernel-backed invocation and JSON-RPC helpers with
  the same receipt-bearing contract.
- ACP permission preview gained a capability-aware path so the outward ACP
  surface no longer implies config-only permission previews are kernel
  mediation.
- Crate-level and method-level comments now distinguish explicit
  kernel-mediated helpers from direct passthrough compatibility helpers.

## Files Touched

- `crates/arc-a2a-edge/src/lib.rs`
- `crates/arc-acp-edge/src/lib.rs`

## Validation

- `cargo test -p arc-a2a-edge`
- `cargo test -p arc-acp-edge`

## Outcome

The outward A2A/ACP edge crates now have a real, receipt-bearing kernel path.
The remaining repo-wide truth reconciliation is phase `380`, not a blocker on
moving the runtime-hardening chain into phase `379`.
