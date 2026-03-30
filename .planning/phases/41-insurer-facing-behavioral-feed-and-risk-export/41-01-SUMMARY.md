---
phase: 41-insurer-facing-behavioral-feed-and-risk-export
plan: 01
subsystem: behavioral-feed-contract
tags:
  - risk
  - export
  - reporting
requires: []
provides:
  - A stable behavioral-feed query and report schema for external risk consumers
  - A signed export envelope reusable for behavioral feed delivery
  - Protocol text describing the behavioral feed as a truthful evidence export
key-files:
  modified:
    - crates/arc-kernel/src/operator_report.rs
    - crates/arc-core/src/receipt.rs
    - spec/PROTOCOL.md
requirements-completed:
  - RISK-01
completed: 2026-03-26
---

# Phase 41 Plan 01 Summary

Phase 41-01 defined the insurer-facing behavioral feed as a typed signed
export instead of a loose serialization of existing operator reports.

## Accomplishments

- added a stable `arc.behavioral-feed.v1` contract with explicit filters,
  privacy/export boundary metadata, decision summaries, settlement summaries,
  governed-action summaries, optional reputation summaries, and receipt detail
  rows
- added a reusable signed export envelope in `arc-core` so behavioral feeds can
  be signed and verified like other ARC evidence artifacts
- documented the new trust-control behavioral-feed endpoint in the protocol
  contract

## Verification

- `cargo test -p arc-kernel operator_report`
