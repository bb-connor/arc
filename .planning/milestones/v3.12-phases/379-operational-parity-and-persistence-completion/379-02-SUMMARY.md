---
phase: 379-operational-parity-and-persistence-completion
plan: 02
subsystem: runtime
tags: [tower, kubernetes, body-binding, capability-validation]
requirements:
  completed: [OPER-02]
  remaining: [OPER-03]
completed: 2026-04-14
verification:
  - cargo test -p arc-tower
---

# Phase 379 Plan 02 Summary

`arc-tower` now binds raw request bytes into evaluation and replays the same
bytes downstream on the supported replayable body path. The Kubernetes
capability-validation slice remained active after this plan and was closed in
follow-on plan `379-03`.

## Accomplishments

- Narrowed `ArcService` to supported replayable request-body types and made the
  runtime bind `body_hash` / `body_length` from the exact buffered bytes it
  forwards downstream.
- Added focused `arc-tower` tests for raw-byte hashing/replay and updated the
  Axum/Tower integration coverage to stay truthful about the supported body
  path.
- `arc-tower` verification stayed scoped to the middleware/body-binding lane;
  Kubernetes trust-anchor validation moved into dedicated follow-on plan
  `379-03`.

## Verification

- `cargo test -p arc-tower`

## Phase Status

Plan `379-02` completes `OPER-02`. Phase `379` remained active for the
Kubernetes capability-validation slice (`OPER-03`), which is captured in
`379-03`.
