---
phase: 395-protocol-lifecycle-and-authority-surface-closure
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 395 Summary

## Outcome

The public A2A and ACP surfaces now advertise only the lifecycle and authority
semantics they actually ship.

- A2A authoritative execution remains receipt-bearing and blocking by default;
  `message/stream` is explicitly rejected on the authoritative surface and
  compatibility entrypoints are marked as non-authoritative migration helpers.
- ACP authoritative execution remains preview + blocking invoke only;
  unsupported lifecycle methods are rejected explicitly on both authoritative
  and compatibility surfaces.
- Discovery collisions are handled deterministically and truthfully instead of
  silently shadowing one surface with another.

## Requirements Closed

- `SURFACE-01`
- `SURFACE-02`
- `SURFACE-03`
- `SURFACE-04`
