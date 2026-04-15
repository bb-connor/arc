---
phase: 400-lifecycle-equivalent-protocol-mediation
plan: 01
status: complete
created: 2026-04-14
updated: 2026-04-14
---

# Phase 400 Summary

## Outcome

The public A2A and ACP surfaces now make only the lifecycle/authority claims
they can actually defend.

- A2A authoritative mediation stays blocking and receipt-bearing by default,
  and explicitly rejects unsupported `message/stream` on the authoritative
  surface.
- ACP authoritative mediation stays preview + blocking invoke, and explicitly
  rejects unsupported lifecycle methods instead of implying more.
- Compatibility helpers remain clearly non-authoritative and are gated away
  from the default/public claim surface.

## Requirements Closed

- `LIFE-01`
- `LIFE-02`
- `LIFE-03`
