# Phase 404 Summary

Phase 404 landed authoritative deferred-task lifecycle mediation on both
outbound edge surfaces instead of keeping the older blocking-only model.

## What Shipped

- `arc-a2a-edge` now supports:
  - blocking `message/send`
  - deferred `message/stream`
  - follow-up `task/get`
  - follow-up `task/cancel`
- `arc-acp-edge` now supports:
  - blocking `tool/invoke`
  - deferred `tool/stream`
  - follow-up `tool/resume`
  - follow-up `tool/cancel`
- both edges now surface truthful lifecycle metadata for pending, cancelled,
  and terminal authoritative task states
- A2A/ACP bridge fidelity caveats were updated to describe the shipped
  deferred-task model instead of the older rejection-only behavior
- bridge/spec/protocol docs, qualification matrix language, and planning
  traceability were reconciled to the new runtime

## Requirements Closed

- `LIFE2-01`
- `LIFE2-02`
- `LIFE2-03`
