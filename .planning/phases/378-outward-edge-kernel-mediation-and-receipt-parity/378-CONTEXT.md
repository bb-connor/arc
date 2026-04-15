---
phase: 378-outward-edge-kernel-mediation-and-receipt-parity
milestone: v3.12
created: 2026-04-14
status: in_progress
---

# Phase 378 Context

## Goal

Make the outward `arc-a2a-edge` and `arc-acp-edge` crates tell the truth about
kernel mediation by providing explicit kernel-backed execution paths with
signed receipt output, while narrowing any remaining direct passthrough paths
to bounded compatibility helpers rather than the default trust story.

## Current Reality

- Both edge crates advertised kernel mediation and signed receipts at the crate
  level even though the live send/invoke paths only called
  `ToolServerConnection::invoke(...)` directly.
- `arc-a2a-edge` had no kernel execution API, no receipt-bearing response
  surface, and no way for downstream servers to distinguish a direct passthrough
  task from a kernel-governed one.
- `arc-acp-edge` had the same problem on `tool/invoke`, while
  `session/request_permission` was only a config-level preview rather than a
  capability-aware authorization check.
- The kernel already exposes a stable `ToolCallRequest` /
  `evaluate_tool_call_blocking` surface, so the missing piece is edge wiring,
  not a new kernel abstraction.

## Boundaries

- Keep the slice inside `arc-a2a-edge` and `arc-acp-edge`.
- Use explicit kernel-backed helper methods rather than redesigning the wire
  protocols or inventing a generic orchestrator layer.
- Preserve the legacy direct passthrough helpers for compatibility tests, but
  make them explicitly non-authoritative in docs/comments.
- Do not broaden into repo-wide doc reconciliation; that belongs to phase
  `380`.

## Decision

Start phase `378` with one bounded execution slice:

1. Add explicit kernel-backed send/invoke helpers in both edge crates that
   build `ToolCallRequest`, call the kernel, and attach signed receipt metadata
   to the returned A2A/ACP response objects.
2. Add capability-aware ACP permission preview using caller-provided capability
   context so the permission surface no longer claims config-only behavior is
   kernel mediation.
3. Narrow crate-level and method-level comments so the direct passthrough APIs
   are clearly described as compatibility helpers rather than the authoritative
   ARC trust path.
