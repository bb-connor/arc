---
phase: 395-protocol-lifecycle-and-authority-surface-closure
milestone: v3.13
created: 2026-04-14
status: planned
requirements: [SURFACE-01, SURFACE-02, SURFACE-03, SURFACE-04]
---

# Phase 395 Context

## Why This Phase Exists

Phases `390` through `392` made the default A2A and ACP authority path
truthful, but the public protocol surfaces still oversell lifecycle parity:

- A2A still collapses `message/send` and `message/stream` into the same
  blocking path.
- ACP still exposes a narrower blocking JSON-RPC surface than some design and
  discovery language implies.
- Compatibility helpers remain public enough to be confused with authoritative
  receipt-bearing execution.
- Discovery still needs deterministic handling for duplicate names and similar
  outward publication collisions.

## Phase Boundary

This phase must make the public A2A/ACP story as truthful as the underlying
authority path.

It must:

- implement missing lifecycle behavior where practical
- narrow advertised surfaces where the richer lifecycle is still future
- isolate compatibility helpers so they cannot be confused with the default
  authoritative path
- remove silent or misleading discovery behavior around collisions

It must not:

- reopen the already-landed orchestrator substrate from phases `390-392`
- absorb final claim qualification, which belongs to phase `396`
