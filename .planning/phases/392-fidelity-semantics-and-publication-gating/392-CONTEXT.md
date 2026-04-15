---
phase: 392-fidelity-semantics-and-publication-gating
milestone: v3.13
created: 2026-04-14
status: complete
requirements: [FID-01, FID-02, FID-03]
---

# Phase 392 Context

## Why This Phase Exists

Phases `390` and `391` closed the generic-orchestrator and split-authority
gaps, but bridge publication was still using edge-local heuristic labels
(`Full`, `Partial`, `Degraded`) that were too vague to support truthful
cross-protocol claims.

The remaining gap was specifically semantic honesty:

- unsupported projections still needed to be suppressed from discovery rather
  than merely labeled
- streaming, cancellation, permission, and partial-output behavior needed to
  be classified explicitly instead of inferred from side effects alone
- outward docs/specs needed to match the runtime behavior

## Required Outcome

ARC must classify bridge publication with one shared contract:

- `Lossless`
- `Adapted { caveats }`
- `Unsupported { reason }`

That contract must drive actual A2A/ACP discovery behavior, not just comments
or future architecture notes.
