---
phase: 390-generic-cross-protocol-orchestrator
status: passed
completed: 2026-04-14
---

# Phase 390 Verification

## Shared Runtime Verification

- `cargo test -p arc-cross-protocol`

This suite proves the new shared substrate can:

- project a stable cross-protocol capability reference and envelope
- preserve bridge trace lineage and receipt references
- fail closed when the bridged target is out of scope

## Edge Adoption Verification

- `cargo test -p arc-a2a-edge -p arc-acp-edge`

These suites prove the default authoritative A2A and ACP execution paths now
run through `CrossProtocolOrchestrator`, emit orchestrator-labeled metadata,
and keep receipt-bearing allow/deny behavior intact.
