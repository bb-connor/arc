---
phase: 392-fidelity-semantics-and-publication-gating
plan: 01
subsystem: bridge-fidelity
tags: [a2a, acp, cross-protocol, discovery, docs]
requirements:
  completed: [FID-01, FID-02, FID-03]
completed: 2026-04-14
verification:
  - cargo test -p arc-cross-protocol -p arc-a2a-edge -p arc-acp-edge
  - git diff --check -- crates/arc-cross-protocol/src/lib.rs crates/arc-a2a-edge/src/lib.rs crates/arc-acp-edge/src/lib.rs docs/protocols/CROSS-PROTOCOL-BRIDGING.md docs/protocols/EDGE-CRATE-SYMMETRY.md spec/BRIDGES.md .planning/PROJECT.md .planning/MILESTONES.md .planning/ROADMAP.md .planning/REQUIREMENTS.md .planning/STATE.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-CONTEXT.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-01-PLAN.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-01-SUMMARY.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-VERIFICATION.md
---

# Phase 392 Plan 01 Summary

Phase `392` is complete. Bridge publication now uses one shared truthful
fidelity model instead of edge-local heuristic labels.

## Accomplishments

- Extended `arc-cross-protocol` with shared semantic-hint extraction from
  `x-arc-publish`, `x-arc-approval-required`, `x-arc-streaming`,
  `x-arc-cancellation`, and `x-arc-partial-output`.
- Upgraded `arc-a2a-edge` to the shared `BridgeFidelity` contract and made
  unsupported skills disappear from Agent Card discovery by default.
- Upgraded `arc-acp-edge` to the same shared contract and made unsupported
  capabilities disappear from `session/list_capabilities`.
- Added targeted tests proving approval, cancellation, streaming, and
  partial-output semantics are classified through explicit rules rather than
  `has_side_effects` heuristics alone.
- Reconciled the protocol/spec docs so they now describe `Lossless`,
  `Adapted`, and `Unsupported` publication gating honestly.

## Verification

- `cargo test -p arc-cross-protocol -p arc-a2a-edge -p arc-acp-edge`
- `git diff --check -- crates/arc-cross-protocol/src/lib.rs crates/arc-a2a-edge/src/lib.rs crates/arc-acp-edge/src/lib.rs docs/protocols/CROSS-PROTOCOL-BRIDGING.md docs/protocols/EDGE-CRATE-SYMMETRY.md spec/BRIDGES.md .planning/PROJECT.md .planning/MILESTONES.md .planning/ROADMAP.md .planning/REQUIREMENTS.md .planning/STATE.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-CONTEXT.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-01-PLAN.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-01-SUMMARY.md .planning/phases/392-fidelity-semantics-and-publication-gating/392-VERIFICATION.md`

## Phase Status

Phase `392` is complete. The next queued closure lane is phase `393`
(`Ledger and Narrative Reconciliation`).
