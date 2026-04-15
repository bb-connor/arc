---
phase: 390-generic-cross-protocol-orchestrator
plan: 01
subsystem: cross-protocol-runtime
tags: [a2a, acp, orchestration, bridge-lineage, receipts]
requirements:
  completed: [ORCH-01, ORCH-02, ORCH-03]
completed: 2026-04-14
verification:
  - cargo test -p arc-cross-protocol -p arc-a2a-edge -p arc-acp-edge
---

# Phase 390 Plan 01 Summary

Phase `390` is complete. ARC now has a real shared cross-protocol runtime
substrate instead of leaving orchestration as docs plus duplicated edge-local
bridge logic.

## Accomplishments

- Added `crates/arc-cross-protocol` with reusable `DiscoveryProtocol`,
  truthful `BridgeFidelity`, `CrossProtocolCapabilityRef`,
  `CrossProtocolCapabilityEnvelope`, `CrossProtocolTraceContext`,
  `CapabilityBridge`, and `CrossProtocolOrchestrator` contracts.
- Implemented orchestrator-backed execution over the existing kernel tool-call
  surface, including capability-reference extraction/injection, attenuated
  scope projection, fail-closed out-of-scope handling, and receipt-lineage
  metadata with `traceId`, `bridgeId`, and `receiptRef`.
- Moved the default authoritative A2A execution path in
  `crates/arc-a2a-edge/src/lib.rs` onto `CrossProtocolOrchestrator`.
- Moved the default authoritative ACP invocation path in
  `crates/arc-acp-edge/src/lib.rs` onto the same shared orchestrator path.
- Updated edge metadata expectations so orchestrated runtime calls are clearly
  labeled as `cross_protocol_orchestrator` rather than plain edge-local kernel
  dispatch.

## Verification

- `cargo test -p arc-cross-protocol -p arc-a2a-edge -p arc-acp-edge`

## Phase Status

Phase `390` is complete. The next queued closure lane is phase `391`
(`Authoritative Edge Unification`), which now builds on a real shared
orchestration substrate instead of a proposal-only architecture.
