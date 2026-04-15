---
phase: 390-generic-cross-protocol-orchestrator
milestone: v3.13
created: 2026-04-14
status: completed
---

# Phase 390 Context

## Goal

Implement a reusable `CrossProtocolOrchestrator` plus `CapabilityBridge` and
capability-envelope contracts so bridged protocol execution no longer depends
on bespoke edge-local authority flow.

## Current Reality

- `docs/protocols/CROSS-PROTOCOL-BRIDGING.md` and
  `docs/protocols/EDGE-CRATE-SYMMETRY.md` define the real target shape, but
  the generic orchestrator and bridge contracts are still only documented.
- `crates/arc-a2a-edge/src/lib.rs` and `crates/arc-acp-edge/src/lib.rs` now
  default to kernel-backed execution, but each crate still owns its own
  protocol parsing, capability handling, fidelity labeling, receipt metadata,
  and compatibility-path semantics.
- Both outward edge crates still expose their own local `BridgeFidelity`
  enums with the older `Full` / `Partial` / `Degraded` model instead of the
  doc-level `Lossless` / `Adapted { caveats }` / `Unsupported { reason }`
  contract.
- There is no shared cross-protocol capability reference or attenuation
  envelope, no shared hop-trace model, and no reusable orchestrator that can
  enforce bridge lineage across protocol boundaries.
- The lower-level runtime substrate already exists: `arc-kernel` exposes
  `ToolCallRequest` and evaluated tool-call responses, while `arc-http-core`
  and `arc-core` already carry the signed receipt primitives.

## Boundaries

- Keep this phase focused on the shared orchestration substrate, not the full
  repo-wide edge migration. Phase `391` owns the remaining edge unification and
  compatibility-path quarantine.
- Prefer one reusable crate-level home for cross-protocol runtime primitives so
  A2A and ACP can consume the same contracts without duplicating types again.
- Preserve the existing explicit passthrough compatibility helpers for now, but
  do not broaden or relabel them during this phase.
- Defer final publication-gating semantics, metadata caveats, and unsupported
  projection rules to phase `392` once the orchestrator exists.

## Key Risks

- If the orchestrator lands only as a doc-only or test-only abstraction, the
  milestone will still fail `ORCH-01` because the default runtime would remain
  split across edge-local paths.
- If capability propagation omits provenance, parent hash, or attenuation
  fields, phase `391` will still need bespoke authority logic and the bridge
  contract will not be credible.
- If receipt lineage remains edge-specific metadata rather than a shared trace
  model, the later claim-qualification work will still lack one honest
  cross-hop evidence story.
- If the new substrate is embedded inside one edge crate instead of a shared
  home, the repo will appear to have “an orchestrator” while still forcing new
  protocol bridges to copy authority logic.

## Relevant Runtime Seams

- `docs/protocols/CROSS-PROTOCOL-BRIDGING.md` defines the intended
  `CapabilityBridge`, `CrossProtocolCapabilityRef`,
  `CrossProtocolCapabilityEnvelope`, trace, and orchestrator contracts.
- `docs/protocols/EDGE-CRATE-SYMMETRY.md` defines the truthful fidelity model
  ARC should graduate to once the shared bridge runtime exists.
- `crates/arc-a2a-edge/src/lib.rs` shows the current kernel-backed A2A path and
  the remaining duplicated bridge-local fidelity and passthrough logic.
- `crates/arc-acp-edge/src/lib.rs` shows the current kernel-backed ACP path and
  the same duplicated bridge-local contracts.
- `crates/arc-kernel` and `crates/arc-http-core/src/receipt.rs` already
  provide the inner execution and signed receipt substrate that the
  orchestrator should compose instead of replacing.

## Decision

Start phase `390` with one shared-runtime slice:

1. Introduce a dedicated reusable cross-protocol runtime home with the core
   bridge contracts: discovery protocol, truthful fidelity type, capability
   reference, attenuation envelope, hop trace, and receipt-lineage metadata.
2. Implement `CrossProtocolOrchestrator` on top of the existing kernel tool-call
   and receipt primitives so it can accept a bridged request, enforce
   capability attenuation, dispatch through the kernel, and record bridge hop
   lineage.
3. Prove the substrate by routing one authoritative A2A path and one
   authoritative ACP path through the orchestrator without yet performing the
   full compatibility-path quarantine.
4. Add focused tests for capability propagation, fail-closed attenuation, and
   bridge-lineage receipt metadata so phase `391` starts from a real shared
   runtime instead of another design sketch.
