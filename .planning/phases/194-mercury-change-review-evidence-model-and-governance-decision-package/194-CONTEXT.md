# Phase 194: MERCURY Change-Review Evidence Model and Governance Decision Package - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define one machine-readable governance decision package and one bounded
audience-specific review-package family over the existing proof, inquiry,
reviewer, and supervised-live qualification artifacts.

</domain>

<decisions>
## Implementation Decisions

### Contract Shape
- add one governance decision package contract in `arc-mercury-core`
- add one governance review package contract for workflow-owner and
  control-team audiences
- keep both contracts as wrappers over existing Mercury artifacts

### Governance Semantics
- encode change classes for model, prompt, policy, parameter, and release
  review
- require explicit fail-closed control-state posture
- reject empty owners or duplicate change classes

### Claude's Discretion
- exact field naming inside the governance contracts
- exact packaging shape for decision vs review artifacts

</decisions>

<canonical_refs>
## Canonical References

### Technical constraints
- `docs/mercury/TECHNICAL_ARCHITECTURE.md` — governance packaging must reuse
  the same proof and inquiry contracts
- `docs/mercury/GOVERNANCE_WORKBENCH.md` — selected path, owners, and
  non-goals

### Existing artifacts
- `crates/arc-mercury-core/src/proof_package.rs` — proof and inquiry package
  contracts
- `crates/arc-mercury/src/commands.rs` — supervised-live qualification export

</canonical_refs>

<code_context>
## Existing Code Insights

- supervised-live qualification already emits the proof package, reviewer
  package, and qualification report the governance package must reference
- downstream review already demonstrates the pattern of wrapping existing
  Mercury artifacts without redefining ARC truth

</code_context>

<deferred>
## Deferred Ideas

- multiple governance decision profiles
- generic workflow or ticket orchestration
- connector-specific governance packages

</deferred>
