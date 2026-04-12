# Phase 213: Shared Service Boundary Review and Product Ownership Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze what stays ARC-owned versus product-owned across MERCURY and ARC-Wall
before the hardening lane grows into a merged shell or another buyer path.

</domain>

<decisions>
## Implementation Decisions

### Selected Hardening Lane
- execute the repo's `E-026` step after the first ARC-Wall lane
- keep MERCURY and ARC-Wall as separate apps on ARC
- put machine-readable cross-product boundary contracts in generic ARC control-
  plane code rather than in either product crate

### Selected Shared Services
- receipt truth
- checkpoint publication
- offline evidence export
- proof verification

### Scope Guardrails
- defer new MERCURY workflow lanes
- defer additional ARC-Wall buyer motions
- defer a merged product shell or generic console

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc-control-plane` already owns generic offline evidence export support
- `arc-cli` already exposes generic admin and validation commands
- MERCURY and ARC-Wall already prove the separate app-on-ARC pattern

### Established Patterns
- bounded lanes get machine-readable contracts, one export command, one
  validate command, and one explicit decision artifact
- product docs should point to one active path and explicit non-goals

</code_context>

<deferred>
## Deferred Ideas

- merged portfolio shell
- generic platform console
- new buyer motion or connector lanes during this milestone

</deferred>
