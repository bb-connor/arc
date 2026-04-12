# Phase 214: Cross-Product Governance, Release, and Trust-Material Operating Model - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define one release, incident, and trust-material operating model for the
current MERCURY plus ARC-Wall product set without creating a merged shell.

</domain>

<decisions>
## Implementation Decisions

### Selected Control Owners
- shared release owner: `arc-release-control`
- shared trust-material owner: `arc-key-custody`
- MERCURY product owners: `mercury-platform-owner` and `mercury-product-ops`
- ARC-Wall product owners: `barrier-control-room` and `arc-wall-ops`

### Selected Shared Controls
- one release-approval matrix across substrate versus product-only changes
- one incident escalation path from product support to shared ARC control
- one shared trust-material boundary for receipt and checkpoint keys

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- the new product-surface contract module can encode governance and trust-
  material boundaries directly beside the shared-service catalog
- the new CLI surface can export governance data without introducing a new app

### Established Patterns
- cross-product controls should live in ARC generic control-plane code
- operator docs must make fail-closed rules explicit before backlog work starts

</code_context>

<deferred>
## Deferred Ideas

- merged product release shell
- generic platform console ownership
- new buyer or product lanes

</deferred>
