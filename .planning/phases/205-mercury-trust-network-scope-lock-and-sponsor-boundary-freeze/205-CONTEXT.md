# Phase 205: MERCURY Trust-Network Scope Lock and Sponsor Boundary Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze one trust-network path, one sponsor boundary, one trust anchor, one
interoperability surface, one reviewer population, and explicit non-goals
before new trust-network contracts or sharing exports land.

</domain>

<decisions>
## Implementation Decisions

### Selected Trust-Network Path
- choose one trust-network lane over the completed embedded-OEM lane
- keep the lane rooted in the same controlled release, rollback, and inquiry
  workflow already frozen for Mercury
- avoid opening a generic trust broker, multi-network witness service,
  ARC-Wall, or multi-product platform work

### Sponsor Boundary and Owners
- sponsor boundary stays bounded to `counterparty_review_exchange`
- trust anchor stays bounded to `arc_checkpoint_witness_chain`
- interoperability surface stays bounded to `proof_inquiry_bundle_exchange`
- reviewer population stays bounded to `counterparty_review`
- ownership stays explicit as `counterparty-review-network-sponsor` and
  `mercury-trust-network-ops`

### Scope Guardrails
- defer additional sponsor boundaries, multi-network witness breadth, generic
  ecosystem interoperability, ARC-Wall, and multi-product hardening
- keep one active Mercury expansion program at a time

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/main.rs` already exposes the dedicated Mercury app
  surface with bounded expansion commands
- `crates/arc-mercury/src/commands.rs` already generates supervised-live,
  downstream-review, governance-workbench, assurance-suite, and embedded-OEM
  packages

### Established Patterns
- Mercury expansion lanes use dedicated docs plus one `export` and one
  `validate` command
- every bounded lane closes with one explicit decision artifact instead of
  implied future scope

### Integration Points
- trust-network work should layer on the embedded-OEM output rather than
  creating a parallel truth path
- roadmap, GTM, partnership, README, and technical docs must all point to the
  same bounded sponsor boundary

</code_context>

<specifics>
## Specific Ideas

- keep the trust-network lane sponsor-facing, not ecosystem-platform-facing
- make the interop surface a manifest plus bounded shared bundle, not a
  generic trust service API

</specifics>

<deferred>
## Deferred Ideas

- additional sponsor boundaries
- multi-network trust-broker or witness services
- generic ecosystem interoperability infrastructure
- ARC-Wall
- multi-product platform hardening

</deferred>
