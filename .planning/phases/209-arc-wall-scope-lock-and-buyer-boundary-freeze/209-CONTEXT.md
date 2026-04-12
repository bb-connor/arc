# Phase 209: ARC-Wall Scope Lock and Buyer Boundary Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze one ARC-Wall buyer motion, one control-owner boundary, one domain pair,
and one explicit set of non-goals before contract or guard work lands.

</domain>

<decisions>
## Implementation Decisions

### Selected ARC-Wall Path
- choose one ARC-Wall lane over the completed trust-network milestone
- keep the lane outside MERCURY as a companion product on ARC
- scope the buyer motion to `control_room_barrier_review`

### Selected Control Boundary
- control surface stays bounded to `tool_access_domain_boundary`
- source/protected domain pair stays bounded to `research -> execution`
- ownership stays explicit as `barrier-control-room` and `arc-wall-ops`

### Scope Guardrails
- defer additional buyer motions, generic barrier-platform breadth, folding
  ARC-Wall into MERCURY, and `E-026` platform hardening
- keep the first ARC-Wall claim limited to one denied cross-domain tool-access
  path

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- ARC already ships generic guards, receipts, checkpoints, and evidence export
- MERCURY already proves the separate app-on-ARC pattern this lane should
  follow

### Established Patterns
- bounded expansion lanes get dedicated docs, one export command, one validate
  command, and one explicit decision artifact
- product docs should point at one named path instead of a category of
  possible future products

</code_context>

<deferred>
## Deferred Ideas

- multiple buyer motions
- generic barrier-platform breadth
- MERCURY workflow evidence expansion
- multi-product platform hardening

</deferred>
