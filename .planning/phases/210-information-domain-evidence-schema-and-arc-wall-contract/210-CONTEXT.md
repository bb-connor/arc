# Phase 210: Information-Domain Evidence Schema and ARC-Wall Contract - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define one machine-readable ARC-Wall contract family for information-domain
tool-access evidence, rooted in ARC receipt and evidence-export truth.

</domain>

<decisions>
## Implementation Decisions

### Contract Family
- create a dedicated `arc-wall-core` crate rather than layering ARC-Wall into
  `arc-mercury-core`
- define typed contracts for the control profile, policy snapshot,
  authorization context, guard outcome, denied-access record, buyer-review
  package, and top-level control package

### Guardrail
- keep the contract family limited to one buyer motion and one domain pair
- validate every contract fail-closed and prevent duplicate artifact or tool
  definitions

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- the Mercury core crates already establish the pattern for typed lane-specific
  package contracts and validation
- ARC receipts and evidence export remain generic and reusable without ARC-Wall
  changing them

</code_context>

<deferred>
## Deferred Ideas

- broader policy expression languages
- multiple buyer package families
- generic platform-hardening abstractions

</deferred>
