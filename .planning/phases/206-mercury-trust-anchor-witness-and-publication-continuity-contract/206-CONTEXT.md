# Phase 206: MERCURY Trust-Anchor, Witness, and Publication Continuity Contract - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define the machine-readable trust-network profile and package contracts that
bind one sponsor boundary, one trust anchor, one witness chain, and one
bounded artifact family back to the same Mercury proof chain.

</domain>

<decisions>
## Implementation Decisions

### Contract Shape
- add a dedicated `trust_network` core module instead of widening embedded-OEM
  or assurance contracts
- type the sponsor boundary, trust anchor, interoperability surface, witness
  steps, and artifact family explicitly
- require fail-closed validation and unique witness-step or artifact sets

### Boundary Preservation
- keep trust-network contracts layered on the embedded-OEM lane
- reference the embedded OEM package and manifest rather than redefining proof
  or reviewer truth
- preserve the same workflow boundary and `counterparty_review` reviewer lane

</decisions>

<code_context>
## Existing Code Insights

### Reusable Patterns
- `embedded_oem.rs` already shows the bounded package/profile pattern for a
  single Phase 5 expansion lane
- `assurance_suite.rs` and `governance_workbench.rs` already use explicit enum
  surfaces and validation guards

### Required Integration Points
- `crates/arc-mercury-core/src/lib.rs` must re-export the new trust-network
  types
- core tests should cover profile validation and package duplicate protection

</code_context>

<deferred>
## Deferred Ideas

- generic trust broker contracts
- multiple sponsor boundaries
- ARC-Wall-specific evidence types

</deferred>
