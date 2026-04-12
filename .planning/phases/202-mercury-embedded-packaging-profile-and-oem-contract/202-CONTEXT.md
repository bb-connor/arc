# Phase 202: MERCURY Embedded Packaging Profile and OEM Contract - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define one machine-readable embedded OEM contract family over the validated
assurance and governance artifacts.

</domain>

<decisions>
## Implementation Decisions

### Contract Family
- add one embedded OEM profile contract
- add one embedded OEM package contract
- keep both contracts rooted in the existing assurance-suite and
  governance-workbench artifacts

### Surface Definitions
- encode one partner surface: `reviewer_workbench_embed`
- encode one SDK surface: `signed_artifact_bundle`
- bind the package to one reviewer population: `counterparty_review`

### Scope Guardrails
- avoid defining a generic SDK API family
- avoid multi-partner configuration breadth
- keep ARC generic and keep the new contract Mercury-specific

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury-core/src/assurance_suite.rs` already defines reviewer
  populations and artifact families
- `crates/arc-mercury-core/src/governance_workbench.rs` already defines
  fail-closed package validation patterns

### Established Patterns
- Mercury contract modules expose schema constants, enums, contract structs,
  `validate()` methods, and focused unit tests
- package artifacts use relative-path entries plus duplicate-kind rejection

</code_context>

<deferred>
## Deferred Ideas

- generic SDK method surfaces
- trust-network interoperability contracts
- multi-product shared-service contracts

</deferred>
