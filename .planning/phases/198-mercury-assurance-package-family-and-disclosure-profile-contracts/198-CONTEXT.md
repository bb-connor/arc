# Phase 198: MERCURY Assurance Package Family and Disclosure Profile Contracts - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Define one machine-readable assurance package family and disclosure-profile
contract for internal, auditor, and counterparty review over the existing
proof and governance model.

</domain>

<decisions>
## Implementation Decisions

### Package Family
- add one top-level assurance-suite package contract
- add one disclosure-profile contract, one review-package contract, and one
  investigation-package contract per reviewer population
- keep all package references rooted in existing proof, inquiry, reviewer,
  qualification, and governance artifacts

### Reviewer Semantics
- encode `internal_review`, `auditor_review`, and `counterparty_review` as
  typed reviewer populations
- keep verifier-equivalent review only where the disclosure profile supports
  it
- require fail-closed continuity for event IDs, source-record IDs, and
  idempotency keys in investigation packages

### Scope Guardrails
- do not redefine ARC truth
- do not imply a generic portal schema
- keep the package family limited to one reviewer-facing assurance lane

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury-core/src/downstream_review.rs` already defines bounded
  downstream assurance contracts
- `crates/arc-mercury-core/src/governance_workbench.rs` already defines one
  bounded governance package family

### Established Patterns
- Mercury contract modules validate schema IDs, required fields, fail-closed
  flags, and duplicate-role protection
- `crates/arc-mercury-core/src/lib.rs` re-exports typed contracts from
  dedicated modules

### Integration Points
- assurance contracts should sit in a dedicated `assurance_suite.rs` module
- the app surface should import the new contracts without mutating the older
  downstream package family

</code_context>

<specifics>
## Specific Ideas

- keep the assurance family parallel to governance/downstream patterns
- use one top-level package plus typed reviewer-population artifacts

</specifics>

<deferred>
## Deferred Ideas

- additional reviewer populations
- generic portal schemas
- non-Mercury package families

</deferred>
