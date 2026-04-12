# Phase 190: MERCURY Downstream Distribution Package and Delivery Contract - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Define one machine-readable downstream distribution profile over the existing
proof, inquiry, reviewer, and qualification artifacts, including delivery and
acknowledgement semantics.

</domain>

<decisions>
## Implementation Decisions

### Contract Shape
- add one downstream review package contract in `arc-mercury-core`
- add one assurance-package contract for internal and external review audiences
- keep both contracts as wrappers over existing proof and inquiry artifacts

### Delivery Semantics
- require acknowledgement and fail-closed delivery semantics
- model the selected transport as a bounded file-drop path
- generate a consumer manifest and delivery acknowledgement as explicit export
  outputs

### Claude's Discretion
- exact field naming inside the package contracts
- exact summary output shape for CLI export

</decisions>

<canonical_refs>
## Canonical References

### Technical constraints
- `docs/mercury/TECHNICAL_ARCHITECTURE.md` — downstream distribution must
  reuse the same proof and inquiry contracts
- `docs/mercury/DOWNSTREAM_REVIEW_DISTRIBUTION.md` — selected consumer profile,
  owners, and non-goals

### Existing artifacts
- `crates/arc-mercury-core/src/proof_package.rs` — proof and inquiry package
  contracts
- `crates/arc-mercury/src/commands.rs` — supervised-live qualification export

</canonical_refs>

<code_context>
## Existing Code Insights

- supervised-live qualification already emits the reviewer package and
  qualification report the downstream package must reference
- inquiry export can be reused to derive internal and external assurance views

</code_context>

<deferred>
## Deferred Ideas

- package verification outside the bounded downstream lane
- multiple consumer profiles in the same contract

</deferred>
