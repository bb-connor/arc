# Phase 197: MERCURY Assurance Suite Scope Lock and Reviewer Population Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze one assurance-suite path, its reviewer populations, owners, and explicit
non-goals before new assurance contracts or reviewer-facing export surfaces
land.

</domain>

<decisions>
## Implementation Decisions

### Selected Assurance Path
- choose one assurance-suite lane over the existing qualified workflow and
  governance package
- keep the lane rooted in the same controlled release, rollback, and inquiry
  workflow already frozen for Mercury
- avoid opening a generic portal, multiple reviewer programs, or OEM work

### Reviewer Populations and Owners
- reviewer populations stay bounded to `internal_review`, `auditor_review`,
  and `counterparty_review`
- reviewer ownership stays explicit as `mercury-assurance-review`
- support ownership stays explicit as `mercury-assurance-ops`

### Scope Guardrails
- defer additional reviewer populations, additional downstream/governance
  breadth, generic portal productization, OEM packaging, trust-network work,
  and deep runtime coupling
- keep one active Mercury expansion program at a time

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/main.rs` already exposes the dedicated Mercury app
  surface with bounded expansion commands
- `crates/arc-mercury/src/commands.rs` already generates supervised-live,
  downstream-review, and governance-workbench packages

### Established Patterns
- Mercury expansion lanes use dedicated docs plus one `export` and one
  `validate` command
- every bounded lane closes with one explicit decision artifact instead of
  implied future scope

### Integration Points
- assurance-suite work should layer on the existing governance-workbench
  package rather than creating a parallel truth path
- README, roadmap, GTM, and partner docs must all point to the same active
  bounded lane

</code_context>

<specifics>
## Specific Ideas

- keep the assurance lane reviewer-facing, not portal-facing
- keep the active path explicit in roadmap, GTM, partner, and pilot docs

</specifics>

<deferred>
## Deferred Ideas

- additional reviewer populations
- generic review portal breadth
- OEM packaging and trust-network work

</deferred>
