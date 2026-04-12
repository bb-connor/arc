# Phase 200: MERCURY Assurance Validation, Reviewer Operations, and Expansion Decision - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Validate the assurance-suite lane end to end, document reviewer operations and
support controls, and close the milestone with one explicit next-step
decision.

</domain>

<decisions>
## Implementation Decisions

### Validation Bundle
- add a dedicated `mercury assurance-suite validate` command
- generate the assurance validation corpus by calling the bounded export path
- emit one validation report and one explicit decision artifact

### Operating Model
- publish reviewer-owner, support-owner, failure-recovery, and fail-closed
  operating guidance in dedicated assurance docs
- keep the validation claim narrow and reviewer-facing

### Scope Guardrails
- close the milestone with one explicit `proceed_assurance_suite_only`
  decision
- defer broader reviewer populations, portal breadth, additional
  downstream/governance lanes, OEM packaging, and trust-network work

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- the bounded export path in `crates/arc-mercury/src/commands.rs` can feed the
  validation path directly
- existing governance/downstream validation commands already emit one report
  and one decision artifact

### Established Patterns
- validation packages live under `target/` and include both the exported lane
  and the close-out decision
- milestone closeout requires docs, validation commands, and explicit next-step
  boundary all to agree

### Integration Points
- the assurance validation command should mirror the older Mercury lane
  patterns rather than inventing a new close-out model
- the planning ledger should close `v2.47` only after validation artifacts
  exist on disk

</code_context>

<specifics>
## Specific Ideas

- keep the decision explicit and narrow
- make the validation package directly reviewable by engineering, product, and
  partner reviewers

</specifics>

<deferred>
## Deferred Ideas

- broader Phase 5 work
- generic portal or OEM packaging

</deferred>
