# Phase 195: MERCURY Release, Rollback, Approval, and Exception Workflow Controls - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Implement one bounded governance-workbench export path for approval, release,
rollback, and exception workflow control over the new governance package
contracts.

</domain>

<decisions>
## Implementation Decisions

### CLI Surface
- add one `mercury governance-workbench` command family in the dedicated
  Mercury app
- keep the command rooted in the existing supervised-live qualification
  output rather than introducing a new truth path

### Export Shape
- write one governance decision package
- write one bounded control-state file
- write workflow-owner and control-team review packages over audience-specific
  inquiry exports

### Regression Boundary
- add tests proving the governance export stays rooted in the same Mercury
  proof chain and bounded docs

</decisions>

<canonical_refs>
## Canonical References

### Contract and operator boundary
- `crates/arc-mercury-core/src/governance_workbench.rs` — governance contract
  types and validation rules
- `docs/mercury/GOVERNANCE_WORKBENCH.md` — selected path, owners, and
  supported surface

### Existing export pattern
- `crates/arc-mercury/src/commands.rs` — supervised-live qualification and
  downstream review export helpers
- `crates/arc-mercury/tests/cli.rs` — existing CLI regression style

</canonical_refs>

<code_context>
## Existing Code Insights

- downstream review already demonstrates how to derive audience-specific
  exports from the same proof package
- the dedicated `arc-mercury` app surface preserves the ARC generic / Mercury
  opinionated boundary during new workflow additions

</code_context>

<deferred>
## Deferred Ideas

- multi-workflow governance orchestration
- richer UI or case-management surfaces
- runtime coupling into OMS/EMS or FIX systems

</deferred>
