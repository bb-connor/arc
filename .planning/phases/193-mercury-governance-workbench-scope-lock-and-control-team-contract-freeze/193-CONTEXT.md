# Phase 193: MERCURY Governance Workbench Scope Lock and Control-Team Contract Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze one governance-workbench workflow path, its owners, review audiences,
and explicit non-goals before new governance contracts or workflow controls
land.

</domain>

<decisions>
## Implementation Decisions

### Selected Governance Path
- choose one `change_review_release_control` workflow as the only active
  governance-workbench path
- keep the path rooted in the same controlled release, rollback, and inquiry
  workflow already frozen for Mercury
- avoid opening multiple governance, connector, or orchestration programs

### Ownership and Review Boundary
- workflow ownership stays explicit as `mercury-workflow-owner`
- control-team ownership stays explicit as `mercury-control-review`
- governance review remains bounded to workflow-owner and control-team
  packages

### Scope Guardrails
- defer additional governance breadth, additional downstream consumers,
  generic orchestration, OMS/EMS or FIX coupling, OEM packaging, and
  trust-network work
- keep one active Mercury expansion program at a time

</decisions>

<canonical_refs>
## Canonical References

### Product and GTM
- `docs/mercury/IMPLEMENTATION_ROADMAP.md` — phase-4 expansion tracks and the
  currently activated path
- `docs/mercury/GO_TO_MARKET.md` — post-bridge expansion sequencing
- `docs/mercury/PARTNERSHIP_STRATEGY.md` — one active expansion path and
  partner priority order

### Existing Mercury boundary
- `docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md` — prior downstream
  next-step boundary
- `docs/mercury/README.md` — canonical Mercury suite map and status framing

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/main.rs` already exposes the dedicated Mercury app
  surface
- `crates/arc-mercury/src/commands.rs` already generates supervised-live
  qualification and downstream review packages

### Integration Points
- governance workbench should layer on the same proof, inquiry, reviewer, and
  qualification artifacts rather than creating a parallel truth path

</code_context>

<deferred>
## Deferred Ideas

- multiple governance workflow families
- additional downstream connectors
- generic workflow routing or task orchestration
- OEM packaging and trust-network work

</deferred>
