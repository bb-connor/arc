# Phase 189: MERCURY Downstream Review Scope Lock and Consumer Contract Freeze - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Freeze one downstream archive/review/case-management expansion path, its owner,
delivery contract, and explicit non-goals before connector or assurance code
lands.

</domain>

<decisions>
## Implementation Decisions

### Selected Consumer Path
- choose one case-management review consumer lane as the only active
  downstream expansion path
- define the consumer profile as `case_management_review`
- keep delivery bounded to a file-drop contract rather than bespoke API
  orchestration

### Ownership and Support Boundary
- destination ownership remains explicit on the partner case-management side
- MERCURY support ownership lives with `mercury-review-ops`
- delivery failure must fail closed and must not imply broader consumer
  coverage

### Scope Guardrails
- defer archive breadth, surveillance breadth, governance-workbench breadth,
  OMS/EMS or FIX coupling, OEM packaging, and trust-network work
- keep one active expansion program at a time

</decisions>

<canonical_refs>
## Canonical References

### Product and GTM
- `docs/mercury/IMPLEMENTATION_ROADMAP.md` — phase-4 expansion tracks and the
  downstream-consumer gate
- `docs/mercury/GO_TO_MARKET.md` — downstream-consumer priority before deep
  runtime coupling
- `docs/mercury/PARTNERSHIP_STRATEGY.md` — one active expansion path and near-term
  partner targets

### Existing evidence surfaces
- `docs/mercury/SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md` — current reviewer
  package and output shape
- `docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md` — prior bridge-close
  decision boundary

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/commands.rs` already generates the supervised-live
  qualification package
- `crates/arc-mercury/src/main.rs` already exposes proof, inquiry, pilot, and
  supervised-live product commands

### Integration Points
- the downstream lane should layer on the existing proof, inquiry, reviewer,
  and qualification artifacts rather than creating a second evidence path

</code_context>

<deferred>
## Deferred Ideas

- surveillance or archive-specific consumer lanes
- governance-workbench workflows
- OEM packaging and trust-network work

</deferred>
