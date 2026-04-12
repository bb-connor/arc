# Phase 201: MERCURY Embedded OEM Scope Lock and Partner Boundary Freeze - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Freeze one embedded OEM path, its partner surface, its bounded SDK surface,
its owners, and its explicit non-goals before new OEM contracts or partner
bundle exports land.

</domain>

<decisions>
## Implementation Decisions

### Selected Embedded Path
- choose one embedded OEM lane over the existing assurance-suite and
  governance-workbench artifacts
- keep the lane rooted in the same controlled release, rollback, and inquiry
  workflow already frozen for Mercury
- avoid opening a generic SDK platform, multi-partner OEM breadth, trust
  services, or ARC-Wall work

### Partner Surface and Owners
- partner surface stays bounded to `reviewer_workbench_embed`
- SDK surface stays bounded to `signed_artifact_bundle`
- reviewer population stays bounded to `counterparty_review`
- ownership stays explicit as `partner-review-platform-owner` and
  `mercury-embedded-ops`

### Scope Guardrails
- defer additional partner surfaces, generic SDK breadth, multi-partner OEM
  programs, trust-network services, and ARC-Wall
- keep one active Mercury expansion program at a time

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/main.rs` already exposes the dedicated Mercury app
  surface with bounded expansion commands
- `crates/arc-mercury/src/commands.rs` already generates supervised-live,
  downstream-review, governance-workbench, and assurance-suite packages

### Established Patterns
- Mercury expansion lanes use dedicated docs plus one `export` and one
  `validate` command
- every bounded lane closes with one explicit decision artifact instead of
  implied future scope

### Integration Points
- embedded OEM work should layer on the assurance-suite output rather than
  creating a parallel truth path
- roadmap, GTM, architecture, investor, and partnership docs must all point to
  the same active bounded lane

</code_context>

<specifics>
## Specific Ideas

- keep the OEM lane partner-facing, not platform-facing
- make the SDK surface a manifest plus bundle contract, not a broad client SDK

</specifics>

<deferred>
## Deferred Ideas

- additional partner surfaces
- multi-partner OEM breadth
- generic SDK platform work
- trust-network services
- ARC-Wall

</deferred>
