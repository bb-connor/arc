# Phase 199: MERCURY Reviewer Export Surfaces and Investigation Packaging - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Implement one bounded reviewer-facing assurance lane for package generation and
investigation-ready export over the same evidence and disclosure boundary.

</domain>

<decisions>
## Implementation Decisions

### Export Surface
- add a dedicated `mercury assurance-suite export` command
- build the assurance lane on top of the existing governance-workbench export
- emit one top-level assurance-suite package plus reviewer-population folders

### Reviewer and Investigation Artifacts
- generate disclosure profiles, inquiry packages, review packages, and
  investigation packages for internal, auditor, and counterparty review
- keep investigation packages anchored to workflow IDs, event IDs,
  source-record IDs, and idempotency keys from the same proof package
- preserve reviewer-population-specific verifier-equivalence semantics

### Scope Guardrails
- keep the surface bounded to one reviewer-family lane
- do not imply a generic review portal
- regression-test the app surface instead of relying on doc claims

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-mercury/src/commands.rs` already exports downstream-review and
  governance-workbench lanes from the same proof chain
- `crates/arc-mercury/tests/cli.rs` already covers bounded Mercury commands
  with repo-native binary execution

### Established Patterns
- Mercury app commands pair one `export` path with one `validate` path
- export summaries and validation reports are serialized to JSON and can be
  emitted to stdout for tests

### Integration Points
- the new assurance lane should become a top-level `AssuranceSuite` branch in
  `crates/arc-mercury/src/main.rs`
- the README and suite map should surface the assurance command alongside the
  older downstream and governance lanes

</code_context>

<specifics>
## Specific Ideas

- keep reviewer-population directories explicit on disk
- keep investigation packages populated from proof-package metadata, not
  handwritten placeholders

</specifics>

<deferred>
## Deferred Ideas

- generic reviewer UI or portal work
- population-specific bespoke tools beyond bounded package export

</deferred>
