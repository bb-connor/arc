# Phase 191: MERCURY Review-System Connector and Assurance Export Path - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Implement one bounded export path into the selected downstream review consumer
and add internal/external assurance packaging around the same underlying
artifacts.

</domain>

<decisions>
## Implementation Decisions

### CLI Surface
- add `mercury downstream-review export --output ...`
- keep the command repo-native and deterministic like the supervised-live
  qualification flow

### Assurance Packaging
- generate one internal assurance package and one external assurance package
- derive both from the same supervised-live proof package
- keep reviewer and qualification artifacts shared between the two views

### Consumer Drop
- stage the external-facing handoff into one consumer-drop directory
- include a manifest and acknowledgement in that drop

</decisions>

<canonical_refs>
## Canonical References

### Contract and delivery docs
- `docs/mercury/DOWNSTREAM_REVIEW_DISTRIBUTION.md` — selected lane and
  non-goals
- `docs/mercury/DOWNSTREAM_REVIEW_OPERATIONS.md` — fail-closed and support rules

### Existing code
- `crates/arc-mercury/src/main.rs` — CLI surface
- `crates/arc-mercury/src/commands.rs` — existing qualification and export code
- `crates/arc-mercury/tests/cli.rs` — CLI regression pattern

</canonical_refs>

<code_context>
## Existing Code Insights

- `cmd_mercury_supervised_live_qualify` already provides the qualification
  artifacts the downstream lane should wrap
- CLI tests already validate repo-native output directories and JSON summaries

</code_context>

<deferred>
## Deferred Ideas

- direct partner API integrations
- additional downstream consumer profiles

</deferred>
