# Phase 179: GSD Health, Roadmap Parsing, and Assurance Artifact Backfill - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Restore trustworthy GSD planning output for the active `v2.42` ladder and
backfill the validation artifacts that later audits use as proof of completion.

</domain>

<decisions>
## Implementation Decisions

### Milestone Scope As Source Of Truth
- derive active/latest milestone scope from `.planning/MILESTONES.md` plus
  `.planning/STATE.md` instead of inferring it from all ROADMAP headings
- keep future planned phases visible in the active milestone without requiring
  directories to exist yet

### Validation Noise Reduction
- treat pre-roadmap legacy phase directories as legacy, not current roadmap
  drift
- only require `wave` frontmatter where a plan file actually uses frontmatter

### Assurance Backfill
- backfill `VALIDATION.md` files for the late web3 ladder and the one older
  research-backed phase that still kept health in a degraded state
- keep the validation docs tied to the actual commands and qualification lanes
  already used when those phases shipped

</decisions>

<code_context>
## Existing Tooling Insights

- `roadmap analyze` was counting all phase headings in the stripped ROADMAP
  and using disk plan counts only, which forced incorrect aggregate counts and
  a false `100%` progress result
- `init milestone-op` counted every phase directory on disk instead of the
  active milestone scope
- `validate consistency` and `validate health` treated planned future phases,
  legacy omitted phases, and frontmatter-free plan files as current-state
  errors or warnings
- the late web3 ladder from phases `169` through `177` had verification docs
  but no Nyquist `VALIDATION.md` artifacts yet

</code_context>

<deferred>
## Deferred Ideas

- runtime boundary decomposition and ownership hardening remain phase `180`

</deferred>
