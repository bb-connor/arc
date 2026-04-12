# Phase 177: Release Governance, Audit Truth, and Candidate Documentation Alignment - Context

**Gathered:** 2026-04-02
**Status:** Complete

<domain>
## Phase Boundary

Make ARC's release-governance, audit, checklist, and reviewer-facing
candidate docs authoritative for the current post-`v2.41` production
candidate and explicit about local versus hosted release gates.

</domain>

<decisions>
## Implementation Decisions

### Release Decision Hierarchy
- make `docs/release/RELEASE_AUDIT.md` the explicit authoritative repo-local
  release-go record
- keep `docs/release/RELEASE_CANDIDATE.md` as the supported-scope document,
  `docs/release/QUALIFICATION.md` as the evidence contract,
  `docs/release/GA_CHECKLIST.md` as the operator checklist, and the partner
  proof docs as reviewer packages

### Current Candidate Normalization
- normalize stale `v2.8` and `v2.39` launch-candidate phrasing to the current
  post-`v2.41` production candidate
- carry the hosted web3 runtime, `e2e`, ops, and promotion evidence family
  into the release-governance surfaces that rely on hosted observation

### Scope Discipline
- keep this phase on release-truth and governance alignment only
- defer protocol/standards parity, research supersession, and tooling repair
  to phases `178` and `179`

</decisions>

<code_context>
## Existing Doc Insights

- `docs/release/RELEASE_AUDIT.md` still described the decision through an
  older launch-candidate frame and did not explicitly enumerate the new web3
  runtime gates at the top-level decision contract
- `docs/release/GA_CHECKLIST.md` still referenced the old `v2.8` launch
  candidate even though the shipped candidate had advanced through `v2.41`
- `docs/release/PARTNER_PROOF.md` and
  `docs/release/ARC_WEB3_PARTNER_PROOF.md` were reviewer-oriented already, but
  they did not clearly state that they were not the authoritative release-go
  record
- `docs/release/RELEASE_CANDIDATE.md` and
  `docs/release/QUALIFICATION.md` already carried most of the current hosted
  evidence model, so the phase could normalize roles and references without
  inventing new release gates

</code_context>

<deferred>
## Deferred Ideas

- protocol/standards parity and research supersession bridging remain phase
  `178`
- GSD parser health and Nyquist backfill remain phase `179`
- runtime boundary decomposition remains phase `180`

</deferred>
