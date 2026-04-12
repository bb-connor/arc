# Phase 152: arc-link Qualification, Failure Drills, and Boundary Documentation - Context

**Gathered:** 2026-04-01
**Status:** Ready for planning

<domain>
## Phase Boundary

Qualify the completed `arc-link` runtime across the main oracle failure modes,
publish concrete operator recovery guidance, and rewrite ARC's public boundary
so the milestone closes on implemented runtime evidence rather than research
intent.

</domain>

<decisions>
## Implementation Decisions

### Qualification Shape
- Keep qualification executable and local by centering it on crate tests,
  standards artifacts, and release-document updates.
- Cover stale, divergent, manipulated, missing, paused, and sequencer-down or
  recovery-gated cases explicitly.
- Reuse deterministic stub backends instead of relying on live external
  infrastructure for milestone closure.

### Operator Guidance
- Publish one dedicated `arc-link` operator runbook with failure drills rather
  than scattering phase `152` guidance across generic operations docs.
- Tie drills directly to the new runtime report statuses and override controls
  added in phase `151`.

### Boundary Documentation
- Update the `arc-link` standards profile first, then propagate the narrowed
  public claim into release candidate, qualification, and protocol docs.
- Keep non-goals explicit: no Data Streams premium tier, no Functions,
  Automation, CCIP, or x402 claim in this milestone.

### Milestone Closure
- Close `v2.35` only after phase records, requirement mapping, milestone audit,
  and planning-state advancement all agree that phase `153` is next.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-link/src/lib.rs` test scaffolding already has static backends and
  deterministic sample rates for failure-path coverage.
- `crates/arc-kernel/src/lib.rs` already has cross-currency tests that prove
  receipt behavior on oracle success and failure.
- `docs/standards/ARC_LINK_PROFILE.md` and
  `docs/standards/ARC_LINK_KERNEL_RECEIPT_POLICY.md` are the current bounded
  standards surface that phase `152` needs to finalize.

### Established Patterns
- Milestone closure uses a `vX.YY-MILESTONE-AUDIT.md` scorecard plus phase
  verification files.
- Qualification artifacts in this repo normally live in code tests plus
  `docs/release/QUALIFICATION.md`.
- Release-boundary rewrites stay conservative and name explicit supported lanes
  plus explicit non-goals.

### Integration Points
- `docs/release/RELEASE_CANDIDATE.md`
- `docs/release/QUALIFICATION.md`
- `spec/PROTOCOL.md`
- `.planning/ROADMAP.md`, `.planning/PROJECT.md`, `.planning/MILESTONES.md`,
  `.planning/REQUIREMENTS.md`, and `.planning/STATE.md`

</code_context>

<specifics>
## Specific Ideas

- Publish a machine-readable `ARC_LINK_QUALIFICATION_MATRIX.json` so the
  milestone closes with the same artifact discipline as other late-roadmap
  milestones.
- Add a runtime monitor report example and an operator config example to keep
  the claimed surface concrete.
- Use the new phase `151` runtime report terms directly in the runbook so the
  operational and code surfaces stay aligned.

</specifics>

<deferred>
## Deferred Ideas

- External partner or hosted-environment proof for `arc-link`; that belongs to
  the later web3 production-qualification milestone.
- Multi-chain settlement reconciliation beyond the current cross-currency
  kernel boundary.

</deferred>
