---
gsd_state_version: 1.0
milestone: v2.69
milestone_name: CI Gate and Release Qualification
status: active
stopped_at: v2.69 repo-side evidence complete locally; waiting on hosted GitHub Actions rerun and release-candidate tag
last_updated: "2026-04-12T23:57:35Z"
last_activity: 2026-04-12 -- completed local v2.69 repo-side execution, including full release qualification with signed artifacts and conformance evidence; hosted GitHub observation still pending
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 3
  completed_plans: 3
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-12)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v2.69 CI Gate and Release Qualification -- the repo-side
fixes and signed local qualification bundle are complete, but hosted GitHub
Actions observation and release-candidate tagging still gate external
publication.

## Current Position

Phase: 286 of 302 (Release Qualification Observation)
Plan: 01
Status: repo-side work complete locally; hosted GitHub rerun and release tag pending
Last activity: 2026-04-12 -- Completed local v2.69 repo-side fixes, conformance validation, and full release qualification; wrote phase artifacts for 284-286 and kept the milestone active pending hosted observation.

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.65: 260 phases completed across 64 milestones

## Accumulated Context

### Decisions

- The ship readiness ladder (v2.66-v2.73) was defined from a comprehensive
  5-agent codebase review that identified: 3 untested crates (arc-hosted-mcp,
  arc-wall, arc-siem), 22 literal panic assertions inside `arc-kernel/src`,
  no property-based testing or benchmarks, empty coverage directory, hosted CI
  observation still required, no Docker packaging, and no agent-framework
  integration examples.
- v2.66 is complete locally. Phase 276 was scoped to the real seams the repo
  exposes today: hosted-mcp/kernel -> siem on the shared receipt DB, plus
  ARC-Wall companion receipts flowing into siem on the same ARC substrate.
- v2.67 is complete locally. Phase 277 proved the 22 literal `panic!` sites
  were all test-only; the real hardening work landed at the canonical JSON
  transport boundary plus source hygiene inside `arc-kernel/src`.
- v2.68 is complete locally. Phase 281 added proptest coverage in `arc-core`
  and `arc-kernel`, Phase 282 added Criterion baselines for core primitives,
  and Phase 283 wired tarpaulin into CI/release qualification with a measured
  `67.43%` baseline and a `67%` enforced floor.
- v2.69 repo-side work is complete locally. Phase 284 repaired the current
  hosted workflow breakpoints, Phase 285 proved all five conformance waves
  against the shipped JS/Python and Go live peers in the local release lane,
  and Phase 286 now emits signed per-wave certification artifacts plus a root
  checksum/manifest bundle from `scripts/qualify-release.sh`.
- v2.66+v2.67+v2.68 are independent and can execute in parallel.
- v2.69 (CI gate) gates on v2.66+v2.67+v2.68.
- v2.70 (DX/packaging) gates on v2.69.
- v2.71+v2.72+v2.73 can execute in parallel after v2.70.
- All prior MERCURY and ARC-core decisions from v2.65 remain in force.

### Pending Todos

- Publish the v2.69 repo-side fixes and rerun the hosted `CI` and
  `Release Qualification` workflows on GitHub.
- Create the release candidate tag only after hosted observation confirms all
  gates are green.
- Milestone archive/tag/cleanup for v2.66, v2.67, and v2.68 remains an
  explicit operator decision.

### Blockers/Concerns

- Hosted workflow observation remains outside this local environment.
- The passing qualification bundle is local-only right now:
  `target/release-qualification/artifact-manifest.json` records `source:
  local`, `candidateSha: local`, and no GitHub workflow run identifiers.
- v2.66, v2.67, and v2.68 archive, git tag, and cleanup were not run
  automatically because those lifecycle steps require explicit confirmation.
- Several runtime/domain entrypoints remain too large for comfortable ownership.

## Session Continuity

Last session: 2026-04-12
Stopped at: v2.69 repo-side execution complete locally; hosted rerun/tag still pending.
Next action: publish the v2.69 fixes, rerun hosted GitHub Actions, and tag the release candidate only after green observation
Resume file: None
