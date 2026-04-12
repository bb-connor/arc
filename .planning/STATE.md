---
gsd_state_version: 1.0
milestone: v2.66
milestone_name: Test Coverage for Untested Crates
status: defining requirements
stopped_at: milestone v2.66 started; defining requirements and roadmap for ship readiness ladder
last_updated: "2026-04-12T00:00:00Z"
last_activity: 2026-04-12 -- started v2.66 ship readiness ladder (v2.66-v2.73)
progress:
  total_phases: 4
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-12)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v2.66 Test Coverage for Untested Crates -- first of 8
ship readiness milestones (v2.66-v2.73) closing the gap between
production-candidate and production release.

## Current Position

Phase: Not started (defining requirements)
Plan: --
Status: Defining requirements and roadmap for the ship readiness ladder.
Last activity: 2026-04-12 -- Started milestone v2.66 as first of 8 ship
readiness milestones. The full ladder covers test coverage (v2.66), kernel
hardening (v2.67), quality infrastructure (v2.68), CI gate (v2.69), developer
experience (v2.70), web3 live activation (v2.71), distributed systems (v2.72),
and formal verification (v2.73).

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.65: 260 phases completed across 64 milestones

## Accumulated Context

### Decisions

- The ship readiness ladder (v2.66-v2.73) was defined from a comprehensive
  5-agent codebase review that identified: 3 untested crates (arc-hosted-mcp,
  arc-wall, arc-siem), 22 kernel panics as DoS vectors, no property-based
  testing or benchmarks, empty coverage directory, hosted CI observation still
  required, no Docker packaging, and no agent-framework integration examples.
- v2.66+v2.67+v2.68 are independent and can execute in parallel.
- v2.69 (CI gate) gates on v2.66+v2.67+v2.68.
- v2.70 (DX/packaging) gates on v2.69.
- v2.71+v2.72+v2.73 can execute in parallel after v2.70.
- All prior MERCURY and ARC-core decisions from v2.65 remain in force.

### Pending Todos

- Keep the hosted CI and Release Qualification observation hold in place
  before any external publication.
- Resolve historical milestone archive boundaries before phase-directory cleanup.

### Blockers/Concerns

- Hosted workflow observation remains outside this local environment.
- Several runtime/domain entrypoints remain too large for comfortable ownership.

## Session Continuity

Last session: 2026-04-12
Stopped at: v2.66 milestone initialized; defining requirements
Resume file: None
