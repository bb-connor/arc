---
gsd_state_version: 1.0
milestone: v2.83
milestone_name: Coverage, Hardening, and Production Qualification
status: active
stopped_at: phase 315 complete; phase 316 queued
last_updated: "2026-04-14T00:37:14Z"
last_activity: 2026-04-13 -- completed phase 315 by closing the workspace integration-test gap, adding security/storage success-failure-edge coverage, and verifying A2A/MCP exchange lanes
progress:
  total_phases: 4
  completed_phases: 1
  total_plans: 3
  completed_plans: 3
  percent: 25
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-13)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v2.83 Coverage, Hardening, and Production Qualification --
raise the production bar with crate-level integration tests, higher measured
coverage, store-layer hardening, API-surface cleanup, and structured errors.

## Current Position

Phase: 316 (next)
Plan: 316 discuss/plan next
Status: v2.83 active locally; `v2.82` is complete and archived locally
Last activity: 2026-04-13 -- completed `315`, adding integration smoke lanes
across the previously zero-test crates plus focused credentials/policy/store
and A2A/MCP exchange coverage.

Progress: [###-------] 25%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.7: 32 phases planned across 8 milestones

## Accumulated Context

### Decisions

- v2.80-v2.83 milestones were defined from a comprehensive five-agent codebase
  review (2026-04-13) that identified: 32K-line arc-core gravity well, five
  files exceeding 6K lines, synchronous &mut self kernel blocking concurrency,
  deprecated serde_yaml, dual reqwest versions, 12 crates with zero integration
  tests, naming confusion (ARC vs CHIO), unpublished SDKs, non-implementable
  protocol spec, and 82 too_many_arguments suppressions.
- v2.80 gates v2.81 and v2.82. v2.81 and v2.82 can execute in parallel.
  v2.83 gates on v2.81.
- The ship readiness ladder (v2.66-v2.73) is complete locally except for the
  deferred v2.71 (external web3 prerequisites).
- All prior MERCURY and ARC-core decisions from v2.65 remain in force.
- MERCURY and ARC-Wall schema expansion is explicitly paused until the protocol
  substrate is production-ready.
- `arc-core-types` stays narrow while heavyweight ARC business domains now live
  in dedicated crates and the broad consumers declare those domain crates
  directly.
- Narrow consumers can migrate without source churn by aliasing
  `package = "arc-core-types"` under the existing `arc-core` dependency key.
- `arc init` should stay self-contained: generated starter projects use a
  standalone Rust MCP stub plus the installed `arc` binary instead of depending
  on unpublished ARC crates.
- Phase `308` should keep the official SDK examples aligned to the real
  `arc trust serve` + `arc mcp serve-http --control-url ...` topology rather
  than introducing a second demo stack before the Docker milestone lands.
- Phase `310` anchored the tutorial and framework examples to the same hosted
  HTTP edge topology rather than reviving the old stdio demo path.

### Pending Todos

- Discuss and plan `316` so coverage push work stays focused on genuinely
  untested paths while the SQLite layer gains concurrent-access support.
- Resolve deferred `v2.71` external prerequisites if live-chain activation
  becomes active again.
- v3.0-v3.7 universal security kernel milestones are now planned with 32
  phases and 93 requirements. Execute v2.83 phases 316-318 first, then
  begin v3.0 phase 319.

### Blockers/Concerns

- The live planning pointers for `v2.83` are updated locally, but a clean
  closeout/tag pass is still outstanding because the top-level planning files
  carried unrelated local edits before milestone archival.
- The default web3-enabled graph still carries alloy’s transitive hashbrown
  split; the core-path no-default-features graph is now the validated slim path.

## Session Continuity

Last session: 2026-04-13
Stopped at: phase `315` complete; ready to start `316`
Next action: discuss/plan `316`, then execute the coverage push and store
hardening work
Resume file: None
