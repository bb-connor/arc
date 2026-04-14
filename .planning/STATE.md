---
gsd_state_version: 1.0
milestone: v2.66
milestone_name: Test Coverage for Untested Crates
status: completed
stopped_at: Completed 373-01-PLAN.md
last_updated: "2026-04-14T20:52:15.626Z"
last_activity: 2026-04-14 -- added the v3.12 milestone audit, corrected the
progress:
  total_phases: 342
  completed_phases: 250
  total_plans: 725
  completed_plans: 742
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-14)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v3.12 Cross-Protocol Integrity and Truth Completion is
complete locally; the next repo-management step is milestone archival/closeout
before resuming the parallel v4.0 lane.

## Current Position

Phase: 381 (complete locally)
Plan: 01 complete; milestone ready for closeout
Status: all v3.12 corrective work is complete locally. ACP live-path
cryptographic enforcement is in place, the outward A2A/ACP edges default to
kernel-backed execution with explicit compatibility helpers, the remaining
operational parity gaps are closed, and the docs/planning stack now reflects
the narrowed truthful ARC claim.
Last activity: 2026-04-14 -- added the v3.12 milestone audit, corrected the
remaining roadmap/planning metadata drift, and confirmed the
milestone-ready-for-closeout state across the planning stack.

Progress: [##########] 100%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.12: 59 phases planned across 13 milestones
- v4.0: 4 phases planned (parallel strategic lane)
- v4.1: 4 phases planned (depends on v4.0; guard SDK + CLI)
- v4.2: 4 phases planned (depends on v4.1; WIT migration + multi-language SDKs)

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
- v4.0 WASM Guard Runtime Completion runs in parallel with the v3.12
  corrective lane (and remains independent from the unfinished v2.83 closeout).
  Design authority is `docs/guards/05-V1-DECISION.md`. ABI is raw core-WASM
  (not WIT), stateless per-call Store, HushSpec-first pipeline order.
- Phase 373-01 established the WasmHostState pattern: per-invocation fresh
  Store with config and bounded log buffer, host functions registered via
  Linker::func_wrap with typed Caller closures, and shared Arc<Engine> across
  all WasmtimeBackend instances.
- The 2026-04-14 cross-protocol debate established the correct ARC claim:
  the kernel/substrate breakthrough is real, but the broader "fully realized
  universal cross-protocol governance kernel" claim still requires ACP
  cryptographic enforcement, truthful outward-edge mediation, operational
  parity, and repo-wide truth reconciliation.
- v3.12 exists specifically to close that credibility gap. It is the active
  corrective lane even though v4.0 was already planned in parallel and v2.83
  remains locally unarchived.

### Pending Todos

- Close and archive `v3.12` now that phases `377` through `381` are complete
  locally.
- Close or explicitly defer the remaining `v2.83` coverage / qualification
  loose ends once the repo's top-level truth narrative is stable.
- Resume `v4.0` planning/execution after the v3.12 corrective lane no longer
  competes with the repo's active truth narrative.

### Blockers/Concerns

- `v3.12` is complete locally but not yet archived, so the repo still carries
  an active-milestone marker until closeout is performed.
- `v2.83` is still locally incomplete, so it should be explicitly archived or
  deferred later instead of silently remaining the repo's "active" milestone.
- `v4.0` already reserved phases `373-376`, so `v3.12` begins at `377`; future
  v4.x placeholders must stay shifted to avoid roadmap collisions.
- The default web3-enabled graph still carries alloy's transitive hashbrown
  split; the core-path no-default-features graph remains the validated slim
  path when `v2.71` eventually resumes.

## v4.0 WASM Guard Runtime Completion

Phase: 373 (in progress)
Plan: 01 of 2 complete
Status: Plan 01 complete -- WasmHostState, shared Arc<Engine>, three host
functions (arc.log, arc.get_config, arc.get_time_unix_secs) implemented and
tested. Plan 02 (arc_alloc/arc_deny_reason guest export detection) is next.
Last activity: 2026-04-14 -- completed 373-01 host foundation plan with 9
WAT-based tests, refactored WasmtimeBackend to Store<WasmHostState>


## v4.1 Guard SDK and Developer Experience

Phase: 382 (not started)
Plan: --
Status: Roadmap created; phases 382-385 defined; depends on v4.0 completion
Last activity: 2026-04-14 -- v4.1 roadmap renumbered to 382-385 to avoid
colliding with active v3.12 phases

## Session Continuity

Last session: 2026-04-14T20:52:15.611Z
Stopped at: Completed 373-01-PLAN.md
Next action: Execute 373-02-PLAN.md (arc_alloc/arc_deny_reason guest export detection)
Resume file: None
