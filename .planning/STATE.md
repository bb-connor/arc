---
gsd_state_version: 1.0
milestone: v2.66
milestone_name: Test Coverage for Untested Crates
status: v3.13 is active. The generic cross-protocol orchestrator slice now has
stopped_at: Completed 374-01-PLAN.md (WASM guard security hardening)
last_updated: "2026-04-14T21:34:54.562Z"
last_activity: 2026-04-14 -- created phase 390 context and plan artifacts for
progress:
  total_phases: 347
  completed_phases: 251
  total_plans: 728
  completed_plans: 748
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-14)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v3.13 Universal Orchestration Closure is now the active
planning lane. Phase `390` has context and one executable plan, so the
immediate task is implementation of the shared orchestrator substrate while
keeping v3.12 in the locally complete pending-archive state and v4.0 as a
parallel strategic lane.

## Current Position

Phase: 390 (planned, execution not started)
Plan: 01 (`Shared Orchestrator Substrate and First Edge Adoption`)
Status: v3.13 is active. The generic cross-protocol orchestrator slice now has
one concrete implementation plan covering shared bridge contracts,
attenuation, receipt-lineage tracing, and first adoption in the A2A and ACP
authoritative paths.
Last activity: 2026-04-14 -- created phase 390 context and plan artifacts for
the cross-protocol orchestrator, and kept v3.12 explicitly in the locally
complete pending-archive state.

Progress: [----------] 0%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.13: 64 phases planned across 14 milestones
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
- v4.0 WASM Guard Runtime Completion runs in parallel with the v3.13
  orchestration-closure lane (and remains independent from the unfinished
  v2.83 closeout).
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
- v3.12 closed the first credibility gap and established the narrow truthful
  ARC claim, but the follow-on review found four remaining closures: generic
  orchestration, authoritative edge unification, bridge-fidelity truth, and
  late-v3 ledger reconciliation.
- v3.13 exists specifically to close those four remaining gaps even though
  v4.0 was already planned in parallel and v2.83 remains locally unarchived.
- Phase `390` will introduce a reusable cross-protocol runtime home instead of
  embedding the orchestrator inside either outward edge crate, because the
  remaining gap is split authority, not missing edge-local helper methods.
- [Phase 373]: Phase 373-02 established the optional guest export probing pattern: get_typed_func().ok() returns None when export absent, enabling graceful degradation for both arc_alloc (allocator) and arc_deny_reason (structured deny reasons).
- [Phase 374]: trap_on_grow_failure(true) chosen for fail-closed memory enforcement in WASM guards
- [Phase 374]: Import validation after Module::new() leverages wasmtime's import introspection; module size validation before Module::new() avoids unnecessary compilation

### Pending Todos

- Execute Phase `390` plan `01` (`Shared Orchestrator Substrate and First Edge
  Adoption`) as the first v3.13 implementation slice.
- Archive `v3.12` now that phases `377` through `381` are complete locally.
- Reconcile the remaining `v3.9`-`v3.11` ledger truth debt under Phase `393`.
- Resume `v4.0` planning/execution in parallel as capacity allows.

### Blockers/Concerns

- `v3.12` is complete locally but not yet archived, so the repo still carries
  milestone-closeout debt alongside the new v3.13 planning lane.
- `v2.83` is still locally incomplete, so it should be explicitly archived or
  deferred later instead of silently remaining the repo's "active" milestone.
- `v4.0` already reserved phases `373-376`, so `v3.12` begins at `377`; future
  v4.x placeholders must stay shifted to avoid roadmap collisions.
- The default web3-enabled graph still carries alloy's transitive hashbrown
  split; the core-path no-default-features graph remains the validated slim
  path when `v2.71` eventually resumes.

## v4.0 WASM Guard Runtime Completion

Phase: 373 (complete)
Plan: 02 of 2 complete
Status: Phase 373 complete -- WasmHostState, shared Arc<Engine>, three host
functions, arc_alloc guest allocator probing with offset-0 fallback, and
arc_deny_reason structured deny reason extraction with legacy NUL-string
fallback. All 32 crate tests pass, clippy clean.
Last activity: 2026-04-14 -- completed 373-02 guest export detection plan with
8 WAT-based tests covering arc_alloc and arc_deny_reason code paths


## v4.1 Guard SDK and Developer Experience

Phase: 382 (not started)
Plan: --
Status: Roadmap created; phases 382-385 defined; depends on v4.0 completion
Last activity: 2026-04-14 -- v3.13 was started from the post-v3 review, with
phases 390-394 reserved after the v4.x placeholder ranges

## Session Continuity

Last session: 2026-04-14T21:34:54.535Z
Stopped at: Completed 374-01-PLAN.md (WASM guard security hardening)
Next action: `/gsd:execute-phase 390` to implement the shared cross-protocol orchestrator substrate
Resume file: None
