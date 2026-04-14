---
gsd_state_version: 1.0
milestone: v2.66
milestone_name: Test Coverage for Untested Crates
status: completed
stopped_at: Completed 376-01-PLAN.md
last_updated: "2026-04-14T22:59:40.258Z"
last_activity: 2026-04-14 -- completed phase 392 by replacing heuristic edge
progress:
  total_phases: 347
  completed_phases: 256
  total_plans: 734
  completed_plans: 757
  percent: 60
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-14)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v3.13 Universal Orchestration Closure is now the active
execution lane. Phases `390` through `392` are complete, so the immediate task
is planning and executing phase `393` (`Ledger and Narrative Reconciliation`)
while keeping v3.12 in the locally complete pending-archive state and v4.0 as
a parallel strategic lane.

## Current Position

Phase: 393 (not started)
Plan: —
Status: v3.13 is active. Phases `390` through `392` are complete and landed
the shared orchestrator substrate, authoritative ACP live-path guarding,
explicit compatibility-only A2A/ACP passthrough surfaces, and truthful bridge
publication gates with tested caveats. The next closure slice is phase `393`,
which must reconcile late-v3 milestone truth and older narrative overclaims to
the now-explicit runtime behavior.
Last activity: 2026-04-14 -- completed phase 392 by replacing heuristic edge
fidelity labels with truthful `Lossless` / `Adapted` / `Unsupported`
publication semantics, tests, and protocol/spec documentation.

Progress: [######----] 60%

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
- Phase `390` is now complete: `arc-cross-protocol` landed as the shared
  runtime home, and the default authoritative A2A/ACP execution paths now emit
  orchestrator-labeled lineage metadata instead of edge-local kernel metadata.
- Phase `392` is now complete: A2A and ACP edge discovery surfaces use shared
  semantic hints and truthful publication gating, unsupported bridges stay
  unpublished, and adapted bridges carry tested caveats for approval,
  streaming, cancellation, and partial-output semantics.
- [Phase 373]: Phase 373-02 established the optional guest export probing pattern: get_typed_func().ok() returns None when export absent, enabling graceful degradation for both arc_alloc (allocator) and arc_deny_reason (structured deny reasons).
- [Phase 374]: trap_on_grow_failure(true) chosen for fail-closed memory enforcement in WASM guards
- [Phase 374]: Import validation after Module::new() leverages wasmtime's import introspection; module size validation before Module::new() avoids unnecessary compilation
- [Phase 374]: build_request() uses function-local import of ToolAction and calls extract_action() for host-side action classification
- [Phase 374]: GuardRequest session_metadata removed (ABI cleanup); unrecognized tools map to mcp_tool via extract_action fallback
- [Phase 375]: Manifest parsing deps (sha2, hex, serde_yml) are NOT feature-gated; manifest types work without wasmtime
- [Phase 375]: WasmGuard::new() extended with manifest_sha256: Option<String>; fuel consumed read within backend lock scope before dropping
- [Phase 375]: guard_evidence_metadata() returns serde_json::Value for flexible downstream receipt integration
- [Phase 375]: load_wasm_guards() sorts by (advisory as u8, priority) for non-advisory-first ordering at equal priority
- [Phase 375]: arc-config added as direct dependency to arc-wasm-guards for WasmGuardEntry; WasmtimeBackend defaults used for memory/module-size limits
- [Phase 375]: build_guard_pipeline() takes pre-composed guard vectors to separate pipeline composition from guard creation
- [Phase 376]: File-level lint suppression (#![allow(clippy::unwrap_used, clippy::expect_used)]) required for benchmark binaries since cfg_attr(test) does not apply to bench targets

### Pending Todos

- Plan and execute phase `393` (`Ledger and Narrative Reconciliation`) on top
  of the landed shared orchestrator, unified authoritative edge path, and
  truthful bridge publication semantics.
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

Phase: 376 (in progress -- 01 of 02 plans done)
Plan: 01 of 2 complete
Status: Phase 376 plan 01 complete -- Criterion benchmark harness with
compilation (50 KiB + 5 MiB WAT modules) and instantiation overhead benchmarks.
All 83 crate tests pass, clippy clean, bench dry-run succeeds. Plan 02 is next.
Last activity: 2026-04-14 -- completed 376-01 benchmark harness with
compilation and instantiation benchmark groups


## v4.1 Guard SDK and Developer Experience

Phase: 382 (not started)
Plan: --
Status: Roadmap created; phases 382-385 defined; depends on v4.0 completion
Last activity: 2026-04-14 -- v3.13 was started from the post-v3 review, with
phases 390-394 reserved after the v4.x placeholder ranges

## Session Continuity

Last session: 2026-04-14T22:59:40.214Z
Stopped at: Completed 376-01-PLAN.md
Next action: execute phase 376 plan 02
Resume file: None
