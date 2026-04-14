---
gsd_state_version: 1.0
milestone: v3.13
milestone_name: Universal Orchestration Closure
status: active
stopped_at: Executing phase 394 after landing OpenAPI override enforcement in arc-api-protect
last_updated: "2026-04-14T23:22:26Z"
last_activity: 2026-04-14 -- began phase 394 implementation by landing OpenAPI override enforcement and tests in arc-api-protect
progress:
  total_phases: 7
  completed_phases: 4
  total_plans: 7
  completed_plans: 4
  percent: 57
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-14)

**Core value:** ARC must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** v3.13 Universal Orchestration Closure is now the active
execution lane. Phases `390` through `393` are complete, so the immediate task
is executing phase `394` (`HTTP Authority and Evidence Convergence`) while
keeping v3.12 in the locally complete pending-archive state and v4.0 as a
parallel strategic lane.

## Current Position

Phase: 394 (in progress)
Plan: 01 (in progress)
Status: v3.13 is active. Phases `390` through `393` are complete and landed
the shared orchestrator substrate, authoritative ACP live-path guarding,
explicit compatibility-only A2A/ACP passthrough surfaces, and truthful bridge
publication gates with tested caveats. Phase `393` then reconciled the late-v3
ledger, stale planning metadata, and older overclaiming narrative material.
Phase `394` is now in progress: the first runtime slice landed by preserving
`x-arc-side-effects` and `x-arc-approval-required` overrides when
`arc-api-protect` builds its route table from OpenAPI. Remaining 394 work is
receipt-status semantics, proxy header fidelity, and `arc-tower`
authority/evidence convergence. Phases `395` and `396` remain queued behind
that runtime work.
Last activity: 2026-04-14 -- began phase 394 by landing OpenAPI override
enforcement and focused proxy tests.

Progress: [#####-----] 57%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.13: 66 phases planned across 14 milestones
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
- Phase `393` was expanded before execution to explicitly own late-v3 ledger
  truth, stale planning metadata, and doc/runtime claim mismatches; the
  remaining implementation gaps now live in phase `394` (HTTP convergence),
  phase `395` (protocol lifecycle and authority-surface closure), and phase
  `396` (claim upgrade qualification).
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
- [Phase 376]: Full production hot path (Store + Linker + host functions + instantiate + serialize + write + call) measured in evaluate latency benchmarks to match runtime.rs::evaluate()
- [Phase 376]: ResourceLimiter benchmark uses assert!(result.is_err()) as correctness gate; benchmark failure means ResourceLimiter is misconfigured
- [Phase 382]: arc-guard-sdk crate uses no host-side dependencies (wasmtime, arc-core, arc-kernel); types mirror host abi.rs serde annotations exactly
- [Phase 382]: Guest-side GuardVerdict::Deny carries mandatory String reason (not Option) because denying guards should always explain why; the host-side Option comes from the arc_deny_reason fallback path
- [Phase 382]: Vec-based thread-local allocator chosen over bump allocator for simplicity; each arc_alloc pushes a fresh Vec, arc_free matches by pointer+length
- [Phase 382]: Host function wrappers use cfg(target_arch = "wasm32") gating with no-op/default fallbacks; matches wasm-bindgen convention for dual-target compilation
- [Phase 382]: serialize_deny_reason() extracted from arc_deny_reason for testability; i32 buf_ptr truncates 64-bit heap pointers on native, so the pure-logic function enables safe testing
- [Phase 382]: const thread_local initializer pattern (RefCell::new(None)) used consistently across alloc.rs and glue.rs for Rust 1.93 clippy compliance

### Roadmap Evolution

- `v3.13` was extended from phases `390-394` to `390-396` so the post-phase-392
  audit gaps have explicit owners instead of leaking into vague “qualification”
  work.
- Phase `394` now owns HTTP authority/evidence convergence.
- Phase `395` now owns A2A/ACP lifecycle and authority-surface closure.
- Phase `396` now owns the final post-closure claim qualification.

### Pending Todos

- Continue executing phase `394` (`HTTP Authority and Evidence Convergence`) on
  top of the landed shared orchestrator, unified authoritative edge path,
  truthful bridge publication semantics, completed phase `393`
  reconciliation, and the newly landed OpenAPI override enforcement slice.
- Archive `v3.12` now that phases `377` through `381` are complete locally.
- Execute the runtime closure items owned by phases `394` through `396`.
- Resume `v4.0` planning/execution in parallel as capacity allows.

### Blockers/Concerns

- `v3.12` is complete locally but not yet archived, so the repo still carries
  milestone-closeout debt alongside the active v3.13 execution lane.
- `v2.83` is still partially complete locally (phases `316` and `317` remain
  pending), so it should stay marked as unresolved prior-lane debt instead of
  silently reading as either archived or active.
- `v4.0` already reserved phases `373-376`, so `v3.12` begins at `377`; future
  v4.x placeholders must stay shifted to avoid roadmap collisions.
- The default web3-enabled graph still carries alloy's transitive hashbrown
  split; the core-path no-default-features graph remains the validated slim
  path when `v2.71` eventually resumes.

## v4.0 WASM Guard Runtime Completion

Phase: 376 (complete -- 02 of 02 plans done)
Plan: 02 of 2 complete
Status: Phase 376 complete -- all 5 WGBENCH requirements validated: module
compilation timing, instantiation overhead, evaluate latency (trivial + realistic),
fuel metering overhead comparison, and ResourceLimiter adversarial trap validation.
All 83 crate tests pass, clippy clean, 8 bench_functions pass in dry-run mode.
Last activity: 2026-04-14 -- completed 376-02 with evaluate latency, fuel
overhead, and ResourceLimiter benchmarks


## v4.1 Guard SDK and Developer Experience

Phase: 382 (complete -- 02 of 02 plans done)
Plan: 02 of 2 complete
Status: Phase 382 complete -- arc-guard-sdk crate has full guest-side API:
ABI-identical types (GuardRequest, GuardVerdict, GuestDenyResponse), Vec-based
allocator (arc_alloc, arc_free), typed host bindings (arc.log, arc.get_config,
arc.get_time), ABI glue (read_request, encode_verdict, arc_deny_reason), and
expanded prelude. 24 tests passing, clippy clean, fmt clean.
Last activity: 2026-04-14 -- completed 382-02 with host function bindings, ABI
glue, and expanded prelude

## Session Continuity

Last session: 2026-04-14T23:35:05Z
Stopped at: Completed 382-02-PLAN.md (host bindings, ABI glue, arc_deny_reason)
Next action: begin Phase 383 (proc macro and example guards)
Resume file: None
