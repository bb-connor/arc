---
gsd_state_version: 1.0
milestone: v3.18
milestone_name: Bounded Chio Ship Readiness Closure
status: complete_local_pending_archival
stopped_at: Completed the post-v3.18 closure tracker, including portable browser qualification, CI and release gating, runtime-semantics doc sync, and the final release-truth gate
last_updated: "2026-04-19T06:10:00Z"
last_activity: "2026-04-19 -- completed the post-v3.18 closure tracker and left only archival plus hosted release observation"
progress:
  total_phases: 374
  completed_phases: 289
  total_plans: 818
  completed_plans: 818
  percent: 78
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-19)

**Core value:** Chio must provide deterministic, least-privilege agent
authority with auditable outcomes, bounded spend, and cryptographic proof
artifacts that enable economic security, regulatory compliance, and portable
trust.
**Current focus:** no newer ship lane is active. `v3.18 Bounded Chio Ship
Readiness Closure` is complete locally and pending archival, and the
post-`v3.18` closure tracker is also complete locally. The next work is
archival plus hosted release observation on the bounded candidate. `v3.17`
remains the retained repo-local comptroller-capable packaging decision.

## Current Position

Phase: complete
Plan: n/a
Status: `v3.18` is now the latest completed milestone and bounded Chio
ship-readiness lane. The retained decision boundary is: Chio is
comptroller-capable software on repo-local proof, and bounded Chio is now the
primary ship-facing release boundary. The post-`v3.18` closure tracker is now
complete locally, so the remaining work is archival and hosted workflow
observation rather than more repo-local runtime closure.
Last activity: 2026-04-19 -- completed the post-`v3.18` closure tracker and
the final release-truth sync gate.

Progress: [#######...] 77%

## Performance Metrics

**Velocity:**
- v1.0 completed: 6 phases, 24 plans
- v2.0 completed: 6 phases, 19 plans
- v2.1-v2.73: 290 phases completed across 72 milestones
- v2.80-v2.83: 16 phases planned across 4 milestones
- v3.0-v3.15: 78 phases completed across 16 milestones
- v3.16: 6 phases completed locally (universal control-plane thesis)
- v3.17: 4 phases completed locally (market-position proof)
- v3.18: 5 phases completed locally (bounded Chio ship readiness closure)
- v4.0: 4 phases planned (parallel strategic lane)
- v4.1: 4 phases planned (depends on v4.0; guard SDK + CLI)
- v4.2: 4 phases planned (depends on v4.1; WIT migration + multi-language SDKs)

## Accumulated Context

### Decisions

- v2.80-v2.83 milestones were defined from a comprehensive five-agent codebase
  review (2026-04-13) that identified: 32K-line chio-core gravity well, five
  files exceeding 6K lines, synchronous &mut self kernel blocking concurrency,
  deprecated serde_yaml, dual reqwest versions, 12 crates with zero integration
  tests, naming confusion (Chio vs CHIO), unpublished SDKs, non-implementable
  protocol spec, and 82 too_many_arguments suppressions.
- v2.80 gates v2.81 and v2.82. v2.81 and v2.82 can execute in parallel.
  v2.83 gates on v2.81.
- The ship readiness ladder (v2.66-v2.73) is complete locally except for the
  deferred v2.71 (external web3 prerequisites).
- All prior MERCURY and Chio-core decisions from v2.65 remain in force.
- MERCURY and Chio-Wall schema expansion is explicitly paused until the protocol
  substrate is production-ready.
- `chio-core-types` stays narrow while heavyweight Chio business domains now live
  in dedicated crates and the broad consumers declare those domain crates
  directly.
- Narrow consumers can migrate without source churn by aliasing
  `package = "chio-core-types"` under the existing `chio-core` dependency key.
- `arc init` should stay self-contained: generated starter projects use a
  standalone Rust MCP stub plus the installed `arc` binary instead of depending
  on unpublished Chio crates.
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
- The 2026-04-14 cross-protocol debate established the correct Chio claim:
  the kernel/substrate breakthrough is real, but the broader "fully realized
  universal cross-protocol governance kernel" claim still requires ACP
  cryptographic enforcement, truthful outward-edge mediation, operational
  parity, and repo-wide truth reconciliation.
- The 2026-04-15 post-`v3.17` release review established the Track A P0
  blocker ladder: bounded Chio is close, but honest ship still requires claim
  discipline, planning truth, delegation-boundary truth, hosted/auth profile
  truth, governed provenance truth, and one bounded operational profile.
- v3.12 closed the first credibility gap and established the narrow truthful
  Chio claim, but the follow-on review found four remaining closures: generic
  orchestration, authoritative edge unification, bridge-fidelity truth, and
  late-v3 ledger reconciliation.
- v3.13 exists specifically to close those four remaining gaps even though
  v4.0 was already planned in parallel and v2.83 remains locally unarchived;
  its runtime/substrate closure landed locally, and the remaining
  ledger/archive closeout was completed in archived `v3.14`.
- Phase `390` is now complete: `chio-cross-protocol` landed as the shared
  runtime home, and the default authoritative A2A/ACP execution paths now emit
  orchestrator-labeled lineage metadata instead of edge-local kernel metadata.
- Phase `392` is now complete: A2A and ACP edge discovery surfaces use shared
  semantic hints and truthful publication gating, unsupported bridges stay
  unpublished, and adapted bridges carry tested caveats for approval,
  streaming, cancellation, and partial-output semantics.
- Phase `393` was expanded before execution to explicitly own late-v3 ledger
  truth, stale planning metadata, and doc/runtime claim mismatches, while the
  remaining historical ledger/archive closure work ultimately completed in
  archived `v3.14`.
- [Phase 373]: Phase 373-02 established the optional guest export probing pattern: get_typed_func().ok() returns None when export absent, enabling graceful degradation for both chio_alloc (allocator) and chio_deny_reason (structured deny reasons).
- [Phase 374]: trap_on_grow_failure(true) chosen for fail-closed memory enforcement in WASM guards
- [Phase 374]: Import validation after Module::new() leverages wasmtime's import introspection; module size validation before Module::new() avoids unnecessary compilation
- [Phase 374]: build_request() uses function-local import of ToolAction and calls extract_action() for host-side action classification
- [Phase 374]: GuardRequest session_metadata removed (ABI cleanup); unrecognized tools map to mcp_tool via extract_action fallback
- [Phase 375]: Manifest parsing deps (sha2, hex, serde_yml) are NOT feature-gated; manifest types work without wasmtime
- [Phase 375]: WasmGuard::new() extended with manifest_sha256: Option<String>; fuel consumed read within backend lock scope before dropping
- [Phase 375]: guard_evidence_metadata() returns serde_json::Value for flexible downstream receipt integration
- [Phase 375]: load_wasm_guards() sorts by (advisory as u8, priority) for non-advisory-first ordering at equal priority
- [Phase 375]: chio-config added as direct dependency to chio-wasm-guards for WasmGuardEntry; WasmtimeBackend defaults used for memory/module-size limits
- [Phase 375]: build_guard_pipeline() takes pre-composed guard vectors to separate pipeline composition from guard creation
- [Phase 376]: File-level lint suppression (#![allow(clippy::unwrap_used, clippy::expect_used)]) required for benchmark binaries since cfg_attr(test) does not apply to bench targets
- [Phase 376]: Full production hot path (Store + Linker + host functions + instantiate + serialize + write + call) measured in evaluate latency benchmarks to match runtime.rs::evaluate()
- [Phase 376]: ResourceLimiter benchmark uses assert!(result.is_err()) as correctness gate; benchmark failure means ResourceLimiter is misconfigured
- [Phase 382]: chio-guard-sdk crate uses no host-side dependencies (wasmtime, chio-core, chio-kernel); types mirror host abi.rs serde annotations exactly
- [Phase 382]: Guest-side GuardVerdict::Deny carries mandatory String reason (not Option) because denying guards should always explain why; the host-side Option comes from the chio_deny_reason fallback path
- [Phase 382]: Vec-based thread-local allocator chosen over bump allocator for simplicity; each chio_alloc pushes a fresh Vec, chio_free matches by pointer+length
- [Phase 382]: Host function wrappers use cfg(target_arch = "wasm32") gating with no-op/default fallbacks; matches wasm-bindgen convention for dual-target compilation
- [Phase 382]: serialize_deny_reason() extracted from chio_deny_reason for testability; i32 buf_ptr truncates 64-bit heap pointers on native, so the pure-logic function enables safe testing
- [Phase 382]: const thread_local initializer pattern (RefCell::new(None)) used consistently across alloc.rs and glue.rs for Rust 1.93 clippy compliance
- [Phase 383]: Proc-macro crate generates path references (chio_guard_sdk::*) instead of depending on chio-guard-sdk; user fn renamed to __arc_guard_user_{name} for ABI symbol isolation
- [Phase 383]: Example guard crate template: cdylib crate-type under examples/guards/, chio-guard-sdk + chio-guard-sdk-macros deps, #[chio_guard] fn evaluate pattern
- [Phase 383]: Integration test pattern: load_example_wasm(artifact_name) with CARGO_MANIFEST_DIR-relative path, fresh WasmtimeBackend per test, match on GuardVerdict::Deny for reason assertions
- [Phase 384]: Inline string templates for guard scaffold (3 small files, no template directory needed); package name derived from final path component; SDK deps use version strings not path deps
- [Phase 384]: wasmparser 0.221 as direct chio-cli dep (not workspace); cmd_guard_inspect is informational-only (does not fail on ABI incompatibility)
- [Phase 385]: Fresh WasmtimeBackend per fixture/iteration for fuel and memory state isolation in test and bench commands
- [Phase 385]: TestFixture YAML format uses flat list with GuardRequest shape for request field, expected_verdict (allow/deny), and optional deny_reason_contains
- [Phase 385]: Percentile uses index = len * pct / 100 clamped to len-1 for non-interpolating semantics
- [Phase 385]: Fresh WasmtimeBackend per fixture/iteration for fuel and memory state isolation in test and bench commands
- [Phase 385]: pack_from_dir takes explicit path for testability; archive stores wasm as filename-only for portability; install uses temp-dir extraction for gzip stream compatibility
- [Phase 386]: WIT types placed inside interface block (not top-level) because WIT parser requires variant/record inside interface scope
- [Phase 386]: ComponentState(StoreLimits) wrapper for import-free component Store data; WasmHostState reserved for core-module path with host imports
- [Phase 386]: Guard::instantiate in wasmtime 29 returns Guard directly (not tuple); adapted plan's destructuring accordingly
- [Phase 386]: wasmparser::Parser static methods used for authoritative core/component format detection; create_backend() returns Box<dyn WasmGuardAbi> for transparent dual-mode dispatch
- [Phase 387]: jco types (not guest-types) generates correct export-side .d.ts bindings for the guard world
- [Phase 387]: dist/tool-gate.wasm is 11 MiB (SpiderMonkey engine); ComponentBackend max_module_size may need adjustment
- [Phase 387]: TypeScript guard pattern: import jco-generated types, export evaluate(GuardRequest): Verdict, compile via esbuild+componentize-js
- [Phase 387]: ComponentBackend::with_limits(16 MiB memory, 15 MiB module) for jco-compiled TS guards exceeding default 10 MiB max_module_size
- [Phase 388]: wit-bindgen-go generates bindings into internal/ with guard package re-exporting types as aliases; example imports both guard and types packages
- [Phase 388]: Extended WIT world lists WASI imports individually (environment, stdin, stdout, stderr, clocks, filesystem, random) for TinyGo compatibility; wasi-virt strips them post-compilation
- [Phase 388]: componentize-py --world-module guard used to name generated bindings 'guard' for ergonomic imports; entrypoint renamed to app.py because APP_NAME must not clash with world module
- [Phase 388]: componentize-py 0.22.1 generates Guard protocol class (not Evaluate); dist/tool-gate.wasm is 17.6 MiB Component Model binary (version 0x0d)
- [Phase 388]: Python guard limits: 40 MiB module, 64 MiB memory (CPython needs more than SpiderMonkey); Go guards fit default 10 MiB limits
- [Phase 388]: Go guard tests use runtime path existence checks instead of #[ignore] for informative skip messages with build instructions
- [Phase 389]: Fresh backend per fixture for fuel state isolation in conformance runner
- [Phase 389]: GuardEntry carries wasm_bytes + factory fn for deferred loading; Rust guard mandatory, TS/Python/Go optional with graceful skip
- [Phase 389]: Fuel parity threshold set to 100x (not 2x) because core WASM modules vs Component Model guards differ by 60-90x inherently due to embedded runtime engines

### Roadmap Evolution

- `v3.13` was extended from phases `390-394` to `390-396` so the post-phase-392
  audit gaps have explicit owners instead of leaking into vague “qualification”
  work.
- Phase `394` now owns HTTP authority/evidence convergence.
- Phase `395` now owns A2A/ACP lifecycle and authority-surface closure.
- Phase `396` now owns the final post-closure claim qualification.
- Phases `394` through `396` are now complete locally; the remaining work is
  milestone archival rather than more v3.13 implementation.

### Pending Todos

- Archive `v3.15 Universal Protocol Fabric Realization`.
- Archive `v3.16 Universal Control-Plane Thesis`.
- Archive `v3.17 Comptroller Market Position Proof`.
- Archive `v3.18 Bounded Chio Ship Readiness Closure`.
- Observe hosted `CI` and `Release Qualification` on the bounded candidate commit before any external tag or publication.
- Resume `v4.0` planning or execution in parallel as capacity allows.

### Blockers/Concerns

- `v3.12`, `v3.13`, and `v3.14` are archived locally. `v3.15`, `v3.16`,
  `v3.17`, and `v3.18` are complete locally but not yet archived.
- `v2.83` is still partially complete locally because phase `316` remains
  pending, so it should stay marked as unresolved prior-lane debt instead of
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
Status: Phase 382 complete -- chio-guard-sdk crate has full guest-side API:
ABI-identical types (GuardRequest, GuardVerdict, GuestDenyResponse), Vec-based
allocator (chio_alloc, chio_free), typed host bindings (arc.log, arc.get_config,
arc.get_time), ABI glue (read_request, encode_verdict, chio_deny_reason), and
expanded prelude. 24 tests passing, clippy clean, fmt clean.
Last activity: 2026-04-14 -- completed 382-02 with host function bindings, ABI
glue, and expanded prelude

## v4.2 Multi-Language Guard SDKs

Phase: 388 (complete -- 03 of 03 plans done)
Plan: 03 of 3 complete
Status: Phase 388 complete -- Python SDK, Go SDK, and integration tests for
both languages. Python guard (18 MiB CPython-embedded) loads and evaluates
correctly with raised limits. Go guard tests conditional on TinyGo toolchain.
All three language SDKs (TS, Python, Go) have integration test coverage.
Last activity: 2026-04-15 -- completed 388-03 with Python and Go guard
integration tests

## Session Continuity

Last session: 2026-04-19T06:10:00Z
Stopped at: Completed the post-v3.18 closure tracker and final release-truth sync
Next action: archive `v3.15` through `v3.18`, then observe hosted release workflows on the bounded candidate
Resume file: None
