# Phase 373: WASM Runtime Host Foundation - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Complete the arc-wasm-guards host-side runtime foundation: shared Arc<Engine>,
WasmHostState struct, host functions (arc.log, arc.get_config,
arc.get_time_unix_secs), arc_alloc/arc_deny_reason guest export detection,
and bounded log buffer. Transforms the Phase 347 skeleton into a proper
host execution environment.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key design constraints from docs/guards/05-V1-DECISION.md:

- Raw core-WASM ABI (not WIT/Component Model)
- Stateless per-call: fresh Store per invocation
- Sync only: kernel Guard trait is synchronous
- Fail-closed everywhere
- JSON over linear memory
- No WASI: guards get only arc.* host function imports

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend with per-guard Engine (must refactor to shared Arc<Engine>)
- `crates/arc-wasm-guards/src/abi.rs` -- GuardRequest, GuardVerdict, WasmGuardAbi trait, ABI constants
- `crates/arc-wasm-guards/src/config.rs` -- WasmGuardConfig with name, path, fuel_limit, priority, advisory
- `crates/arc-wasm-guards/src/error.rs` -- WasmGuardError enum

### Established Patterns
- Store<()> currently uses unit type -- must replace with WasmHostState
- Offset-0 memory write for request data (fallback when no arc_alloc)
- Offset-64K NUL-terminated string for deny reason (fallback when no arc_deny_reason)
- Mutex<Box<dyn WasmGuardAbi>> for thread-safe backend access

### Integration Points
- arc_kernel::Guard trait (evaluate method)
- GuardContext with request, scope, agent_id, server_id, session_filesystem_roots, matched_grant_index
- WasmGuardRuntime.into_guards() -> Vec<Box<dyn Guard>>

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
