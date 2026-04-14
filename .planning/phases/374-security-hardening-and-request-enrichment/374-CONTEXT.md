# Phase 374: Security Hardening and Request Enrichment - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Security-harden the WASM guard runtime (ResourceLimiter for memory caps, import
validation to reject non-arc imports, module size validation) and enrich
GuardRequest with host-extracted action context fields (action_type,
extracted_path, extracted_target, filesystem_roots, matched_grant_index) while
removing the always-None session_metadata field.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key design constraints from docs/guards/05-V1-DECISION.md:

- ResourceLimiter caps at configurable limit, default 16 MiB
- No WASI: modules importing outside arc namespace must be rejected at load time
- Module size validated before compilation (configurable max)
- GuardRequest enrichment uses existing extract_action() from arc-guards
- session_metadata removal is a breaking ABI change but acceptable (always None)
- Fail-closed: memory cap violation, import validation failure, oversized modules all deny

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState with StoreLimits already wired (Phase 373)
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend with Arc<Engine> and Store<WasmHostState>
- `crates/arc-wasm-guards/src/abi.rs` -- GuardRequest struct (needs field additions + session_metadata removal)
- `crates/arc-guards/src/action.rs` -- extract_action() and ActionType enum for action context
- `crates/arc-kernel/src/kernel/mod.rs` -- GuardContext with session_filesystem_roots and matched_grant_index

### Established Patterns
- StoreLimits already set on WasmHostState (Phase 373 prepared this)
- wasmtime::ResourceLimiter trait for memory limiting
- Module import iteration via wasmtime::Module::imports()
- WasmGuardConfig already has fuel_limit field pattern for adding max_memory_bytes/max_module_size

### Integration Points
- GuardContext provides session_filesystem_roots and matched_grant_index
- extract_action() from arc-guards provides action_type, extracted_path, extracted_target
- WasmGuardConfig in arc-config schema has deny_unknown_fields (new config fields need schema change)

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
