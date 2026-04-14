# Phase 375: Guard Manifest, Startup Wiring, and Receipt Integration - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Guard manifest format (guard-manifest.yaml) with SHA-256 verification, startup
wiring that loads HushSpec-compiled guards first then WASM guards sorted by
priority then advisory guards, and receipt metadata including fuel consumed and
manifest SHA-256 hash.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- guard-manifest.yaml format: name, version, abi_version, wasm_path, config, wasm_sha256
- SHA-256 verification of .wasm binary against declared hash at load time
- abi_version validation: reject unsupported versions
- Config values from manifest config block loaded into WasmHostState
- HushSpec-first pipeline order: compile_policy() guards -> WASM by priority -> advisory
- WasmGuardEntry sorted by priority field before loading (fix known gotcha)
- Fuel consumed and manifest SHA-256 in receipt metadata
- Use arc_policy::compiler::compile_policy() for HushSpec guards (not default_pipeline)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmGuardRuntime with load_guard()
- `crates/arc-wasm-guards/src/config.rs` -- WasmGuardConfig
- `crates/arc-wasm-guards/src/host.rs` -- WasmHostState with config HashMap
- `crates/arc-policy/src/compiler.rs` -- compile_policy() -> GuardPipeline
- `crates/arc-config/src/schema.rs` -- WasmGuardEntry with deny_unknown_fields

### Established Patterns
- serde for YAML deserialization (serde_yaml or similar)
- SHA-256 via sha2 crate (already in workspace)
- GuardPipeline ordering from arc-guards/src/pipeline.rs

### Integration Points
- WasmGuardRuntime.load_guard() needs manifest-aware loading
- Kernel receipt metadata for fuel/hash
- Startup code that constructs the guard pipeline

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
