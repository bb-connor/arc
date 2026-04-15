# Phase 386: WIT Interface and Dual-Mode Host - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Define the arc:guard@0.1.0 WIT interface, implement Component Model host support
via wasmtime::component::bindgen!, and add dual-mode loading that detects whether
a .wasm file is a core module (raw ABI) or Component Model component (WIT ABI)
and evaluates through the correct path.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- WIT package at wit/arc-guard/world.wit defines arc:guard@0.1.0 world
- evaluate function accepts guard-request record, returns verdict variant
- Host uses wasmtime::component::bindgen! to generate Rust types from WIT
- Dual-mode: detect core module vs component at load time
- Existing raw-ABI guards continue to work unchanged
- WIT package includes versioned world definition with doc comments
- SDK toolchains (jco, componentize-py, TinyGo) can consume the WIT

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend (raw ABI path)
- `crates/arc-wasm-guards/src/abi.rs` -- GuardRequest/GuardVerdict (WIT types should match)
- wasmtime 29.0.1 includes component model support (wasmtime::component)

### Integration Points
- wit/arc-guard/ directory for WIT package
- crates/arc-wasm-guards/ gets component model loading path
- Cargo.toml may need wasmtime component feature flag
- Dual-mode detection in load_module or a new component loading path

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
