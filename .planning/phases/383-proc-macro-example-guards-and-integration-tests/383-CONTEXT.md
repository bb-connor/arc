# Phase 383: Proc Macro, Example Guards, and Integration Tests - Context

**Gathered:** 2026-04-14
**Status:** Ready for planning

<domain>
## Phase Boundary

Create the arc-guard-sdk-macros crate with #[arc_guard] proc macro that generates
all ABI exports from a single annotated function. Build example guards that
demonstrate the SDK surface. Write integration tests that compile example guards
to wasm32-unknown-unknown and verify they load and evaluate correctly in the
WasmtimeBackend host runtime.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- #[arc_guard] proc macro generates: evaluate ABI export, arc_alloc, arc_free, arc_deny_reason
- Guard author writes: #[arc_guard] fn evaluate(req: GuardRequest) -> GuardVerdict { ... }
- Example guards: tool-name allow/deny, enriched field inspection, host function usage
- Examples must compile to wasm32-unknown-unknown and produce valid .wasm binaries
- Integration tests load compiled .wasm into WasmtimeBackend and verify verdicts
- Proc macro crate type: proc-macro (separate crate required by Rust)
- wasm32-unknown-unknown target must be installed for compilation

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-guard-sdk/` -- Guest SDK with types, allocator, host bindings, glue (Phase 382)
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend for loading and evaluating .wasm
- `crates/arc-wasm-guards/src/host.rs` -- Host functions that example guards will call

### Established Patterns
- proc-macro crates use syn, quote, proc-macro2 dependencies
- Integration tests in tests/ directory or as separate test binaries
- WAT-based tests used in Phases 373-376 (but here we test real compiled .wasm)

### Integration Points
- arc-guard-sdk-macros depends on proc-macro2, syn, quote
- Example guards depend on arc-guard-sdk + arc-guard-sdk-macros
- Integration tests depend on arc-wasm-guards with wasmtime-runtime feature
- wasm32-unknown-unknown target for cargo build --target

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
