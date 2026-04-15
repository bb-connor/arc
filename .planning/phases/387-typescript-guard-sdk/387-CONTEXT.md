# Phase 387: TypeScript Guard SDK - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship arc-guard-ts TypeScript guard SDK with typed interfaces generated from the
WIT definition, jco/ComponentizeJS compilation to WASM components, example guard,
and host integration validation.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- Package at packages/sdk/arc-guard-ts/
- Types generated from WIT definition (arc:guard@0.1.0) via jco
- TypeScript guard compiles to WASM component via jco componentize
- Example guard with build instructions (zero to .wasm in under 5 commands)
- Compiled guard loads and evaluates correctly in host dual-mode runtime
- Types must match WIT contract, not be hand-maintained

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `wit/arc-guard/world.wit` -- WIT definition (Phase 386)
- `crates/arc-wasm-guards/src/component.rs` -- ComponentBackend for loading
- `crates/arc-wasm-guards/src/runtime.rs` -- create_backend() for dual-mode
- `packages/sdk/arc-ts/` -- Existing TypeScript SDK patterns

### Integration Points
- jco/ComponentizeJS toolchain for TS -> WASM component compilation
- Host dual-mode runtime loads component .wasm via ComponentBackend
- WIT types generate TypeScript interfaces

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
