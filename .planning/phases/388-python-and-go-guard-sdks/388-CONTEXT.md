# Phase 388: Python and Go Guard SDKs - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Ship arc-guard-py (componentize-py) and arc-guard-go (TinyGo wasip2) SDKs with
typed bindings from WIT, example guards, and host integration validation for
both languages. Both depend on Phase 386's WIT foundation.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- Python SDK at packages/sdk/arc-guard-py/ using componentize-py
- Go SDK at packages/sdk/arc-guard-go/ using TinyGo with wasip2 target
- Types generated from WIT definition (arc:guard@0.1.0)
- Example guards for both languages with build instructions
- Compiled guards load and evaluate in host dual-mode runtime
- Build from zero to .wasm in under 5 commands per language

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `wit/arc-guard/world.wit` -- WIT definition (Phase 386)
- `crates/arc-wasm-guards/src/component.rs` -- ComponentBackend
- `crates/arc-wasm-guards/src/runtime.rs` -- create_backend() dual-mode
- `packages/sdk/arc-guard-ts/` -- TS SDK pattern (Phase 387)
- `packages/sdk/arc-py/` -- Existing Python SDK patterns
- `packages/sdk/arc-go/` -- Existing Go SDK patterns

### Integration Points
- componentize-py for Python -> WASM component compilation
- TinyGo wasip2 for Go -> WASM component compilation
- Host dual-mode runtime loads via ComponentBackend

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
