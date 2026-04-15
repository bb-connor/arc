# Phase 384: CLI Scaffolding -- New, Build, Inspect - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Add guard subcommands to the existing arc CLI: `arc guard new <name>` scaffolds
a new guard project, `arc guard build` compiles to wasm32-unknown-unknown, and
`arc guard inspect <path>` reads a .wasm binary and reports exports and ABI
compatibility. These are the first three steps of the guard development lifecycle.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- CLI location: arc-cli/src/cli/guard.rs (new module in existing arc-cli crate)
- `arc guard new my-guard` creates: Cargo.toml (depends on arc-guard-sdk + macros), src/lib.rs (#[arc_guard] skeleton), guard-manifest.yaml (placeholder)
- `arc guard build` compiles to wasm32-unknown-unknown in release mode, reports output path and size
- `arc guard inspect path/to/guard.wasm` prints: exported functions, ABI compatibility (evaluate, arc_alloc, arc_deny_reason present), linear memory config
- Uses wasmparser for .wasm inspection (already in workspace via wasmtime)
- clap subcommands for CLI structure (already used by arc-cli)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc-cli/` -- Existing CLI crate with clap-based command structure
- `examples/guards/tool-gate/` -- Example guard project (template for `arc guard new`)
- `crates/arc-guard-sdk-macros/` -- Proc macro crate (Phase 383)

### Established Patterns
- clap derive API for CLI commands
- Subcommand pattern in existing arc-cli
- guard-manifest.yaml format from Phase 375

### Integration Points
- arc-cli/Cargo.toml needs wasmparser dependency for inspect
- Arc CLI main.rs needs guard subcommand registration
- wasm32-unknown-unknown target for build command

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
