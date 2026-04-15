# Phase 385: CLI Test, Bench, Pack, and Install - Context

**Gathered:** 2026-04-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Complete the guard development lifecycle CLI: `arc guard test` runs .wasm against
YAML fixtures, `arc guard bench` measures fuel/latency, `arc guard pack` creates
.arcguard archives, `arc guard install` extracts them. Completes v4.1.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion -- pure infrastructure
phase. Key constraints:

- `arc guard test` loads .wasm, runs against YAML fixture files specifying request/expected verdict/deny reason
- YAML fixture format: request fields, expected verdict (allow/deny), optional deny reason substring
- `arc guard bench <path>` measures fuel and execution time, reports p50/p99
- `arc guard pack` creates .arcguard gzipped tar (guard-manifest.yaml + .wasm)
- `arc guard install <path>` extracts .arcguard to configured guard directory
- All commands in crates/arc-cli/src/guard.rs (extend existing module from Phase 384)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-cli/src/guard.rs` -- Guard subcommand module (Phase 384: new, build, inspect)
- `crates/arc-cli/src/cli/types.rs` -- GuardCommands enum (needs Test, Bench, Pack, Install variants)
- `crates/arc-wasm-guards/src/runtime.rs` -- WasmtimeBackend for test/bench execution
- `crates/arc-wasm-guards/src/host.rs` -- Host function setup

### Integration Points
- GuardCommands enum in types.rs needs 4 new variants
- guard.rs needs 4 new command handler functions
- arc-cli/Cargo.toml may need flate2/tar for archive operations
- YAML fixture format for test command

</code_context>

<specifics>
## Specific Ideas

No specific requirements -- infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
