# Phase 304: Mega-File Module Decomposition - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Decompose the current oversized Rust entrypoints into focused internal module
trees without changing public behavior or the exported ARC surface. This phase
delivers structural file and module boundaries only: `trust_control.rs`,
`arc-kernel/src/lib.rs`, `arc-cli/src/main.rs`, `receipt_store.rs`, and
`arc-mcp-edge/src/runtime.rs` must stop acting as giant aggregation units, and
the non-test source tree must end with no file over 3,000 lines.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- All implementation choices are at Claude's discretion — pure infrastructure
  phase.
- Preserve public APIs, CLI behavior, wire formats, and test semantics while
  moving code behind internal module boundaries.
- Prefer decomposition along existing semantic seams already visible in the
  code: trust-control subdomains, CLI command families, kernel subsystems,
  receipt-store query/reporting helpers, and MCP runtime protocol/task lanes.
- Use thin entrypoint files that re-export or dispatch into submodules rather
  than inventing new abstractions in this phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-cli/src/trust_control/health.rs` already proves the trust-control
  surface can be split behind `#[path = ...]` modules without breaking the
  command entrypoint.
- `crates/arc-mcp-edge/src/runtime/protocol.rs` already extracts one focused
  submodule from the current `runtime.rs` file.
- `crates/arc-cli/src/` already contains separate files for adjacent command
  families such as `admin.rs`, `did.rs`, `passport.rs`, `policy.rs`,
  `reputation.rs`, and `remote_mcp/`.
- `crates/arc-kernel/src/` and `crates/arc-store-sqlite/src/` already use
  file-per-subsystem layouts outside their oversized aggregation files.

### Established Patterns
- The repo already uses thin crate roots that expose dedicated subsystem
  modules, as seen in `arc-kernel/src/lib.rs`.
- Transitional decomposition via `#[path = ...] mod ...;` is already accepted
  in the codebase and should be reused to keep diffs incremental.
- CLI and runtime code generally organize around command families, transport
  concerns, persistence concerns, and reporting/query helpers rather than broad
  utility buckets.

### Integration Points
- `crates/arc-cli/src/trust_control.rs` is the current integration root for
  trust-control HTTP routes, federation, passport, certification, and remote
  control-plane state.
- `crates/arc-cli/src/main.rs` is the user-facing dispatch root that must end
  as a thin command router.
- `crates/arc-kernel/src/lib.rs` is the trusted kernel entrypoint and re-export
  surface; decomposition must preserve crate-level visibility.
- `crates/arc-store-sqlite/src/receipt_store.rs` is the durable evidence and
  reporting hub for SQLite persistence.
- `crates/arc-mcp-edge/src/runtime.rs` is the MCP session/runtime loop and must
  keep its protocol coupling intact while being split into focused modules.

</code_context>

<specifics>
## Specific Ideas

- Current oversized files from the codebase scan:
  - `crates/arc-cli/src/trust_control.rs` — 21,082 lines
  - `crates/arc-kernel/src/lib.rs` — 11,788 lines
  - `crates/arc-cli/src/main.rs` — 10,387 lines
  - `crates/arc-store-sqlite/src/receipt_store.rs` — 9,861 lines
  - `crates/arc-mcp-edge/src/runtime.rs` — 6,483 lines
- Nearby oversized files such as `crates/arc-mercury/src/commands.rs` and
  `crates/arc-cli/src/remote_mcp.rs` may still require follow-on handling to
  satisfy the global file-length requirement, but phase 304 should first clear
  the roadmap-named targets and then re-run the size gate.

</specifics>

<deferred>
## Deferred Ideas

- Any behavioral redesign of the CLI, trust-control API, kernel semantics, or
  MCP runtime belongs in later phases; this phase is structural only.
- Any additional mega-file cleanup outside the named targets should be treated
  as follow-on work unless it is strictly necessary to satisfy DECOMP-09.

</deferred>
