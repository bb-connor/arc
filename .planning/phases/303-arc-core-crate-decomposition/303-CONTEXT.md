# Phase 303: arc-core Crate Decomposition - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Split the monolithic `arc-core` crate into a minimal shared `arc-core-types`
crate plus domain-oriented crates so downstream crates only compile the types
they actually depend on, without changing ARC behavior.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure
phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Workspace crate boundaries are already established under `crates/`, with
  `Cargo.toml` managing shared versions and crate membership centrally.
- `crates/arc-core/src/lib.rs` already segments the monolith into domain
  modules (`capability`, `receipt`, `credit`, `market`, `governance`,
  `federation`, etc.), which provides the extraction seam for new crates.
- Most dependent crates already consume `arc-core` via path dependencies in
  their own `Cargo.toml`, so the migration surface is explicit and auditable.

### Established Patterns
- Rust workspace members use focused crate boundaries with `lib.rs` as the
  stable public export surface.
- Shared domain and protocol types are centralized in reusable crates rather
  than duplicated across products.
- Public APIs prefer strong typing, typed errors, and stable re-exports from
  crate roots.

### Integration Points
- Root `Cargo.toml` workspace membership and shared dependencies will need to
  add the new decomposition crates.
- `crates/arc-core/src/lib.rs` is the primary extraction and compatibility
  boundary for the split.
- All crates currently depending on `arc-core` will need dependency and import
  updates to target `arc-core-types` and any extracted domain crates.

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase.

</specifics>

<deferred>
## Deferred Ideas

None.

</deferred>
