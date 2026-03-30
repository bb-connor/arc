# Phase 25 Research

**Phase:** 25-cli-thinning-and-service-boundary-extraction
**Date:** 2026-03-25
**Status:** Complete

## Research Question

What is the lowest-breakage way to extract `trust_control.rs` and
`remote_mcp.rs` out of `arc-cli` when both currently depend on CLI-local
modules and helper functions?

## Findings

### 1. Direct extraction is not currently clean

`crates/arc-cli/src/trust_control.rs` depends on:
- `certify`
- `enterprise_federation`
- `evidence_export`
- `issuance`
- `passport_verifier`
- `reputation`
- authority key helpers
- `CliError`

`crates/arc-cli/src/remote_mcp.rs` depends on:
- `policy::load_policy`
- `trust_control` query/client types
- `build_kernel`
- `configure_receipt_store`
- `configure_revocation_store`
- `configure_capability_authority`
- `configure_budget_store`
- `issue_default_capabilities`
- authority key helpers
- `CliError`

That means a literal file move to `arc-control-plane` and `arc-hosted-mcp`
would either:
- create a dependency cycle back into `arc-cli`, or
- duplicate a large amount of shared logic.

### 2. There is an implicit shared support layer already

The current CLI crate contains a mixed set of concerns:
- command parsing and dispatch
- service runtimes (`trust_control.rs`, `remote_mcp.rs`)
- shared runtime helpers in `main.rs`
- app-support modules such as policy loading, certification registry,
  federation registry, issuance wrappers, and verifier registries

The extraction can be made honest if that shared support layer becomes its own
library boundary first.

### 3. Recommended execution shape

The least-breakage path for Phase 25 is:
1. Create a shared support crate for reusable runtime helpers and support
   modules currently anchored in `arc-cli`.
2. Move trust-control into `arc-control-plane` on top of that shared support
   crate.
3. Move hosted MCP into `arc-hosted-mcp`, reusing the same shared support
   pieces and the extracted trust-control client APIs.
4. Reduce `arc-cli` to command definitions and thin command dispatch.

## Recommended Assumption

Phase 25 should allow one small additional support crate as an implementation
detail, even though the roadmap names only the two service crates. Without that
shared boundary, the extraction is not a realistic low-breakage move.

## Verification Targets For Execution

- `cargo test -p arc-cli --test provider_admin -- --nocapture`
- `cargo test -p arc-cli --test certify -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test -p arc-cli --test receipt_query -- --nocapture`

## Non-Goals

- Do not start the SQLite store split in this phase.
- Do not change operator-visible HTTP routes or CLI flags in this phase.
