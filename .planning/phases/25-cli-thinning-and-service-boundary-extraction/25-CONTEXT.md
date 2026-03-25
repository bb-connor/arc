# Phase 25: CLI Thinning and Service Boundary Extraction - Context

**Gathered:** 2026-03-25
**Status:** In Progress

<domain>
## Phase Boundary

Phase 25 is the first architectural extraction in `v2.4`. The intent is to
stop treating `pact-cli` as both command shell and service runtime host, then
move the trust-control and hosted-MCP surfaces into dedicated crates without
changing their operator-visible behavior.

</domain>

<decisions>
## Implementation Decisions

### Compatibility First
- Keep the existing CLI command shapes and HTTP contracts stable while the code
  moves underneath them.
- Prefer compatibility facades and temporary re-exports over a one-shot
  signature rewrite.

### Real Blocker Found During Discuss
- `trust_control.rs` and `remote_mcp.rs` are not self-contained service files.
  They depend on CLI-local support modules and helper functions from
  `main.rs`.
- Treat the shared support boundary as part of Plan 25-01 rather than forcing a
  direct crate extraction that would create cycles or duplicate large amounts of
  logic.

### Extraction Order
- First isolate the shared support pieces that both services currently pull from
  `pact-cli`.
- Then extract trust-control to `pact-control-plane`.
- Then extract hosted MCP to `pact-hosted-mcp`, after the trust-control client
  and common helpers are no longer anchored in the CLI crate.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 25 goal, crate moves, and success criteria
- `.planning/REQUIREMENTS.md` -- `ARCH-01`, `ARCH-02`, `ARCH-03`
- `Cargo.toml` -- current workspace members
- `crates/pact-cli/Cargo.toml` -- current CLI dependency surface
- `crates/pact-cli/src/main.rs` -- current mixed command/runtime entrypoint and
  shared helper functions
- `crates/pact-cli/src/trust_control.rs` -- trust-control server and client
  implementation
- `crates/pact-cli/src/remote_mcp.rs` -- hosted MCP runtime implementation
- `crates/pact-cli/src/policy.rs` -- policy loading and runtime policy types
- `crates/pact-cli/src/certify.rs` -- certification registry support
- `crates/pact-cli/src/enterprise_federation.rs` -- enterprise provider registry
- `crates/pact-cli/src/issuance.rs` -- issuance-policy wrappers for capability
  authority
- `crates/pact-cli/src/passport_verifier.rs` -- verifier policy and challenge
  registry support
- `crates/pact-cli/src/evidence_export.rs` -- export/import helper surface
- `crates/pact-cli/src/reputation.rs` -- reputation-report helper surface

</canonical_refs>

<code_context>
## Existing Code Insights

- `crates/pact-cli/src/trust_control.rs` imports CLI-local modules including
  `certify`, `enterprise_federation`, `evidence_export`, `issuance`,
  `passport_verifier`, and `reputation`, plus authority helper functions and
  `CliError`.
- `crates/pact-cli/src/remote_mcp.rs` imports `build_kernel`,
  `configure_receipt_store`, `configure_revocation_store`,
  `configure_capability_authority`, `configure_budget_store`,
  `issue_default_capabilities`, authority keypair helpers, `policy::load_policy`,
  and `trust_control` query/client types.
- `crates/pact-cli/src/main.rs` still centralizes kernel construction, local
  authority file management, local-vs-remote store wiring, and top-level command
  dispatch.
- A direct file move from `pact-cli` into two new crates will not compile
  cleanly without first creating a shared support boundary for the reused logic.

</code_context>

<deferred>
## Deferred Ideas

- Decide the final name of the shared support crate during execution
  (`pact-runtime-support` vs `pact-app-support`) once the dependency graph is
  laid out concretely.
- Fold deeper trust-control and hosted-MCP module splits into this phase only
  after the crate boundaries compile and tests are back to green.
- Leave the kernel/store split for Phase 26; do not blur the milestones by
  dragging SQLite extraction into Phase 25.

</deferred>

---

*Phase: 25-cli-thinning-and-service-boundary-extraction*
*Context gathered: 2026-03-25*
