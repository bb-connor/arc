# Phase 23: Observability and Protocol v2 Alignment - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 23 closes the production-diagnostics and spec-drift gap in `v2.3`. The
focus is not new trust product breadth. It is exposing the runtime state that
operators actually need in production and rewriting the protocol doc so it
describes the shipped repository profile instead of an aspirational draft.

</domain>

<decisions>
## Implementation Decisions

### Observability Contract
- Expand trust-control `/health` into an additive JSON contract that exposes
  authority, store, federation, and cluster state explicitly.
- Add hosted-edge `/admin/health` instead of forcing operators to infer runtime
  health from session listings alone.
- Treat A2A observability as a combination of explicit fail-closed error
  classes and durable task-registry state rather than inventing a separate
  adapter-local health server.

### Documentation Cut
- Add one operator-facing observability guide instead of scattering ad hoc
  troubleshooting notes across unrelated docs.
- Rewrite `spec/PROTOCOL.md` to the shipped `v2` contract and call out
  intentional non-goals explicitly.

### Verification
- Prove the new health fields through trust-control and hosted-edge integration
  tests rather than relying on doc-only descriptions.
- Use targeted `rg` verification for the observability and protocol docs so the
  milestone records the exact operator contract that was documented.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 23 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `PROD-11`, `PROD-12`
- `crates/pact-cli/src/trust_control.rs` -- trust-control `/health`
- `crates/pact-cli/src/remote_mcp.rs` -- hosted-edge `/admin/health`
- `crates/pact-cli/tests/provider_admin.rs` -- trust-control health regression
- `crates/pact-cli/tests/mcp_serve_http.rs` -- hosted-edge health regression
- `crates/pact-cli/tests/certify.rs` -- certification health coverage
- `docs/release/OBSERVABILITY.md` -- operator diagnostics contract
- `docs/release/OPERATIONS_RUNBOOK.md` -- deploy-time use of the health/admin
  surfaces
- `spec/PROTOCOL.md` -- shipped protocol and artifact contract
- `docs/A2A_ADAPTER_GUIDE.md` -- A2A diagnostics and durable task correlation

</canonical_refs>

<code_context>
## Existing Code Insights

- Trust-control already had `/health`, but it only reported basic readiness and
  leader context; it did not explain federation or registry state.
- Hosted MCP edges already had session and authority admin APIs, but no single
  summarized health contract.
- Provider-admin, verifier-policy, and certification state already existed in
  file-backed registries; the gap was reporting that state clearly and truthfully.
- `spec/PROTOCOL.md` was still the older pre-RFC draft and no longer matched
  the shipped capability, receipt, trust-control, portable-trust, and
  certification surface.

</code_context>

<deferred>
## Deferred Ideas

- Add metrics export or alerting integrations once a production metrics backend
  contract exists.
- Split the remaining oversized runtime files further in later milestones.
- Broaden A2A observability beyond task-registry and fail-closed error
  semantics if the adapter later grows a long-running service process.

</deferred>

---

*Phase: 23-observability-and-protocol-v2-alignment*
*Context gathered: 2026-03-25*
