# Phase 17: A2A Auth Matrix and Partner Admission Hardening - Context

**Gathered:** 2026-03-25
**Status:** Completed

<domain>
## Phase Boundary

Phase 17 closes the remaining operator-configurable A2A auth surfaces and
partner-admission checks that were still too implicit in the alpha adapter.
The shipped result keeps discovery and invocation fail closed while letting
operators provide provider-specific request headers, query params, and cookies
without writing bespoke per-call glue.

</domain>

<decisions>
## Implementation Decisions

### Explicit Request Auth Surfaces
- Discovery and invoke now share adapter-level request headers, query params,
  and cookies.
- These surfaces are explicit configuration, not hidden fallback behavior.
- Auth negotiation still resolves from the peer's advertised requirements and
  fails closed when the operator has not configured a satisfiable scheme.

### Partner Admission Contract
- Partner admission is an explicit policy object rather than ad hoc host checks.
- Admission can require tenant, skill, security scheme, and allowed interface
  origins.
- Discovery rejects peers that do not satisfy the declared partner policy
  before any mediated traffic is sent.

### Diagnostics
- Auth and admission failures include partner, skill, interface, and tenant
  context.
- The adapter does not silently downgrade from an advertised requirement to a
  weaker configured credential path.

</decisions>

<canonical_refs>
## Canonical References

- `.planning/ROADMAP.md` -- Phase 17 goal and success criteria
- `.planning/REQUIREMENTS.md` -- `A2A-01`, `A2A-02`
- `crates/pact-a2a-adapter/src/lib.rs` -- adapter config, auth negotiation, and
  partner policy implementation
- `docs/A2A_ADAPTER_GUIDE.md` -- operator-facing auth and partner-admission docs

</canonical_refs>

<code_context>
## Existing Code Insights

- The adapter alpha already supported bearer, basic, api-key, OAuth client
  credentials, OpenID discovery, mTLS, streaming, and task follow-up flows.
- The remaining gap was not raw protocol support; it was operator usability and
  explicit fail-closed partner admission around those flows.
- Adapter integration tests already covered the auth matrix, making the best
  implementation seam `A2aAdapterConfig` plus discovery-time validation.

</code_context>

<deferred>
## Deferred Ideas

- Dynamic partner catalogs or signed admission policies
- Centralized admin CRUD for A2A partner policy objects
- Provider-specific auth plugins beyond explicit request shaping

</deferred>

---

*Phase: 17-a2a-auth-matrix-and-partner-admission-hardening*
*Context gathered: 2026-03-25*
