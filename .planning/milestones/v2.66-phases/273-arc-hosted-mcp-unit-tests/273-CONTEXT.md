# Phase 273: arc-hosted-mcp Unit Tests - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Add hosted-MCP test coverage that exercises the real HTTP/session/auth runtime
behind `arc-hosted-mcp` so regressions in session lifecycle, tenant isolation,
OAuth and bearer admission, and structured fail-closed error handling are
caught under test before CI.

</domain>

<decisions>
## Implementation Decisions

### Test Surface
- Prefer black-box integration tests in `crates/arc-hosted-mcp/tests/` over
  production refactors; the crate is a thin wrapper over
  `crates/arc-cli/src/remote_mcp.rs`, so the tests should validate the hosted
  crate's exported runtime behavior rather than re-test private helpers only.
- Reuse the repo's existing hosted-MCP test style: spawn the real HTTP server,
  use temp dirs and random localhost ports, and talk to `/mcp`, `/oauth/*`,
  and `/admin/*` over real HTTP instead of heavy mocks.
- Keep helper code local to the new hosted-MCP test file or a small
  test-only support module beside it; do not introduce a new shared test
  framework unless duplication becomes material during implementation.
- Treat the existing `remote_mcp_impl::tests` unit tests as supporting
  coverage only; phase success requires session/runtime coverage that drives
  the full hosted surface.

### Session Lifecycle Coverage
- Cover initialize plus token-backed session reuse, then force expiry with the
  existing short-TTL environment hooks so lifecycle behavior is asserted with
  fast deterministic tests instead of sleeps measured in minutes.
- Use observable HTTP behavior as the source of truth: `MCP-Session-Id`,
  `/admin/sessions/{id}/trust`, `/admin/sessions`, and structured terminal
  responses should prove create/resume/expire semantics.
- Validate lifecycle failures as protocol responses, not log scraping: expired,
  draining, deleted, or unknown sessions must return the documented structured
  HTTP errors or terminal-session payloads.
- Preserve the earlier ARC decision from hosted auth phases that session reuse
  stays fail-closed when the authenticated context no longer matches.

### Auth and Tenant Isolation
- Cover static bearer, JWT/JWKS, and local OAuth auth-code-with-PKCE flows
  under test because those are the concrete runtime admission paths already
  implemented in the repo and named in the phase success criteria.
- Reuse the existing JWT and OAuth fixtures from `crates/arc-cli/tests` as the
  canonical behavior reference, including tenant and organization claims.
- For tenant isolation, assert that sessions created under different tenant or
  principal claims cannot reuse one another's `mcp-session-id`, cannot obtain
  each other's trust/session views through user-authenticated flows, and leave
  attributable receipt evidence tied to the correct subject/tenant.
- Do not widen admin behavior for this phase; admin endpoints remain separately
  authenticated, while tenant isolation assertions focus on session-authenticated
  runtime behavior and receipt attribution.

### Error Assertions
- Favor explicit structured-error assertions for malformed JSON-RPC bodies,
  missing required headers, invalid session headers, expired tokens, and wrong
  audience or principal mismatches.
- Reuse existing fail-closed messages from `remote_mcp.rs` where practical so
  tests pin the current contract instead of introducing a second error dialect.
- Add negative tests only where the response shape is stable and meaningful to
  downstream callers; avoid brittle assertions on incidental wording outside the
  protocol contract.
- Treat "never panic" as an executable requirement by running these cases
  through the live HTTP surface and asserting error responses instead of
  process crashes or hangs.

### Claude's Discretion
Implementation details such as whether helpers live in one or two test files,
how much fixture code is copied versus extracted, and whether a small amount of
test-only cleanup in `arc-hosted-mcp` is needed are at Claude's discretion as
long as the phase stays focused on hosted-MCP test coverage.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/arc-cli/tests/mcp_serve_http.rs` already contains hosted-MCP HTTP
  server spawn helpers, session initialization helpers, and lifecycle/auth/error
  test patterns that can be adapted for `arc-hosted-mcp`.
- `crates/arc-cli/tests/mcp_auth_server.rs` already contains local OAuth
  authorization-code + PKCE helpers and token-exchange fixtures that match the
  phase's auth-flow requirements.
- `crates/arc-cli/src/remote_mcp.rs` already exposes unit-tested JWT and
  introspection verifier helpers through `arc-hosted-mcp` via `#[path]`.

### Established Patterns
- Integration tests in this repo favor real subprocesses, temp directories,
  local SQLite files, random localhost ports, and direct HTTP assertions.
- Test helpers stay near the tests that use them rather than being centralized
  unless there is clear repeated value.
- Security-sensitive behavior is expected to fail closed with typed/structured
  responses, and tests should assert those runtime contracts directly.

### Integration Points
- Hosted runtime entrypoints live in `crates/arc-cli/src/remote_mcp.rs` and are
  re-exported by `crates/arc-hosted-mcp/src/lib.rs`.
- Session lifecycle and terminal behavior surface through `/mcp`,
  `MCP-Session-Id`, `/admin/sessions`, and `/admin/sessions/{session_id}/trust`.
- OAuth and bearer admission surfaces live at `/.well-known/oauth-*`,
  `/oauth/authorize`, and `/oauth/token`, with receipt attribution observable
  through the hosted/admin receipt endpoints.

</code_context>

<specifics>
## Specific Ideas

Use the existing `mcp_serve_http` and `mcp_auth_server` test files as the
behavioral reference, but keep the new phase scoped to the `arc-hosted-mcp`
crate by adding hosted-focused integration tests there rather than treating
`arc-cli` coverage as sufficient.

</specifics>

<deferred>
## Deferred Ideas

Soak/load testing, browser-facing OAuth UX polish, admin-dashboard assertions,
and cross-crate end-to-end workflow coverage belong to later ship-readiness
phases, especially phase 276.

</deferred>
