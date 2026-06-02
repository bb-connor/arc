# chio-mcp-remote architecture note

## Boundaries

- `lib.rs` owns the public crate surface, remote MCP module wiring, and the `serve_http(RemoteServeHttpConfig)` entrypoint.
- `remote_mcp/http_service.rs` owns Axum routing, HTTP request admission, SSE response shaping, hosted MCP session dispatch, OAuth discovery metadata, and request-time authorization validation.
- `remote_mcp/oauth.rs` owns local authorization-server flow handling, token exchange, bearer extraction, JWT and introspection authentication, protocol header validation, and HTTP error projection.
- `remote_mcp/session_core.rs` owns remote session lifecycle state, resumable records, shared hosted upstream ownership, session workers, capability issuance, and kernel construction.
- `remote_mcp/session_store.rs` owns SQLite-backed active session rows, terminal tombstones, resume-record loading, tombstone loading, tombstone purging, and persisted capability freshness checks.
- `remote_mcp/admin.rs` owns operator-only health, authority, receipt, revocation, budget, session, and trust-control routes.

## Pain Points

- `http_service.rs` owns the public hosted MCP admission boundary, but `MCP-Session-Id` parsing is currently represented as `Option<String>`.
- That optional helper conflates three different protocol states: header missing, header present but malformed, and header present on initialize where any session header is forbidden.
- Empty or padded session identifiers can therefore proceed to session lookup as ordinary unknown sessions instead of failing at HTTP admission as invalid protocol input.
- The flat `include!` layout still makes it easy for admission helpers, lifecycle helpers, and OAuth error projection to bleed into each other instead of forming explicit internal APIs.

## Constraints

- Preserve the public `serve_http(RemoteServeHttpConfig)` entrypoint and `RemoteServeHttpConfig` fields.
- Preserve hosted MCP wire behavior for `POST /mcp`, `GET /mcp`, `DELETE /mcp`, `MCP-Session-Id`, `MCP-Protocol-Version`, SSE replay, and ready-state admission.
- Preserve OAuth bearer, JWT, introspection, DPoP, mTLS thumbprint, attestation-bound, resource-indicator, and request-time authorization fail-closed semantics.
- Preserve receipt, revocation, budget, capability, session lifecycle, resumability, shared hosted owner, and admin route behavior.
- Keep changes scoped to `chio-mcp-remote` unless dependent tests prove a compatibility update is required.

## Dependents

- `chio-cli` exposes `chio mcp serve-http` through this crate.
- `chio-hosted-mcp` is a compatibility surface that re-exports the remote server entrypoint.
- `docs/guides/MIGRATING-FROM-MCP.md`, `docs/release/OPERATIONS_RUNBOOK.md`, and `spec/PROTOCOL.md` describe the hosted MCP HTTP/SSE lifecycle.
- `spec/SECURITY.md` defines hosted MCP TLS, DPoP, mTLS, and sender-proof requirements.
- Admin session diagnostics depend on terminal tombstone records staying internally consistent.

## Planned Improvement

Introduce an internal hosted-session header admission boundary with explicit missing, invalid, and valid states for `MCP-Session-Id`. Established-session `POST`, `GET`, and `DELETE` requests should require a non-empty canonical header value before session lookup, while initialize requests should reject any present session header regardless of its value. This is architectural because it turns a public wire-protocol invariant into a typed boundary at the Axum edge without changing the public `serve_http` API or the generated session identifier format.
