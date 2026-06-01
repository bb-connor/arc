# chio-mcp-remote architecture note

## Boundaries

- `lib.rs` owns the public crate surface, remote MCP module wiring, and the `serve_http(RemoteServeHttpConfig)` entrypoint.
- `remote_mcp/http_service.rs` owns Axum routing, HTTP request admission, SSE response shaping, hosted MCP session dispatch, OAuth discovery metadata, and request-time authorization validation.
- `remote_mcp/oauth.rs` owns local authorization-server flow handling, token exchange, bearer extraction, JWT and introspection authentication, protocol header validation, and HTTP error projection.
- `remote_mcp/session_core.rs` owns remote session lifecycle state, resumable records, shared hosted upstream ownership, session workers, capability issuance, and kernel construction.
- `remote_mcp/session_store.rs` owns SQLite-backed active session rows, terminal tombstones, resume-record loading, tombstone loading, tombstone purging, and persisted capability freshness checks.
- `remote_mcp/admin.rs` owns operator-only health, authority, receipt, revocation, budget, session, and trust-control routes.

## Pain Points

- `session_core.rs` mixes session lifecycle orchestration with raw SQLite table definitions and persistence helpers.
- Active resumable rows fail closed when the row key and serialized payload disagree, but terminal tombstone rows are loaded without the same key/payload consistency check.
- A corrupt terminal tombstone can therefore enter the in-memory ledger under one lookup key while reporting a different `sessionId` in admin diagnostics.
- The flat `include!` layout makes ownership unclear enough that storage invariants are easy to apply to active rows but miss tombstone rows.

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

Move SQLite-backed remote session state into an internal persistence module and make terminal tombstone loading enforce the same row-key versus payload-session invariant already used for active resumable rows. This is architectural because it gives session storage one owning boundary and tightens the recovery/admin diagnostic trust boundary without changing hosted MCP wire APIs.
