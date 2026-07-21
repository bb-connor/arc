# chio-mcp-remote architecture note

## Boundaries

- `lib.rs` owns the public crate surface, remote MCP module wiring, and the `serve_http(RemoteServeHttpConfig)` entrypoint.
- `remote_mcp/http_service.rs` owns Axum routing, HTTP request admission, SSE response shaping, hosted MCP session dispatch, and peer capability parsing.
- `remote_mcp/http_service_auth.rs` owns HTTP session-id extraction, remote auth-state construction, OAuth discovery metadata, local authorization-server wiring, request-time authorization validation, sender constraints, and DPoP runtime checks.
- `remote_mcp/oauth.rs` owns local authorization-server flow handling, token exchange, bearer extraction, JWT and introspection authentication, protocol header validation, and HTTP error projection.
- `remote_mcp/session_core.rs` owns remote session lifecycle state, session workers, capability issuance, and kernel construction.
- `remote_mcp/session_identity.rs` owns OIDC/JWKS discovery, JWT key resolution, federated principal construction, and enterprise identity context helpers.
- `remote_mcp/session_resume.rs` owns auth, policy, exact admitted-registry, and upstream service fingerprints, federated agent derivation, the dedicated resume HMAC keyring, record HMACs, and bounded old-key verification grace.
- `remote_mcp/session_shared_upstream.rs` owns shared hosted upstream ownership, notification taps, and fan-out accounting.
- `remote_mcp/session_forms.rs` owns admin query structs plus OAuth authorization and token request forms.
- `remote_mcp/session_store.rs` owns SQLite-backed active session rows, authenticated terminal tombstones, retained terminal generation fences, atomic terminalization, monotonic resume generations, replay-safe loading, tombstone purging, and persisted capability freshness checks.
- `remote_mcp/admin.rs` owns operator-only health, authority, receipt, revocation, budget, session, and trust-control routes.

## Runtime Lifecycle

1. `serve_http` creates the async runtime, resolves the selected auth mode and
   OAuth metadata, validates the dedicated resume keyring when persistence is
   enabled, and restores eligible sessions before accepting connections.
2. Every `/mcp` request passes origin validation and request authentication,
   producing a `SessionAuthContext` before session lookup or creation.
3. Initialize loads policy, builds or reuses the adapted upstream, constructs a
   per-session kernel with durable stores, issues capabilities, and starts the
   edge worker. Any partial construction failure aborts the session.
4. Established requests revalidate session id, protocol version, and auth
   context. Responses and notifications use SSE with bounded event replay.
5. Ready sessions persist authenticated resume state. The reaper expires idle
   sessions, completes drains, and purges diagnostic tombstones without
   removing the monotonic terminal-generation fence.

## Admission Boundaries

`MCP-Session-Id` has an internal admission boundary with explicit missing,
invalid, and valid states. Established-session `POST`, `GET`, and `DELETE`
requests require a non-empty canonical header value before session lookup;
initialize requests reject any present session header regardless of its value.
This typed boundary at the Axum edge enforces the public wire-protocol invariant
without changing the public `serve_http` API or the generated session identifier
format.

Static bearer material from `--auth-token` and `--admin-token` is validated at
configuration load time: values must be non-empty, unpadded, and control-free
before they can seed `RemoteAuthMode::StaticBearer` or admin route authorization
state, so a malformed value fails at startup rather than becoming an unusable or
log-breaking bearer credential.

Durable resume state has an independent cryptographic boundary. Enabling a
session database without a dedicated resume HMAC keyring fails startup. Active
records carry a monotonic per-session generation. Terminalization signs a
tombstone and compact terminal intent. Before upstream shutdown, it writes the
authenticated intent and deletes the active row in one immediate SQLite
transaction. Only after shutdown succeeds does it finalize the diagnostic
tombstone in a second transaction. A crash at either boundary therefore leaves
the session non-resumable. The intent fence remains after diagnostic tombstone
retention so a missing, deleted, or corrupt tombstone cannot make an older
validly MACed active row resumable. Key selection binds an explicit key ID and
version into every HMAC envelope. Previous keys verify only within their
configured grace deadline and are never selected for new writes. Runtime key
bytes and parsed keyring buffers are zeroized on drop, and the keyring is opened
through one no-follow descriptor before its type, size, mode, owner, single-link
custody, mutation metadata, and contents are validated. Restoring a session
persists a new monotonic context generation and fresh isolation epoch before
launching its upstream process. Stored
capabilities are discarded and reissued against that incarnation, so a
capability bound to the prior process cannot authorize the replacement.

## Constraints

- Preserve the public `serve_http(RemoteServeHttpConfig)` entrypoint and `RemoteServeHttpConfig` fields.
- Preserve hosted MCP wire behavior for `POST /mcp`, `GET /mcp`, `DELETE /mcp`, `MCP-Session-Id`, `MCP-Protocol-Version`, SSE replay, and ready-state admission.
- Preserve OAuth bearer, JWT, introspection, DPoP, mTLS thumbprint, attestation-bound, resource-indicator, and request-time authorization fail-closed semantics.
- Static bearer and admin tokens must be validated before constructing
  `RemoteAuthMode` or admin route state.
- Preserve receipt, revocation, budget, capability, session lifecycle, resumability, shared hosted owner, and admin route behavior.
- OIDC discovery, JWKS, and introspection require an explicit HTTP egress
  contract and fail before connection when the target is not authorized.
- Admin routes require same-origin or localhost origin checks plus a
  constant-time bearer comparison; an unset admin token denies every request.
- Cross-crate coupling is confined to the public entrypoint and wire contracts above.

## Dependents

- `chio-cli` exposes `chio mcp serve-http` through this crate.
- `chio-hosted-mcp` is a compatibility surface that re-exports the remote server entrypoint.
- `docs/guides/MIGRATING-FROM-MCP.md`, `docs/release/OPERATIONS_RUNBOOK.md`, and `spec/PROTOCOL.md` describe the hosted MCP HTTP/SSE lifecycle.
- `spec/SECURITY.md` defines hosted MCP TLS, DPoP, mTLS, and sender-proof requirements.
- Admin session diagnostics depend on terminal tombstone records staying internally consistent.
