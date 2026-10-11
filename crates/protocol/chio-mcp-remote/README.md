# chio-mcp-remote

Runs the Chio-governed MCP server that remote clients reach over HTTP: MCP
Streamable HTTP session lifecycle, OAuth 2.0 bearer and DPoP authentication,
enterprise identity federation, and per-session `chio-kernel` dispatch that
produces signed receipts. It is one of Chio's public entry points
(`public_entrypoint = true`), exposed as a single `serve_http` call.

It does not speak MCP wire protocol itself or manage an upstream process
directly: it builds sessions on `chio-mcp-adapter`'s `AdaptedMcpServer` and
reaches the `chio-mcp-edge` session engine only through the adapter's
re-exported `edge::*` module. Where `chio-mcp-adapter` wraps one MCP server
for in-process or stdio use, this crate puts that adapted server behind an
authenticated HTTP/SSE edge with its own session ledger, OAuth surface, and
admin API.

## Responsibilities

- Run the Axum HTTP surface for the MCP Streamable HTTP transport
  (`POST`/`GET`/`DELETE /mcp`): SSE delivery, `Last-Event-ID` replay from a
  bounded retained-notification window, and per-IP rate limiting (600
  requests per 60-second window, 4096 tracked keys, 8 MiB POST body cap).
- Authenticate every request under one of three bearer modes (static token,
  JWT, or token introspection), verifying EdDSA/RS256-512/PS256-512/ES256-384
  signatures plus DPoP proof-of-possession, mTLS thumbprint, and runtime
  attestation sender constraints.
- Bound DPoP replay identity parts before canonicalizing the signed proof and
  retain sender nonces through the inclusive signed validity horizon, including
  tolerated future issue time. A local cache TTL cannot shorten that horizon.
  The shared kernel cache enforces both count and retained-identity byte limits;
  exhaustion denies rather than evicting a live sender proof. This remains
  process-local replay protection, not durable DPoP custody.
- Optionally run a self-issued OAuth 2.0 authorization server
  (`LocalAuthorizationServer`) with PKCE authorization-code and
  token-exchange grants, for deployments without an external identity
  provider.
- Federate enterprise identity: OIDC/JWKS discovery, issuer matching against
  an `EnterpriseProviderRegistry`, and deterministic per-principal Chio agent
  keypairs.
- Spawn a dedicated `chio-kernel` per session (or fan out one upstream
  subprocess across sessions in `shared_hosted_owner` mode), wired to the
  receipt, revocation, budget, and capability-authority stores, so every tool
  call yields a signed `ChioReceipt`.
- Persist resumable sessions and terminal tombstones to SQLite with an
  integrity-tagged restore path, so a restart can resume in-flight sessions
  without re-authenticating.
- Serve `/admin/*` operator routes (health, authority rotation, receipts,
  revocations, budgets, session trust/drain/shutdown, exact-call approval
  records and decisions, Prometheus metrics)
  behind a constant-time bearer check.
- Publish OAuth protected-resource and authorization-server discovery
  metadata carrying Chio's governed-authorization profile.

## Public API

- `serve_http(config: RemoteServeHttpConfig) -> Result<(), CliError>` -
  blocking entrypoint; starts a Tokio runtime and serves until shutdown.
- `RemoteServeHttpConfig` - deployment configuration: listen address,
  auth-mode selection (static bearer, JWT, introspection, local authorization
  server), OAuth and DPoP settings, egress contract, SQLite store paths,
  policy path, server identity, hosted-isolation mode, and the wrapped
  upstream command.
- `CliError`, `JwtProviderProfile` - re-exported from `chio-control-plane`.
- `enforce_oidc_egress_contract(url: &Url, egress_contract: &HttpEgressContract)
  -> Result<(), CliError>` - runs the production OIDC-discovery egress gate
  outside a full server, for negative-conformance testing.

## Testing

Hosted operator approval uses `POST /admin/approvals`,
`GET /admin/approvals/{id}`, and `POST /admin/approvals/{id}/decision`.
It requires durable admission/session state, a distinct operator credential and
an explicit `RemoteServeHttpConfig.approval` configuration. The public
`RemoteApprovalConfig::load` reader accepts a bounded JSON document naming the
tenant, allowed approver public keys, replay-source path and already-activated
replay-authority binding. Startup does not provision or activate that source.
Changing this authority configuration changes the runtime fingerprint, so an
incompatible persisted session cannot resume under an old approval roster.

Submit an exact session capability, request ID, tool and argument object to create
a pending record. The returned intent binds the complete capability, canonical
arguments, exact installed kernel policy hash and configured tenant. An operator
from the configured roster signs a `GovernedApprovalToken` over the returned
intent hash, subject and request ID, with token ID `<record.id>-decision` and an
expiry no later than the pending record. Send it as `{"token": <signed token>}` to
the decision endpoint. Plain `{"decision":"approved"}` requests are rejected.
The operator's original signature remains in the record and returned execution
parameters; the server's receipt key signs only the local record's integrity.

These routes never dispatch a tool. At the shared session ingress, an ordinary
signed approval must exactly match the retained Approved record for this call.
Pending, Denied, expired, missing, altered or ambiguous artifacts refuse before
the edge worker can reserve or dispatch work. The gate revalidates the retained
signature, session, current policy, capability, intent, arguments and lifetime.
It applies equally to HTTP and native session callers. Independent policy-owned
threshold collections keep their separate kernel approval protocol.

Accepted artifacts enter the ordinary kernel `tools/call` path, which revalidates
current capability/approver authority, exact binding and durable single-use
ownership before native server execution. MCP uses server execution and does not
configure API-protect's caller executor.
Records from the former unsigned-decision contract cannot issue new authority;
submit a new request after the explicit authority configuration is installed.

See the [operator procedure](../../../integrations/required-agents/qualification/APPROVALS.md)
for deployment, signing and recovery.

`cargo test -p chio-mcp-remote`

`chio-conformance`'s `ssrf_oidc_jwks_loopback` integration test calls
`enforce_oidc_egress_contract` directly, asserting loopback and link-local
OIDC discovery URLs are denied before any connection is attempted.

## See also

- `chio-mcp-adapter` - wraps and governs the upstream MCP server this crate
  hosts; supplies `AdaptedMcpServer` and the re-exported `chio-mcp-edge`
  contracts under `edge::*`.
- `chio-mcp-edge` - the MCP protocol/session engine underneath
  `chio-mcp-adapter`; this crate has no direct dependency on it.
- `chio-hosted-mcp` - compatibility shim that re-exports `serve_http` and
  `RemoteServeHttpConfig` verbatim.
- `chio-cli` - exposes this crate's entrypoint as `chio mcp serve-http`.
- `chio-kernel` - policy evaluation, guard pipeline, and receipt signing; one
  instance runs per session.
- `chio-control-plane` - authority keypair management, policy loading, and
  store configuration.

## Listener transport

See the [shared HTTP transport guide](../../../docs/security/http-transport.md) for
TLS identity files, explicit plaintext policy, client endpoint rules and revocation
response semantics.
