# Architecture

## Responsibility and boundary

`serve_http(RemoteServeHttpConfig)` runs the hosted MCP service synchronously.
The runtime owns HTTP admission, authenticated sessions, subprocess workers,
SSE response ownership, replay, administrative routes, and session recovery.
The configuration supplies policy, publisher admission, native launch authority,
listener transport, credentials, egress contracts, and persistence paths.
`RemoteClock`, `TrustedProxyConfig`, and `RemoteApprovalConfig` expose supporting
configuration boundaries; OAuth error types preserve structured rejection codes.

Operators own credential custody, upstream command authorization, policy choice,
and deployment acceptance. Native launch uses an explicit factory supplied by
the host. Ordinary session construction rejects flow-required manifests because
it constructs an ordinary kernel without an active-defense flow host.

## Structure

`lib.rs` combines private modules and included session/service fragments.
`remote_mcp/session_core` splits factory, session, ledger, writer, and authority
mode logic. Identity, forms, credentials, resume, recovery, and shared-upstream
files implement the associated lifecycle boundaries.
`http_service` and `http_service_auth` install routes and authentication state.
`http_body` owns bounded POST reads; `session_worker` runs edge workers.
`oauth` splits bearer/JWT support, request validation, and local server code.
`approvals` separates records, validation, and redemption.
`admin` exposes authenticated operator operations and revocation batches.
`input`, `sender_constraint`, and `transport_identity` preserve ingress provenance.
`clock` and `rate_limit` share authority time and bounded rate windows.

## Data and control flow

`serve_http` creates a Tokio runtime and enters private async serving.
Startup prepares TLS or explicit plaintext transport, authenticates configured
proxy separation, binds the listener, resolves identity-provider metadata,
and validates auth/discovery configuration.
`RemoteSessionFactory::new` loads policy and a publisher-signed manifest using
an independently registered key, validates store participation and launch
binding, and opens configured durable admission and resume custody.
Persisted sessions are restored before routes begin serving.

POST `/mcp` initializes sessions and accepts subsequent JSON-RPC messages.
Initialize returns SSE with `MCP-Session-Id`; clients acknowledge initialization
before using ready-state methods. GET provides session notifications/replay,
while DELETE closes a session. `Last-Event-ID` identifies the replay cursor.
Request-correlated replies remain attached to their POST response owner.
Session-owned events can enter GET replay; the default retained window is 64.
Shared-owner mode serializes upstream work while retaining per-session tasks.

A session worker wraps an admitted MCP server in a kernel-backed edge.
Shutdown terminalizes sessions, commits replay fences, closes transport evidence
custody, and finalizes diagnostic tombstones before closing a shared owner.

## Trust and invariants

Authentication supports static bearer, configured JWT keys, discovered keys,
introspection, and local signing-key verification. Conflicting modes reject
startup. Missing authentication also rejects startup.
Introspection requires an egress contract and validates its URL/DNS binding.
Local authorization routes exist in code; the protocol describes a separate
acceptance boundary for the hosted authorization-server product.

`read_limited_mcp_post_body` rejects invalid lengths and bounds reads at 8 MiB.
MCP middleware allows 600 requests per 60-second socket-derived IP bucket.
IPv4-mapped addresses normalize and IPv6 buckets use their /64 prefix.
The limiter retains at most 4,096 keys and evicts the earliest deadline at capacity.
`RemoteClock` shares high-water fences across cloned service owners.

Trusted proxy configuration requires explicit socket peer IPs and a private
32-512 byte ASCII token separate from service credentials.
Proxy middleware strips identity headers and attaches authenticated provenance.
Caller-supplied forwarding headers do not authenticate that provenance.
Durable resume uses a dedicated HMAC keyring and runtime binding fingerprints.
Default lifecycle settings expire idle sessions after 15 minutes, allow five
seconds for draining, reap every 250 ms, and retain tombstones for 30 minutes.
Environment settings can change those lifecycle defaults.
SSE routes have no blanket request timeout; connection hygiene and drain
limits remain active. Operators must account for idle streaming connections.

## Dependencies

`chio-control-plane` builds kernels, policy, authority, and trust-control clients.
`chio-mcp-adapter` supplies subprocess wrapping and shared edge contracts.
`chio-store-sqlite` and Rusqlite supply configured persistence.
`chio-http-serve` supplies listener transport, connection hygiene, and shutdown.
`chio-egress-contract` gates identity-provider HTTP; Reqwest performs requests.
Axum/Tokio host routes and workers; cryptographic crates support JWT and HMAC.
`chio-secure-ipc` and security types carry custody and authority primitives.

## Verification

Run `cargo test -p chio-mcp-remote` for controlled runtime tests.
`remote_mcp/tests` covers bearer verification, DPoP replay, durable bounds,
clock custody, transport ownership, worker lifecycle, and session recovery.
`hosted_tests` exercises HTTP auth, isolation, admin, protocol refusals,
operator approvals, and cross-crate kernel dispatch using configured fixtures.
Transport identity and rate-limit tests cover provenance and availability bounds.
These fixtures establish exercised service behavior; deployment custody,
identity-provider operation, and external client interoperability need host evidence.
