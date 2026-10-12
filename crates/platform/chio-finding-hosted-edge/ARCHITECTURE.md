# chio-finding-hosted-edge architecture

## Responsibility and boundary

The edge owns credential authentication, principal/request binding, trusted
proxy reconstruction, HTTP routes, and public error classification. Durable
identity, replay accounting, domain append, and projections are delegated to
`HostedAuthPort`, `HostedApiKeyLifecyclePort`, and `HostedMarketBackend`.
The crate has no direct PostgreSQL dependency.

`HostedAuthenticator` consumes exactly one credential enum variant. Successful
authentication yields `HostedAuthenticatedPrincipal`. The request-contract API
accepts that principal as an input and validates tenant/metadata binding;
constructing the public principal struct does not authenticate credentials.

## Structure

`auth.rs` owns capability/DPoP and HMAC API-key verification and tenant method
policies. `contracts.rs` defines tenant selectors, request contracts, mutation
responses, and domain event envelopes. `input.rs` preserves original canonical
JSON bytes under bounds; `error.rs` maps native causes to public error bodies.

`lifecycle.rs` creates secret-free signed API-key issue/revoke evidence and calls
the lifecycle port. `proxy.rs` reconstructs one trusted Forwarded context.
`server.rs` owns route/action/role selection, artifact pins, admission limits,
readiness, and the loopback server. Its submodules test durable-error
classification and expose operator diagnostics.

`tls.rs` validates certificate/key material and retains the last valid server
configuration across failed reloads. `operations.rs` exposes bounded rate limits,
circuit breakers, readiness snapshots, and registered metric counters.

## Request and authentication flow

`hosted_market_router` exposes health routes, release identity, paged finding
reads, publication, and selected domain-event writes. Trusted-proxy middleware
wraps the router. Guarded routes receive body and concurrency limits; saturation
returns a hosted error envelope. Health probes bypass that concurrency limiter,
and readiness caches backend probes to bound repeated database work.

Publication checks canonical body bytes and verifies the finding before
credential authentication. Mutation parsing also precedes authentication.
Authentication binds tenant, governed action, method, external target, body hash,
and optional idempotency key. Only authenticated writes invoke the backend.

Capability mode requires a pinned issuer, valid bounded lifetime, and one invoke
grant for the deployment/tenant audience and action. That grant requires DPoP
and a nonzero invocation budget. Delegation, caveats, attenuations, resource and
prompt grants, and cost-bearing grants are refused by this hosted profile.
DPoP binds the subject, capability, server, tool, request action hash, and proof
freshness. Durable admission distinguishes exact request resumption, replay,
and exhausted invocation budget.

API-key mode decodes a 32-byte secret and verifies a domain-separated HMAC over
tenant/key identity using the deployment pepper. Comparison is constant time.
The durable key supplies allowed actions; an enabled principal supplies the
required role and optional artifact signing key. There is no mode fallback.

## Trust and authority invariants

Tenant selection uses the validating tenant constructor. Request contracts
require idempotency for POST, PUT, and DELETE. The original canonical body hash
is shared by authentication and the resulting contract.

Publication requires the principal's artifact key to equal the finding issuer.
Signed mutation routes pin artifact keys to authenticated principals. Delivery
uses the configured kernel key; penalty writes also require the configured
operator authority identity. The backend independently validates persisted
artifacts and applies revision/idempotency fences.

Proxy reconstruction requires a configured loopback peer, a constant-time
shared-token match, one Forwarded header, and the configured HTTPS host. Legacy
forwarding headers and multi-hop lists are refused. The serving helper rejects
non-loopback sockets. Public TLS termination is an application/proxy concern;
`HostedTlsState` provides validated rustls material for consumers that use it.

The state uses an authority clock fence shared by clones. Public errors retain
bounded codes and retry classification; private credential and payload strings
are not reflected in their message. API-key secrets and pepper bytes are
redacted in Debug and zeroized by their owning implementations.

## Dependencies and verification

Axum and Tokio supply HTTP routing and serving. `chio-kernel` supplies DPoP
proofs, `chio-finding` verifies finding artifacts, and `chio-core-types` supplies
canonicalization and cryptographic primitives. HMAC, SHA-256, subtle, and zeroize
support secret verification; rustls, webpki, and x509-parser validate TLS material.

`cargo test -p chio-finding-hosted-edge --lib` exercises credential isolation,
request/proof binding, role and artifact pins, proxy spoof rejection, schema
contracts, error classes, load shedding, readiness caching, authority-clock
regression, certificate chain validation, and reload behavior. Backends in these
router tests are mocks; certificates are local temporary fixtures.
