# chio-control-plane Architecture Notes

## Module Boundaries

`lib.rs` exposes CLI-facing helpers for policy loading, kernel construction,
local store wiring, and authority seed management. The `trust_control` module
owns the HTTP trust service, remote clients, cluster replication, and report
endpoints. Its submodules split the broad route surface into service types,
service runtime, configuration/public registry helpers, domain handlers,
health projection, and cluster/report logic. Federation, SCIM lifecycle,
passport verifier, enterprise-provider, attestation, issuance, evidence export,
reputation, and certification support remain separate crate-local modules.

## Pain Points

`TrustServiceConfig` is the root authority boundary for the service, but its
security-sensitive invariants are currently scattered through lower handler
helpers. Empty service tokens, blank tenant-read tokens, tenant-token collisions,
and invalid cluster timing are only detected after route setup or during a
specific request path. That makes invalid trust-control state harder to audit
and lets different endpoints fail at different layers for the same bad config.

The remote trust-control client is the mirror boundary for `chio-cli`,
evidence export, reputation, and remote receipt/revocation/budget/authority
stores. `build_client` currently accepts any non-empty comma-separated endpoint
string after trimming list entries, and carries bearer-token material through
without rejecting blank or padded values. Malformed schemes, URL userinfo,
query strings, fragments, and padded tokens therefore become late transport or
auth failures instead of failing closed at client construction.

## Security and API Constraints

The trust-control service must fail closed before it starts serving authority,
revocation, receipt, budget, passport, federation, certification, or economic
report endpoints. Public APIs should stay source-compatible. Existing valid
configurations must keep their behavior, cluster peer authentication must keep
its existing signature material, and bearer-token comparison must stay constant
time where request auth is evaluated.

Remote clients have the same no-ambient-authority rule: service tokens travel
only in explicit bearer headers, never through endpoint URL userinfo or query
material. Local HTTP trust-control endpoints remain supported, HTTPS remains
supported, comma-separated failover endpoints remain supported, and the client
API keeps returning `CliError` without changing public method signatures.

## Affected Dependents

No transitive crate edits are expected. `chio-cli` and callers still construct
`TrustServiceConfig` with the same fields and call the same service/client
entrypoints. The intended behavior change is limited to invalid trust-control
configuration being rejected at the service boundary instead of surfacing later
as request-time internal errors.

No transitive crate edits are expected for the client boundary either. Existing
CLI helpers and store builders all call `build_client`, so the behavior change
is centralized: invalid remote control URLs or bearer tokens are rejected before
the remote client exists.

## Planned Material Improvement

Add a central `TrustServiceConfig` validation boundary and call it before
`serve_async` binds sockets or loads runtime state. The validator should reject
blank service tokens, blank tenant ids, blank tenant-read tokens, tenant tokens
that equal the admin service token, and zero cluster sync intervals.

Add a matching `TrustControlClient` construction validator. It should reject
blank or padded service tokens, empty endpoint lists, non-HTTP(S) endpoints,
userinfo, query strings, and fragments, then preserve the existing normalized
endpoint list for valid clients.
