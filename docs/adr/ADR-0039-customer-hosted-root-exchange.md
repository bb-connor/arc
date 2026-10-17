# ADR-0039: Customer-Hosted Root Exchange

- Status: Proposed
- Decision owner: founder
- Related: ADR-0005, ADR-0007
- Number allocation: ADR-0023 through ADR-0037 are reserved by ADR-0038, so this record takes the next free number.

## Context

PROTOCOL section 8.2 blocks hosted OAuth authorization-server product work
until an OAuth AS ADR or an equivalent decision note is accepted. Section 2 of
PROTOCOL lists the same block for OAuth authorization-server product status.

A provider that puts `chio mcp serve-http` in front of an MCP server or a paid
API is called by other companies' agents. Those callers arrive with their own
enterprise identity: an Okta Cross App Access identity assertion (ID-JAG), an
ordinary Microsoft Entra application token, a Microsoft Entra Agent ID token,
another OIDC issuer's JWT, or an opaque token checked by introspection. The
provider needs one place that accepts each of these, checks it against the
provider's own policy, and issues a short-lived Chio capability whose root
names the assertion it came from, so that every receipt can be traced to the
caller's identity provider without trusting the provider's database.

Today the local authorization server inside `serve-http` exchanges only
access tokens it issued itself, and every registered client is public.
`serve-http` also issues session capabilities directly, outside any exchange,
and derives per-principal subject keys from the authority seed.

## Decision

The provider runs the root exchange inside its own `serve-http` process, on
the existing local authorization server, with exchange and policy keys the
provider controls. Backbay operates no exchange in v1.

Every root capability that `serve-http` admits is issued by this exchange and
carries a `root_anchor` naming its anchor kind, the digest of its delegation
context, the digest of the signed root policy that admitted it, and the expiry
of the assertion behind it. Direct unanchored issuance is removed: session
issuance that bypasses the exchange is deleted, and no other path mints a
root.

Every authentication path `serve-http` keeps ends in the same exchange. The
static bearer (`--auth-token`) is kept and maps to an operator-issued root
naming an explicitly configured principal. Generic OIDC JWT, introspection,
generic Entra, Entra Agent ID and the local authorization server's own login
and re-exchange each map to exactly one anchor kind.

The exchange signer is a local seed file or the pinned remote trust-control
authority.

## Scope

Grants on the local authorization server token endpoint:

- `authorization_code` for local users (`chio_local_as`).
- `urn:ietf:params:oauth:grant-type:jwt-bearer` with an ID-JAG assertion
  (`oauth_id_jag`).
- `urn:ietf:params:oauth:grant-type:token-exchange` with an ID-JAG or Entra
  subject token, returning a Chio capability.
- `urn:ietf:params:oauth:grant-type:token-exchange` re-exchange of a local
  authorization server access token. Re-exchange only narrows scope and
  resource, and keeps the subject root's assertion expiry.

`jwt-bearer` and `token-exchange` with an external subject token require
confidential client authentication: `private_key_jwt`, or the method the
stable MCP Enterprise-Managed Authorization profile requires.

Bearer intake at the edge ends in the same exchange:

- generic OIDC JWT (`oidc_jwt`);
- RFC 7662 introspection (`oauth_introspection`);
- generic Entra application and workload tokens (`entra_jwt`), one root per
  token keyed by `(issuer, uti)`;
- Entra Agent ID tokens (`entra_agent_id`), one root per token keyed by
  `(issuer, uti)`;
- static bearer (`operator_static_bearer`), an operator-issued root naming the
  principal the operator configured. The token alone never confers a
  principal.

Operator-issued roots through the admin route use `chio_operator_key`.

No refresh tokens are issued. Dynamic client registration is not added
beyond the existing startup client registry.

## Security properties

- Every exchange rule is fail-closed: an unsupported grant or token type, a
  failed client authentication, a header naming key material (`jku`, `x5u`,
  `jwk`, `x5c`) or carrying `crit`, an algorithm outside the rule's list, a
  failed signature, an issuer or audience mismatch, a time check outside the
  rule's skew, a bound replay key, zero or several matching policy rules, an
  empty effective scope, an unreachable key endpoint, a signer failure or a
  matching revocation entry each deny the exchange.
- Replay keys are single use and namespaced by anchor kind and issuer, so one
  issuer's token identifiers cannot collide with or block another's.
- Identity-provider keys are fetched only from the enterprise provider record
  the matching rule references and pins by identity digest.
- The identity provider is never consulted after the root is minted.
- A root's lifetime is capped by the expiry of the assertion behind it.
- The exchange, kernel, policy and local authorization server keys are
  distinct. Startup refuses when any two are equal.
- The policy key is pinned in `serve-http` configuration. A root policy signed
  by any other key refuses startup.
- One `serve-http` process serves one state directory, held under an
  exclusive advisory lock on a local filesystem.

## Standards pinned

- RFC 6749 (OAuth 2.0).
- RFC 7523 (JWT bearer grant and `private_key_jwt` client authentication).
- RFC 8693 (token exchange).
- RFC 8707 (resource indicators).
- RFC 9728 (protected resource metadata).
- MCP Enterprise-Managed Authorization, stable profile.
- The IETF Identity Assertion JWT Authorization Grant draft revision that the
  stable MCP profile references, recorded in the implementation when it
  starts.

## Consequences

- PROTOCOL section 8.2 is unblocked for the scope above only. It does not
  unblock a general OAuth authorization-server product.
- The hosted-edge qualification lane re-runs on the anchored flow and the
  qualified label is suspended, publicly, until it passes.
- Removed: session capability issuance that bypasses the exchange, the
  seed-derived federation subject keys, and every other direct unanchored
  issuance path. Local authorization server re-exchange stays, as the
  narrowing-only `chio_local_as` re-exchange of an anchored root.
- The enterprise provider registry is the one source of provider identity
  (issuer, keys or introspection endpoint, audience, subject mapping, trust
  material reference, enabled state). Root policy rules reference a record by
  id and pin its identity digest. The `--auth-jwt-provider-profile` flag and
  the `serve-http` provider verification flags are removed. A disabled or
  removed provider denies the next exchange and the next call under roots it
  anchors.
- The `serve-http` per-store database path flags are replaced by one
  `--state-dir`.
- The static bearer is documented as a development, test and conformance mode
  whose identity is attested by the operator and carries no identity-provider
  evidence.
- A Backbay-hosted exchange requires a new ADR.

## Alternatives rejected

- **Trust-control as the exchange.** Every provider would run a second
  deployable. Trust-control stays available as an exchange signer only.
- **Self-anchored roots at the edge.** A proof-of-possession root with no
  exchange behind it gives the edge no policy decision to record and no
  assertion to trace. The edge accepts only exchange-issued roots.
- **Direct issuance beside the exchange.** Two issuance paths means two sets
  of rules to qualify and audit, and a receipt could not show which one
  admitted a call.
- **Public clients on the assertion grants.** A stolen assertion would be
  redeemable by anyone who knows the `client_id`.
