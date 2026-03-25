# Identity Federation Guide

PACT now ships the next identity-federation alpha for bearer-authenticated
`pact mcp serve-http` deployments, including both JWT verification and opaque
bearer admission via token introspection.

## What It Does

- Canonicalizes authenticated OAuth bearer principals as:
  - `oidc:<issuer>#sub:<sub>`
  - `oidc:<issuer>#client:<client_id>` when `sub` is absent
- Supports provider-aware principal mapping for Azure AD style tokens:
  - `oidc:<issuer>#oid:<oid>` for user principals when `--auth-jwt-provider-profile azure-ad`
    is configured
  - falls back to `azp` / `appid` / `client_id` for client principals on that profile
- Derives a stable PACT subject key from that federated principal when
  `--identity-federation-seed-file` is configured.
- Issues default session capabilities against that stable subject instead of a
  random per-session subject.
- Exposes the mapping through the admin session APIs via `authContext` and
  per-capability `subjectPublicKey`.
- Exposes normalized enterprise identity context through
  `authContext.method.enterpriseIdentity`, including provider id, provider
  record id, federation method, canonical principal, derived subject key,
  tenant, organization, groups, roles, source-attribute provenance, and
  `trustMaterialRef`.
- Preserves normalized enterprise identity metadata in
  `authContext.method.federatedClaims` when the verified token supplies it:
  `clientId`, `objectId`, `tenantId`, `organizationId`, `groups`, and
  `roles`.
- Can bootstrap JWT admission from `--auth-jwt-discovery-url` plus discovered
  JWKS instead of requiring a manually copied public key.
- Can admit opaque bearer tokens via `--auth-introspection-url`, including
  confidential-client authentication to the introspection endpoint.

This means repeated sessions for the same enterprise principal converge on the
same PACT subject and therefore the same receipt attribution path.

## CLI

Use `pact mcp serve-http` with explicit JWT admission:

```bash
pact mcp serve-http \
  --policy ./policy.yaml \
  --server-id wrapped-http-mock \
  --server-name "Wrapped HTTP Mock" \
  --listen 127.0.0.1:8931 \
  --auth-jwt-public-key <ed25519-public-key-hex> \
  --auth-jwt-issuer https://issuer.example \
  --auth-jwt-audience pact-mcp \
  --identity-federation-seed-file ./identity-federation.seed \
  --admin-token <admin-token> \
  -- python3 ./mock_server.py
```

Or use OIDC discovery plus provider-aware mapping:

```bash
pact mcp serve-http \
  --policy ./policy.yaml \
  --server-id wrapped-http-mock \
  --server-name "Wrapped HTTP Mock" \
  --listen 127.0.0.1:8931 \
  --auth-jwt-discovery-url https://id.example.com/tenant/v2.0/.well-known/openid-configuration \
  --auth-jwt-provider-profile azure-ad \
  --auth-jwt-audience pact-mcp \
  --identity-federation-seed-file ./identity-federation.seed \
  --admin-token <admin-token> \
  -- python3 ./mock_server.py
```

Or use OAuth2 token introspection for opaque bearer tokens:

```bash
pact mcp serve-http \
  --policy ./policy.yaml \
  --server-id wrapped-http-mock \
  --server-name "Wrapped HTTP Mock" \
  --listen 127.0.0.1:8931 \
  --auth-introspection-url https://id.example.com/oauth2/introspect \
  --auth-introspection-client-id pact-edge \
  --auth-introspection-client-secret "$PACT_EDGE_SECRET" \
  --auth-jwt-issuer https://id.example.com/oauth2/default \
  --auth-jwt-audience pact-mcp \
  --identity-federation-seed-file ./identity-federation.seed \
  --admin-token <admin-token> \
  -- python3 ./mock_server.py
```

To share an explicit provider-admin registry with the edge and trust-control:

```bash
pact mcp serve-http \
  --policy ./policy.yaml \
  --server-id wrapped-http-mock \
  --listen 127.0.0.1:8931 \
  --auth-jwt-discovery-url https://id.example.com/.well-known/openid-configuration \
  --identity-federation-seed-file ./identity-federation.seed \
  --enterprise-providers-file ./enterprise-providers.json \
  --admin-token <admin-token> \
  -- python3 ./mock_server.py

pact trust serve \
  --listen 127.0.0.1:8940 \
  --service-token <service-token> \
  --enterprise-providers-file ./enterprise-providers.json
```

## Provider-Admin Registry

PACT now ships a file-backed provider-admin registry for enterprise federation.
Each provider record is an explicit `oidc_jwks`, `oauth_introspection`,
`scim`, or `saml` source with:

- provenance (`configured_from`, `source_ref`, `trust_material_ref`)
- trust-boundary metadata (allowed issuers, tenants, organizations)
- subject-mapping rules for principal, tenant, organization, groups, and roles
- validation errors that keep invalid records visible for diagnostics but
  unavailable for admission

CLI surface:

```text
pact trust provider list
pact trust provider get --provider-id <id>
pact trust provider upsert --input provider.json
pact trust provider delete --provider-id <id>
```

HTTP surface on trust-control:

```text
GET    /v1/federation/providers
GET    /v1/federation/providers/{provider_id}
PUT    /v1/federation/providers/{provider_id}
DELETE /v1/federation/providers/{provider_id}
```

`list` and `get` responses include `validation_errors`, provenance metadata,
and trust-boundary metadata so operators can debug incomplete or rejected
configs without guessing from logs.

## Operational Behavior

- Same federated principal + same seed file => same derived PACT subject key.
- Different federated principal + same seed file => different derived PACT
  subject key.
- OIDC discovery and discovered `jwks_uri` must use `https`, or localhost-only
  `http` during local testing.
- The token introspection endpoint must also use `https`, or localhost-only
  `http` during local testing.
- Discovery-backed admission accepts `EdDSA`, RSA (`RS256` / `RS384` /
  `RS512`, `PS256` / `PS384` / `PS512`), and EC (`ES256`, `ES384`) signing
  keys from JWKS. If the IdP exposes no compatible signing key, startup fails
  closed.
- JWT verification resolves trusted keys by `kid` plus algorithm
  compatibility. Tokens without `kid` are accepted only when the JWKS exposes
  exactly one compatible signing key for the declared `alg`.
- When present on verified JWT or introspection responses, enterprise identity
  claims are normalized into `authContext.method.federatedClaims` so operators
  can inspect group, role, tenant, organization, client, and object identity
  without re-parsing raw token payloads.
- When provider-admin records are configured, the edge also emits
  `authContext.method.enterpriseIdentity` with provider provenance and
  source-attribute traces for the normalized principal, tenant, organization,
  groups, and roles.
- If identity federation is not configured, bearer-authenticated sessions
  still authenticate, but session subjects remain random per session.
- Static bearer sessions are unchanged; this alpha only applies to OAuth
  bearer admission.

## Enterprise-Provider Lane

Portable-trust admission now distinguishes two paths:

- Legacy bearer-only path: bearer admission can still surface
  `enterpriseIdentity` for observability, but if no validated
  provider-admin record is selected, `pact trust federated-issue` preserves
  the legacy bearer admission behavior.
- Enterprise-provider lane: this is active only when
  `enterpriseIdentity.providerRecordId` resolves to a validated provider-admin
  record. Once active, federated issue fails closed unless the admission
  policy matches the provider, tenant, organization, groups, and roles from
  the normalized enterprise identity context.

When the enterprise-provider lane is active, allow responses expose
`enterprise_audit` / `enterpriseAudit` with:

- provider id and provider record id
- provider kind and federation method
- canonical principal and derived subject key
- tenant, organization, groups, and roles
- source-attribute provenance (`attributeSources`)
- `trust_material_ref` / `trustMaterialRef`
- matched origin profile and decision reason

When admission denies in the enterprise-provider lane, trust-control returns a
structured error body that still includes the enterprise audit context so the
operator can see which provider, organization, group, or role inputs failed.

## Current Boundaries

- This is a bearer-authenticated alpha for `serve-http`.
- It now implements startup-time OIDC discovery plus JWKS bootstrap for
  `EdDSA`, RSA, and P-256/P-384 ECDSA JWTs, explicit OAuth2 token
  introspection for opaque bearer tokens, and provider-profile principal
  mapping for Generic/Auth0/Okta/Azure AD claim shapes.
- It now also preserves normalized enterprise identity metadata from verified
  JWT and introspection claims inside `authContext.method.federatedClaims`,
  including `clientId`, `objectId`, `tenantId`, `organizationId`, `groups`,
  and `roles` when available.
- The shipped verification lane has end-to-end coverage for discovery-backed
  `RS256` and `ES256` admission, focused verifier coverage for `PS256` and
  `ES384`, end-to-end opaque-token admission through an introspection endpoint
  with confidential-client auth, and admin trust-surface verification for
  direct JWT, Azure-profile OIDC discovery, and introspected opaque tokens.
- It now supports explicit `scim` and `saml` provider record types plus
  fail-closed identity normalization and policy gating, but it does not yet
  implement automatic SCIM provisioning lifecycle or reusable IdP-specific
  management workflows beyond the shared provider-admin registry.
- It does not yet propagate enterprise identity into portable credentials or
  cross-org federation artifacts beyond the session/admin trust surface,
  federated-issue `enterprise_audit`, and stable subject mapping exposed by
  the remote edge and receipts.
- This phase does not ship reusable verifier artifact distribution or
  multi-issuer passport composition; those land in later phases.
