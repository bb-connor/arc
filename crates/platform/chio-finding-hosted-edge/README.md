# chio-finding-hosted-edge

Authentication, request contracts, and the Axum HTTP boundary for Chio's
hosted finding market. The edge depends on store-neutral backend/authentication
ports, validates artifact authority at ingress, and serves behind an
authenticated loopback proxy.

## Usage

Bind a mandatory tenant header to a previously authenticated principal and
construct a mutation's request contract offline.

```rust
use chio_finding_hosted_edge::{
    HostedAuthMethod, HostedAuthenticatedPrincipal, HostedHttpMethod,
    HostedPrincipalRole, HostedRequestContract, HostedTenantBinding,
};

let binding = HostedTenantBinding::from_header(Some("tenant:acme-1"))?;
let principal = HostedAuthenticatedPrincipal {
    tenant_id: binding.tenant_id().clone(),
    principal_id: "seller-1".into(),
    role: HostedPrincipalRole::Seller,
    method: HostedAuthMethod::ApiKey,
    credential_id: "key-1".into(),
    artifact_signer_key: None,
};
let request = HostedRequestContract::new(
    &binding, &principal, "request-1", "finding.publish",
    HostedHttpMethod::Post, "https://market.example/v1/findings/publish",
    "a".repeat(64), Some("event-1".into()), 1,
)?;
assert_eq!(request.idempotency_key(), Some("event-1"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

The principal and digest above are illustrative inputs. Contract construction
checks metadata and tenant binding. Real requests obtain their principal from
`HostedAuthenticator::authenticate` and hash the validated request bytes.

## Guarantees

- `HostedTenantBinding::from_header` refuses missing or padded tenant selectors;
  `HostedRequestContract::new` requires matching tenant and mutation idempotency.
- `HostedAuthenticator::authenticate` checks the selected credential family,
  tenant policy, action, principal role, and capability/DPoP request binding.
- `HostedTrustedProxy::reconstruct` accepts one authenticated loopback peer and
  one Forwarded context bound to the configured HTTPS origin.
- `hosted_market_router` bounds bodies and concurrent guarded requests;
  publication pins the finding issuer to the authenticated principal.
- Delivery mutation uses the configured kernel receipt key; penalty mutation
  binds the configured authority identity and key.

## Status

Implemented edge library with mock-backend router/authentication tests and
local certificate tests. `serve_hosted_market_loopback` requires a separately
configured trusted proxy for the public TLS endpoint. Bounded JSON parsing and
artifact checks can precede credential authentication; writes reach the backend
after authentication. Durable replay and invocation accounting require the
configured `HostedAuthPort` implementation. Operational deployment acceptance
is separate from these library tests.

## Related

- [Architecture](ARCHITECTURE.md)
- [Store-neutral ports](../chio-finding-market-port/README.md)
- [PostgreSQL adapter](../chio-finding-market-store-postgres/README.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)

Licensed under [Apache-2.0](../../../LICENSE).
