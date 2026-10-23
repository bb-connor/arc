# chio-http-core

Provides shared HTTP request, identity, verdict, receipt, and authority APIs
for Chio adapters. `HttpAuthority` mediates HTTP authorization through a
kernel; transport hosts wire authentication, routes, persistence, and
forwarding.

## Usage

Evaluate a local session-allowed GET using the explicit ephemeral
constructor. This example signs a decision receipt without forwarding an
HTTP request. Durable deployments use the builder with receipt, revocation,
and admission stores.

```rust
use std::collections::HashMap;
use chio_http_core::{CallerIdentity, HttpAuthority, HttpAuthorityInput,
    HttpAuthorityPolicy, HttpMethod, Keypair};

let authority = HttpAuthority::new_ephemeral(
    Keypair::from_seed(&[5; 32]), "example-policy".into());
let query = HashMap::new();
let result = authority.evaluate(HttpAuthorityInput {
    request_id: "request-demo".into(), method: HttpMethod::Get,
    route_pattern: "/catalog".into(), path: "/catalog", query: &query,
    caller: CallerIdentity::anonymous(), body_hash: None, body_length: 0,
    session_id: None, capability_id_hint: None, presented_capability: None,
    requested_tool_server: None, requested_tool_name: None,
    requested_arguments: None, model_metadata: None,
    unsupported_authorization_extension: None, execution_nonce: None,
    policy: HttpAuthorityPolicy::SessionAllow,
})?;
assert!(result.verdict.is_allowed());
assert!(result.receipt.verify_integrity_embedded_key()?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Enabled | Empty feature set. |
| `reqwest-egress` | Disabled | Re-exports contract-aware client building and sending from `chio-egress-contract`. |

## Guarantees

`HttpAuthority::prepare` reads the kernel authority clock, validates
presented capability binding, and rejects unsupported authorization
extensions. `evaluate` prepares and signs a decision receipt. Invalid
presented capabilities deny even otherwise session-allowed requests.

`ChioHttpRequest::content_hash` canonically binds method, route pattern,
actual path, query, and supplied body hash. `HttpReceipt::verify_integrity_embedded_key`
checks authority semantics, recomputed receipt ID, and the embedded kernel
signature; consumers independently pin that kernel key.

## Status

Implemented framework-neutral HTTP substrate and handlers.
`CallerIdentity::verified` is carried authentication metadata supplied by
the host. Ordinary authority constructors require durable state for
mediation; ephemeral constructors explicitly select process-local state.
Policy evaluation and its receipt precede transport execution and final
response recording.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#66-http-receipts)
- [chio-http-session](../chio-http-session/README.md)
- [License](../../../LICENSE)
