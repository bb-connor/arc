# chio-api-protect

`chio-api-protect` fronts an HTTP API with OpenAPI route policy, kernel
mediation, and signed HTTP receipts. `ProtectProxy` owns the listener and
upstream forwarding; `RequestEvaluator` exposes the HTTP authority to embedders.
The library backs `chio api protect` in `chio-cli`.

## Usage

Build a route table offline, without opening a listener or contacting an API:

```rust
use chio_api_protect::ProtectProxy;
use chio_http_core::HttpMethod;
use chio_openapi::PolicyDecision;

let spec = r#"{
  "openapi": "3.1.0",
  "info": {"title": "Inventory", "version": "1.0.0"},
  "paths": {
    "/items": {
      "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}},
      "post": {"operationId": "createItem", "responses": {"201": {"description": "created"}}}
    }
  }
}"#;
let routes = ProtectProxy::routes_from_spec(spec)?;
assert_eq!(routes.len(), 2);
assert!(routes.iter().any(|route|
    route.method == HttpMethod::Get && route.policy == PolicyDecision::SessionAllow));
assert!(routes.iter().any(|route|
    route.method == HttpMethod::Post && route.policy == PolicyDecision::DenyByDefault));
# Ok::<(), chio_api_protect::ProtectError>(())
```

`routes_from_spec` treats the document as unpinned. A read classification alone
permits no anonymous traffic: `RequestEvaluator::with_anonymous_reads(true)` or
`ProtectConfig::allow_anonymous_reads` explicitly enables known read routes.
Unknown routes deny even with that opt-in.

## Guarantees

- `RequestEvaluator::evaluate` and `evaluate_chio_request` delegate to
  `HttpAuthority`; the latter derives route policy from the local table rather
  than the submitted route pattern. Exact paths outrank templates, and ambiguous
  encoded paths fail closed in `match_route_with_status`.
- `ProtectProxy::run_with_observer` validates spec provenance, transport, control
  credentials, signing custody, and durable-store configuration before serving.
  `x-chio-side-effects: false` relaxes side-effect classification only for a
  local `spec_path` whose exact bytes match `spec_sha256`.
- `proxy_handler` forwards only an allowed verdict under the upstream egress
  contract. Denials and completed upstream hops finalize and record receipts;
  malformed input and control-authentication failures can return before mediation.
- Durable serving requires a persistent `receipt_db` and an existing
  `signer_seed_file`. In-memory SQLite paths require the explicit
  `allow_ephemeral_receipts` opt-in. Ephemeral receipts and revocations disappear
  on restart; `RequestEvaluator::new_ephemeral` makes that choice explicit.

## Serving and authority

Serving uses Tokio, an upstream HTTP(S) API, and `ServerTransportConfig` for
TLS or an explicit permitted plaintext listener. Durable admission requires Unix
serving-owner support and a sibling SQLite authority under `<receipt-path>.authority-locks`.
External `budget_db` or `control_url` configuration rejects with durable receipts.
The upstream timeout defaults to 20 seconds and includes response-body reading;
the proxy performs no application retry and drains for that timeout plus 5 seconds.

A dedicated `sidecar_control_token` protects capability lifecycle, receipt
submission, approval, reconciliation, and metrics routes, including on loopback.
Missing configuration disables them. The proxy rejects that credential's bytes
in request headers before egress. `trusted_capability_issuers` adds capability
authorities; receipt verification independently pins the sidecar signer.

`POST /chio/evaluate` runs HTTP authority evaluation. `POST /v1/evaluate` runs
kernel preflight, reserves a budget hold, and returns an execution nonce when
configured with a hold-capable authority and control credential. Execution and
reconciliation belong to the trusted execution site; the reservation route
dispatches no tool. Authenticated caller start/report additionally requires
durable admission and an operator-pinned executor.

`POST /v1/evaluate/advisory` is disabled unless `allow_advisory` is set; its
signed output carries `authorization: false`. Capability validation checks a
token's trust and freshness without authorizing a concrete call. Attenuation
always returns 403 because the subject's private key stays with the subject.

## Execution-bound approvals

Ordinary approvals require `ProtectApprovalConfig`, an already activated replay
authority, a configured approver roster, and authenticated execution. Threshold
collection requires an operator-installed context resolver. The mediated endpoint
rejects directly supplied threshold tokens/proposals and supplemental authorization.
Governed prepayment requires a configured payment adapter.

## Status

The route evaluator, proxy, durable admission, and sidecar handlers are
implemented. The offline example exercises route construction. Unit and
integration tests exercise local authority and loopback proxy behavior; deployment
acceptance also requires operator custody, transport, upstream, and executor
configuration. `load_spec_from_file` reads local text without parsing or a byte
limit; proxy startup uses its separate bounded loader. `discover_spec` performs
network probes and returns text for subsequent parsing.

## Related

- [Architecture](ARCHITECTURE.md)
- [HTTP protocol surfaces](../../../spec/PROTOCOL.md#http-and-openapi-surfaces)
- [HTTP substrate](../../../spec/HTTP-SUBSTRATE.md#2-sidecar-evaluation-protocol)
- [Control authority](../../../docs/security/sidecar-control-authority.md)
- [HTTP authority](../../platform/chio-http-core/README.md)

License: [root license](../../../LICENSE).
