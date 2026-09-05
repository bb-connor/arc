# chio-api-protect

Zero-code reverse proxy that fronts an existing HTTP API and requires every
mediated request to clear the Chio kernel guard pipeline before it reaches
the upstream. It derives a route table and default policy from an OpenAPI
spec, evaluates and forwards requests, and signs an `HttpReceipt` for every
outcome, allowed or denied. It is the library behind `chio api protect` and
`chio start` in `chio-cli`.

## Responsibilities

- Acquire an OpenAPI spec (`discover_spec` probes well-known upstream paths;
  `load_spec_from_file` reads a local path) and build a route table with a
  `chio_openapi::PolicyDecision` per method/path pair.
- Match each inbound request against the route table and evaluate it through
  `chio_http_core::HttpAuthority` (`RequestEvaluator`), extracting caller
  identity from `Authorization`/`X-API-Key` headers and any presented
  capability from `X-Chio-Capability` or `?chio_capability=`.
- Run the reverse proxy (`ProtectProxy`, Axum-based): forward allowed
  requests to the upstream under a locked-down `HttpEgressContract`, finalize
  the decision receipt with the real response status, and return a signed
  deny receipt fail-closed otherwise.
- Persist receipts and capability revocations to SQLite when `receipt_db` is
  set; refuse to start without a durable store unless
  `allow_ephemeral_receipts` is explicitly set.
- Require a configured control token for capability minting, release,
  validation, attenuation, receipt submission, human-approval workflows,
  reconciliation, and Prometheus metrics. Loopback callers authenticate too;
  missing configuration disables these control endpoints. Public liveness,
  receipt verification, and independently authorized evaluation routes do not
  inherit control authority.

## Public API

- `ProtectConfig` - upstream URL, spec source, listen address, receipt DB
  path, ephemeral opt-in, sidecar control token, signer seed, trusted
  capability issuers, upstream request timeout.
- `ProtectProxy` - `new(config)`, `run()` / `run_with_observer(|addr| ..)`,
  `routes_from_spec(spec_content)` (route-table construction for tests).
- `RequestEvaluator` - `new_ephemeral(routes, keypair, policy_hash)` and
  variants adding a trusted-issuer list and/or a caller-supplied
  `ApprovalStore`; `new_with_durable_stores(...)` for production use (fails
  closed unless `allow_ephemeral` opts into losing state on restart);
  `evaluate`, `evaluate_with_execution_nonce`, `evaluate_chio_request`,
  `finalize_receipt`, `receipt_backend()`, `revocation_backend()`. Pre-rename
  `new*` constructors remain as deprecated shims.
- `RouteEntry { pattern, method, operation_id, policy }`.
- `EvaluationResult { verdict, receipt, evidence, execution_nonce }`.
- `ProtectError` - spec load/parse, config, upstream, evaluation, pending
  approval, receipt sign/store, IO, and HTTP client errors.
- `discover_spec(upstream)`, `load_spec_from_file(path)`.
- `DEFAULT_UPSTREAM_REQUEST_TIMEOUT` (20 seconds).

## Usage

```rust
use chio_api_protect::{ProtectConfig, ProtectProxy, DEFAULT_UPSTREAM_REQUEST_TIMEOUT};

let config = ProtectConfig {
    upstream: "https://api.example.com".to_string(),
    spec_content: None,
    spec_path: Some("openapi.json".to_string()),
    listen_addr: "127.0.0.1:9090".to_string(),
    receipt_db: Some("receipts.db".to_string()),
    allow_ephemeral_receipts: false,
    sidecar_control_token: None, // Control endpoints disabled, including on loopback.
    signer_seed_hex: None,
    trusted_capability_issuers: Vec::new(),
    control_url: None,
    control_token: None,
    budget_db: None,
    revocation_db: None,
    require_nonce: false,
    allow_advisory: false,
    upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
};

ProtectProxy::new(config).run().await?;
```

To enable operator endpoints, supply a dedicated nonempty
`ProtectConfig::sidecar_control_token` and send it as a single
`Authorization: Bearer <token>` header. The CLI reads
`CHIO_SIDECAR_CONTROL_TOKEN` (or `CHIO_API_PROTECT_CONTROL_TOKEN`). Keep the
credential out of agent and tool-process environments; it grants broad
operator/tool-server authority, not a scoped agent capability. Missing, blank,
wrong, or duplicate credentials return `403 chio_control_forbidden`.
See [the control authority contract](../../../docs/security/sidecar-control-authority.md).

## Sidecar routes that are not production authorization paths

The proxy mounts SDK helper routes beside the upstream reverse proxy. Only
`POST /chio/evaluate` and the upstream proxy path itself run kernel-mediated
evaluation. `POST /v1/evaluate` is a separate pre-execution reservation gate:
it requires a local hold-capable budget store and a configured control token
for downstream reconciliation. It mints execution nonces, never dispatches a
tool or accepts a presented nonce as completion. The trusted execution site
settles through authenticated `POST /v1/reconcile`.

Do not use the following as a concrete-call authorization gate:

- `POST /v1/evaluate/advisory` - signs a `TrustLevel::Advisory` receipt after
  a local revocation and parameter-hash check only. Response sets
  `chio-trust-level: advisory` and `authorization: false`.
- `POST /v1/capabilities/attenuate` - always `403`; the sidecar never holds
  the parent subject's signing key.
- `POST /v1/capabilities/validate` - checks signature, trusted issuer,
  revocation (including the delegation chain), and expiry only; it does not
  evaluate policy or scope against a concrete call.
- `POST /v1/capabilities` / `POST /v1/capabilities/mint` - mint
  sidecar-signed tokens for development and SDK ergonomics.
- `POST /v1/receipts` - accepts operator-submitted receipts for logging;
  acceptance does not imply the kernel mediated the original action.

## Testing

`cargo test -p chio-api-protect`

`crates/tooling/chio-conformance` also drives this crate's real proxy
dispatch path (`ssrf_external_guard_api_protect_dispatch.rs`), a
negative-conformance test for the upstream egress contract.

## See also

- `chio-http-core` - `HttpAuthority`, the evaluation engine this crate calls
  for every request, plus the shared sidecar types (`ChioHttpRequest`,
  `HttpReceipt`, `ApprovalAdmin`).
- `chio-kernel` - guard pipeline and the `ApprovalStore`/`ReceiptStore`/
  `RevocationStore` traits `HttpAuthority` runs against.
- `chio-openapi` - spec parsing, Chio policy extensions, and default policy
  derivation.
- `chio-store-sqlite` - durable backing for the kernel's receipt, revocation,
  and approval stores.
- `chio-cli` - invokes this crate for `chio api protect` and `chio start`.
