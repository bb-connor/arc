# chio-api-protect

Zero-code reverse proxy that fronts an existing HTTP API with Chio policy,
capability enforcement, and signed receipts. Proxied HTTP requests clear the
embedded HTTP authority before reaching the upstream. Direct tool calls use a
separate reservation and reconciliation path. This is the library behind
`chio api protect` and `chio start` in `chio-cli`.

## Responsibilities

- Acquire an OpenAPI spec (`discover_spec` probes well-known upstream paths;
  `load_spec_from_file` reads a local path) and build a route table with a
  `chio_openapi::PolicyDecision` per method/path pair.
- Match proxied requests and `POST /chio/evaluate` against the route table and
  evaluate them through `chio_http_core::HttpAuthority` (`RequestEvaluator`).
  Caller identity comes from `Authorization`/`X-API-Key`; capabilities come
  from `X-Chio-Capability` or `?chio_capability=`.
- Authorize direct tool calls through the process-lifetime mediation kernel at
  `POST /v1/evaluate`, then settle their reserved holds at
  `POST /v1/reconcile`.
- Run the reverse proxy (`ProtectProxy`, Axum-based): forward allowed
  requests to the upstream under a locked-down `HttpEgressContract`, finalize
  the decision receipt with the real response status, and return a signed
  deny receipt fail-closed otherwise.
- Persist HTTP receipts, tool receipts, approvals, and capability revocations
  when `receipt_db` is set. Refuse to start without a durable receipt store
  unless `allow_ephemeral_receipts` is explicit.
- Expose capability, receipt, approval, metrics, evaluation, and reconciliation
  routes with route-specific control gates.

## Public API

- `ProtectConfig` - upstream and spec settings, receipt and revocation storage,
  control-plane and local budget settings, control tokens, signer seed, trusted
  issuers, advisory mode, nonce compatibility flag, and upstream timeout.
- `ProtectProxy` - `new(config)`, `run()` / `run_with_observer(|addr| ..)`,
  `routes_from_spec(spec_content)`, `with_verified_manifest_registry(...)`,
  `with_threshold_approval_collector(...)`, and `with_payment_adapter(...)`.
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
    receipt_db: Some("/var/lib/chio/receipts.db".to_string()),
    allow_ephemeral_receipts: false,
    sidecar_control_token: None,
    signer_seed_hex: None,
    trusted_capability_issuers: Vec::new(),
    trusted_historical_receipt_signers: Vec::new(),
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

The example enables the HTTP proxy path. Durable direct tool mediation
additionally requires `receipt_db`, a restart-stable `signer_seed_hex`, a local
hold-capable `budget_db`, and a nonblank `sidecar_control_token`. A remote
`control_url` alone cannot persist the hold required by `/v1/evaluate` and
`/v1/reconcile`.

## Authorization routes

Three routes run kernel authorization:

- The catch-all proxy path evaluates an HTTP request and forwards an allow
  verdict under the upstream `HttpEgressContract`.
- `POST /chio/evaluate` evaluates a `ChioHttpRequest` through the same
  OpenAPI-derived `HttpAuthority` without forwarding it.
- `POST /v1/evaluate` authorizes a direct tool call through the separate
  long-lived mediation kernel.

`POST /v1/evaluate` is a pure pre-execution gate. It verifies the capability
and supplied security artifacts, opens a caller-owned budget reservation, and
returns `{ status, receipt, execution_nonce }`. It does not dispatch a tool,
consume a nonce, reconcile a hold, or settle spend. A presented
`execution_nonce` is rejected. Authorization requires a local `budget_db` and
a configured nonblank `sidecar_control_token`; the evaluate caller does not
present that token.

The mediated request accepts these fields:

- Required: `capability`, `tool_server`, `tool_name`.
- Optional: `parameters`, `agent_id`, `request_id`, `governed_intent`,
  `approval_token`, `approval_tokens`, `threshold_approval_proposal`,
  `supplemental_authorization`, `declassification_grant`, `dpop_proof`.
- Explicitly rejected when present: `execution_nonce`.

Unknown fields are rejected. `approval_token` and `approval_tokens` are
mutually exclusive. The canonical threshold form supplies `approval_tokens`
with `threshold_approval_proposal`; those artifacts and the governed intent
must bind the explicit `request_id`. When `request_id` is absent, the sidecar
mints one, so any pre-signed approval token or proposal requires the caller to
supply its bound id. A supplemental authorization has the wire shape
`{ "reference": string, "artifact": [u8, ...] }`. It is forwarded to the
kernel rather than ignored, but the default `ProtectProxy` installs no
supplemental quota verifier or admission registrar, so supplying it denies
fail-closed.

`POST /v1/reconcile` accepts `{ execution_nonce, arguments, realized_cost }`
from the trusted tool server. It verifies and consumes the nonce, settles the
reserved hold, and returns the authoritative spend receipt. It always requires
the matching configured bearer token, including for loopback callers.

## Helper and control routes

- `POST /v1/evaluate/advisory` - signs a `TrustLevel::Advisory` receipt after
  local revocation and parameter-hash checks only. It is available only when
  `allow_advisory` is true; otherwise it returns `409` with
  `chio_advisory_disabled`. A successful response sets
  `chio-trust-level: advisory` and `authorization: false`.
- `POST /v1/capabilities/attenuate` - always `403`; the sidecar never holds
  the parent subject's signing key.
- `POST /v1/capabilities/validate` - checks trusted issuer, signature,
  expiry, leaf and ancestor revocation, and optional `expected_subject` and
  `expected_scope` constraints. It does not authorize a concrete call.
- `POST /v1/capabilities` / `POST /v1/capabilities/mint` - mint
  sidecar-signed tokens for development and SDK ergonomics.
- `POST /v1/receipts` - accepts operator-submitted receipts for logging;
  acceptance does not imply the kernel mediated the original action.

Mint, release, validate, attenuate, receipt submission, approvals, and metrics
use the general control gate. With a nonblank `sidecar_control_token`, every
caller must present the matching bearer token. With no configured token, only
loopback callers pass. A configured blank token rejects every caller.
`/chio/verify`, `/v1/receipts/verify`, `/chio/evaluate`, `/v1/evaluate`, and the
advisory route are not behind this general gate. `/v1/reconcile` uses the
stricter bearer-only rule described above.

## Durability

- `receipt_db` must be a durable plain SQLite path unless
  `allow_ephemeral_receipts` is true. `:memory:` and `mode=memory` do not count
  as durable.
- A durable `receipt_db` co-locates receipt and approval data and opens a
  durable sibling revocation store. In explicit ephemeral mode, receipts and
  revocations are process-local.
- `revocation_db` is an additional operator revocation source loaded
  fail-closed at startup. It does not replace `receipt_db` and updates written
  after startup require restart or an in-process release/control channel.
- A configured threshold approval collector requires the durable approval
  store derived from `receipt_db`, even when ephemeral operation is otherwise
  allowed.

## Testing

`cargo test -p chio-api-protect`

`crates/tooling/chio-conformance` also drives this crate's real proxy
dispatch path (`ssrf_external_guard_api_protect_dispatch.rs`), a
negative-conformance test for the upstream egress contract.

## See also

- `chio-http-core` - `HttpAuthority` for proxied HTTP and `/chio/evaluate`, plus
  shared sidecar types (`ChioHttpRequest`, `HttpReceipt`, `ApprovalAdmin`).
- `chio-kernel` - the direct mediation kernel, guard pipeline, budget and nonce
  primitives, and the `ApprovalStore`/`ReceiptStore`/`RevocationStore` traits.
- `chio-openapi` - spec parsing, Chio policy extensions, and default policy
  derivation.
- `chio-store-sqlite` - durable backing for the kernel's receipt, revocation,
  and approval stores.
- `chio-cli` - invokes this crate for `chio api protect` and `chio start`.
