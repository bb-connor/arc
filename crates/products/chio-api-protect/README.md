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
    transport: Default::default(),
    upstream: "https://api.example.com".to_string(),
    spec_content: None,
    spec_path: Some("openapi.json".to_string()),
    spec_sha256: None,
    allow_anonymous_reads: false,
    listen_addr: "127.0.0.1:9090".to_string(),
    receipt_db: Some("receipts.db".to_string()),
    allow_ephemeral_receipts: false,
    sidecar_control_token: None, // Control endpoints disabled, including on loopback.
    receipt_retention: None,
    signer_seed_file: Some("/var/lib/chio/authority.seed".into()),
    signer_seed_hex: None,
    trusted_capability_issuers: Vec::new(),
    control_url: None,
    control_token: None,
    budget_db: None,
    revocation_db: None,
    require_nonce: false,
    allow_advisory: false,
    approval: None,
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

Nonempty configured tokens must have valid Bearer-token syntax and fit within
512 bytes after trimming; invalid configuration rejects before startup I/O.
The upstream proxy rejects control-token bytes in any request header value,
including duplicate and binary values, before admission or forwarding.
With control enabled, a 64 KiB aggregate name/value header budget bounds this
scan. Ordinary unrelated upstream credentials are preserved.

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
  sidecar-signed tokens bound to the caller's supplied public key. Both reject
  labels and malformed keys. The caller keeps the private key; structured
  grants with `dpop_required: true` require its proof on mediated evaluation.
- `POST /v1/receipts` - accepts operator-submitted receipts for logging;
  acceptance does not imply the kernel mediated the original action.

## Execution-bound approvals

Ordinary approvals require `ProtectConfig::approval`, a durable receipt/admission
store, and an authenticated caller executor. The CLI reads the same JSON
configuration from `CHIO_API_PROTECT_APPROVAL_CONFIG`. It contains `tenant_id`,
`approvers` (public keys), `replay_source_path`, the existing activated replay
`binding`, and `caller_executor`. Loading this file does not activate or import a
replay source. Provision and activate the operation-owned source through the
SQLite admission authority migration APIs before serving it. Missing or mismatched
authority fails closed at startup.

The control bearer grants access to workflow routes. Approver authority comes
from the separately configured public-key roster and a signed decision. Neither
the bearer nor the receipt signer automatically becomes an approver.

1. `POST /approvals/submit` carries the complete signed `capability`,
   `tool_server`, `tool_name`, exact `parameters`, and `requested_by` equal to
   the capability subject public key. Optional fields are `summary`,
   `ttl_seconds`, `triggered_by`, and a governed intent envelope. The server
   validates the capability and builds a `BoundToolInvocation`, hashing the
   arguments and full capability together with its tenant, policy and generated
   request identity. A client-supplied parameter hash is rejected.
2. Retrieve the pending request through `GET /approvals/{id}`. An independent
   configured approver signs a `GovernedApprovalToken` over the returned intent
   hash and approval ID. Submit it to `POST /approvals/{id}/respond` as
   `{"outcome":"approved","approver":<public key>,"token":<signed token>}`.
   The compatibility `/operator-respond` route requires the same signed body.
3. `POST /v1/evaluate` carries `approval_id` and the original complete capability,
   route and arguments. It loads the retained signed decision and compares every
   binding to current authority before reserving the call. Direct approval-token
   submission to this route is rejected. A successful reservation still requires
   authenticated `/v1/caller/start` with the signed decision credential and an
   executor using durable single-use dispatch custody.

Decision records retain the original request and signed token in SQLite. Legacy
resolved records without those artifacts remain readable but cannot authorize a
call. Reservation and dispatch reuse the operation-owned replay authority;
reopening the HTTP store does not restore spent approval authority. Current
capability and ancestor revocations, signer roster, tenant, policy, and token
expiry are rechecked before fresh admission and dispatch. Decisions are immutable;
there is no independent per-token revoke endpoint. Revoke the capability or retire
the signer to withdraw authority before dispatch.

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

## Listener transport

See the [shared HTTP transport guide](../../../docs/security/http-transport.md) for
TLS identity files, explicit plaintext policy, client endpoint rules and revocation
response semantics.

## Durable evidence and explicit retention

Durable mode requires an existing owner-only signing seed file. Startup never
creates or repairs custody; provision a private 32-byte seed as hexadecimal,
owned by the service account, without symlinks or hard links (0600 on Unix).
`signer_seed_hex` is limited to explicit ephemeral embedding and conflicts with
a seed file. Native launchers use `--authority-seed-file`.

HTTP projections retain the entire signed HTTP receipt inside the signed core
record under `metadata.chio_http_receipt_v1`. HTTP and tool evidence share the
kernel's immutable SQLite writer and checkpoint chain. Duplicate sidecar
submissions cannot replace existing evidence. Kernel result redelivery is
idempotent; reserve and reconcile responses expose `evidence_persisted` and
preserve signed recovery evidence after an irreversible settlement.

`POST /v1/receipts` produces an advisory observation of an operator report.
Verification checks its signature but returns `authorized: false`. It does not
attest that the reported job ran or succeeded.

Retention is disabled until all three policy values are explicit:

```bash
chio --authority-seed-file /var/lib/chio/authority.seed start \
  --receipt-store /var/lib/chio/receipts.db \
  --receipt-retention-days 180 \
  --receipt-archive /var/lib/chio/receipts-archive.db \
  --receipt-retention-interval-secs 3600
```

The same flags apply to `chio api protect`. Embedders set
`ProtectConfig.receipt_retention: Some(ProtectRetentionConfig { ... })`.
The archive parent directory must exist; intervals are 1 through 86400 seconds.
Rotation moves whole eligible checkpoint batches, so the live window may be
longer than the chosen duration. It does not delete archived evidence or compact
admission/outcome blobs. One owned worker records failures in readiness and stops
before the final receipt-writer flush on graceful shutdown.

Ordinary receipt queries and evidence exports authenticate both live and archived
history, preserve sequence cursors and reconstruct original inclusion proofs.
They refuse a missing or corrupt archive. Validation reads the authenticated
archive prefix; `query_live_receipts` is an explicitly live-only diagnostic API.
A copied archive tail beyond the committed live watermark is excluded.

Legacy mutable `http_receipts` / `tool_receipts` rows are preserved without
loading their history at startup. Legacy revocations remain enforced. Export
refuses when legacy receipt rows exist rather than silently omitting them or
re-signing historical claims. Preserve the original database and select a new
evidence database to migrate. Keep the old revocation source configured or
migrate its revocations through the operator authority before switching stores.
