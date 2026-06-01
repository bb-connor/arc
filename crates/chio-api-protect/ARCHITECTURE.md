# chio-api-protect Architecture

`chio-api-protect` owns the zero-code HTTP sidecar product behind
`chio api protect` and `chio start`. It translates inbound HTTP requests into
Chio HTTP authority inputs, signs decision and final receipts, persists local
receipt and revocation state when configured, and exposes sidecar control routes
for capability minting, release, receipt submission, receipt verification, and
human approval workflows.

## Module Boundaries

- `src/lib.rs` is the public crate boundary: `ProtectConfig`, `ProtectProxy`,
  `RequestEvaluator`, `EvaluationResult`, `RouteEntry`, `ProtectError`, and spec
  loading helpers.
- `src/evaluator.rs` owns OpenAPI route matching, caller identity extraction,
  capability extraction, policy-mode mapping, and the call into
  `chio_http_core::HttpAuthority`.
- `src/proxy.rs` is the product router and test harness container. The
  implementation is split through `src/proxy/*` for approval routes, HTTP
  utilities, receipt helpers, router assembly, sidecar endpoints, scope checks,
  and state/storage.
- `src/spec_discovery.rs` owns OpenAPI discovery/loading and the upstream egress
  contract. It must not weaken outbound host, scheme, redirect, or loopback
  constraints.
- `src/error.rs` is the product error surface. It maps library failures into
  operator-visible errors without exposing secrets.

## Pain Points

- Caller identity extraction exists in both `evaluator.rs` and
  `proxy/http_util.rs`. Divergence here changes signed receipt caller hashes
  depending on which product path handled the request.
- `proxy.rs` still acts as a large integration-test container. That is
  acceptable for now because the tests exercise product routes end to end, but
  new code should stay in the focused `src/proxy/*` modules.
- Sidecar compatibility routes serve multiple SDK shapes. Tight validation is
  preferable to silently normalizing malformed authorization material.

## Security And API Constraints

- Side-effect HTTP methods and routes marked approval-required must fail closed
  before upstream forwarding unless a valid capability authorizes the request.
- Chio transport credentials, including `x-chio-capability` and
  `chio_capability`, must not be forwarded upstream.
- Control endpoints are loopback-only unless a configured bearer token matches
  in constant time.
- Receipt signatures, caller identity hashes, response-status rebinding, and
  durable revocation semantics must remain stable across restarts.
- Public API compatibility is preserved. Internal helper movement can occur, but
  exported `ProtectConfig`, `ProtectProxy`, `RequestEvaluator`, and discovery
  helpers must keep their existing signatures unless separately approved.

## Affected Dependents

- `chio-cli` invokes this crate for `chio api protect` and `chio start`.
- SDK compatibility routes are exercised by Python and controller integrations
  that call `/v1/capabilities`, `/v1/evaluate`, and `/v1/receipts`.
- `chio-http-core`, `chio-kernel`, `chio-openapi`, and `chio-store-sqlite`
  remain the owners of authority evaluation, approval store semantics, OpenAPI
  parsing, and durable stores. This crate should adapt to them, not duplicate
  their protocol logic.

## Planned Improvement

Unify caller identity normalization so direct proxy requests and evaluator
requests reject the same malformed bearer/API-key credentials and produce the
same anonymous identity fallback. This is architectural rather than cosmetic:
the signed receipt caller identity is part of the product trust boundary, and
split parsing lets one path treat blank or padded authorization material as an
authenticated caller while another path treats it as anonymous.
