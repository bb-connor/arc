# chio-tower architecture

## Responsibility and boundary

Wraps replayable Tower HTTP services with Chio request evaluation and signed
HTTP receipts, and supplies kernel service layering utilities.

Implemented Tower middleware for Axum and replayable bytes-backed HTTP bodies.
The HTTP/2 integration test approximates unary gRPC traffic with `Full<Bytes>`;
actual `tonic::body::Body` replay is outside that tested contract.

## Structure

`layer` constructs `ChioLayer` and builder-backed evaluation state.

`service` buffers request bodies, evaluates, calls the inner service, and
  attaches receipt metadata to responses.

`evaluator` wraps HTTP authority and persists converted HTTP receipts.

`identity` and `request_metadata` extract caller and request information.

`kernel_service` provides kernel dispatch, tracing, and tenant concurrency layers.

`metrics`, `host_call`, and `error` define telemetry and failure vocabulary.

## Data and control flow

A layer clones its evaluator into the wrapped `ChioService`. Requests
are bounded and collected so evaluation and the inner service see the same
replayable body bytes. Metadata includes the method, path, and query.

The evaluator prepares authority input using the route resolver and caller
identity. The HTTP authority produces an admission decision and receipt
material. Accepted requests proceed to the wrapped service.

Response completion finalizes receipt status, signs the HTTP receipt, and
appends converted receipt records when a durable sink is attached.
Kernel-service utilities provide a separate layering surface for tool calls.

## Trust and invariants

`ChioEvaluator::new` has no durable stores and starts fail-closed.
`new_ephemeral` explicitly allows in-memory state for local use. Builder
configuration controls receipt, revocation, and durable admission stores.

Default identity extraction treats bearer, API-key, and cookie presentations
as unverified labels. Host authentication and tenant binding require trusted
configuration. A label derived from a token is not proof of token validity.

The evaluator defaults to fail-closed and exposes an explicit fail-open
setting. Receipt auditing depends on persistence configuration and successful
conversion to a verifiable record. Body replay requires a compatible body
type; tests do not establish every Tower or gRPC body implementation.

## Dependencies

`chio-http-core` supplies HTTP authority, receipt, and identity types.
`chio-kernel` supplies stores and dispatch. Tower traits compose services;
HTTP body utilities and bytes implement replay. Metrics and tracing
dependencies expose bounded service telemetry.

## Verification

Unit tests cover evaluators, identity extraction, body limits, and receipts.
Integration tests cover Axum, bytes-backed HTTP/2, overload, and per-tenant
concurrency. Async kernel dispatch fixtures require a multi-thread Tokio runtime.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-tower
```

See the [README](README.md) for a minimal public API example and requirements.
