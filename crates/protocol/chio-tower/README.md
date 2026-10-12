# chio-tower

Wraps replayable Tower HTTP services with Chio request evaluation and signed
HTTP receipts, and supplies kernel service layering utilities.

## Usage

```rust
use chio_core_types::crypto::Keypair;
use chio_tower::ChioLayer;
use tower::Layer;

let layer = ChioLayer::new_ephemeral(Keypair::generate(), "local-policy".into());
let inner = tower::service_fn(
    |_request: http::Request<http_body_util::Full<bytes::Bytes>>| async {
        Ok::<_, std::convert::Infallible>(http::Response::new(()))
    },
);
let _service = layer.layer(inner);
```

The example constructs an offline layer with explicitly ephemeral stores.
For durable operation, configure receipt and revocation stores through the
builder. Plain `ChioLayer::new` denies mediated calls until durable state is wired.

## Guarantees

- `ChioService` bounds request bodies before evaluation and replays accepted
  request bytes to the wrapped service.
- `ChioEvaluator` uses `HttpAuthority` for admission and signs HTTP decisions.
  Durable receipt persistence depends on configured stores.
- `extract_identity` hashes presented credentials into caller labels and marks
  those identities unverified; trusted authentication requires host integration.

## Status

Implemented Tower middleware for Axum and replayable bytes-backed HTTP bodies.
The HTTP/2 integration test approximates unary gRPC traffic with `Full<Bytes>`;
actual `tonic::body::Body` replay is outside that tested contract.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-mcp-edge](../chio-mcp-edge/README.md)

## License

[Workspace license](../../../LICENSE).
