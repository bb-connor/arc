# chio-http-serve

Provides shared Axum request hygiene, connection caps, TLS transport preparation, shutdown signaling, and bounded drain with a flush hook.

This crate sits at Chio's protocol boundary. Its embedding application
chooses the surrounding runtime and transport wiring.

## Usage

The example runs locally without opening a listener or spawning an agent.

```rust
use axum::Router;
use chio_http_serve::{apply_server_hygiene, ServeHygieneConfig, ShutdownController};

let config = ServeHygieneConfig::default();
let _router: Router = apply_server_hygiene(Router::new(), &config);
let shutdown = ShutdownController::manual();
shutdown.trigger();
assert!(shutdown.is_shutdown());
```

## Guarantees

`apply_server_hygiene` installs configured timeout and concurrency layers. `MaxConnListener` holds a permit for each connection lifetime. `run_until_drained` bounds post-signal waiting and propagates serve/flush errors.

Use one ShutdownController for graceful serving and drain. Forced drain
permits detached handlers to continue, so the flush hook must tolerate writers.

## Status

Implemented reusable serving primitives. Hosts wire graceful shutdown, connection caps, body extractors, and durable receipt storage. TLS serves HTTP/1.1 without client certificate authentication.

The crate is workspace-internal (`publish = false`). Its tests exercise
library behavior; deployment configuration needs its own verification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#http-and-openapi-surfaces)
- [chio-envoy-ext-authz](../chio-envoy-ext-authz/README.md)

## License

See the workspace [license](../../../LICENSE).
