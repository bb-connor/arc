# chio-mcp-remote

Hosts an MCP HTTP edge backed by authenticated Chio kernel sessions and a
wrapped MCP subprocess. The runtime owns HTTP routes, session workers, replay,
remote administration, and configured bearer-token verification.

## Usage

Pass an operator-configured `RemoteServeHttpConfig` to the blocking service
entrypoint. This wrapper type-checks without starting a listener or subprocess.

```rust
use chio_mcp_remote::{serve_http, CliError, RemoteServeHttpConfig};

fn run_host(config: RemoteServeHttpConfig) -> Result<(), CliError> {
    serve_http(config)
}
let _entrypoint: fn(RemoteServeHttpConfig) -> Result<(), CliError> = run_host;
```

A live configuration needs policy and publisher-signed manifest files, a
registered manifest key, authentication, listener transport, and a
`NativeMcpLaunchFactory` authorizing the exact wrapped command. Configure
persistent stores and a resume HMAC keyring when session recovery is required.
The configuration has no default constructor.

## Guarantees

- `serve_http` prepares listener transport, rejects incompatible auth modes,
  and requires configured bearer authentication before installing routes.
- `RemoteSessionFactory::new` requires a publisher-signed manifest and an
  independently registered key; flow-required manifests reject ordinary hosting.
- `read_limited_mcp_post_body` bounds bodies at 8 MiB during reading.
  MCP rate middleware limits each socket-derived IP bucket to 600 requests/minute.
- `TrustedProxyConfig` requires explicit peers and a separate private token.
  Identity headers gain authority only through authenticated proxy provenance.
- Durable resume requires a dedicated HMAC keyring and checks runtime binding;
  `RemoteClock` clones share a clock-regression fence.

## Status

Implements POST initialization, GET/SSE notifications and replay, DELETE session
closure, admin routes, JWT and introspection verification, and session recovery.
Tests exercise HTTP auth, session isolation, worker lifecycle, refusals,
revocation, and recovery with controlled peers and stores.
Local authorization endpoint code exists; the protocol retains a separate
acceptance boundary for a hosted OAuth authorization-server product.
Operator custody and deployment acceptance require their own evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Hosted wire format](../../../spec/PROTOCOL.md#43-hosted-wire-format)
- [Hosted facade](../chio-hosted-mcp/README.md)
- [License](../../../LICENSE)
