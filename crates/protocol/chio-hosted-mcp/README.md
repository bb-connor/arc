# chio-hosted-mcp

Provides a small facade over remote MCP serving and control-plane setup.
The public surface reexports runtime functions; HTTP, session, and
authentication implementation lives in `chio-mcp-remote`.

## Usage

Pass an operator-configured `RemoteServeHttpConfig` to the blocking service
entrypoint. This wrapper type-checks without starting a listener or subprocess.

```rust
use chio_hosted_mcp::{serve_http, CliError, RemoteServeHttpConfig};

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

- `serve_http` delegates to `chio-mcp-remote`, which validates transport,
  authentication, admitted manifests, launch authority, and session stores.
- Reexported store and authority helpers execute their control-plane checks.
  The facade adds no validation or policy decisions of its own.
- The facade's dependency test requires exactly `chio-control-plane` and
  `chio-mcp-remote` as normal dependencies.

## Status

This crate implements a reexport boundary and has no independent server loop.
The remote crate owns behavioral tests; the facade test checks dependency scope.
Local authorization endpoint code exists; the protocol retains a separate
acceptance boundary for a hosted OAuth authorization-server product.
Operator custody and deployment acceptance require their own evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Hosted wire format](../../../spec/PROTOCOL.md#43-hosted-wire-format)
- [Remote runtime](../chio-mcp-remote/README.md)
- [License](../../../LICENSE)
