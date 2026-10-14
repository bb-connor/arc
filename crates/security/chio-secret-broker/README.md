# Chio Secret Broker

`chio-secret-broker` holds tenant credentials and uses them in authorized HTTPS
requests. It sits between the kernel's durable admission authority and upstream
providers. Callers send `CredentialRef` identifiers and signed requests; the daemon
resolves encrypted material and injects its provider-owned header inside the
broker process. The package also includes a prepared MCP proxy and host adapters.

## Usage

Construct and validate the caller-owned part of a broker request offline:

```rust
use chio_secret_broker::protocol::{
    normalize_headers, BrokerDestination, BrokerRequest, CallerOptions, HeaderField,
};

let request = BrokerRequest {
    destination: BrokerDestination::parse(
        "https://api.example.com/v1/messages", "POST", false,
    )?,
    headers: normalize_headers([
        HeaderField::normalized("Content-Type", b"application/json")?,
    ])?,
    body: br#"{"message":"hello"}"#.to_vec(),
    approved_preview_sha256: None,
    options: CallerOptions {
        timeout_ms: 5_000,
        streaming: false,
        response_limit_bytes: 65_536,
    },
};
request.validate_bounds()?;
assert_eq!(request.destination.authority(), "api.example.com");
assert_eq!(request.headers[0].name, "content-type");
# Ok::<(), chio_secret_broker::BrokerError>(())
```

This example needs no optional features, service, credential, or network access.
`validate_bounds` checks structure and limits; it accepts explicit IP-loopback
HTTP and does not verify authority. Production execution additionally checks the
signed capability, caller proof, live parent, revocation state, provider policy,
registered attempt, retained preparation, and original captured quota.

A host uses `BrokerIpcClient::register_attempt`, `prepare_dispatch_connection`,
and execution IPC to join that admission flow. `BrokerDaemonConfig::load` and
`BrokerDaemonRuntime::build` compose the serving daemon. Brokerd requires
`--config`, `--master-key-fd`, and `--signing-key-fd`; the inherited descriptors
must contain distinct read-only, fully sealed, owner-checked 32-byte keys.
See [architecture](ARCHITECTURE.md) for startup and recovery requirements.

## Features

No feature is enabled by default. The daemon and generic HTTPS executor are
available without enabling kernel integration.

| Feature | Default | Effect |
| --- | --- | --- |
| `kernel-admission` | Off | Adds kernel quota verification, registration, capture, and authority integration; enables `chio-kernel`, `async-trait`, and `tokio`. |
| `native-mcp` | Off | Enables `kernel-admission` and MCP, manifest, and tracing dependencies; exposes native MCP launch integration on Linux. |
| `real-linux-enforcement` | Off | Enables `native-mcp` and Linux enforcement paths in process boundary tests. |

## Guarantees

- `verify_capability` pins issuer, algorithm, audience, and validity interval;
  `verify_request_proof` binds the caller key, request digests, and freshness.
- `BrokerService` requires authenticated registration and retained preparation,
  verifies the original capture, and durably claims dispatch before transport.
  `replay_completed` validates the exact stored completion; uncertain dispatch
  outcomes cannot authorize another send.
- `EncryptedBlobSecretBackend` scopes encrypted blobs to the tenant. Credential
  materialization and provider header preparation are crate-private. Secret
  buffers use secrecy and zeroization; normal IPC returns sanitized responses
  and signed evidence.
- `GovernedAdminAuthorizer` requires threshold approvals and a durable operation
  journal for credential mutation and capability administration.
- `BrokerDaemonRuntime::build` pins the signing identity, database ownership,
  migration posture, and authority connection before publishing broker sockets.

## Status

The implemented daemon composition uses Linux process isolation, Unix sockets,
rustls HTTPS, four broker SQLite databases, and an independently anchored
enterprise migration ledger. Sealed key consumption supports Linux and Android;
other platforms return custody errors. Non-Unix daemon construction fails.
The host OS, broker service principal, configured authority, and upstream provider
remain trusted. Durable recovery depends on preserving databases and key identity.

Kernel verification alone performs no credential access or dispatch. Native MCP
requires an installed admission and launch composition. Tests use local providers
and fixture authority or lifecycle services alongside process integrations;
their results describe those exercised compositions. Release certification and
public provider deployment require their own evidence.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol: authoritative spend](../../../spec/PROTOCOL.md#62-authoritative-spend-execution-nonce-atomic-hold-mediated-spend-profile)
- [Prepared broker connections](../../../docs/security/broker-prepared-connections.md)
- [Secure IPC](../chio-secure-ipc/README.md)
- [License](../../../LICENSE)
