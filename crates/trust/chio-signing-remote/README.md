# chio-signing-remote

Remote Ed25519 `SigningBackend` implementations for Chio: a generic HTTP
signing contract and HashiCorp Vault Transit. Both bind an explicit key handle,
version, and public key, then locally verify returned signatures over the
exact message bytes.

## Usage

Construct pinned client configuration offline. Construction sends no request;
`verify_key` and `sign_bytes` contact the configured service.

```rust
use chio_core::Keypair;
use chio_signing_remote::{HttpSigningBackend, RemoteSigningKey};
let fixture_key = Keypair::from_seed(&[7; 32]);
let pin = RemoteSigningKey::new("receipt-key", 1, fixture_key.public_key())?;
assert_eq!(pin.key_version(), 1);
let backend = HttpSigningBackend::new(
    "https://signer.example.com", pin, "example-credential"
)?;
let _backend = backend.with_timeout(std::time::Duration::from_secs(3));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Replace the fixture public key and credential with operator-owned pins and
authentication. Vault callers use `VaultTransitSigningBackend::new` with a
Transit mount and may add a namespace using `with_namespace`.

## Guarantees

- `RemoteSigningKey::new` rejects zero versions, invalid handles, unsupported
  algorithms, and weak Ed25519 keys.
- HTTP signing checks schema, request digest, handle/version/algorithm, and
  message digest before strict local signature verification.
- Vault signing requires the configured `vault:v<version>:` prefix, decodes a
  64-byte signature, and applies strict verification with the pinned key.
- Messages must be nonempty and at most 1 MiB. Response reads stop after
  64 KiB plus one byte; oversized and ambiguous JSON responses are rejected.
- URLs require HTTPS except loopback HTTP. Redirects are disabled;
  configured tokens render as redacted values in client debug output.

## Status

Implemented clients with local HTTP server tests. Each `verify_key` method
provides an explicit remote preflight; construction does not run it.
Service availability, remote authorization, key custody, and deployment
acceptance depend on the operator's signer and transport configuration.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#wysiwys-signing-invariant)
- [chio-custody-hw](../chio-custody-hw/README.md)

[License](../../../LICENSE)
