# chio-did

`chio-did` constructs and resolves Chio's self-certifying Ed25519 identity.
It maps a canonical `did:chio` identifier to a DID document locally, without
registry access. Credentials use these identifiers for issuer and holder keys.

## Usage

Create an identity and attach an HTTPS receipt-log endpoint. Resolution performs
no network request; the endpoint is metadata supplied by the caller.

```rust
use chio_core_types::Keypair;
use chio_did::{DidChio, DidService, ResolveOptions, resolve_did_chio};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let did = DidChio::from_public_key(Keypair::from_seed(&[7; 32]).public_key())?;
    let options = ResolveOptions::default().with_service(
        DidService::receipt_log(&did, 0, "https://trust.example.com/receipts")?
    );
    let document = resolve_did_chio(&did.to_string(), &options)?;
    assert_eq!(document.authentication, vec![did.verification_method_id()]);
    assert_eq!(document.service.len(), 1);
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `fuzz` | Off | Exposes the fuzz entry point and enables `arbitrary` and `serde_json`. |

## Guarantees

- `DidChio::from_str` requires `did:chio:` followed by exactly 64 lowercase hex
  characters and decodes the Ed25519 public key.
- `DidChio::from_public_key` rejects algorithms other than Ed25519.
- `resolve_with_options` emits one `#key-1` verification method, referenced by
  authentication and assertion methods, with base58btc multicodec key material.
- `DidService::new` parses the URL and requires HTTPS. Direct construction or
  deserialization of public `DidService` fields bypasses that constructor.

## Status

Local resolution and service constructors are implemented. Service reachability,
key possession, issuer trust, revocation, and endpoint ownership require caller
checks. `DidDocument` deserialization alone establishes no identity authenticity.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol identity](../../../spec/PROTOCOL.md#44-identity)
- [Credentials](../chio-credentials/README.md)

## License

[Workspace license](../../../LICENSE)
