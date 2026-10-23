# chio-core

`chio-core` is Chio's unified import surface for protocol primitives and
selected economy and trust domains. It re-exports `chio-core-types` and domain
crates, and implements extension contracts, public identity-network contracts,
and portable identity binding descriptions locally.

## Usage

Sign the signing wrapper over a canonical body under a registered schema id:

```rust
use chio_core::{verify_wrapped_bytes, CanonicalBytes, Keypair};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = Keypair::from_seed(&[7; 32]);
    let body = CanonicalBytes::from_serializable(&json!({"b": 2, "a": 1}))?;
    assert_eq!(body.as_bytes(), br#"{"a":1,"b":2}"#);
    let signature = key.sign_wrapped("chio.receipt.v1", &body)?;
    verify_wrapped_bytes(&key.public_key(), "chio.receipt.v1", &body, &signature)?;
    Ok(())
}
```

The fixed seed makes this example reproducible. Applications must manage their
own signing keys and trusted issuer selection.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default`  | Yes | Empty; the facade's dependencies retain their declared defaults. |
| `pq`  | No | Enables `chio-core-types/pq` and exposes PQ types through this facade. |

## Guarantees

- `Keypair::sign_wrapped` signs only the signing wrapper under a registered
  schema id.
- `validate_extension_inventory` rejects writable canonical truth surfaces
  and inconsistent evidence-mode policy activation requirements.
- `negotiate_extension` reports malformed inventories, packages, and manifests
  as rejection reasons before compatibility negotiation.
- `validate_public_identity_profile` checks supported families, provenance
  methods, references, and binding policy.

## Status

This is an implemented workspace facade with `publish = false`.
Its local modules use `std`; use `chio-core-types` directly when configuring a
portable `no_std + alloc` consumer. Re-exported domain types retain the
validation and operational boundaries of their owning crates. Importing an
artifact type does not activate a runtime or establish release certification.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol scope and compatibility](../../../spec/PROTOCOL.md#2-scope-and-compatibility)
- [Portable substrate](../chio-core-types/README.md)

## License

See the workspace [license](../../../LICENSE).
