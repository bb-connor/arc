# chio-core-types

`chio-core-types` owns Chio's shared capability, receipt, manifest, session,
canonical JSON, hashing, and signing vocabulary. Kernels and adapters use this
substrate without importing the larger domain facade in `chio-core`.

## Usage

Validate raw JSON before using its canonical bytes as signed input:

```rust
use chio_core_types::canonical_json_bytes_from_str;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = canonical_json_bytes_from_str(r#"{"b":2,"a":1}"#)?;
    assert_eq!(bytes, br#"{"a":1,"b":2}"#);
    assert!(canonical_json_bytes_from_str(r#"{"a":1,"a":2}"#).is_err());
    Ok(())
}
```

Typed-value serializers cannot recover duplicate keys discarded by an earlier
parser. Select the strict raw-text entry point at an untrusted signing boundary.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default`  | Yes | Enables `std`. |
| `std`  | Yes | Enables hosted dependency features and `thiserror`; disabling defaults selects `no_std + alloc` source. |
| `kani`  | No | Selects `sha2/force-soft` for portable SHA-256 verification. |
| `fips`  | No | Enables AWS-LC-backed P-256/P-384 backends and requires `std`. |
| `pq`  | No | Enables `fips204` and ML-DSA-65/hybrid signing types. |
| `delegation`  | No | Compatibility no-op; recursive delegation is always compiled. |

Backend availability alone does not establish a deployment's certification.
WASM builds enable `getrandom/js` through a target-specific dependency.

## Guarantees

- `canonical_json_bytes_from_str` rejects duplicate keys and invalid signing
  number representations before canonicalization.
- `CanonicalBytes<CanonicalJsonWitness>` exposes immutable serializer-produced
  bytes for signing and hashing.
- `validate_attenuation` requires the child's scope to be a subset of its parent.
- `Keypair::sign_wrapped` signs the signing wrapper over canonical bytes under a
  registered schema id and refuses an unregistered id.
- `verify_wrapped` takes the algorithm from the pinned key only and returns an
  error on any refusal.

## Status

The substrate is implemented and marked `publish = false` in this workspace.
It supplies validation primitives; callers own admission, trusted key selection,
clock inputs, replay state, and durable storage. Generated schema bindings are
regenerate-only artifacts outside the crate-root public exports.

## Related

- [Architecture](ARCHITECTURE.md)
- [Canonical JSON contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [Unified facade](../chio-core/README.md)

## License

See the workspace [license](../../../LICENSE).
