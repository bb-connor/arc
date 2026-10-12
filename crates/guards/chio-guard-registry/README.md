# chio-guard-registry

Distributes Chio guard artifacts through OCI registries and a digest-addressed
local cache. It validates artifact packaging and coordinates local Sigstore
verification through `chio-attest-verify`. Kernel guard execution belongs to
`chio-wasm-guards`.

## Usage

Parse a pull reference without network or filesystem operations:

```rust
use chio_guard_registry::GuardOciRef;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reference: GuardOciRef = format!(
        "oci://registry.example.com/team/guard@sha256:{}", "a".repeat(64)
    ).parse()?;
    assert_eq!(reference.registry(), "registry.example.com");
    assert_eq!(reference.repository(), "team/guard");
    Ok(())
}
```

The sample uses default features and the crate's public reference parser.
For retrieval, call `GuardRegistryClient::pull_guard_to_cache` with a cache,
credentials, and optional Sigstore verification dependencies. Then apply
`load_guard_with_policy` before admitting a cached module.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; transport, cache, and verification APIs are available. |
| `marketplace` | No | Adds marketplace price/reputation metadata and discovery helpers. |
| `pq` | No | Enables the shared verifier's PQ feature for crypto-floor regression tests; cosign bundles remain classically signed. |

## Guarantees

- `GuardOciRef::from_str` requires `oci://`, an explicit registry, and a lowercase
  SHA-256 digest. Pull references reject tags accompanying a digest.
- Artifact validation checks the pinned OCI manifest and descriptor bytes,
  sizes, media types, and WIT/module/guard-manifest layer order.
- `GuardSigstoreVerifier::verify_bundle` requires independently verified Rekor
  inclusion. Reporting APIs preserve unverified inclusion metadata.
- `verify_dual_mode` invokes both supplied verifiers and requires matching
  artifact digests, matching normalized identities, and verified Rekor inclusion.
- `load_guard_with_policy` checks cache completeness and integrity before calling
  the supplied signature verifier. Offline misses deny.

## Status

OCI publication, pull, referrer discovery, cache validation, and offline load
policy are implemented. Pulling without injected Sigstore dependencies can cache
artifacts with `sigstore_verified = false`; callers must enforce load admission.
Registry paths and signer annotations do not grant host-function capabilities.
The ignored Zot integration test requires Docker and downloads a registry image.
Marketplace metadata does not perform payment or runtime policy activation.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [WASM guards](../chio-wasm-guards/README.md)
- [Attestation verifier](../../trust/chio-attest-verify/README.md)

[License](../../../LICENSE)
