# chio-attest-verify

Shared Sigstore verification for Chio artifacts. `AttestVerifier` accepts
artifact bytes, detached signatures/certificates, or Sigstore bundles and
returns certificate identity, digest, time, and transparency metadata.
Tenant policy loading and optional quote backends share this boundary.

## Usage

Check the offline rejection path with explicit operator identity expectations:

```rust
use chio_attest_verify::{AttestVerifier, ExpectedIdentity, SigstoreVerifier};
let verifier = SigstoreVerifier::with_embedded_root()?;
let expected = ExpectedIdentity::doc_hidden_inline(
    r"https://example\.com/release", "https://issuer.example.com"
);
assert!(verifier.verify_bundle(b"artifact bytes", b"{}", &expected).is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

An empty bundle supplies no verification material. Real calls require a
matching signed bundle and trusted identity. Tenant-aware callers resolve
identity from policies authenticated by `TenantPolicyLoader::load_signed`.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Empty; Sigstore and tenant policy APIs remain available. |
| `pq` | No | Enables ML-DSA dependency and core hybrid signature support. |
| `tee-quotes` | No | Enables TDX, SEV-SNP, Nitro, and ECDSA quote dependencies. |
| `kani` | No | Selects software SHA-256 and core Kani support; harnesses require `cfg(kani)`. |
| `kani-research` | No | Includes `kani` and opt-in unproved crypto research harnesses. |

## Guarantees

- `SigstoreVerifier::verify_bytes` validates Fulcio anchoring, current
  certificate validity, exact OIDC issuer, anchored SAN regex, and signature.
- `verify_bundle` hashes artifact bytes and delegates bundle verification,
  then applies certificate identity checks. JSON is bounded to 16 MiB.
- Every Sigstore result currently sets `rekor_inclusion_verified = false`.
  Chio does not independently verify Rekor Merkle inclusion and SET here.
- `TenantPolicyLoader::load_signed` verifies canonical policy bytes, then
  checks the declared signing time against its configured age horizon.

## Status

Implemented Sigstore boundary. Optional quote backends verify signatures,
report bindings, and selected measurements against supplied collateral.
Their chain helpers check byte shape/root equality without verifying X.509
chain signatures; real vendor collateral and hardware acceptance require
additional validation. TDX has no explicit measurement expectation.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [chio-weights](../chio-weights/README.md)

[License](../../../LICENSE)
