# chio-kernel-mobile

Synchronous Rust and UniFFI entry points for embedding Chio's portable kernel
in an iOS or Android application. JSON carries capabilities, requests, and
receipts across the language boundary. The library emits static, shared, and
Rust library artifacts.

## Usage

The Rust entry point is available on a native host. Malformed input returns a
structured error before capability evaluation:

```rust
use chio_kernel_mobile::{evaluate, ChioMobileError};

let result = evaluate("{}".to_string());
assert!(matches!(result, Err(ChioMobileError::InvalidJson { .. })));
```

Generate Swift or Kotlin bindings using the workspace-locked UniFFI example:

```bash
cargo run --locked -p chio-kernel-mobile --example bindgen -- --help
```

Follow the [bindings guide](bindings/README.md) for language generation and
linking. iOS builds need an Apple SDK on Darwin and the matching Rust target;
Android builds need the matching Rust target, Android NDK, and linker setup.
The target-backed script covers `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, and `aarch64-linux-android` when provisioned.

## Guarantees

- `evaluate` rejects unsupported authorization extensions, checks portable
  capability admission, and converts kernel denials into JSON deny responses.
- `sign_receipt` requires a content preimage in hex, rejects malformed or zero
  seeds, and refuses mismatched content hashes or kernel keys through core signing.
- `sign_receipt_relaying_trusted_body` trusts the upstream content hash.
- `verify_passport` delegates pinned-issuer, signature, and time checks to core.
- Platform evidence verification delegates to `chio-custody-hw` with production
  App Attest settings and caller-supplied Play Integrity JWKS disabled.

## Status

Implemented FFI surface with Rust roundtrip and cross-FFI tests. Evaluation uses
an empty guard pipeline and a caller-seeded in-memory budget registry per call.
The app owns revocation, durable accounting, transport, and receipt storage.
`attest_app_attest` and `attest_play_integrity` produce challenge envelopes;
the host obtains the platform evidence. `inspect_mobile_receipt_envelopes`
returns a non-authoritative shape inspection. Production Play Integrity
verification currently fails closed: the pinned Google root is a synthetic
fixture, and this mobile API disables caller-supplied JWKS. Host tests alone do not establish
iOS or Android behavior; validate each platform on its provisioned target.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability contract](../../../spec/PROTOCOL.md#5-capability-contract)
- [Portable kernel](../chio-kernel-core/README.md)
- [License](../../../LICENSE)
