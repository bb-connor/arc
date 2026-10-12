# chio-attest-buyer-core

Offline verification of Chio workflow proof packages binds receipts,
bilateral DSSE, leases, governance, and BBS disclosure to verifier-owned
trust material and a challenge context. The crate returns an audit report
without contacting a service or mutating admission authority.

## Usage

Verify the repository's signed three-vendor fixture with its matching
fixture trust bundle and context:

```rust
use chio_attest_buyer_core::{
    context::verification_context_from_json,
    proof_package::proof_package_from_json,
    report::verify_package,
    trust_bundle::verifier_trust_bundle_from_json,
};
let package = proof_package_from_json(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
)))?;
let trust = verifier_trust_bundle_from_json(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
)))?;
let context = verification_context_from_json(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/chio-3vendor/fixtures/verification-context.json"
)))?;
assert!(verify_package(&package, &trust, &context)?.accepted);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Production callers choose trust material independently of the submitted
package and provide a fresh audience, challenge, purpose, and time window.

## Guarantees

- `verify_package` checks workflow signatures and step links, pinned peer
  and vendor hints, trusted leases and governance receipts, strict bilateral
  invocation verification, and the context-bound BBS disclosure contract.
- `ChioVerifierTrustBundle::from_document` requires nonempty trust families,
  explicit active authority lifecycles, disclosure policy, and a signed
  revocation checkpoint. Historical unsigned epoch input is rejected.
- `verify_package_report` retains successful checks before a failure and
  records hashes of the package, trust document, and context when available.
- JSON readers apply a 16 MiB original-input bound and signed decoding.
  `proof_package_from_json` parses; verification checks its schema and claims.

## Status

Implemented offline verifier with repository fixtures and a Criterion
verification benchmark. Supported disclosure uses a BBS reveal set.
Hidden range predicates, VC Data Integrity BBS interoperability, and zkVM
claims are rejected. Verification time is pinned to checkpoint issuance;
applications own wall-clock freshness and trusted checkpoint selection.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [chio-attest-buyer](../chio-attest-buyer/README.md)

[License](../../../LICENSE)
