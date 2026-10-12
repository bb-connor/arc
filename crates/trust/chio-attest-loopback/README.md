# chio-attest-loopback

Repository support for a fixed three-vendor Chio proof workflow. It builds
signed receipts, leases, governance, bilateral DSSE, aggregate workflow
receipts, and BBS disclosure for offline verification and runtime harnesses.

## Usage

Build and verify the local fixture package without writing files:

```rust
use chio_attest_loopback::{
    fresh_proof_package, verification_context, verify_package,
    verifier_trust_bundle_document_for_package, ChioVerifierTrustBundle,
};
let package = fresh_proof_package()?;
let trust = ChioVerifierTrustBundle::from_document(
    verifier_trust_bundle_document_for_package(&package)?
)?;
let report = verify_package(&package, &trust, &verification_context())?;
assert!(report.accepted);
assert_eq!(package.tool_receipts.len(), 3);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The generated package and trust material use committed fixture keys and a
fixed verification window. A fresh BBS proof can vary its proof bytes.

## Guarantees

- `fresh_proof_package` regenerates a disclosure proof over the assembled
  workflow body and checks that its subject matches that body.
- `proof_package_from_runtime_receipts` requires three fixture-bound receipts:
  matching tool/server/capability, allow decision, action hash, metadata,
  vendor key, and valid signature.
- `proof_package_from_runtime_artifacts` also checks supplied workflow steps
  and bilateral evidence against the issued lease/governance material.
- `write_signed_negative_case_inputs` re-signs deliberately inconsistent
  cases so downstream tests exercise semantic binding failures.

## Status

Test-support and bounded runtime harness library. Public seed helpers expose
fixture signing keys. Runtime receipt inputs remain tied to the same vendor
identities and workflow. Treat fixture trust bundles and copied reports as
local test material; operational buyer closure needs independent runtime
trust, kernel denial, and proof regeneration.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [chio-attest-buyer-core](../chio-attest-buyer-core/README.md)

[License](../../../LICENSE)
