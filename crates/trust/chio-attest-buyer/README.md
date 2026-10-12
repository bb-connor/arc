# chio-attest-buyer

Chio-owned buyer packet and review APIs connect runtime evidence checks to
`chio-attest-buyer-core` proof replay. The public types preserve artifact
roles, byte hashes, lineage classifications, and structured rejection reports.

## Usage

Run the repository's offline three-vendor proof fixture through the JSON
boundary. Its trust bundle and verification context are test inputs.

```rust
use chio_attest_buyer::verify_proof_package_json;
let report = verify_proof_package_json(
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../examples/chio-3vendor/fixtures/verifier-trust-bundle.json")),
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../examples/chio-3vendor/fixtures/verification-context.json")),
)?;
assert!(report.accepted);
assert!(report.failure_code.is_none());
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a hydrated review, supply `BuyerAttestationReviewSource` bytes for every
required artifact. Use
`verify_buyer_attestation_review_package_with_proof_replay_json` to add core
proof replay after the runtime review succeeds.

## Guarantees

- JSON readers enforce a 16 MiB original-input bound and duplicate-aware
  signed decoding. Packet and review readers then validate typed boundaries.
- `verify_buyer_attestation_packet` delegates cross-artifact binding checks;
  packet-carried DSSE hashes alone leave verification unresolved.
- The proof-replay review entrypoint turns an otherwise accepted review into
  a rejected report when `chio-attest-buyer-core` rejects its proof package.
- `BuyerAttestationError::code` preserves a public rejection code while
  runtime buyer codes are mapped into this crate's namespace.

## Status

Implemented local evidence verification. Acceptance depends on externally
chosen trust and context material. Budget references do not claim settlement;
full runtime closure also requires kernel admission and regenerated proofs.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [chio-attest-buyer-core](../chio-attest-buyer-core/README.md)

[License](../../../LICENSE)
