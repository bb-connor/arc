# chio-eval-receipt

Unsigned export and reference verification for `chio.eval-report.bundle.v1`,
which packages scenario receipts with eval-run and pinned corpus metadata.
The crate uses `chio-core-types` to verify embedded receipts and re-exports
its authoritative-spend predicates for consumers with admitted kernel keys
and an execution nonce.

## Usage

Verify the repository's offline golden fixture:

```rust
use chio_eval_receipt::verify_fixture_bundle;

let json = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"), "/../../../tests/bindings/vectors/eval/v1.json"
));
let verified = verify_fixture_bundle(json)?;
assert_eq!(verified.receipt_count, 3);
assert_eq!(verified.signature_count, 1);
# Ok::<(), chio_eval_receipt::BundleError>(())
```

Fixture verification accepts deterministic `test-sha256` outer signatures
and three exact local receipt fixtures. Select `verify_bundle` for
production inputs; its outer-signature implementation currently rejects
every signature kind, so production bundles cannot succeed.

From the repository root, the same fixture can be checked with:

```sh
cargo run -p chio-eval-receipt -- verify-fixture tests/bindings/vectors/eval/v1.json
```

`export_scenario_run` preserves payload bytes and produces a typed `Bundle`
with empty signatures. Use `EvalRunMeta::from_parts` and
`Receipt::from_parts` to reject empty or padded identity inputs.
The returned structures have public mutable fields; callers must preserve
their validity and supply JSON serialization separately.

## Guarantees

- `verify_schema_envelope` rejects unknown fields, missing required fields,
  invalid enum values, and empty receipt or signature arrays.
- `verify_corpus` matches the compiled digest and 48-scenario count.
  It does not read or hash the corpus manifest.
- `verify_receipts` hashes each payload's exact bytes.
  `verify_chio_receipt_payload` rejects duplicate keys in embedded signed
  JSON and calls `ChioReceipt::verify_integrity_embedded_key`.
- `is_authoritative_spend_receipt` separately checks admitted signer,
  mediated allow semantics, reconciled hold, profile, and nonce bindings.
  Call `receipt_meets_guarantee_floor` separately to enforce a store floor.

`PresentedNonceView` has no subject or request accessors, so the spend helper
does not establish those protocol 6.2 bindings. Consumers requiring that
authority must verify them through an authoritative nonce/admission path.

## Status

Unsigned export and fixture verification are implemented. Production outer
signature verification remains disabled. `verify-memo` checks the synthetic
SHA-256 sample scheme; it provides no partner identity attestation.
Bundle verification does not admit signer keys or validate scenario verdicts
against receipt decisions. No Cargo features are declared; the crate is
unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Export contract](EXPORT-CONTRACT.md)
- [Core types](../../core/chio-core-types/README.md)
- [Protocol receipt semantics](../../../spec/PROTOCOL.md#61-receipt-semantics-and-decisions)
- [Python binding](py/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
