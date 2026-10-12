# chio-commerce-order

Verifies supplied commerce-order evidence: state transitions, mandate
allowances, provider trust, payment status, settlement, and optional
coverage/trust-market context. It produces a digest-bound order summary for
Chio transaction proof consumers.

## Usage

Demonstrate rejection of a bundle missing its committed event log. The
context fixture is embedded at compile time. Complete verification requires
the committed artifact bytes and independently selected authority keys.

```rust
use chio_commerce_order::{verify_commerce_order, CommerceOrderContext,
    CommerceOrderError, CommerceOrderVerificationBundle};

let context: CommerceOrderContext = serde_json::from_slice(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "commerce-payments/offline-psp-valid/order-context.json")))?;
let bundle = CommerceOrderVerificationBundle {
    order_context: context, event_log_bytes: vec![],
    event_authority_receipts: vec![], payment_lifecycle_bytes: vec![],
    mandate_ledger_bytes: vec![], provider_passport_bytes: vec![],
    reputation_snapshot_bytes: vec![], federation_trust_bundle_bytes: vec![],
    settlement_packet_bytes: vec![], mandate_protocol_payloads: vec![],
    risk_comptroller_report_bytes: None, verified_trust_market_context: None,
    trusted_event_authority_receipt_kernel_keys: vec![],
    trusted_payment_signer_keys: vec![], trusted_provider_trust_signer_keys: vec![],
    trusted_risk_comptroller_signer_keys: vec![],
};
assert!(matches!(verify_commerce_order(&bundle),
    Err(CommerceOrderError::DigestMismatch { field, .. }) if field == "event log"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`verify_commerce_order` bounds supplied document bytes/count, calls
`CommerceOrderContext::validate_shape`, and recomputes quote/artifact
digests before replay. Replay verifies authority receipts and transition
consistency; payment/provider validation uses supplied signer pins.

Required coverage verifies a signed risk report’s coverage projection.
Required trust-market context checks a supplied
`CommerceVerifiedTrustMarketContext` for matching references and provider
subject. Callers obtain that context from an independently completed
trust-market verification.

## Status

Implemented offline order-evidence verifier and selective summary
generation. It consumes supplied PSP/protocol evidence and executes no
payment or settlement. Provider evidence freshness is evaluated relative to
order-context time. A typed verified trust-market context is supplied
evidence whose provenance the caller must enforce.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#644-commerce-order-and-settlement-family)
- [chio-trust-market-context](../chio-trust-market-context/README.md)
- [License](../../../LICENSE)
