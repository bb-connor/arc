# chio-listing

`chio-listing` defines Chio registry listings, replica aggregation, marketplace
pricing hints, and explicit local trust activation. It also supplies outcome
pricing, SLA, predicate, delivery, and verdict contracts. Consumers supply
registry reports and operator policy; this library performs no discovery I/O.

## Usage

Create a signed pricing hint for a published listing. The hint states the
operator's price and SLA; search later checks its binding to the listing.

```rust
use chio_listing::{
    crypto::Keypair, ListingPricingHint, ListingSla, MonetaryAmount,
    SignedListingPricingHint, LISTING_PRICING_HINT_SCHEMA,
};

let operator = Keypair::from_seed(&[7; 32]);
let hint = ListingPricingHint {
    schema: LISTING_PRICING_HINT_SCHEMA.into(),
    listing_id: "listing/example".into(),
    namespace: "https://registry.example".into(),
    provider_operator_id: "operator/example".into(),
    capability_scope: "tools:search".into(),
    price_per_call: MonetaryAmount { units: 10, currency: "USD".into() },
    sla: ListingSla {
        max_latency_ms: 250,
        availability_bps: 9_990,
        throughput_rps: 50,
    },
    revocation_rate_bps: 10,
    recent_receipts_volume: 500,
    issued_at: 100,
    expires_at: 200,
};
hint.validate()?;
let signed = SignedListingPricingHint::sign(hint, &operator)?;
assert!(signed.verify_signature()?);
assert!(signed.body.is_live_at(150));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`search` joins supplied reports and pricing hints using `ListingQuery`.
`compare` builds relative price and SLA rows. `resolve_admissible_listing`
checks active status, live pricing, and the retained fresh replica marker.
Consumers must refresh reports and check listing expiry before use; local
runtime trust requires its own activation decision.

## Guarantees

- `GenericListingBoundary::validate` requires visibility-only publication,
  explicit trust activation, and disabled automatic admission.
- `ensure_generic_listing_signed_by_namespace_owner` checks body validation,
  envelope signature, and equality with the body's declared owner key.
  Consumers establish trust in that declared ownership separately.
- `aggregate_generic_listing_reports` rejects stale or invalid reports and
  excludes divergent replicas. `search` requires active listings and live,
  signed pricing hints bound to their namespace owner and publisher.
- `evaluate_generic_trust_activation` requires a pinned local signer and
  binds activation to the current listing identity, body hash, and timestamp.
  Activation requiring bond backing always remains non-admitted in this evaluator.

## Status

Registry, marketplace, trust-activation, and outcome contracts are implemented
as library checks. Pricing and SLA counters are supplied statements. The crate
has no persistent registry, endpoint client, bond resolver, or tool executor.
Its Cargo package is marked `publish = false`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Portable trust and federation](../../../spec/PROTOCOL.md#10-portable-trust-and-federation)
- [Open-market bidding](../chio-open-market/README.md)
- [License](../../../LICENSE)
