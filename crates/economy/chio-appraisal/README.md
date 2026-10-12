# chio-appraisal

`chio-appraisal` projects runtime attestation evidence into portable appraisal
artifacts and evaluates signed imports against local policy. It also computes
marketplace invocation prices from a base price and caller-supplied reputation
tier. Underwriting and market callers consume these data and evaluation APIs.

## Usage

Compute a checked invocation price in minor currency units:

```rust
use chio_appraisal::{
    compute_checked_marketplace_invocation_price, MarketplaceBasePrice,
    MarketplacePricingContext, MarketplaceReputationTier,
};

fn main() -> Result<(), chio_appraisal::MarketplacePricingError> {
    let base = MarketplaceBasePrice::try_new(1_000, "USD")?;
    let context = MarketplacePricingContext::try_new(
        "tenant-a", MarketplaceReputationTier::Tier1,
    )?;
    let price = compute_checked_marketplace_invocation_price(&base, &context)?;
    assert_eq!(price.units, 950);
    assert_eq!(price.currency, "USD");
    Ok(())
}
```

The checked entry point validates the tenant identifier and uppercase
three-letter currency shape. The compatibility pricing helper assumes inputs
were validated. Neither helper determines a tenant's reputation tier.

## Guarantees

`verify_signed_runtime_attestation_record` requires an independently pinned
attestation authority key, validates its canonical envelope signature, and
applies local policy and evidence validity checks. Authority authorization,
revocation, hardware-quote verification, and fresh nonce binding belong to the
caller. `verify_runtime_attestation_record` rejects unsigned evidence that
would otherwise gain accepted assurance from local policy.

`evaluate_imported_runtime_attestation_appraisal` evaluates signature, schema,
family, age, exporter acceptance, and configured issuer/key/claim restrictions.
Its output carries `Allow`, `Attenuate`, or `Reject` and explicit reason codes.
`derive_runtime_attestation_appraisal` only projects carried evidence fields.

## Status

The crate implements in-memory artifact derivation, signed-envelope helpers,
local import evaluation, and pricing. It has no network client or persistent
store. Azure MAA, AWS Nitro, Google attestation, and enterprise verifier schemas
have explicit claim projections. Signed descriptor verification authenticates
the carried envelope key; applications must establish that key's trust.
No Cargo features are declared.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Underwriting](../chio-underwriting/README.md)
- [Core types](../../core/chio-core-types/README.md)
- [License](../../../LICENSE)
