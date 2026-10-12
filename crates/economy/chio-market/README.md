# chio-market

`chio-market` defines Chio liability-provider, quote, placement, claim, payout,
and settlement contracts. Its insurance flow consumes governed premium inputs
and receipt evidence through caller-provided seams. Its parametric module
verifies policies and evidence corpora, evaluates triggers, and prepares claim
lifecycle transitions for shared economic state.

## Usage

Evaluate a linear parametric payout using a count-valued trigger magnitude.
The arithmetic helper checks currency, magnitude units, overflow, and coverage.
Policy and evidence authentication precede this step in the full claim flow.

```rust
use chio_market::{PayoutSchedule, TriggerMagnitude, TriggerMagnitudeUnit,
                  TriggerPredicate};
use chio_market::capability::scope::MonetaryAmount;

let predicate = TriggerPredicate::SettlementFailureCount { min_failures: 1 };
predicate.validate()?;
let schedule = PayoutSchedule::Linear {
    base: MonetaryAmount { units: 100, currency: "USD".into() },
    per_unit_minor: 50,
    magnitude_unit: TriggerMagnitudeUnit::Count,
};
let coverage = MonetaryAmount { units: 1_000, currency: "USD".into() };
let payout = schedule.evaluate(
    &predicate, &TriggerMagnitude::Count { value: 3 }, &coverage,
)?;
assert_eq!(payout.units, 250);
assert_eq!(payout.currency, "USD");
# Ok::<(), chio_market::ParametricContractError>(())
```

For premium binding, call `quote_and_bind` with a `PremiumSource` and a
`chio_fiscal::FiscalResolver`. For receipt-backed claims, `BoundPolicy::file_claim`
uses a `ReceiptEvidenceSource` and a `ClaimSettlementSink` supplied by the host.

## Guarantees

- `quote_and_bind` rejects missing identity/scope, zero duration, unavailable
  premium inputs, fiscal pricing refusal, and expiry arithmetic overflow.
- `BoundPolicy::file_claim` checks policy liveness and currency, requires
  receipt fingerprints, compares resolved digests, verifies signatures using
  resolved signer keys, and caps payout at coverage. The evidence source must
  supply trusted keys and correct digest-to-byte bindings.
- `VerifiedParametricPolicy::verify` checks the configured signer, signed
  coverage, and policy/context bindings. Its canonical-byte loader bounds and
  validates the wire input before verification.
- `PayoutSchedule::evaluate` rejects incompatible units, currencies,
  arithmetic overflow, zero payouts, and amounts above coverage.

## Status

The library implements contract validation and caller-driven insurance and
parametric flows. Provider support flags default to a curated registry with
automatic trust admission, permissionless federation, and bound-coverage
support disabled. A service must configure the supported provider path.
Persistence, settlement dispatch, and duplicate-effect coordination live in
the host. The Cargo package is marked `publish = false`.

## Related

- [Architecture](ARCHITECTURE.md)
- [Commerce evidence and authority](../../../spec/PROTOCOL.md#644-commerce-order-and-settlement-family)
- [Underwriting](../chio-underwriting/README.md)
- [License](../../../LICENSE)
