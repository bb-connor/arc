# chio-link

`chio-link` resolves exchange rates for cross-currency budget decisions.
`ChioLinkOracle` reads Chainlink or Pyth behind `OracleBackend`, maintains an
in-memory cache, applies operator and sequencer controls, and exports rate
observations. Conversion helpers turn rates into minor-unit costs.

## Usage

Convert a caller-supplied observation without network access:

```rust
use chio_link::{convert::convert_supported_units, ExchangeRate};

fn main() -> Result<(), chio_link::PriceOracleError> {
    let rate = ExchangeRate {
        base: "ETH".into(), quote: "USD".into(),
        rate_numerator: 300_000, rate_denominator: 100,
        updated_at: 1_000, fetched_at: 1_010,
        source: "example".into(), feed_reference: "offline-observation".into(),
        max_age_seconds: 60, conversion_margin_bps: 200,
        confidence_numerator: None, confidence_denominator: None,
    };
    rate.ensure_fresh(1_020)?;
    let cost = convert_supported_units(
        1_000_000_000_000_000, &rate, rate.conversion_margin_bps,
    )?;
    assert_eq!(cost, 306);
    let evidence = rate.to_conversion_evidence(
        1_000_000_000_000_000, "ETH", "USD", cost, 1_020,
    )?;
    assert!(evidence.signature.is_none());
    Ok(())
}
```

This converts 0.001 ETH at 3,000 USD/ETH with a 2% margin into 306 USD cents.
The conversion helper checks arithmetic and scales; freshness is checked
separately. The example observation has no external authenticity claim.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables nothing. |
| `web3` | No | Enables Alloy Chainlink RPC and sequencer reads. Pyth, cache, conversion, and runtime types remain available when disabled; Chainlink requests return `UnsupportedBackend`. |

## Guarantees

`ChioLinkOracle` enforces configured pause, chain, and sequencer controls before
cache or backend resolution. Backend responses must match the configured pair
and pass `ExchangeRate::ensure_fresh`. When both source reads succeed, the
circuit breaker rejects excessive divergence. Secondary-source failure permits
an otherwise valid primary result.

`convert_units` uses checked `u128` arithmetic and ceiling rounding for costs
and margins. `to_conversion_evidence` checks freshness and integer width but
accepts the supplied cost/currency fields; downstream validators bind those
fields. It emits unsigned evidence with the Chio link authority label.

## Status

Chainlink and Hermes HTTP adapters, injected backends, runtime reports, and
operator overrides are implemented. Cache and overrides live in process memory.
Network adapters enforce `HttpEgressContract`; callers own feed trust and
reconciliation with authoritative charging. Pyth parses Hermes observations
without verifying a Pyth signed update in this crate.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Web3 evidence validators](../chio-web3/README.md)
- [Egress contract](../../protocol/chio-egress-contract/README.md)
- [License](../../../LICENSE)
