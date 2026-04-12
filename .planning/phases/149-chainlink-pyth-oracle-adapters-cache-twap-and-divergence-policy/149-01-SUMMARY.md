# Plan 149-01 Summary

Implemented the new `arc-link` crate with a bounded `PriceOracle` contract,
one canonical `ExchangeRate` shape, and real backend adapters for Chainlink
and Pyth.

## Delivered

- `crates/arc-link/src/lib.rs`
- `crates/arc-link/src/chainlink.rs`
- `crates/arc-link/src/pyth.rs`

## Notes

Chainlink reads now use Alloy contract calls against pinned feed addresses, and
Pyth fallback reads now use the Hermes latest-price API with explicit feed ID
verification and normalization.
