# Plan 151-03 Summary

Implemented deterministic operator controls so unsafe cross-currency
enforcement can be paused, narrowed, or forced onto one backend without
silently widening trust.

## Delivered

- `crates/arc-link/src/lib.rs`
- `crates/arc-link/src/chainlink.rs`
- `crates/arc-link/src/pyth.rs`
- `crates/arc-kernel/src/lib.rs`

## Notes

Global pause, chain disable, pair disable, fallback suppression, and forced
backend selection now return explicit runtime errors and surface into the
health report rather than relying on undocumented operator convention.
