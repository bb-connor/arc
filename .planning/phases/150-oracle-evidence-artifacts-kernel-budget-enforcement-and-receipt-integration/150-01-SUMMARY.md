# Plan 150-01 Summary

Added the `price_oracle` seam to `ArcKernel` and used it to reconcile
cross-currency reported tool cost into grant currency through the new
`arc-link` runtime.

## Delivered

- `crates/arc-kernel/Cargo.toml`
- `crates/arc-kernel/src/lib.rs`

## Notes

The kernel now supports explicit cross-currency conversion at the post-
execution reconciliation point without changing the existing pre-execution
worst-case budget charge model.
