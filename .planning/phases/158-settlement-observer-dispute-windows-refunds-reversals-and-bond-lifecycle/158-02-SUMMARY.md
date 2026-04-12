# Plan 158-02 Summary

Projected on-chain settlement outcomes back into canonical ARC lifecycle
artifacts.

## Delivered

- `crates/arc-settle/src/observe.rs`
- `crates/arc-settle/src/evm.rs`

## Notes

`arc-settle` now emits explicit `settled`, `partially_settled`, `timed_out`,
`failed`, `reorged`, `reversed`, and `charged_back` settlement outcomes
without mutating earlier signed truth.
