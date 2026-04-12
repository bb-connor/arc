# Plan 158-01 Summary

Added the observation and finality layer for `arc-settle`.

## Delivered

- `crates/arc-settle/src/observe.rs`
- `docs/standards/ARC_SETTLE_FINALITY_REPORT_EXAMPLE.json`

## Notes

The runtime now distinguishes confirmation wait, dispute-window wait,
finalized, and reorged state using the configured amount-tier policy.
