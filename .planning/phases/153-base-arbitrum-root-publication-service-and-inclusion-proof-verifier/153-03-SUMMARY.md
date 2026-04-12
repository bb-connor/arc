# Plan 153-03 Summary

Closed the EVM publication-control surface with one explicit readiness guard
covering authorization, latest sequence, and delegate semantics.

## Delivered

- `crates/arc-anchor/src/evm.rs`
- `docs/standards/ARC_ANCHOR_DISCOVERY_EXAMPLE.json`

## Notes

The operator remains the owner of anchored roots even when a delegate publisher
is configured for a supported lane.
