# Plan 151-01 Summary

Extended `arc-link` configuration so operators pin one explicit trusted-chain
inventory and one explicit pair-to-chain mapping before cross-currency
enforcement is allowed.

## Delivered

- `crates/arc-link/src/config.rs`
- `docs/standards/ARC_LINK_BASE_MAINNET_CONFIG.json`

## Notes

Base is the enabled default chain, Arbitrum is the explicit standby inventory,
and config validation now fails closed when pairs or overrides reference
unknown chains.
