# Summary 131-03

Documented anchor and oracle settlement preconditions.

## Delivered

- made Merkle-path settlement receipts require anchored proof evidence in
  `crates/arc-core/src/web3.rs`
- documented anchor and oracle preconditions in
  `docs/standards/ARC_WEB3_PROFILE.md` and `spec/PROTOCOL.md`
- kept future tracks such as CCIP and permissionless discovery explicitly out
  of scope for the first official web3 lane

## Result

Settlement preconditions are reproducible and bounded before live rail
dispatch claims reconciled truth.
