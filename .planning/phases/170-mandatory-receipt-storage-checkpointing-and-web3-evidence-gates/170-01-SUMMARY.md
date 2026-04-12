# Plan 170-01 Summary

Made receipt persistence and checkpoint issuance explicit prerequisites for
web3-enabled runtime activation.

## Delivered

- `crates/arc-cli/src/policy.rs`
- `crates/arc-control-plane/src/lib.rs`
- `crates/arc-kernel/src/lib.rs`
- `crates/arc-kernel/src/receipt_store.rs`
- `crates/arc-store-sqlite/src/receipt_store.rs`

## Notes

The kernel now exposes an explicit fail-closed web3 evidence gate, policy can
require it, control-plane startup enforces it, and only receipt stores that
support kernel-signed checkpoints satisfy the bounded web3 lane.
