# Plan 171-02 Summary

Made `arc-link` the explicit and only supported runtime FX authority for the
official web3 lane.

## Delivered

- `crates/arc-core/src/web3.rs`
- `crates/arc-link/src/lib.rs`
- `crates/arc-settle/src/config.rs`
- `crates/arc-settle/src/lib.rs`
- `docs/standards/ARC_LINK_PROFILE.md`
- `docs/standards/ARC_LINK_KERNEL_RECEIPT_POLICY.md`
- `docs/standards/ARC_WEB3_PROFILE.md`
- `docs/standards/ARC_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json`

## Notes

`OracleConversionEvidence` now carries `authority = arc_link_runtime_v1`,
`arc-link` populates it directly, settlement config records
`arc_link_receipt_evidence` as the bounded authority model, and the price
resolver is documented as a contract-side reference reader rather than a
second source of truth.
