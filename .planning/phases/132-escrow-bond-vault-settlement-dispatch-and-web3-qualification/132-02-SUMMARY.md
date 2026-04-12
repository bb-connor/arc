# Summary 132-02

Implemented reversal, partial-settlement, and failure lifecycle semantics.

## Delivered

- modeled `partially_settled`, `reversed`, `charged_back`, `timed_out`,
  `failed`, and `reorged` lifecycle states in `crates/arc-core/src/web3.rs`
- bound anchor-proof and oracle-evidence support boundaries into dispatch and
  receipt validation
- kept reversal and failure handling explicit rather than treating them as
  undocumented exceptions

## Result

Real-rail settlement now has auditable lifecycle semantics for happy-path,
partial, and recovery cases.
