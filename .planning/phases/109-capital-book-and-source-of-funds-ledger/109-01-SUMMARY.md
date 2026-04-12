# Summary 109-01

Defined ARC's live capital-book artifact in `crates/arc-core/src/credit.rs`
and exported it through `crates/arc-core/src/lib.rs` and
`crates/arc-kernel/src/lib.rs`.

Implemented:

- `CapitalBookQuery` with explicit subject scope and bounded receipt, facility,
  bond, and loss-event limits
- signed `CapitalBookReport` and `SignedCapitalBookReport` artifacts over
  canonical receipt, facility, bond, and loss-lifecycle evidence
- explicit source rows for facility commitments and reserve books
- explicit committed, held, drawn, disbursed, released, repaid, and impaired
  state in one subject-scoped capital summary

This gives ARC one concrete source-of-funds artifact without widening into
custody execution or cross-currency netting.
