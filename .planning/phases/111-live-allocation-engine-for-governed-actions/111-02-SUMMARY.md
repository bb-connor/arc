# Summary 111-02

Implemented the live allocation engine in `crates/arc-cli/src/trust_control.rs`
and the CLI surface in `crates/arc-cli/src/main.rs`.

Implemented:

- signed issuance at `POST /v1/capital/allocations/issue`
- CLI issuance via `arc trust capital-allocation issue`
- deterministic governed-receipt selection that fails closed when the scoped
  query matches zero or multiple actionable receipts without `receiptId`
- source selection bound to the active capital book, active granted facility,
  and current reserve book rather than implicit operator joins
- typed allocation outcomes that surface `allocate`, `queue`,
  `manual_review`, or `deny` instead of implying execution

The engine remains simulation-first. It can draft the reserve and transfer
movements ARC would take, but it does not dispatch funds or treat allocation as
proof that external execution already happened.
