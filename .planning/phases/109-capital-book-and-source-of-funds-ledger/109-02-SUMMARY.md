# Summary 109-02

Implemented the capital-book projection and ledger-event semantics in
`crates/arc-cli/src/trust_control.rs` and
`crates/arc-store-sqlite/src/receipt_store.rs`.

Implemented:

- signed report export at `GET /v1/reports/capital-book`
- CLI export via `arc trust capital-book export`
- conservative source-of-funds attribution over current facility, bond, and
  loss-lifecycle state
- role-aware `commit`, `hold`, `draw`, `disburse`, `release`, `repay`, and
  `impair` events linked back to receipt, facility, bond, and lifecycle
  evidence
- fail-closed rejection for mixed currency, missing or mismatched subject
  attribution, ambiguous live facilities or bonds, and books with no active
  granted facility to explain committed capital

The projection now also selects the newest matching behavioral-feed receipts
instead of paging oldest-first, so live capital posture is derived from the
current exposure window rather than from stale receipt slices.
