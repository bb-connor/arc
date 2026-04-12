# Summary 111-03

Documented the live capital-allocation boundary in `spec/PROTOCOL.md`,
`docs/AGENT_ECONOMY.md`, and `docs/release/QUALIFICATION.md`.

Documented:

- ARC's signed capital-allocation decision as the governed-action contract over
  the live capital book
- the requirement for one selected governed receipt, one explicit
  source-of-funds story, one authority chain, and one bounded execution
  envelope
- explicit fail-closed conditions for ambiguous receipt selection, missing
  reserve backing, stale authority, and utilization or concentration boundary
  hits
- the qualification lane that proves the artifact remains simulation-first and
  operator-auditable

This closes the documentation gap between ARC's live capital-book story, its
custody-neutral instruction contract, and its first honest governed-action
allocation claim.
