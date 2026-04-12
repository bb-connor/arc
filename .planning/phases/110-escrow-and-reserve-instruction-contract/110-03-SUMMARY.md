# Summary 110-03

Documented the custody-neutral instruction boundary in `spec/PROTOCOL.md`,
`docs/AGENT_ECONOMY.md`, and `docs/release/QUALIFICATION.md`.

Documented:

- ARC's signed capital-instruction artifact as the explicit reserve and escrow
  movement contract over the live capital book
- the requirement for one authority chain, one execution window, one rail
  descriptor, and one intended-versus-reconciled state projection
- explicit fail-closed conditions for stale authority, mismatched custody
  steps, contradictory timing, source/action mismatch, overstated amounts, and
  mismatched observed execution
- the qualification lane that proves both the artifact and its negative paths

This closes the documentation gap between ARC's live capital-book story and
its first honest custody-neutral instruction claim.
