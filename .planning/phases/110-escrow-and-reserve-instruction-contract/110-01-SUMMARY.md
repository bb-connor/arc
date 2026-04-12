# Summary 110-01

Defined ARC's custody-neutral capital-instruction artifact in
`crates/arc-core/src/credit.rs` and exported it through
`crates/arc-core/src/lib.rs` and `crates/arc-kernel/src/lib.rs`.

Implemented:

- `CapitalExecutionInstructionAction` with explicit `lock_reserve`,
  `hold_reserve`, `release_reserve`, `transfer_funds`, and
  `cancel_instruction` actions
- `CapitalExecutionInstructionArtifact` and
  `SignedCapitalExecutionInstruction` as signed envelopes over one resolved
  live capital source
- explicit execution roles, rail descriptors, support-boundary claims, and
  observed-execution projection
- deterministic instruction identifiers derived from the instruction-defining
  inputs rather than issuance time

This gives ARC one explicit instruction contract for live capital movement
without implying that ARC itself is the custody or settlement rail.
