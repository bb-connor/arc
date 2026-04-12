# Summary 111-01

Defined ARC's signed capital-allocation decision artifact in
`crates/arc-core/src/credit.rs` and exported it through
`crates/arc-core/src/lib.rs` and `crates/arc-kernel/src/lib.rs`.

Implemented:

- `CapitalAllocationDecisionArtifact` and
  `SignedCapitalAllocationDecision` as signed envelopes over one governed
  action and one explicit capital-allocation outcome
- typed `allocate`, `queue`, `manual_review`, and `deny` outcomes with
  reason-coded findings
- explicit source-of-funds, reserve-source, authority-chain, execution-window,
  and rail binding on the signed artifact
- deterministic allocation identifiers derived from the allocation-defining
  inputs rather than issuance time

This gives ARC one explicit governed-action allocation contract instead of
requiring operators to infer live capital posture from separate facility, bond,
and instruction artifacts.
