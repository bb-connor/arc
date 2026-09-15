# Public authority and verifier handoff implementation plan

**Goal:** Provision external authority keys before agreement and issue original
funded-work decisions from a separate verifier with its own observation/custody.

**Spec:** ../specs/2026-09-15-authority-verifier-design.md

**Execution:** Inline under the standing instruction to execute next steps. No
sub-agents, no original-checkout edits, no overwrite of earlier evidence.

## 1. Public authority provisioning

- [x] Add `authority_enrollment.rs`: `Pins`, externally signed context creation,
  `enroll(state, pins, context, domain) -> Policy`, and canonical file commands.
  Generate only the provider seed in its role directory. Compare all selected
  keys before creating native stores. Retain the exact enrollment before side
  effects, reject partial state, and validate completed retries without replacing
  the original UUID or policy. Refactor `finding_context.rs` to accept separately
  supplied governance/status signers while preserving fixture callers.
- [x] Add real native tests under `tests/authority_enrollment.rs`. First require
  successful execution with no verifier/checkpoint/status/governance seed in the
  provider directory. Reject every role collision, signed substituted context,
  changed provider seed and lost/partial stores before work can be admitted.

## 2. Public verification and original decision handoff

- [x] Factor public signed-agreement validation and blob-backed submission
  validation from their native request/journal wrappers. Share the actual Finding
  assessment/checker decision derivation, preserving all existing native checks.
- [x] Add `verifier_handoff.rs`: provider export/import, public binding checks,
  exact original claim intent and immutable request custody. Register local versus
  external decision selection atomically in the funding journal.
- [x] Add `verifier_operator.rs`: separate enrollment and SQLite first-response
  custody. Observe the claim through operator-configured `FundingSource`, verify
  with `settlement_observer::verify`, then run the real Python checker. Persist
  complete original observation/request/decision before publishing. Revalidate
  historical replay without refreshing its authority or reading keys.
- [x] Add tests requiring independent observation, matching original identities,
  valid negative output decisions, rejection of altered claims/standing, observer
  and checker failure, conflicting retries and replay after signer loss.

## 3. Actual separate processes

- [x] Add CLI commands for authority context/enrollment and verifier
  init/export/decide/import. Use canonical files with exclusive output creation.
- [x] Add an owned lifecycle that generates role keys separately, enrolls the
  original public context, executes native work, imports an external checkpoint,
  observes the claim from the separate verifier process and imports its decision.
  Run payout and rejected-output refund without transferring private keys.
- [x] Verify public Rust witnesses with Python and assert observed balances,
  original IDs and unique execution/claim/decision/settlement. Retain artifacts in
  the new authority-verifier evidence directory.

## 4. Review and qualification

- [x] Review trust inputs, signature profiles, fresh versus historical time,
  transaction ordering, role key isolation, canonical ingress and unknown-state
  preservation inline. Run standalone tests/Clippy, Python verifier tests,
  formatting/hygiene and relevant native process recovery regressions.
- [x] Record source/executable/artifact hashes, exact commands and supported
  boundaries. Commit conventionally, verify a clean integration worktree and
  unchanged original checkout. Independent administration remains unclaimed.

## Execution notes

Implemented in the existing isolated funded-native-admission worktree, with all
review inline. Ten new Rust tests cover public authority provisioning, role
aliases, signed substitutions, missing/partial state, changed verifier keys and
claim expiration during checking. Actual CLI scenarios cover separately generated
keys, provider enrollment, operator checkpoint custody, receiver-owned claim
observation, payout/refund and dependency-free first-response recovery after
publication failure. The verifier CLI also rejects conflicting/noncanonical
requests and corrupted/missing custody copies.

Review found and corrected a claim-expiration race around the checker. Final
source and executable qualification, exact counts, remaining administration
boundaries and the next delivery gate are recorded in
[execution report 29](../../market/open-agent-work/execution/29-public-authority-verifier.md)
and its manifest. Original checkout preservation is verified against the saved
3,688-file snapshot. No sub-agents, workspace dependency changes or deployment.
