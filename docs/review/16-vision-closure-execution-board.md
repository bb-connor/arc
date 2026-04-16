# Vision Closure Execution Board

Date: 2026-04-15

This board converts the vision-gap debate into an execution program.

The execution order is hard-gated:

1. Phase 1: Authenticated provenance graph closure
2. Phase 2: Budget authority core
3. Phase 3: Transparency substrate

Phase 2 must not merge before the Phase 1 exit gate is green.
Phase 3 must not merge before the Phase 2 exit gate is green.

## Day 0 Controls

- Treat the current working tree as the baseline. Do not revert unrelated in-flight changes.
- Use disjoint write sets inside each wave.
- One integrator owns merge order, rebases, gate execution, and conflict resolution.
- One review lane audits every wave before merge.
- No new scope enters a phase after Wave 1 starts.

## Integrator

- `INT-0`
  - Owns no feature files.
  - Owns merge queue, gate execution, rebases, and steering.
  - Can patch narrow integration conflicts but must not absorb feature work.

## Phase 1

### Goal

Close authenticated provenance as a durable truth model rather than receipt-local metadata.

### Wave 1

- `P1-A Provenance Types + Protocol`
  - Files:
    - `crates/arc-core-types/src/capability.rs`
    - `crates/arc-core-types/src/receipt.rs`
    - `crates/arc-core-types/src/session.rs`
    - `spec/PROTOCOL.md`
    - `docs/standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md`
  - Deliverables:
    - `SessionAnchor`
    - `RequestLineageRecord`
    - `ReceiptLineageStatement`
    - continuation artifact model
    - asserted vs verified provenance separation

- `P1-B Provenance Store + DAG`
  - Files:
    - `crates/arc-kernel/src/receipt_store.rs`
    - `crates/arc-store-sqlite/src/receipt_store/bootstrap.rs`
    - `crates/arc-store-sqlite/src/receipt_store/support.rs`
  - Deliverables:
    - durable provenance tables
    - lineage persistence
    - replay protection
    - report-time verification joins

- `P1-C Provenance Runtime`
  - Files:
    - `crates/arc-kernel/src/session.rs`
    - `crates/arc-kernel/src/request_matching.rs`
    - `crates/arc-kernel/src/kernel/mod.rs`
  - Deliverables:
    - session-anchor rotation
    - request-lineage creation on request start/finalization
    - continuation validation against authoritative lineage

### Wave 2

- `P1-D Receipt/Report/Export Surfaces`
  - Files:
    - `crates/arc-kernel/src/receipt_support.rs`
    - `crates/arc-kernel/src/operator_report.rs`
    - `crates/arc-store-sqlite/src/receipt_store/reports.rs`
    - `crates/arc-kernel/src/evidence_export.rs`
  - Deliverables:
    - evidence-class-aware outward surfaces
    - no asserted lineage treated as proof

- `P1-E Provenance Gates + Docs`
  - Files:
    - `crates/arc-kernel/src/kernel/tests/all.rs`
    - `crates/arc-cli/tests/receipt_query.rs`
    - `crates/arc-store-sqlite/src/receipt_store/tests.rs`
    - `docs/review/04-provenance-call-chain-remediation.md`
    - `docs/review/15-vision-gap-map.md`
  - Deliverables:
    - phase gates
    - updated remediation state
    - updated vision-gap sequencing

### Merge Order

1. Merge `P1-A`
2. Rebase `P1-B` and `P1-C`
3. Merge `P1-B`
4. Merge `P1-C`
5. Start `P1-D` and `P1-E`
6. Merge `P1-D`
7. Merge `P1-E`

### Exit Gate

- Existing:
  - `governed_call_chain_receipt_observes_local_parent_receipt_linkage`
  - `governed_call_chain_receipt_observes_session_parent_request_lineage`
  - `governed_request_rejects_upstream_call_chain_proof_subject_mismatch`
  - `governed_request_rejects_call_chain_delegator_subject_that_conflicts_with_capability_lineage`
  - `test_operator_report_endpoint`
  - `test_authorization_context_report_rejects_invalid_delegated_call_chain_projection`
- Must add:
  - `cross_kernel_continuation_token_verifies_parent_receipt_hash_and_session_anchor`
  - `session_anchor_rotates_on_auth_context_change`
  - `receipt_lineage_statement_links_parent_and_child_receipts`
  - `authorization_context_report_does_not_mark_asserted_call_chain_as_sender_bound`

### Honest Claim After Exit

ARC can say qualified paths authenticate parent linkage across recursive and cross-kernel continuation, and no outward report/export surface upgrades asserted lineage into proof.

## Phase 2

### Goal

Build the budget authority core as an authoritative hold/event state machine and eliminate `usage row + bool` as money truth.

### Wave 1

- `P2-A Budget Authority API`
  - Files:
    - `crates/arc-kernel/src/budget_store.rs`
    - `crates/arc-kernel/src/kernel/mod.rs`
    - `crates/arc-core-types/src/receipt.rs`
  - Deliverables:
    - typed authorize/release/capture/reconcile decisions
    - authority metadata in kernel receipts and retries

- `P2-B Budget Authority Store`
  - Files:
    - `crates/arc-store-sqlite/src/budget_store.rs`
    - `crates/arc-store-sqlite/tests/integration_smoke.rs`
  - Deliverables:
    - holds/events as authoritative source
    - balances derived from authoritative events

- `P2-C Budget Wire + Remote Runtime`
  - Files:
    - `crates/arc-cli/src/trust_control/service_types.rs`
    - `crates/arc-cli/src/trust_control/service_runtime.rs`
  - Deliverables:
    - authority term
    - commit metadata
    - lease metadata
    - remote budget semantics beyond counters

### Wave 2

- `P2-D Cluster Authority Semantics`
  - Files:
    - `crates/arc-cli/src/trust_control/http_handlers_b.rs`
    - `crates/arc-cli/src/trust_control/cluster_and_reports.rs`
    - `crates/arc-cli/tests/trust_cluster.rs`
  - Deliverables:
    - no orphaned exposure on failed quorum
    - cluster replay of holds and events
    - truthful client-visible failure semantics

- `P2-E Financial Surfaces + Model Gates`
  - Files:
    - `crates/arc-kernel/tests/property_budget_store.rs`
    - `crates/arc-cli/tests/receipt_query.rs`
    - `crates/arc-core-types/src/receipt.rs`
  - Deliverables:
    - hold-state properties
    - financial receipt/report truth gates

### Merge Order

1. Merge `P2-A`
2. Rebase `P2-B` and `P2-C`
3. Merge `P2-B`
4. Merge `P2-C`
5. Start `P2-D` and `P2-E`
6. Merge `P2-D`
7. Merge `P2-E`

### Exit Gate

- Existing:
  - `budget_store_hold_authority_requires_monotonic_lease_inmemory`
  - `budget_store_event_id_reuse_rejects_different_hold_authority_sqlite`
  - `budget_store_try_charge_cost_with_ids_is_idempotent_sqlite`
  - `budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite`
  - `sqlite_budget_hold_authority_metadata_persists_across_reopen`
- Must add:
  - `trust_control_cluster_failed_quorum_does_not_leave_orphaned_exposure`
  - `trust_control_cluster_snapshot_replays_holds_and_mutation_events`
  - `remote_budget_store_preserves_authority_term_and_commit_metadata`
  - `financial_receipt_carries_hold_lineage_and_guarantee_level`

### Honest Claim After Exit

ARC can say monetary state is derived from authoritative holds/events and no client-visible failure path leaves ambiguous committed spend or orphaned exposure.

## Phase 3

### Goal

Replace local checkpoint continuity with a real transparency substrate and only then expose stronger public-proof language.

### Wave 1

- `P3-A Transparency Log Core`
  - Files:
    - `crates/arc-kernel/src/checkpoint.rs`
    - `crates/arc-core-types/src/receipt.rs`
  - Deliverables:
    - `log_id`
    - monotonic `entry_seq`
    - signed tree heads
    - consistency proofs

- `P3-B Transparency Persistence`
  - Files:
    - `crates/arc-store-sqlite/src/receipt_store/bootstrap.rs`
    - `crates/arc-store-sqlite/src/receipt_store/support.rs`
    - `crates/arc-store-sqlite/src/receipt_store/tests.rs`
  - Deliverables:
    - unified log surface for tool + child receipts
    - persistence and validation of tree heads and proofs

- `P3-C Proof/Export Contract`
  - Files:
    - `crates/arc-kernel/src/evidence_export.rs`
    - `crates/arc-cli/src/evidence_export.rs`
    - `crates/arc-mercury-core/src/proof_package.rs`
  - Deliverables:
    - `audit` vs `transparency_preview`
    - no append-only public claims without trust anchors

### Wave 2

- `P3-D Public Claim Boundary`
  - Files:
    - `docs/review/05-non-repudiation-remediation.md`
    - `docs/review/15-vision-gap-map.md`
    - `docs/release/QUALIFICATION.md`
    - `docs/standards/ARC_BOUNDED_OPERATIONAL_PROFILE.md`
  - Deliverables:
    - public-proof language aligned with actual trust-anchor and witness state

### Merge Order

1. Merge `P3-A`
2. Rebase `P3-B` and `P3-C`
3. Merge `P3-B`
4. Merge `P3-C`
5. Start `P3-D`
6. Merge `P3-D`

### Exit Gate

- Existing:
  - checkpoint continuity and integrity tests
- Must add:
  - `checkpoint_rejects_same_log_same_tree_size_fork`
  - `checkpoint_consistency_proof_verifies_prefix_growth`
  - `receipt_log_includes_child_receipts_in_tree`
  - `evidence_export_marks_unanchored_publication_as_transparency_preview`
  - `mercury_proof_package_requires_trust_anchor_for_append_only_claim`

### Honest Claim After Exit

ARC can say append-only public proof preview exists on qualified paths without overstating trust anchors, witness coverage, or anti-equivocation beyond what is implemented.

## Phase-Level Day Order

1. Day 0
   - freeze overlapping files
   - publish gates
   - assign owners
   - create merge queue
2. Day 1
   - Phase 1 Wave 1
3. Day 2
   - merge Phase 1 Wave 1 in order
4. Day 3
   - Phase 1 Wave 2
   - run Phase 1 exit gate
5. Day 4
   - Phase 2 Wave 1
6. Day 5
   - merge Phase 2 Wave 1 in order
7. Day 6
   - Phase 2 Wave 2
   - run Phase 2 exit gate
8. Day 7
   - Phase 3 Wave 1
9. Day 8
   - merge Phase 3 Wave 1 in order
10. Day 9
   - Phase 3 Wave 2
   - run Phase 3 exit gate
11. Day 10
   - regression buffer only
   - no new scope

## Steering Rules

- If a Wave 1 contract shifts data-model shapes, Wave 2 owners must rebase and re-read before resuming.
- Review agents audit every merge candidate against the honest-claim text for that phase.
- If a must-add gate exposes semantic drift, stop the phase and fix the contract before adding more code.
- Federation and portable trust clearing begin only after Phase 3 design stabilizes, because portability must sit on authenticated provenance plus published evidence rather than local operator assertions.
