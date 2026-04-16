# Post-Closure Execution Board

Date: 2026-04-16

This board starts after the Phase 1 through Phase 3 vision-closure program.

The next execution order is hard-gated:

1. Wave 0: Reporting truth closure
2. Phase 4: Trust-anchored transparency publication
3. Phase 5: Budget authority protocol

Phase 4 must not merge before the Wave 0 exit gate is green.
Phase 5 must not merge before the Phase 4 exit gate is green.

## Day 0 Controls

- Treat the current working tree as the baseline. Do not revert unrelated in-flight changes.
- Keep write sets disjoint inside each wave.
- One integrator owns rebases, gate execution, merge order, and narrow integration fixes only.
- One review lane audits every merge candidate against the honest-claim text for the current stage.
- No new scope enters a stage after Wave 1 starts.
- Later stages may tighten earlier claim language, but no later stage may widen claims without its own exit gate.

## Integrator

- `INT-1`
  - Files: none
  - Deliverables: merge queue ownership, rebases, stop/go calls, gate execution, and narrow conflict fixes only

## Wave 0

### Goal

Close the remaining reporting mismatch first: hold-lineage and guarantee metadata already exist on receipts, but derived operator and reconciliation surfaces must preserve that block instead of collapsing it into cost-only summaries.

### Wave 1

- `W0-A Report Row Contract + Hydration`
  - Files:
    - `crates/arc-kernel/src/operator_report.rs`
    - `crates/arc-kernel/src/cost_attribution.rs`
    - `crates/arc-store-sqlite/src/receipt_store/reports.rs`
  - Deliverables:
    - `budget_authority` on settlement, metered, behavioral, and cost-attribution rows
    - hydration from signed receipt metadata rather than synthetic recomputation
    - row-level serialization coverage for the nested authority block

- `W0-B Query And Endpoint Gates`
  - Files:
    - `crates/arc-cli/tests/receipt_query.rs`
  - Deliverables:
    - operator-report and settlement-report assertions over `guarantee_level` and `hold_id`
    - receipt-query hold-lineage and guarantee-level assertions
    - diagnostic error text on standalone export-path failures

### Review Thread

- `W0-R Claim-Log Drift Classification`
  - Files:
    - `crates/arc-store-sqlite/src/receipt_store/support.rs`
    - `crates/arc-cli/tests/receipt_query.rs`
  - Deliverables:
    - determine whether standalone metered and behavioral export failures are caused by Wave 0 report projection work or by pre-existing claim-log projection drift
    - if the root cause is direct Wave 0 regression, fix it before closing Wave 0
    - if the root cause is independent claim-log drift, park it as a Phase 4 dependency and do not widen Wave 0 scope

### Merge Order

1. Merge `W0-A`
2. Merge `W0-B`
3. Resolve `W0-R` as either a direct fix or an explicitly parked dependency

### Exit Gate

- Required:
  - `operator_report::tests::settlement_reconciliation_row_serialization_preserves_budget_authority_metadata`
  - `operator_report::tests::metered_and_behavioral_rows_serialize_budget_authority_metadata`
  - `test_operator_report_endpoint`
  - `test_settlement_reconciliation_report_and_action_endpoint`
  - `receipt_query_surfaces_financial_hold_lineage_and_guarantee_level`
  - `test_metered_billing_reconciliation_report_and_action_endpoint`
  - `test_behavioral_feed_export_surfaces`

### Honest Claim After Exit

On the verified operator, settlement, metered, behavioral, and cost-attribution report paths, ARC preserves receipt-level hold-lineage and guarantee metadata through derived reporting surfaces instead of collapsing them into cost-only summaries. This does not by itself widen ARC's economic truth claims beyond the receipt evidence boundary.

## Phase 4

### Goal

Move from local audit continuity and `transparency_preview` language to trust-anchored publication on qualified paths, without overstating witness coverage, anti-equivocation, or external side-effect truth.

### Wave 1

- `P4-A Trust Anchor And Checkpoint Contract`
  - Files:
    - `crates/arc-kernel/src/checkpoint.rs`
    - `crates/arc-core-types/src/receipt.rs`
    - `spec/PROTOCOL.md`
  - Deliverables:
    - `trust_anchor_ref`
    - `signer_cert_ref`
    - `publication_profile_version`
    - checkpoint contracts that stop relying on embedded-key-only verification

- `P4-B Publication And Witness Persistence`
  - Files:
    - `crates/arc-store-sqlite/src/receipt_store/bootstrap.rs`
    - `crates/arc-store-sqlite/src/receipt_store/support.rs`
    - `crates/arc-store-sqlite/src/receipt_store/tests.rs`
  - Deliverables:
    - immutable publication records
    - witness or anchor references
    - freshness tracking
    - conflicting-publication rejection
    - claim-tree completeness closure for tool and child receipts

- `P4-C Export And Verifier Surfaces`
  - Files:
    - `crates/arc-kernel/src/evidence_export.rs`
    - `crates/arc-cli/src/evidence_export.rs`
    - `crates/arc-mercury-core/src/proof_package.rs`
  - Deliverables:
    - proof packages that carry trust-anchor and publication material
    - fail-closed behavior when `append_only` or stronger language lacks that material

### Wave 2

- `P4-D Anchor Or Witness Integration`
  - Files:
    - `crates/arc-anchor/src/ops.rs`
    - `crates/arc-anchor/src/discovery.rs`
    - `crates/arc-anchor/src/bundle.rs`
    - `crates/arc-anchor/tests/integration_smoke.rs`
  - Deliverables:
    - one qualified witness or immutable-anchor publication path
    - publication policy visibility
    - conflict detection and reporting

- `P4-E Claim Boundary And Qualification`
  - Files:
    - `docs/review/05-non-repudiation-remediation.md`
    - `docs/review/15-vision-gap-map.md`
    - `docs/release/QUALIFICATION.md`
    - `docs/release/RELEASE_AUDIT.md`
  - Deliverables:
    - public-proof language aligned to declared trust anchors and publication policy
    - no side-effect truth inflation

### Merge Order

1. Merge `P4-A`
2. Rebase `P4-B` and `P4-C`
3. Merge `P4-B`
4. Merge `P4-C`
5. Start `P4-D` and `P4-E`
6. Merge `P4-D`
7. Merge `P4-E`

### Exit Gate

- Existing:
  - `checkpoint_rejects_same_log_same_tree_size_fork`
  - `checkpoint_consistency_proof_verifies_prefix_growth`
  - `receipt_log_includes_child_receipts_in_tree`
  - `evidence_export_marks_unanchored_publication_as_transparency_preview`
  - `mercury_proof_package_requires_trust_anchor_for_append_only_claim`

- Must add:
  - `checkpoint_verifier_requires_trust_anchor_and_signer_chain`
  - `publication_record_requires_witness_or_immutable_anchor_reference`
  - `witness_rejects_conflicting_checkpoint_same_log_and_tree_size`
  - `evidence_export_fails_closed_on_stale_or_missing_publication`
  - `proof_package_carries_publication_record_and_optional_consistency_chain`
  - `anchor_discovery_reports_publication_policy_and_current_freshness_state`

### Honest Claim After Exit

ARC can say a trusted ARC log admitted a captured event into a published append-only history under declared trust anchors and publication policy. ARC still does not claim to prove external real-world side effects beyond its capture boundary.

## Phase 5

### Goal

Turn the budget authority core into a real budget-authority protocol that binds governed approval, economic parties, rail authorization, meter evidence, and settlement state without collapsing them into one overloaded truth field.

### Wave 1

- `P5-A Economic Envelope Contract`
  - Files:
    - `crates/arc-core-types/src/capability.rs`
    - `crates/arc-core-types/src/receipt.rs`
    - `spec/PROTOCOL.md`
  - Deliverables:
    - canonical economic envelope with payer, merchant, payee destination, rail, asset, amount ceiling, settlement mode, and approval-hash binding

- `P5-B Budget Authority Kernel And Store`
  - Files:
    - `crates/arc-kernel/src/budget_store.rs`
    - `crates/arc-store-sqlite/src/budget_store.rs`
  - Deliverables:
    - hold, capture, release, refund, and finality state machine
    - envelope-bound operations
    - rejection of impossible transitions

- `P5-C Trust-Control HA Command Path`
  - Files:
    - `crates/arc-cli/src/trust_control/service_types.rs`
    - `crates/arc-cli/src/trust_control/service_runtime.rs`
    - `crates/arc-cli/src/trust_control/http_handlers_b.rs`
    - `crates/arc-cli/src/trust_control/cluster_and_reports.rs`
  - Deliverables:
    - first-class budget commands
    - authority term, lease metadata, and commit metadata on every mutation
    - rejection of stale-lease writes
    - replay-safe mutation handling

### Wave 2

- `P5-D Rail And Metering Runtime`
  - Files:
    - `crates/arc-kernel/src/payment.rs`
    - `crates/arc-metering/src/lib.rs`
    - `crates/arc-metering/src/export.rs`
    - `crates/arc-settle/src/payments.rs`
  - Deliverables:
    - rail-backed authorization binding on supported paths
    - verified meter evidence for supported metered flows
    - explicit `not_applicable` semantics for no-adapter paths

- `P5-E Economic Claim Boundary And Adversarial Gates`
  - Files:
    - `crates/arc-kernel/tests/property_budget_store.rs`
    - `crates/arc-cli/tests/receipt_query.rs`
    - `crates/arc-cli/tests/evidence_export.rs`
    - `docs/AGENT_ECONOMY.md`
    - `docs/standards/ARC_PAYMENT_INTEROP_PROFILE.md`
    - `docs/release/QUALIFICATION.md`
    - `docs/review/10-economic-authorization-remediation.md`
    - `docs/review/15-vision-gap-map.md`
  - Deliverables:
    - payer, merchant, payee, asset, and quote mismatch tests
    - over-ceiling capture rejection
    - liability-envelope claim boundary updates
    - explicit separation of budget truth, rail truth, meter truth, and settlement truth

### Merge Order

1. Merge `P5-A`
2. Rebase `P5-B` and `P5-C`
3. Merge `P5-B`
4. Merge `P5-C`
5. Start `P5-D` and `P5-E`
6. Merge `P5-D`
7. Merge `P5-E`

### Exit Gate

- Existing:
  - `budget_store_hold_authority_requires_monotonic_lease_inmemory`
  - `budget_store_event_id_reuse_rejects_different_hold_authority_sqlite`
  - `budget_store_try_charge_cost_with_ids_is_idempotent_sqlite`
  - `budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite`
  - `sqlite_budget_hold_authority_metadata_persists_across_reopen`

- Must add:
  - `economic_authorization_hash_changes_on_payer_merchant_payee_rail_asset_or_quote_change`
  - `payment_authorize_rejects_merchant_or_payee_mismatch`
  - `capture_and_release_require_matching_economic_authorization_hash`
  - `no_adapter_flow_never_emits_settlement_finality`
  - `metered_flow_requires_verified_meter_evidence_for_finalization`
  - `receipt_exposes_budget_authorization_metering_and_settlement_as_separate_truths`
  - `liability_ready_claim_requires_typed_liability_envelope`

### Honest Claim After Exit

For bounded supported profiles, ARC can say it binds governed approval, economic parties, rail authorization, metering evidence, and settlement evidence into one fail-closed execution and review package. ARC still must not claim that budget-only or no-adapter flows establish external settlement finality or legal liability truth.

## Steering Rules

- If a Wave 1 contract changes a public type or proof surface, every later owner rebases and re-reads before resuming.
- Reviewers audit every merge candidate against the honest-claim text for that stage, not against aspiration.
- If a must-add gate fails, stop the stage and fix the boundary before adding scope.
- Transparency publication does not widen economic claims.
- Budget authority protocol does not retroactively widen publication claims.
