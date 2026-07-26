#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

runner="scripts/check-response-recovery.sh"
test -x "${runner}"
bash -n "${runner}"

required_mappings=(
  'cargo test -p chio-quarantine --test state_machine state_machine_accepts_exactly_the_nineteen_specified_edges -- --exact'
  'cargo test -p chio-quarantine --test response_executor applying_lease_renewal_requires_an_unexpired_application_lease_and_exact_live_fence -- --exact'
  'cargo test -p chio-quarantine --lib blast::tests::changed_descendant_under_fence_releases_and_invalidates_approval -- --exact'
  'cargo test -p chio-quarantine --lib blast::tests::exact_fence_is_requeried_and_can_be_recovered_by_exact_action_binding -- --exact'
  'cargo test -p chio-store-sqlite --lib capability_lineage::tests::active_causal_fence_is_idempotent_and_blocks_delegation_in_commit_transaction -- --exact'
  'cargo test -p chio-store-sqlite --test security_state lineage_fences_are_durable_and_orphans_recover_with_higher_fencing_tokens -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::active_response_authorization_rejects_plan_and_capability_binding_mutations -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::active_response_authorization_preserves_typed_revocation_denial -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::active_response_executor_authority_is_required_and_must_match_capability -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::active_response_admission_revalidates_the_full_executable_plan -- --exact'
  'cargo test -p chio-conformance --test protocol_primitives_t1 threshold_rejects_subthreshold_duplicates_replay_and_wrong_bindings -- --exact'
  'cargo test -p chio-conformance --test protocol_primitives_t1 threshold_rejects_proposal_and_token_window_mutations -- --exact'
  'cargo test -p chio-core-types --test governed_active_response_intent active_response_plan_uses_an_explicit_versioned_variant_and_binds_the_complete_body -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::governed_admission_recovers_acknowledgement_loss_and_dispatch_commit -- --exact'
  'cargo test -p chio-quarantine --lib approval::tests::governed_prepare_returns_only_an_exact_live_kernel_binding -- --exact'
  'cargo test -p chio-quarantine --lib approval::tests::malformed_reservations_wrong_bindings_and_zero_digests_fail_closed -- --exact'
  'cargo test -p chio-quarantine --lib approval::tests::reconstruction_is_exact_missing_aware_and_never_rebinds -- --exact'
  'cargo test -p chio-quarantine --lib approval::tests::commit_and_cancel_delegate_exactly_once_and_preserve_tombstones -- --exact'
  'cargo test -p chio-quarantine --lib approval::tests::automatic_plans_never_traverse_the_governed_port -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::public_prepared_commit_rejects_automatic_admission_without_mutation -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::public_prepared_commit_is_idempotent_for_governed_admission -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::concurrent_public_commit_and_cancel_choose_one_safe_terminal_branch -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::proposal_deadline_expiry_definitively_cancels_reserved_governed_dispatch -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::approval_token_expiry_definitively_cancels_reserved_governed_dispatch -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::approval_replay_commit_precedes_dispatch_committed_cas -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::same_live_resume_rolls_committed_approval_forward_after_expiry_and_executes_once -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::initial_cold_publication_retains_governed_commit_states_for_outbox_resume -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::initial_cold_publication_compensates_governed_predispatch_rows -- --exact'
  'cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::operation_anchor_creation_failure_compensates_the_created_operation -- --exact'
  'cargo test -p chio-control-plane --lib security::production_runtime::tests::production_factory_has_only_the_kernel_approval_ledger -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::admission_prepared_persistence_failure_cancels_before_pending_expiry -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::admission_prepared_ack_loss_preserves_reservation_and_executes_once -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::real_kernel_approval_adapter_prepares_reconstructs_commits_and_cold_resumes_once -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::real_kernel_approval_adapter_rejects_projection_mutations_before_store_changes -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::operation_committed_dispatch_resumes_after_executor_readback_is_missing -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::rewritten_prepared_binding_resume_failure_stays_outcome_unknown -- --exact'
  'cargo test -p chio-control-plane --lib security::event_consumer::tests::authoritative_never_committed_probe_closes_prepared_dispatch_terminally -- --exact'
  'cargo test -p chio-quarantine --test response_executor executor_every_effect_kind_six_boundary_crash_matrix_converges_exactly_once -- --exact'
  'cargo test -p chio-quarantine --test response_executor executor_crash_stale_takeover_pending_apply_never_calls_effect_port -- --exact'
  'cargo test -p chio-quarantine --test response_executor executor_crash_stale_takeover_pending_rollback_never_calls_effect_port -- --exact'
  'cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::escalate_alert_recovers_page_ack_loss_retry_and_backend_restart -- --exact'
  'cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::throttle_backend_recovers_apply_and_remove_ack_loss_across_restart -- --exact'
  'cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped -- --exact'
  'cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution -- --exact'
  'cargo test -p chio-control-plane --test capability_set_suspension_backend apply_and_remove_ack_loss_reconcile_across_backend_restart -- --exact'
  'cargo test -p chio-control-plane --test issuance_freeze_backend apply_and_remove_reconcile_every_ack_loss_boundary -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_exact_early_delayed_and_large_forward_jump_dispatch_once -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_sustained_retry_age_pages_at_threshold -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_unknown_effect_outcome_retries_and_pages_without_false_completion -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_restart_routes_persisted_apply_and_rollback_states -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_broken_executor_cannot_complete_nonterminal_state -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_direct_process_rejects_clock_rollback -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_renewal_preserves_token_and_only_current_lease_releases -- --exact'
  'cargo test -p chio-store-sqlite --test response_dispatch terminal_response_work_rejects_scheduler_lease_renewal -- --exact'
  'cargo test -p chio-quarantine --test response_executor executor_overlap_removes_contributions_in_reverse_application_order -- --exact'
  'cargo test -p chio-store-sqlite --test session_throttles overlapping_windows_are_a_conjunction_and_remove_out_of_order -- --exact'
  'cargo test -p chio-store-sqlite --test egress_restrictions restrictions_survive_restart_and_overlap_removes_out_of_order -- --exact'
  'cargo test -p chio-store-sqlite --test containment_overlay_commands exact_commands_survive_ack_loss_restart_and_out_of_order_removal -- --exact'
  'cargo test -p chio-store-sqlite --test capability_set_suspensions overlapping_sets_compose_and_remove_only_the_exact_contribution -- --exact'
  'cargo test -p chio-store-sqlite --test issuance_freezes overlapping_freezes_remain_active_until_each_release_completes -- --exact'
  'cargo test -p chio-control-plane --test active_defense_recovery normal_to_restricted_to_normal_at_ttl -- --exact'
  'cargo test -p chio-control-plane --test active_defense_recovery normal_to_quarantined_to_rollback_partial_remains_denied -- --exact'
  'cargo test -p chio-control-plane --test active_defense_recovery overlapping_temporary_actions_expire_in_both_orders_preserving_remaining_contribution -- --exact'
  'cargo test -p chio-control-plane --test active_defense_recovery exact_subtree_root_and_every_recorded_descendant_lift -- --exact'
  'cargo test -p chio-kernel --test active_defense_containment overlay_store_outage_while_contribution_may_be_active_denies_before_dispatch -- --exact'
  'cargo test -p chio-kernel --test active_defense_containment planner_outage_with_no_active_overlay_leaves_preventive_guards_functional -- --exact'
  'cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_contention_waits_for_expiry_and_stale_takeover_loses -- --exact'
  'cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease -- --exact'
  'cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_claims_simultaneously_due_actions_transactionally_in_deterministic_order -- --exact'
  'cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_stale_fence_loses_after_expiry_takeover -- --exact'
  'cargo test -p chio-core-types --test security_receipts every_active_defense_body_field_tamper_fails_closed -- --exact'
  'cargo test -p chio-lineage --test active_defense_receipts active_defense_lineage_links_every_transition_to_its_plan_trigger_and_prior_receipts -- --exact'
  'cargo test -p chio-quarantine --test response_executor effect_receipts_bind_the_effect_cas_transition_that_produced_the_evidence -- --exact'
  'cargo test -p chio-quarantine --test response_executor active_execution_evidence_binds_exact_response_and_effect_transitions -- --exact'
  'cargo test -p chio-quarantine --test response_executor receipt_truth_rollback_failure_never_reports_lifted -- --exact'
  'cargo test -p chio-core-types --test security_receipts partial_apply_cannot_validate_as_active_completion -- --exact'
  'cargo test -p chio-core-types --test security_receipts partial_rollback_cannot_validate_as_lifted_completion -- --exact'
)

for required in "${required_mappings[@]}"; do
  grep -Fq -- "${required}" "${runner}"
done

run_count="$(grep -c '^  run_tests ' "${runner}")"
exact_count="$(grep -c '^  run_tests .* -- --exact$' "${runner}")"
test "${run_count}" -eq "${#required_mappings[@]}"
test "${exact_count}" -eq "${run_count}"

for forbidden_legacy_approval_symbol in \
  ApprovalReservationStore \
  ApprovalReservationCreate \
  ApprovalReservationState \
  StoredApprovalReservation \
  security_response_approvals; do
  set +e
  legacy_matches="$(
    rg -n --hidden --no-ignore --fixed-strings --glob '*.rs' --glob '!**/target/**' \
      -- "${forbidden_legacy_approval_symbol}" crates
  )"
  legacy_status=$?
  set -e
  if [[ "${legacy_status}" -eq 0 ]]; then
    echo "legacy approval symbol remains: ${forbidden_legacy_approval_symbol}" >&2
    printf '%s\n' "${legacy_matches}" >&2
    exit 1
  fi
  if [[ "${legacy_status}" -ne 1 ]]; then
    echo "legacy approval symbol scan failed: ${forbidden_legacy_approval_symbol}" >&2
    exit "${legacy_status}"
  fi
done

set +e
zero_match_output="$({
  # shellcheck source=scripts/check-response-recovery.sh
  source "${runner}"
  run_tests "zero-match contract probe" bash -c \
    'printf "%s\n" "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out"'
} 2>&1)"
zero_match_status=$?
set -e
test "${zero_match_status}" -ne 0
grep -Fq 'zero-match contract probe matched zero tests' <<<"${zero_match_output}"

echo "Response recovery gate contract passed"
