#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run_tests() {
  local label="$1"
  shift
  local output
  output="$(mktemp "${TMPDIR:-/tmp}/chio-response-gate.XXXXXX")"
  set +e
  "$@" 2>&1 | tee "${output}"
  local status=${PIPESTATUS[0]}
  set -e
  if [[ "${status}" -ne 0 ]]; then
    rm -f "${output}"
    return "${status}"
  fi
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed' "${output}"; then
    echo "${label} matched zero tests" >&2
    rm -f "${output}"
    return 1
  fi
  rm -f "${output}"
}

main() {
  cd "${repo_root}"

  export CARGO_INCREMENTAL=0
  export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

  run_tests "response transition state machine" cargo test -p chio-quarantine --test state_machine state_machine_accepts_exactly_the_nineteen_specified_edges -- --exact
  run_tests "applying-to-applying lease renewal" cargo test -p chio-quarantine --test response_executor applying_lease_renewal_requires_an_unexpired_application_lease_and_exact_live_fence -- --exact

  # Authoritative application-time lineage and bounded orphan recovery.
  run_tests "application-time lineage change invalidates approval" cargo test -p chio-quarantine --lib blast::tests::changed_descendant_under_fence_releases_and_invalidates_approval -- --exact
  run_tests "application-time lineage fence exact recovery" cargo test -p chio-quarantine --lib blast::tests::exact_fence_is_requeried_and_can_be_recovered_by_exact_action_binding -- --exact
  run_tests "authoritative lineage fence blocks concurrent delegation" cargo test -p chio-store-sqlite --lib capability_lineage::tests::active_causal_fence_is_idempotent_and_blocks_delegation_in_commit_transaction -- --exact
  run_tests "orphan lineage fence expiry and recovery" cargo test -p chio-store-sqlite --test security_state lineage_fences_are_durable_and_orphans_recover_with_higher_fencing_tokens -- --exact

  # Operator capability, governed approval, and approval-only admission.
  run_tests "operator capability and response plan mutation matrix" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::active_response_authorization_rejects_plan_and_capability_binding_mutations -- --exact
  run_tests "revoked operator capability denial" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::active_response_authorization_preserves_typed_revocation_denial -- --exact
  run_tests "operator capability executor authority binding" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::active_response_executor_authority_is_required_and_must_match_capability -- --exact
  run_tests "application-time executable plan revalidation" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::active_response_admission_revalidates_the_full_executable_plan -- --exact
  run_tests "approval duplicate replay and binding mutation matrix" cargo test -p chio-conformance --test protocol_primitives_t1 threshold_rejects_subthreshold_duplicates_replay_and_wrong_bindings -- --exact
  run_tests "approval proposal and validity-window mutation matrix" cargo test -p chio-conformance --test protocol_primitives_t1 threshold_rejects_proposal_and_token_window_mutations -- --exact
  run_tests "approval ordered-effect mutation binding" cargo test -p chio-core-types --test governed_active_response_intent active_response_plan_uses_an_explicit_versioned_variant_and_binds_the_complete_body -- --exact
  run_tests "approval-only admission acknowledgement recovery" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::governed_admission_recovers_acknowledgement_loss_and_dispatch_commit -- --exact
  run_tests "governed approval port exact live binding" cargo test -p chio-quarantine --lib approval::tests::governed_prepare_returns_only_an_exact_live_kernel_binding -- --exact
  run_tests "governed approval port malformed reservation denial" cargo test -p chio-quarantine --lib approval::tests::malformed_reservations_wrong_bindings_and_zero_digests_fail_closed -- --exact
  run_tests "governed approval port exact reconstruction" cargo test -p chio-quarantine --lib approval::tests::reconstruction_is_exact_missing_aware_and_never_rebinds -- --exact
  run_tests "governed approval port exact mutation delegation" cargo test -p chio-quarantine --lib approval::tests::commit_and_cancel_delegate_exactly_once_and_preserve_tombstones -- --exact
  run_tests "automatic response bypasses governed approval port" cargo test -p chio-quarantine --lib approval::tests::automatic_plans_never_traverse_the_governed_port -- --exact
  run_tests "approval-port automatic commit rejection" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::public_prepared_commit_rejects_automatic_admission_without_mutation -- --exact
  run_tests "approval-port governed commit idempotency" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::public_prepared_commit_is_idempotent_for_governed_admission -- --exact
  run_tests "approval-port concurrent commit and cancel serialization" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::concurrent_public_commit_and_cancel_choose_one_safe_terminal_branch -- --exact
  run_tests "approval proposal deadline definitive cancellation" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::proposal_deadline_expiry_definitively_cancels_reserved_governed_dispatch -- --exact
  run_tests "approval token deadline definitive cancellation" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::approval_token_expiry_definitively_cancels_reserved_governed_dispatch -- --exact
  run_tests "approval replay commits before dispatch state" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::approval_replay_commit_precedes_dispatch_committed_cas -- --exact
  run_tests "same-process committed approval roll-forward after expiry" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::same_live_resume_rolls_committed_approval_forward_after_expiry_and_executes_once -- --exact
  run_tests "cold publication retains committed approval for outbox resume" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::initial_cold_publication_retains_governed_commit_states_for_outbox_resume -- --exact
  run_tests "cold publication compensates governed pre-dispatch rows" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::initial_cold_publication_compensates_governed_predispatch_rows -- --exact
  run_tests "operation anchor creation failure compensation" cargo test -p chio-kernel --lib kernel::tests::active_response_admission::coordinator::operation_anchor_creation_failure_compensates_the_created_operation -- --exact
  run_tests "production factory authoritative approval ledger" cargo test -p chio-control-plane --lib security::production_runtime::tests::production_factory_has_only_the_kernel_approval_ledger -- --exact
  run_tests "prepared outbox failure cancels admission before expiry" cargo test -p chio-control-plane --lib security::event_consumer::tests::admission_prepared_persistence_failure_cancels_before_pending_expiry -- --exact
  run_tests "prepared outbox acknowledgement loss preserves admission" cargo test -p chio-control-plane --lib security::event_consumer::tests::admission_prepared_ack_loss_preserves_reservation_and_executes_once -- --exact
  run_tests "real approval adapter cold recovery" cargo test -p chio-control-plane --lib security::event_consumer::tests::real_kernel_approval_adapter_prepares_reconstructs_commits_and_cold_resumes_once -- --exact
  run_tests "real approval adapter mutation denial" cargo test -p chio-control-plane --lib security::event_consumer::tests::real_kernel_approval_adapter_rejects_projection_mutations_before_store_changes -- --exact
  run_tests "operation-committed dispatch exact resume" cargo test -p chio-control-plane --lib security::event_consumer::tests::operation_committed_dispatch_resumes_after_executor_readback_is_missing -- --exact
  run_tests "rewritten prepared binding remains outcome unknown" cargo test -p chio-control-plane --lib security::event_consumer::tests::rewritten_prepared_binding_resume_failure_stays_outcome_unknown -- --exact
  run_tests "authoritative never-committed terminalization" cargo test -p chio-control-plane --lib security::event_consumer::tests::authoritative_never_committed_probe_closes_prepared_dispatch_terminally -- --exact

  # The executor supplies the six crash boundaries. Each concrete backend must
  # also prove exact apply/remove recovery through its durable adapter contract.
  run_tests "every effect kind six-boundary crash matrix" cargo test -p chio-quarantine --test response_executor executor_every_effect_kind_six_boundary_crash_matrix_converges_exactly_once -- --exact
  run_tests "EscalateAlert backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::escalate_alert_recovers_page_ack_loss_retry_and_backend_restart -- --exact
  run_tests "ThrottleSession backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::throttle_backend_recovers_apply_and_remove_ack_loss_across_restart -- --exact
  run_tests "RestrictEgress backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped -- --exact
  run_tests "SuspendSession backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution -- --exact
  run_tests "SuspendCapabilitySet backend recovery" cargo test -p chio-control-plane --test capability_set_suspension_backend apply_and_remove_ack_loss_reconcile_across_backend_restart -- --exact
  run_tests "FreezeIssuance backend recovery" cargo test -p chio-control-plane --test issuance_freeze_backend apply_and_remove_reconcile_every_ack_loss_boundary -- --exact

  # TTL dispatch and every restrictive compositional store must preserve the
  # remaining contribution when overlapping effects are removed out of order.
  run_tests "scheduler exact TTL dispatch" cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_exact_early_delayed_and_large_forward_jump_dispatch_once -- --exact
  run_tests "scheduler rejects clock rollback" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_direct_process_rejects_clock_rollback -- --exact
  run_tests "executor overlapping reverse removal" cargo test -p chio-quarantine --test response_executor executor_overlap_removes_contributions_in_reverse_application_order -- --exact
  run_tests "ThrottleSession overlapping out-of-order removal" cargo test -p chio-store-sqlite --test session_throttles overlapping_windows_are_a_conjunction_and_remove_out_of_order -- --exact
  run_tests "RestrictEgress overlapping out-of-order removal" cargo test -p chio-store-sqlite --test egress_restrictions restrictions_survive_restart_and_overlap_removes_out_of_order -- --exact
  run_tests "SuspendSession overlapping out-of-order removal" cargo test -p chio-store-sqlite --test containment_overlay_commands exact_commands_survive_ack_loss_restart_and_out_of_order_removal -- --exact
  run_tests "SuspendCapabilitySet overlapping out-of-order removal" cargo test -p chio-store-sqlite --test capability_set_suspensions overlapping_sets_compose_and_remove_only_the_exact_contribution -- --exact
  run_tests "FreezeIssuance overlapping out-of-order removal" cargo test -p chio-store-sqlite --test issuance_freezes overlapping_freezes_remain_active_until_each_release_completes -- --exact

  # Production posture acceptance joins durable effect state to the early
  # containment guard and verifies every plan-named recovery posture.
  run_tests "normal restricted normal posture at TTL" cargo test -p chio-control-plane --test active_defense_recovery normal_to_restricted_to_normal_at_ttl -- --exact
  run_tests "rollback partial remains contained" cargo test -p chio-control-plane --test active_defense_recovery normal_to_quarantined_to_rollback_partial_remains_denied -- --exact
  run_tests "overlapping posture expiry in both orders" cargo test -p chio-control-plane --test active_defense_recovery overlapping_temporary_actions_expire_in_both_orders_preserving_remaining_contribution -- --exact
  run_tests "exact capability subtree lift" cargo test -p chio-control-plane --test active_defense_recovery exact_subtree_root_and_every_recorded_descendant_lift -- --exact
  run_tests "overlay store outage denies before dispatch" cargo test -p chio-kernel --test active_defense_containment overlay_store_outage_while_contribution_may_be_active_denies_before_dispatch -- --exact
  run_tests "planner outage preserves preventive guards" cargo test -p chio-kernel --test active_defense_containment planner_outage_with_no_active_overlay_leaves_preventive_guards_functional -- --exact

  # Exercise both the scheduler state machine and the production SQLite worker.
  run_tests "scheduler stale-worker lease takeover" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_contention_waits_for_expiry_and_stale_takeover_loses -- --exact
  run_tests "production worker stale-fence takeover" cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_stale_fence_loses_after_expiry_takeover -- --exact

  # Receipt validation and durable production evidence must agree on the exact
  # effect/response transition lineage and must never claim false completion.
  run_tests "active-defense receipt every-field tamper" cargo test -p chio-core-types --test security_receipts every_active_defense_body_field_tamper_fails_closed -- --exact
  run_tests "active-defense receipt lineage matrix" cargo test -p chio-lineage --test active_defense_receipts active_defense_lineage_links_every_transition_to_its_plan_trigger_and_prior_receipts -- --exact
  run_tests "effect receipt transition lineage" cargo test -p chio-quarantine --test response_executor effect_receipts_bind_the_effect_cas_transition_that_produced_the_evidence -- --exact
  run_tests "active execution evidence transition lineage" cargo test -p chio-quarantine --test response_executor active_execution_evidence_binds_exact_response_and_effect_transitions -- --exact
  run_tests "rollback failure receipt truth" cargo test -p chio-quarantine --test response_executor receipt_truth_rollback_failure_never_reports_lifted -- --exact
  run_tests "partial apply receipt truth" cargo test -p chio-core-types --test security_receipts partial_apply_cannot_validate_as_active_completion -- --exact
  run_tests "partial rollback receipt truth" cargo test -p chio-core-types --test security_receipts partial_rollback_cannot_validate_as_lifted_completion -- --exact

  echo "Response recovery gate passed"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
