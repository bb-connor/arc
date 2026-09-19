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
  run_tests "authoritative issuance freeze blocks issue and delegation" cargo test -p chio-security-kernel --test issuance_freeze active_freeze_store_outage_and_tamper_all_fail_closed -- --exact
  run_tests "kernel enforces the installed issuance freeze authority" cargo test -p chio-kernel --lib kernel::tests::installed_issuance_admission_rejects_freeze_and_principal_substitution -- --exact
  run_tests "orphan lineage fence expiry and recovery" cargo test -p chio-store-sqlite --test security_state lineage_fences_are_durable_and_orphans_recover_with_higher_fencing_tokens -- --exact

  # Governed approval is isolated from the ordinary admission saga on current
  # main. Exercise its typed bindings, durable kernel replay, and production
  # adapter recovery without reviving the superseded admission-store design.
  run_tests "approval proposal mutation and exact quorum matrix" cargo test -p chio-conformance --test protocol_primitives_authority_bindings threshold_proposal_mutations_and_exact_quorum_fail_closed -- --exact
  run_tests "approval token binding and validity-window matrix" cargo test -p chio-kernel --lib kernel::tests::governed_approval_token_binds_every_authorization_field_and_time_window -- --exact
  run_tests "approval ordered-effect mutation binding" cargo test -p chio-core-types --test governed_active_response_intent active_response_plan_uses_an_explicit_typed_variant_and_binds_the_complete_body -- --exact
  run_tests "active-response approval durable replay" cargo test -p chio-kernel --lib kernel::tests::active_response_approval_is_durable_and_recovery_does_not_recommit_dispatch -- --exact
  run_tests "governed approval port exact live binding" cargo test -p chio-quarantine --lib approval::tests::governed_prepare_returns_only_an_exact_live_kernel_binding -- --exact
  run_tests "governed approval port malformed reservation denial" cargo test -p chio-quarantine --lib approval::tests::malformed_reservations_wrong_bindings_and_zero_digests_fail_closed -- --exact
  run_tests "governed approval port exact reconstruction" cargo test -p chio-quarantine --lib approval::tests::reconstruction_is_exact_missing_aware_and_never_rebinds -- --exact
  run_tests "governed approval port exact mutation delegation" cargo test -p chio-quarantine --lib approval::tests::commit_and_cancel_delegate_exactly_once_and_preserve_tombstones -- --exact
  run_tests "automatic response bypasses governed approval port" cargo test -p chio-quarantine --lib approval::tests::automatic_plans_never_traverse_the_governed_port -- --exact
  run_tests "automatic response commit wins before fencing" cargo test -p chio-kernel --lib kernel::tests::automatic_active_response_fence::two_kernels_commit_wins_before_the_automatic_fence -- --exact
  run_tests "automatic response fence wins against inflight commit" cargo test -p chio-kernel --lib kernel::tests::automatic_active_response_fence::two_kernels_fence_wins_against_an_inflight_automatic_commit -- --exact
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
  run_tests "stale takeover cannot apply pending effect" cargo test -p chio-quarantine --test response_executor executor_crash_stale_takeover_pending_apply_never_calls_effect_port -- --exact
  run_tests "stale takeover cannot roll back pending effect" cargo test -p chio-quarantine --test response_executor executor_crash_stale_takeover_pending_rollback_never_calls_effect_port -- --exact
  run_tests "EscalateAlert backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::escalate_alert_recovers_page_ack_loss_retry_and_backend_restart -- --exact
  run_tests "ThrottleSession backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::throttle_backend_recovers_apply_and_remove_ack_loss_across_restart -- --exact
  run_tests "RestrictEgress backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped -- --exact
  run_tests "SuspendSession backend recovery" cargo test -p chio-control-plane --lib security::adapters::effect_port::tests::suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution -- --exact
  run_tests "SuspendCapabilitySet backend recovery" cargo test -p chio-control-plane --test capability_set_suspension_backend apply_and_remove_ack_loss_reconcile_across_backend_restart -- --exact
  run_tests "FreezeIssuance backend recovery" cargo test -p chio-control-plane --test issuance_freeze_backend apply_and_remove_reconcile_every_ack_loss_boundary -- --exact

  # TTL dispatch and every restrictive compositional store must preserve the
  # remaining contribution when overlapping effects are removed out of order.
  run_tests "scheduler exact TTL dispatch" cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_exact_early_delayed_and_large_forward_jump_dispatch_once -- --exact
  run_tests "scheduler sustained retry pages at threshold" cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_sustained_retry_age_pages_at_threshold -- --exact
  run_tests "scheduler unknown outcome remains nonterminal" cargo test -p chio-quarantine --test response_scheduler scheduler_ttl_unknown_effect_outcome_retries_and_pages_without_false_completion -- --exact
  run_tests "scheduler restart routes persisted work" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_restart_routes_persisted_apply_and_rollback_states -- --exact
  run_tests "scheduler broken executor cannot complete work" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_broken_executor_cannot_complete_nonterminal_state -- --exact
  run_tests "scheduler rejects clock rollback" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_direct_process_rejects_clock_rollback -- --exact
  run_tests "scheduler renewal preserves current fence" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_renewal_preserves_token_and_only_current_lease_releases -- --exact
  run_tests "terminal scheduler work rejects renewal" cargo test -p chio-store-sqlite --test response_dispatch terminal_response_work_rejects_scheduler_lease_renewal -- --exact
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
  run_tests "overlay store outage denies before dispatch" cargo test -p chio-security-kernel --test active_defense_containment overlay_store_outage_while_contribution_may_be_active_denies_before_dispatch -- --exact
  run_tests "planner outage preserves preventive guards" cargo test -p chio-security-kernel --test active_defense_containment planner_outage_with_no_active_overlay_leaves_preventive_guards_functional -- --exact

  # Exercise both the scheduler state machine and the production SQLite worker.
  run_tests "scheduler stale-worker lease takeover" cargo test -p chio-quarantine --test response_scheduler scheduler_fencing_contention_waits_for_expiry_and_stale_takeover_loses -- --exact
  run_tests "production worker restart replays claim and releases lease" cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease -- --exact
  run_tests "production worker claims simultaneous due work deterministically" cargo test -p chio-control-plane --lib security::scheduler_worker::tests::sqlite_worker_claims_simultaneously_due_actions_transactionally_in_deterministic_order -- --exact
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
