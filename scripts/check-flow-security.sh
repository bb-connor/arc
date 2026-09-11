#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
# Keep permission-sensitive SQLite checks reproducible. Tests still exercise
# their explicit thread/process races; the harness does not overlap fixtures.
umask 022
export RUST_TEST_THREADS=1

run_exact_target() {
  ./scripts/run-exact-cargo-test-inventory.sh "$@"
}

command -v apalache-mc >/dev/null
command -v rustup >/dev/null
rustup target list --installed | grep -qx 'wasm32-unknown-unknown'

python3 scripts/check-apalache-formal-slice.py

apalache-mc check \
  --length=6 \
  --config=formal/tla/MCInformationFlowLattice.cfg \
  formal/tla/InformationFlowLattice.tla

negative_output="$(mktemp "${TMPDIR:-/tmp}/chio-flow-negative.XXXXXX")"
trap 'rm -f "${negative_output}"' EXIT
set +e
apalache-mc check \
  --length=6 \
  --config=formal/tla/_negative_tests/MCInformationFlowLatticeReaderDirectionBroken.cfg \
  formal/tla/_negative_tests/InformationFlowLatticeReaderDirectionBroken.tla \
  2>&1 | tee "${negative_output}"
negative_status=${PIPESTATUS[0]}
set -e
if [[ "${negative_status}" -eq 0 ]]; then
  echo "information-flow reader-direction mutation unexpectedly satisfied SafetyInv" >&2
  exit 1
fi
grep -Eq 'state invariant [0-9]+ violated' "${negative_output}"
grep -Fq 'The outcome is: Error' "${negative_output}"

cargo check -p chio-security-types --no-default-features --target wasm32-unknown-unknown
cargo check -p chio-flow --no-default-features --target wasm32-unknown-unknown

run_exact_target --label "security types library" --expected \
  declassification::tests::invalid_time_and_top_target_reject_before_signing \
  declassification::tests::validated_body_round_trips_strictly \
  flow::tests::blank_principal_and_compartment_are_rejected \
  flow::tests::borrowed_identifier_is_validated_before_owned_allocation \
  flow::tests::bottom_is_unique_public_label \
  flow::tests::c1_control_identifier_is_rejected_by_schema_and_runtime \
  flow::tests::configured_cardinality_overflow_is_rejected \
  flow::tests::configured_limits_cannot_widen_protocol_limits \
  flow::tests::duplicate_owner_json_is_rejected \
  flow::tests::duplicate_reader_and_compartment_values_are_rejected \
  flow::tests::information_label_order_rejects_reversed_readers_and_partial_constraints \
  flow::tests::information_label_schema_positive_and_negative_vectors \
  flow::tests::internal_control_identifier_is_rejected_by_schema_and_runtime \
  flow::tests::known_and_top_canonical_vectors_round_trip \
  flow::tests::noncanonical_input_normalizes_to_identical_canonical_bytes \
  flow::tests::owner_must_be_its_own_reader \
  flow::tests::schema_and_runtime_enforce_every_default_cardinality_bound \
  flow::tests::tool_flow_declaration_is_strict_and_canonical \
  flow::tests::unknown_and_variant_payload_fields_are_rejected \
  flow::tests::utf8_identifier_limit_is_normative_in_bytes \
  -- cargo test -p chio-security-types --lib

run_exact_target --label "security capability-set suspension types" --expected \
  affected_set_commitment_binds_tenant_order_and_membership \
  affected_set_commitment_uses_canonical_object_key_order \
  effect_scoped_contributions_compose_and_remove_out_of_order \
  wrong_set_contribution_and_noncanonical_snapshot_fail_closed \
  -- cargo test -p chio-security-types --features std --test capability_set_suspension
run_exact_target --label "security egress-restriction types" --expected \
  destination_set_requires_nonempty_strict_canonical_order \
  egress_overlay_contracts_bind_session_effect_ttl_and_fence \
  -- cargo test -p chio-security-types --test egress_restriction
run_exact_target --label "security event types" --expected \
  correlated_finding_preserves_event_to_source_receipt_cardinality_and_order \
  event_constructor_enforces_time_and_evidence_bounds \
  portable_event_and_finding_reject_unknown_or_inconsistent_shapes \
  -- cargo test -p chio-security-types --test event
run_exact_target --label "security issuance-freeze types" --expected \
  external_fence_and_exact_set_rebinding_fail_validation \
  installed_identity_survives_bounded_external_lease_renewal_and_takeover \
  overlapping_freezes_are_effect_scoped_and_remove_out_of_order \
  snapshot_order_and_admission_operation_shapes_are_closed \
  -- cargo test -p chio-security-types --features std --test issuance_freeze
run_exact_target --label "security port contracts" --expected \
  authoritative_record_sets_are_strictly_sorted_and_unique \
  bounded_collections_reject_excess_items \
  canonical_bodies_enforce_the_protocol_byte_ceiling \
  identifiers_reject_noncanonical_decoding \
  one_fake_can_satisfy_every_port_contract \
  port_errors_preserve_the_failure_class \
  strict_port_shapes_reject_unknown_fields \
  -- cargo test -p chio-security-types --features std --test ports_compile
run_exact_target --label "security response-dispatch types" --expected \
  dispatch_authorization_binds_every_security_identity \
  dispatch_lease_and_load_outcome_are_explicit \
  dispatch_recovery_binds_the_exact_action_and_fencing_observation \
  execution_dispatch_binding_rejects_zero_and_mismatched_authority_fields \
  -- cargo test -p chio-security-types --features std --test response_dispatch
run_exact_target --label "security response types" --expected \
  mutation_capacity_accepts_the_exact_bound_and_rejects_one_more \
  mutation_capacity_reserves_the_complete_sixty_four_effect_lifecycle \
  mutation_capacity_tracks_rollback_failure_and_retry_boundaries \
  permanent_revocation_is_not_a_reversible_effect_kind \
  prepared_dispatch_binding_is_strict_and_plan_bound \
  prepared_dispatch_binding_rejects_unknown_serialized_fields \
  response_plan_rejects_zero_cryptographic_commitments \
  response_targets_and_mutation_records_reject_unknown_fields \
  response_transition_matrix_contains_only_the_specified_edges \
  -- cargo test -p chio-security-types --test response
run_exact_target --label "security session-throttle types" --expected \
  limits_are_nonzero_and_bounded \
  versions_bind_each_independent_contribution_and_out_of_order_removal \
  window_identity_is_aligned_deterministic_and_effect_scoped \
  -- cargo test -p chio-security-types --features std --test session_throttle

run_exact_target --label "flow lattice and enforcement engine" --expected \
  classification::tests::authenticated_empty_result_retains_request_and_classifier_binding \
  classification::tests::category_join_overflow_denies \
  classification::tests::category_map_is_bounded_and_rejects_top \
  classification::tests::classifier_failure_cannot_collapse_to_authenticated_empty \
  classification::tests::identity_request_and_payload_mismatch_deny \
  classification::tests::pii_phi_secret_and_tenant_categories_join_all_restrictions \
  classification::tests::unknown_category_and_malformed_findings_deny \
  classification::tests::verified_evidence_retains_exact_findings_without_payload_or_debug_locations \
  declassification::tests::all_static_bindings_and_store_failure_deny_before_release \
  declassification::tests::concurrent_consumers_produce_exactly_one_verified_result \
  declassification::tests::exact_grant_consumes_once_and_persists_terminal_dispatch_outcomes \
  declassification::tests::time_purpose_trust_signature_and_label_fail_closed \
  engine::tests::accumulated_knowledge_blocks_unclassified_egress \
  engine::tests::complete_source_joins_payload_floor_and_all_durable_labels \
  engine::tests::every_policy_clearance_must_accept_the_complete_source \
  engine::tests::fence_is_prepared_only_after_taint_persistence \
  engine::tests::fresh_consumption_retains_the_actual_commit_observation \
  engine::tests::many_small_outputs_accumulate_taint_monotonically \
  engine::tests::non_egress_call_retains_taint_without_clearance_or_fence \
  engine::tests::one_shot_downgrade_substitutes_the_exact_signed_target_for_egress \
  engine::tests::payload_only_declassification_binding_cannot_downgrade_accumulated_knowledge \
  engine::tests::post_invocation_joins_classifier_and_declared_floors_before_delivery \
  engine::tests::post_invocation_overflow_transitions_to_top \
  engine::tests::post_invocation_rejects_classification_from_another_representation \
  engine::tests::post_invocation_rejects_classification_from_another_tenant \
  engine::tests::pre_invocation_precheck_persists_full_taint_without_consuming_declassification \
  engine::tests::prepared_declassification_cannot_omit_its_participant \
  engine::tests::prepared_declassification_requires_live_commit_time_before_consumption \
  engine::tests::publisher_clearance_cannot_replace_policy_clearance \
  engine::tests::remote_topology_uses_policy_when_manifest_adds_no_egress_clearance \
  engine::tests::static_denials_do_not_consume_and_replay_cannot_reenter \
  engine::tests::top_source_and_top_policy_clearance_deny \
  engine::tests::verified_grant_cannot_cross_identity_authority_or_expiry_boundary \
  lattice::tests::adding_an_owner_restriction_is_upward_in_the_order \
  lattice::tests::each_operand_flows_to_its_join \
  lattice::tests::join_cardinality_overflow_returns_a_validation_error \
  lattice::tests::join_flows_to_every_generated_common_upper_bound \
  lattice::tests::join_is_associative \
  lattice::tests::join_is_commutative \
  lattice::tests::join_is_idempotent \
  lattice::tests::lattice_order_is_antisymmetric \
  lattice::tests::lattice_order_is_reflexive \
  lattice::tests::lattice_order_is_transitive \
  lattice::tests::narrowing_readers_is_upward_in_the_order \
  lattice::tests::redundant_same_owner_policies_cannot_create_unequal_equivalent_labels \
  lattice::tests::top_is_mathematical_top_but_operationally_denied_on_egress \
  -- cargo test -p chio-flow --features std --lib

run_exact_target --label "strict manifest v2" --expected \
  cage_authorization_binds_registry_manifest_and_every_tool_topology \
  cage_authorization_requires_profile_matched_runtime_topology \
  changing_flow_metadata_invalidates_manifest_signature \
  environment_variable_names_accept_non_sensitive_operational_names \
  environment_variable_names_reject_injection_and_credential_names \
  existing_signed_manifest_loader_never_creates_missing_paths \
  existing_signed_manifest_loader_rejects_symlinks \
  existing_signed_manifest_loader_requires_out_of_band_key_and_server_identity \
  flow_rejects_null_and_explicit_empty_aliases \
  legacy_duration_thresholds_and_dual_latency_rejection_are_exact \
  legacy_permissions_require_operator_profile_and_port_amendment \
  legacy_v1_migration_is_deterministic_and_unsigned \
  required_permissions_reject_implicit_ports_and_loader_environment \
  v2_manifest_signs_and_verifies_with_normalized_permissions \
  v2_rejects_alternate_json_spellings_of_signed_fields \
  v2_rejects_noncanonical_permission_spellings \
  v2_schema_accepts_runtime_shape_and_rejects_unknown_nested_fields \
  verified_registry_admits_provider_server_tools_only_as_remote_egress \
  verified_registry_composes_registered_key_policy_and_runtime_topology \
  verified_registry_rejects_manifest_clearance_that_widens_policy \
  verified_registry_rejects_tampering_and_remote_tools_without_policy_clearance \
  verified_registry_requires_an_exact_live_bridge_security_value \
  verified_registry_runtime_requirement_includes_derived_remote_topology \
  -- cargo test -p chio-manifest --test manifest_v2

run_exact_target --label "security kernel adapters" --expected \
  atomic_post_evidence_remains_bound_to_each_concurrent_response \
  clear_paths_preserve_allow_decisions \
  containment_active_and_store_error_both_prevent_dispatch \
  detector_failure_is_fail_closed \
  enforced_pre_dispatch_hook_commits_and_records_release_at_connector_boundary \
  enforced_pre_dispatch_missing_or_rejected_authority_denies_before_connector \
  every_flow_domain_error_is_fail_closed_pre_and_post \
  flow_pre_dispatch_hook_commits_canonical_authoritative_input \
  flow_pre_dispatch_hook_maps_flow_rejection_without_domain_details \
  flow_pre_dispatch_hook_maps_outcome_persistence_to_non_retryable_recovery \
  generic_pre_invocation_adapter_fails_closed_without_declassification_store \
  pinned_workload_capability_requires_exact_signed_live_context \
  post_output_match_blocks_delivery_after_server_execution \
  public_entrypoint_propagates_authoritative_context_pre_and_post \
  request_lifecycle_linearizes_release_after_post_invocation_block \
  synthetic_and_missing_context_block_under_enforcement \
  trait_conformance_compiles_against_kernel_hooks \
  tripwire_content_digest_separates_identity_and_replays_exactly \
  tripwire_emits_canonical_event_with_existing_observation_receipt_lineage \
  tripwire_event_outage_still_emits_closed_native_observation_receipt \
  tripwire_event_store_outage_preserves_pre_dispatch_deny \
  tripwire_receipt_outage_is_explicit_and_never_allows_dispatch \
  tripwire_signing_failure_is_fail_closed_before_unverified_ingress \
  -- cargo test -p chio-security-kernel --test adapters

run_exact_target --label "durable flow state" --expected \
  acknowledged_correlation_tombstone_source_binding_corruption_fails_readiness \
  lineage_fences_are_durable_and_orphans_recover_with_higher_fencing_tokens \
  concurrent_joins_retain_every_restriction_and_new_sessions_inherit \
  correlation_ingress_orders_due_event_time_ahead_of_a_future_fifo_prefix \
  correlation_ingress_pending_snapshot_survives_a_concurrent_acknowledgement \
  correlation_ingress_upgrades_the_known_legacy_pending_index \
  correlation_schema_drift_fails_startup \
  corrupt_canonical_hash_fails_closed_on_read \
  egress_dispatch_commitment_is_idempotent_and_immutable \
  egress_fence_binds_the_canonical_request_hash \
  egress_fence_rejects_corrupt_flow_state \
  generation_change_invalidates_an_egress_fence \
  injected_clock_controls_scheduler_lease_and_overlay_mutations \
  isolation_epoch_must_be_verified_and_preserves_lineage_taint \
  lineage_change_invalidates_every_principal_context \
  migration_is_idempotent_and_preserves_existing_tables \
  missing_flow_context_generation_fails_closed \
  missing_flow_epoch_or_session_row_fails_closed \
  new_lineage_inherits_existing_epoch_and_cannot_bootstrap_a_new_epoch \
  no_op_shared_label_joins_preserve_sibling_context_integrity \
  overlapping_overlay_contributions_are_removed_independently \
  overlay_effect_identity_cannot_cross_action_boundaries \
  response_effect_generation_migration_preserves_existing_intent \
  response_effect_owner_migration_rejects_unbound_existing_intent \
  scheduler_and_effect_reads_verify_canonical_hashes \
  scheduler_retry_health_migration_preserves_age_conservatively \
  scheduler_retry_health_outbox_survives_restart_and_ack_is_idempotent \
  scheduler_takeover_fences_stale_overlay_mutations \
  security_state_rejects_ephemeral_sqlite_paths \
  session_change_invalidates_same_session_fences_across_lineages \
  session_taint_is_shared_across_lineages_within_an_epoch \
  verified_event_capacity_and_rule_index_roll_back_as_one_sqlite_transaction \
  verified_event_correlation_is_durable_and_advisory_events_remain_segregated \
  -- cargo test -p chio-store-sqlite --test security_state

run_exact_target --label "native flow custody" --allow-filtered --expected \
  admission_operation_store::tests::security_participant_state::output::missing_current_output_catalog_is_not_repaired \
  admission_operation_store::tests::security_participant_state::output::v31_output_journal_upgrade_rejects_partial_future_catalog_without_repair \
  admission_operation_store::tests::security_participant_state::output::v31_upgrade_adds_empty_output_journal_without_rewriting_native_history \
  admission_operation_store::tests::security_participant_state::dispatch_ledger::v30_dispatch_ledger_upgrade_rejects_partial_future_catalog_without_repair \
  admission_operation_store::tests::security_participant_state::dispatch_ledger::v30_upgrade_adds_empty_dispatch_ledger_without_rewriting_native_history \
  admission_operation_store::tests::security_participant_state::mutations::input::input_intent_schema_and_resolution_tampering_fail_recovery_with_recomputed_local_hashes \
  admission_operation_store::tests::security_participant_state::mutations::input::input_join_cutpoints_recover_exactly_one_intent_without_downgrading_to_raw \
  admission_operation_store::tests::security_participant_state::mutations::input::input_join_preserves_actual_lease_and_original_context_checks \
  admission_operation_store::tests::security_participant_state::mutations::input::input_join_records_original_intent_and_one_complete_resolved_command \
  admission_operation_store::tests::security_participant_state::mutations::input::input_resolution_uses_current_inherited_state_but_retry_returns_original_history \
  admission_operation_store::tests::security_participant_state::mutations::input::input_retry_cannot_change_input_or_adopt_the_raw_command_family \
  admission_operation_store::tests::security_participant_state::mutations::input::raw_history_preserves_v1_bytes_and_cannot_be_inferred_as_input_history \
  admission_operation_store::tests::security_participant_state::cutpoints::child_process_crash \
  admission_operation_store::tests::security_participant_state::cutpoints::every_error_cutpoint_rolls_back_or_recovers_the_exact_committed_projection \
  admission_operation_store::tests::security_participant_state::cutpoints::independent_process_abort_and_owner_rotation_never_expose_partial_native_state \
  admission_operation_store::tests::security_participant_state::egress::authority::changed_arguments_payload_context_and_selected_authority_deny_before_writes \
  admission_operation_store::tests::security_participant_state::egress::authority::commit_requires_same_operation_acquisition_and_capture_phase \
  admission_operation_store::tests::security_participant_state::egress::authority::expired_fence_history_is_readable_but_cannot_be_committed \
  admission_operation_store::tests::security_participant_state::egress::authority::imported_pending_fence_cannot_be_adopted_even_when_the_command_matches \
  admission_operation_store::tests::security_participant_state::egress::authority::live_credential_substitution_cannot_reuse_acquisition_or_commitment \
  admission_operation_store::tests::security_participant_state::egress::authority::owner_rotation_requires_a_new_lease_and_preserves_historical_custody \
  admission_operation_store::tests::security_participant_state::egress::crash::child_process_crash \
  admission_operation_store::tests::security_participant_state::egress::crash::independent_process_abort_recovers_acquire_and_commit_without_partial_custody \
  admission_operation_store::tests::security_participant_state::egress::faults::acquisition_and_commit_errors_recover_exactly_one_event_per_phase \
  admission_operation_store::tests::security_participant_state::egress::faults::nested_commitment_field_substitution_rolls_back_the_whole_commit \
  admission_operation_store::tests::security_participant_state::egress::faults::nested_label_write_is_rejected_and_rollback_disables_egress_callback \
  admission_operation_store::tests::security_participant_state::egress::faults::nested_operation_claim_change_cannot_commit_egress_under_stale_custody \
  admission_operation_store::tests::security_participant_state::egress::faults::nested_unrelated_operation_claim_change_is_denied_by_sql_scope \
  admission_operation_store::tests::security_participant_state::egress::integrity::egress_journal_is_immutable_without_recursive_triggers \
  admission_operation_store::tests::security_participant_state::egress::integrity::locally_rehashed_egress_history_cannot_replace_anchored_operation_custody \
  admission_operation_store::tests::security_participant_state::egress::lifecycle::acquire_commit_and_retries_preserve_join_bytes_and_anchor_both_phases \
  admission_operation_store::tests::security_participant_state::egress::lifecycle::interleaved_join_and_egress_replay_in_global_order_without_reviving_stale_fence \
  admission_operation_store::tests::security_participant_state::egress::migration::missing_current_egress_catalog_is_not_repaired \
  admission_operation_store::tests::security_participant_state::egress::migration::v29_upgrade_preserves_native_initialization_join_bytes_and_global_digests \
  admission_operation_store::tests::security_participant_state::egress::migration::v29_upgrade_rejects_partial_or_alias_future_catalog_without_repair \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_commands_preserve_both_phases_and_read_current_operation \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_commands_recheck_selected_binding_live_material_and_actual_lease \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_history_distinguishes_missing_operation_from_missing_custody \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_history_rejects_missing_current_catalog_even_without_events \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_history_survives_expiry_without_renewing_fence_or_lease \
  admission_operation_store::tests::security_participant_state::egress::portable::portable_owner_rotation_preserves_history_without_reviving_old_custody \
  admission_operation_store::tests::security_participant_state::integrity::actual_native_tampering_is_detected_with_canonical_catalog_restored \
  admission_operation_store::tests::security_participant_state::integrity::all_inactive_rows_and_initialization_are_immutable_even_without_recursive_triggers \
  admission_operation_store::tests::security_participant_state::integrity::another_authority_cannot_supply_a_use_identity_or_outcome_predecessor \
  admission_operation_store::tests::security_participant_state::integrity::orphan_native_rows_and_global_reference_mismatch_are_not_accepted \
  admission_operation_store::tests::security_participant_state::integrity::restoring_private_database_before_hydration_cannot_erase_the_anchored_initialization \
  admission_operation_store::tests::security_participant_state::lifecycle::concurrent_exact_hydration_commits_only_one_initialization \
  admission_operation_store::tests::security_participant_state::lifecycle::independently_observed_clock_rollback_denies_hydration_and_readback \
  admission_operation_store::tests::security_participant_state::lifecycle::retry_and_new_owner_readback_need_no_remaining_source_file \
  admission_operation_store::tests::security_participant_state::lifecycle::two_authorities_preserve_every_native_row_without_merging_identifiers \
  admission_operation_store::tests::security_participant_state::lifecycle::unimported_wrong_generation_authority_and_fence_cannot_initialize \
  admission_operation_store::tests::security_participant_state::migration::missing_current_native_barrier_is_never_repaired \
  admission_operation_store::tests::security_participant_state::migration::v27_import_history_and_global_digests_survive_empty_v28_upgrade \
  admission_operation_store::tests::security_participant_state::migration::v27_upgrade_adds_empty_native_tables_but_rejects_partial_future_and_aliases \
  admission_operation_store::tests::security_participant_state::migration::v28_initialization_and_anchor_survive_v29_without_rewriting_history \
  admission_operation_store::tests::security_participant_state::mutations::authority_binding::first_join_cannot_substitute_another_valid_native_authority \
  admission_operation_store::tests::security_participant_state::mutations::authority_binding::native_join_requires_original_store_source_digest_and_presence \
  admission_operation_store::tests::security_participant_state::mutations::authority_binding::original_native_binding_remains_stable_across_serving_owner_rotation \
  admission_operation_store::tests::security_participant_state::mutations::faults::a_nested_delete_cannot_escape_the_monotone_join_contract \
  admission_operation_store::tests::security_participant_state::mutations::faults::child_process_native_join_crash \
  admission_operation_store::tests::security_participant_state::mutations::faults::external_row_tampering_with_restored_catalog_is_rejected_on_reopen \
  admission_operation_store::tests::security_participant_state::mutations::faults::independent_process_abort_and_takeover_preserve_exact_mutation_custody \
  admission_operation_store::tests::security_participant_state::mutations::faults::late_domain_failure_rolls_back_earlier_rows_and_disables_the_callback \
  admission_operation_store::tests::security_participant_state::mutations::faults::native_join_sql_scope_cannot_mutate_another_operations_recovery_claim \
  admission_operation_store::tests::security_participant_state::mutations::faults::restoring_database_before_join_cannot_erase_acknowledged_mutation_history \
  admission_operation_store::tests::security_participant_state::mutations::history_integrity::canonical_mutation_edits_and_missing_history_cannot_survive_owner_recovery \
  admission_operation_store::tests::security_participant_state::mutations::monotonicity::a_nested_label_downgrade_cannot_commit_as_a_monotone_join \
  admission_operation_store::tests::security_participant_state::mutations::monotonicity::historical_rows_cannot_downgrade_when_the_requested_join_is_bottom \
  admission_operation_store::tests::security_participant_state::mutations::monotonicity::nested_generation_identity_tenant_and_transition_changes_roll_back \
  admission_operation_store::tests::security_participant_state::mutations::monotonicity::returned_join_snapshot_must_match_actual_rows_after_nested_effects \
  admission_operation_store::tests::security_participant_state::mutations::native_join_errors_rollback_or_recover_exactly_one_committed_record \
  admission_operation_store::tests::security_participant_state::mutations::operation_owned_join_is_anchored_idempotent_and_keeps_other_authorities_unchanged \
  admission_operation_store::tests::security_participant_state::mutations::owner_takeover_preserves_join_history_without_reacquiring_old_authority \
  admission_operation_store::tests::security_participant_state::mutations::shared::a_caller_clock_ahead_of_authority_cannot_extend_the_mutation_lease \
  admission_operation_store::tests::security_participant_state::mutations::shared::a_later_authority_observation_cannot_hide_a_regressed_operation_decision \
  admission_operation_store::tests::security_participant_state::mutations::shared::decision_and_observation_clocks_keep_their_distinct_causal_order \
  admission_operation_store::tests::security_participant_state::mutations::shared::excessive_row_capture_aborts_the_complete_owned_join \
  admission_operation_store::tests::security_participant_state::mutations::shared::expired_join_readback_returns_history_without_fresh_authority_or_writes \
  admission_operation_store::tests::security_participant_state::mutations::shared::shared_generation_changes_are_captured_and_old_retry_is_historical_only \
  admission_operation_store::tests::security_participant_state::mutations::shared::stale_version_and_expired_leases_cannot_mutate_native_flow \
  admission_operation_store::tests::security_participant_state::mutations::wrong_identity_lease_observation_and_command_substitution_fail_before_writing \
  admission_operation_store::tests::security_participant_state::observation::current_native_rows_are_not_replaced_by_historical_join_results \
  admission_operation_store::tests::security_participant_state::observation::fresh_observation_precedes_admission_without_creating_rows_or_commits \
  admission_operation_store::tests::security_participant_state::observation::fresh_observation_requires_current_owner_but_preserves_original_initialization \
  admission_operation_store::tests::security_participant_state::observation::inherited_labels_do_not_forge_an_exact_context_generation \
  admission_operation_store::tests::security_participant_state::observation::observation_rejects_wrong_initialization_fence_and_time_without_writes \
  admission_operation_store::tests::security_participant_state::observation::unanchored_current_row_changes_cannot_be_observed_as_valid_state \
  -- cargo test -p chio-store-sqlite --lib admission_operation_store::tests::security_participant_state::

run_exact_target --label "native dispatch ledger callbacks" --allow-filtered --expected \
  kernel::tests::native_dispatch_ledger::native_dispatch_ledger_confirms_both_reads_without_activating_dispatch \
  kernel::tests::native_dispatch_ledger::native_dispatch_ledger_faults_deny_even_when_history_survives \
  kernel::tests::native_dispatch_ledger::native_dispatch_ledger_rejects_invalid_inputs_before_egress_mutation \
  -- cargo test -p chio-kernel --lib kernel::tests::native_dispatch_ledger::

run_exact_target --label "public nested credential custody" --allow-filtered --expected \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::public_nested_context_authority_error_clears_inflight_without_claims \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::public_nested_compatibility_entrypoints_cannot_downgrade_required_dpop \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::public_nested_missing_and_substituted_proofs_deny_before_claim_or_effect \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::public_nested_nonce_retry_preserves_original_session_and_dpop_custody \
  admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::public_nested_proofs_claim_exact_dpop_and_reject_cross_request_replay \
  -- cargo test -p chio-store-sqlite --lib admission_operation_store::tests::dpop_replay::claims::kernel_routes::nested_session::

run_exact_target --label "native dispatch participant snapshots" --allow-filtered --expected \
  admission_operation_store::tests::dpop_replay::claims::dispatch_snapshot::native_dpop_ledger_snapshot_retains_exact_claim_after_release \
  admission_operation_store::tests::governed_approval_replay::claims::lifecycle::dispatch_snapshot::native_approval_ledger_snapshot_retains_exact_claim_after_release \
  admission_operation_store::tests::runtime_replay::claims::dispatch_snapshot::native_runtime_ledger_snapshot_retains_exact_claim_after_release \
  -- cargo test -p chio-store-sqlite --lib ledger_snapshot

run_exact_target --label "native flow observation contracts" --allow-filtered --expected \
  admission_operation::native_flow_observation::tests::effective_inherited_state_does_not_claim_a_persisted_context \
  admission_operation::native_flow_observation::tests::inconsistent_key_generation_or_time_cannot_construct_an_observation \
  admission_operation::native_flow_observation::tests::observation_debug_does_not_expose_scope_or_labels \
  -- cargo test -p chio-kernel --lib admission_operation::native_flow_observation::

run_exact_target --label "original security authority selection" --allow-filtered --expected \
  kernel::tests::security_binding::adding_security_context_cannot_recover_an_unbound_terminal \
  kernel::tests::security_binding::changed_security_identity_cannot_recover_a_completed_operation \
  kernel::tests::security_binding::changed_security_identity_is_rejected_before_dispatch_capture \
  kernel::tests::security_binding::changed_security_requirements_cannot_recover_an_unbound_terminal \
  kernel::tests::security_binding::native_authority::codec::context_only_v2_keeps_its_exact_historical_bytes_and_hash \
  kernel::tests::security_binding::native_authority::codec::native_retained_codec_is_strict_and_hash_domain_is_versioned \
  kernel::tests::security_binding::native_authority::native_raw_return_recovery_requires_original_selection \
  kernel::tests::security_binding::native_authority::native_selection_cannot_be_added_to_context_only_history \
  kernel::tests::security_binding::native_authority::native_selection_cannot_fall_back_without_a_durable_store \
  kernel::tests::security_binding::native_authority::native_selection_change_is_rejected_before_dispatch_capture \
  kernel::tests::security_binding::native_authority::native_selection_errors_and_panics_fail_closed_before_admission \
  kernel::tests::security_binding::native_authority::native_selection_rejects_missing_context_or_optional_enforcement_before_begin \
  kernel::tests::security_binding::native_authority::native_selection_requires_retained_admission_outside_mode_coverage \
  kernel::tests::security_binding::native_authority::nested_native_selection_cannot_change_on_terminal_replay \
  kernel::tests::security_binding::native_authority::ordinary_native_selection_cannot_change_on_terminal_replay \
  kernel::tests::security_binding::nested_security_replay_checks_every_identity_field_and_preserves_flow_observations \
  kernel::tests::security_binding::ordinary_security_replay_checks_every_identity_field_and_preserves_flow_observations \
  kernel::tests::security_binding::retention::retained_security_decoder_rejects_schema_downgrade_unknown_fields_and_invalid_generations \
  kernel::tests::security_binding::retention::retained_v2_binds_security_but_not_mutable_flow_generation \
  kernel::tests::security_binding::retention::unbound_retained_v1_keeps_its_exact_hash_and_bytes \
  kernel::tests::security_binding::security_binding_preserves_large_ordinary_requests \
  kernel::tests::security_binding::security_bound_raw_return_recovers_without_a_live_request_or_redispatch \
  -- cargo test -p chio-kernel --lib kernel::tests::security_binding::

run_exact_target --label "original operation authority profile" --allow-filtered --expected \
  admission_operation::authority_profile::tests::profile_codec_checks_schema_fields_and_each_selected_generation \
  admission_operation::authority_profile::tests::profile_debug_contains_no_authority_identifiers \
  admission_operation::authority_profile::tests::profile_requires_explicit_absence_and_consistent_runtime_declarations \
  kernel::tests::authority_profile::changed_runtime_authority_cannot_reuse_original_admission \
  kernel::tests::authority_profile::changed_runtime_generation_cannot_reuse_original_admission \
  kernel::tests::authority_profile::immutable_request_commits_to_every_original_profile_selection \
  kernel::tests::authority_profile::prepared_credentials_cannot_rebind_the_original_authority_profile \
  -- cargo test -p chio-kernel --lib authority_profile
run_exact_target --label "runtime profile non-upgrade" --allow-filtered --expected \
  admission_operation_store::tests::runtime_replay::claims::runtime_claim_cannot_upgrade_absent_or_historical_authority_profile \
  -- cargo test -p chio-store-sqlite --lib admission_operation_store::tests::runtime_replay::claims::runtime_claim_cannot_upgrade_absent_or_historical_authority_profile
run_exact_target --label "native authority admission integration" --expected \
  capture::native_combined_capture_requires_supported_security_dispatch_custody \
  capture::native_generic_dispatch_commit_cannot_bypass_security_dispatch_custody \
  capture::native_split_capture_cannot_bypass_security_dispatch_custody \
  egress_coordinator::actual_kernel_egress_custody_commits_sqlite_history_without_dispatch_activation \
  actual_kernel_admission_binds_the_first_native_join_before_any_dispatch \
  denied_native_preparation_retains_monotone_history \
  native_join_only_hook_cannot_activate_dispatch \
  native_nonce_preflight_cannot_borrow_dispatch_join_authority \
  observation::fresh_observations_drive_first_and_later_admission_but_never_activate_dispatch \
  panicked_native_preparation_retains_monotone_history \
  repeated_native_preparation_cannot_reach_budget_or_runtime \
  silent_native_preparation_cannot_reach_budget_or_runtime \
  -- cargo test -p chio-store-sqlite --test native_authority_binding

run_exact_target --label "physical dispatch hold ownership" --allow-filtered --expected \
  admission_operation_store::tests::budget_atomicity::capture_owner::budget_only_references_preserve_split_capture_and_exact_replay \
  admission_operation_store::tests::budget_atomicity::capture_owner::combined_capture_rejects_another_operations_hold_before_and_after_owner_capture \
  admission_operation_store::tests::budget_atomicity::capture_owner::missing_committed_admission_cannot_be_reclassified_as_a_budget_only_reference \
  -- cargo test -p chio-store-sqlite --lib admission_operation_store::tests::budget_atomicity::capture_owner::

run_exact_target --label "qualified recovery lease boundary" --allow-filtered --expected \
  kernel::tests::recovery_lease::qualification_contains_claim_panic_after_persistence \
  kernel::tests::recovery_lease::qualification_contains_claim_panic_before_persistence \
  kernel::tests::recovery_lease::qualification_contains_operation_read_panic \
  kernel::tests::recovery_lease::qualification_contains_revalidation_panic \
  kernel::tests::recovery_lease::qualification_preserves_ordinary_errors_without_creating_claims \
  -- cargo test -p chio-kernel --lib kernel::tests::recovery_lease
run_exact_target --label "runtime recovery lease containment" --allow-filtered --expected \
  kernel::tests::runtime_participant::acquisition::runtime_lease_panic_denies_swallowed_failure_and_preserves_recovery \
  -- cargo test -p chio-kernel --lib kernel::tests::runtime_participant::acquisition::runtime_lease_panic_denies_swallowed_failure_and_preserves_recovery

run_exact_target --label "kernel-owned native preparation" --allow-filtered --expected \
  kernel::tests::native_acquisition::input::input_callback_cannot_suppress_skip_repeat_or_retarget_the_join \
  kernel::tests::native_acquisition::input::input_join_requires_exact_intent_acknowledgement_and_independent_history \
  kernel::tests::native_acquisition::egress_ports::unsupported_native_egress_ports_reject_commands_and_history_without_mutation \
  kernel::tests::native_acquisition::native_callback_cannot_suppress_skip_repeat_or_retarget_its_join \
  kernel::tests::native_acquisition::native_dispatch_checks_live_selection_before_optional_fallbacks \
  kernel::tests::native_acquisition::native_dispatch_retains_original_requirement_when_live_selection_is_absent \
  kernel::tests::native_acquisition::native_hook_without_preparation_support_denies_before_any_join \
  kernel::tests::native_acquisition::native_join_requires_matching_acknowledgement_and_anchored_readback \
  kernel::tests::native_acquisition::native_preparation_rejects_substituted_original_request_before_any_join \
  kernel::tests::native_acquisition::native_recovery_lease_panic_does_not_poison_the_mutation_sequencer \
  kernel::tests::native_acquisition::nested_native_join_only_hook_cannot_activate_dispatch \
  -- cargo test -p chio-kernel --lib kernel::tests::native_acquisition

run_exact_target --label "kernel-owned native egress" --allow-filtered --expected \
  kernel::tests::native_egress::native_egress_acquisition_faults_never_return_custody_and_read_after_writes \
  kernel::tests::native_egress::native_egress_changed_live_material_or_identity_cannot_prepare \
  kernel::tests::native_egress::native_egress_changed_observation_or_expiry_denies_before_acquisition \
  kernel::tests::native_egress::native_egress_commit_faults_preserve_acquisition_and_deny_success \
  kernel::tests::native_egress::native_egress_coordinator_binds_fresh_generation_and_both_commitments \
  kernel::tests::native_egress::native_egress_generation_change_after_acquisition_prevents_commitment \
  kernel::tests::native_egress::native_egress_observation_time_must_fall_inside_the_read_interval \
  kernel::tests::native_egress::native_egress_operation_change_after_preparation_prevents_acquisition \
  -- cargo test -p chio-kernel --lib kernel::tests::native_egress

run_exact_target --label "native dispatch attachment contracts" --allow-filtered --expected \
  admission_operation::capture::tests::native_dispatch_attachment_commits_with_dispatch_and_cannot_be_replaced \
  admission_operation::capture::tests::native_dispatch_attachment_has_exact_acquisition_and_retention_phases \
  admission_operation::capture::tests::native_dispatch_attachment_rejects_every_unsupported_participant_profile \
  -- cargo test -p chio-kernel --lib admission_operation::capture::tests::native_dispatch_attachment_

run_exact_target --label "native post-join policy" --allow-filtered --expected \
  security::adapters::tests::native_flow::support::capture::output::faults::native_output_journal_precommit_failures_roll_back_rows_events_and_global_head \
  security::adapters::tests::native_flow::support::capture::output::faults::native_output_journal_lost_acknowledgement_recovers_history_without_release_authority \
  security::adapters::tests::native_flow::support::capture::output::faults::native_output_journal_locally_rehashed_history_cannot_replace_the_global_anchor \
  security::adapters::tests::native_flow::support::capture::output::native_output_journal_inherits_all_current_labels_when_output_is_public \
  security::adapters::tests::native_flow::support::capture::output::native_output_journal_propagates_taint_once_without_releasing_or_rewriting_input \
  security::adapters::tests::native_flow::support::capture::output::native_output_journal_rejects_stale_lease_generation_and_substituted_artifacts \
  security::adapters::tests::native_flow::support::capture::combined_credentials::nested::public_nested_native_capture_retains_runtime_approval_and_dpop_for_local_and_egress \
  security::adapters::tests::native_flow::support::capture::combined_credentials::nested::public_nested_declassification_proof_reaches_native_unsupported_profile_denial \
  security::adapters::tests::native_flow::support::capture::combined_credentials::native_capture_preserves_nonempty_runtime_approval_and_dpop_in_one_operation \
  security::adapters::tests::native_flow::support::capture::combined_credentials::native_combined_credentials_deny_missing_proof_or_changed_approved_intent_before_capture \
  security::adapters::tests::native_flow::support::capture::corruption::native_capture_physical_corruption_denies_readback_and_reopen \
  security::adapters::tests::native_flow::support::capture::acknowledgements::native_capture_acknowledgement_faults_preserve_committed_accounting \
  security::adapters::tests::native_flow::support::capture::acknowledgements::native_capture_readback_faults_preserve_committed_accounting \
  security::adapters::tests::native_flow::support::capture::acknowledgements::native_capture_lost_ack_retains_owned_dpop_without_reclaim \
  security::adapters::tests::native_flow::ledger::faults::ledger_write_failures_preserve_committed_egress_through_compensation_and_reopen \
  security::adapters::tests::native_flow::support::capture::native_atomic_capture_faults_roll_back_budget_and_operation_together \
  security::adapters::tests::native_flow::support::capture::native_atomic_capture_preserves_dpop_required_by_another_matching_grant \
  security::adapters::tests::native_flow::support::capture::native_atomic_capture_retains_quota_and_ledger_without_tool_effect \
  security::adapters::tests::native_flow::ledger::native_dispatch_ledger_corruption_or_missing_global_coverage_denies_reopen \
  security::adapters::tests::native_flow::ledger::native_dispatch_ledger_denies_unmatched_grant_without_retention \
  security::adapters::tests::native_flow::ledger::native_dispatch_ledger_retains_exact_policy_and_custody_after_compensation \
  security::adapters::tests::native_flow::policy::native_policy_evidence_binds_exact_inputs_and_decision_without_payload \
  security::adapters::tests::native_flow::policy::native_policy_evidence_commits_large_manifest_without_retaining_its_payload \
  security::adapters::tests::native_flow::policy::native_policy_evidence_retains_unused_category_policy_and_admitted_clearance \
  security::adapters::tests::native_flow::policy::oversized_native_policy_evidence_denies_before_any_egress_custody \
  security::adapters::tests::native_flow::input::native_input_classifier_panic_denies_without_taint_or_budget \
  security::adapters::tests::native_flow::input::native_input_classifier_substitution_denies_without_taint_or_budget \
  security::adapters::tests::native_flow::input::native_input_classifies_before_budget_and_rechecks_after_the_single_join \
  security::adapters::tests::native_flow::input::native_input_declassification_denies_before_classification_or_join \
  security::adapters::tests::native_flow::input::native_input_inherits_global_lineage_before_the_exact_epoch_exists \
  security::adapters::tests::native_flow::input::native_input_inherits_principal_epoch_from_another_lineage \
  security::adapters::tests::native_flow::input::native_input_local_policy_does_not_acquire_egress_custody \
  security::adapters::tests::native_flow::input::native_input_missing_manifest_denies_before_classification_or_join \
  security::adapters::tests::native_flow::input::native_input_operator_floor_is_in_the_original_join \
  security::adapters::tests::native_flow::input::native_input_propagates_inherited_session_only_taint \
  security::adapters::tests::native_flow::input::native_input_stronger_post_join_classification_denies_without_rejoining \
  security::adapters::tests::native_flow::native_local_policy_does_not_manufacture_an_egress_fence \
  security::adapters::tests::native_flow::native_local_policy_revalidates_clock_without_fence_writes \
  security::adapters::tests::native_flow::native_policy_accepts_recorded_restricted_labels_with_matching_clearance \
  security::adapters::tests::native_flow::native_policy_commits_real_egress_custody_without_activating_dispatch \
  security::adapters::tests::native_flow::native_policy_contains_classifier_panic_without_egress_writes \
  security::adapters::tests::native_flow::native_policy_contains_clock_panic_before_egress_acquisition \
  security::adapters::tests::native_flow::native_policy_rejects_classifier_payload_substitution \
  security::adapters::tests::native_flow::native_policy_rejects_classifier_taint_not_in_original_join \
  security::adapters::tests::native_flow::native_policy_rejects_clock_failure_before_egress_acquisition \
  security::adapters::tests::native_flow::native_policy_rejects_declassification_before_classification \
  security::adapters::tests::native_flow::native_policy_rejects_future_clock_before_preparation \
  security::adapters::tests::native_flow::native_policy_rejects_legacy_evidence_configuration \
  security::adapters::tests::native_flow::native_policy_rejects_other_initialized_authority_before_classification \
  security::adapters::tests::native_flow::native_policy_rejects_public_destination_for_recorded_restricted_input \
  security::adapters::tests::native_flow::native_policy_rejects_regressing_clock_before_egress_acquisition \
  security::adapters::tests::native_flow::native_policy_rejects_unrecorded_operator_floor_without_rejoining \
  security::adapters::tests::native_flow::native_policy_requires_admitted_manifest_before_classification \
  security::adapters::tests::native_flow::native_policy_requires_taint_propagation_in_each_recorded_label \
  -- cargo test -p chio-control-plane --lib security::adapters::tests::native_flow::

run_exact_target --label "native capture accounting deltas" --allow-filtered --expected \
  budget_store::composite::native_capture::tests::native_capture_quota_delta_requires_exact_bounded_unique_accounting \
  budget_store::composite::native_capture::tests::native_capture_cumulative_delta_preserves_identity_currency_and_exact_amount \
  -- cargo test -p chio-store-sqlite --lib budget_store::composite::native_capture::tests::

run_exact_target --label "native runtime validity contract" --allow-filtered --expected \
  admission_operation::runtime_participant::validity_tests::runtime_dispatch_validity_is_bounded_and_exclusive \
  -- cargo test -p chio-kernel --lib admission_operation::runtime_participant::validity_tests::

run_exact_target --label "native runtime signed freshness" --allow-filtered --expected \
  operation_owned::combined::native_validity::native_runtime_deadline_includes_every_selected_signed_time_bound \
  operation_owned::combined::native_validity::native_runtime_deadline_includes_the_verified_bilateral_capability_lease \
  operation_owned::combined::native_validity::native_runtime_revalidation_binds_nonempty_signed_treaty_swarm_and_original_plan \
  -- cargo test -p chio-runtime-core --test runtime_admission operation_owned::combined::native_validity::

run_exact_target --label "native policy clock bounds" --allow-filtered --expected \
  security::adapters::native_flow::tests::native_policy_time_bounds_are_inclusive_at_observation_and_exclusive_at_expiry \
  -- cargo test -p chio-control-plane --lib security::adapters::native_flow::tests::

run_exact_target --label "prepared flow dispatch binding" --allow-filtered --expected \
  security::adapters::tests::prepared_dispatch::another_flow_transition_invalidates_preparation_without_consuming \
  security::adapters::tests::prepared_dispatch::clock_rollback_cannot_consume_a_prepared_grant \
  security::adapters::tests::prepared_dispatch::concurrent_preparations_do_not_establish_two_owners \
  security::adapters::tests::prepared_dispatch::evidence_callbacks::expiry_during_evidence_lookup_rejects_before_consumption \
  security::adapters::tests::prepared_dispatch::expired_fence_plan_is_not_renewed_at_commit \
  security::adapters::tests::prepared_dispatch::expired_prepared_grant_is_not_consumed \
  security::adapters::tests::prepared_dispatch::prepared_commit_uses_fresh_consumption_time_without_reclassification \
  security::adapters::tests::prepared_dispatch::prepared_dispatch_binds_transient_grant_without_changing_its_payload_commitment \
  security::adapters::tests::prepared_dispatch::prepared_dispatch_keeps_live_envelope_and_argument_hashes_distinct \
  security::adapters::tests::prepared_dispatch::prepared_dispatch_rejects_envelope_substitution_with_equal_arguments \
  security::adapters::tests::prepared_dispatch::prepared_non_declassifying_commit_uses_the_physical_fence \
  security::adapters::tests::prepared_dispatch::preparing_and_dropping_either_profile_does_not_mutate_sqlite \
  security::adapters::tests::prepared_dispatch::racing_prepared_commits_consume_the_grant_once \
  -- cargo test -p chio-control-plane --lib security::adapters::tests::prepared_dispatch::

run_exact_target --label "security dispatch credential boundaries" --allow-filtered --expected \
  kernel::tests::security_dispatch::credentials::security_rejection_keeps_credentials_reversible_until_dispatch \
  kernel::tests::security_dispatch::credentials::security_rejection_releases_dpop_nonce_and_approval_as_one_attempt \
  kernel::tests::security_dispatch::credentials::security_rejection_reports_unconfirmed_credential_rollback \
  kernel::tests::security_dispatch::legacy_nonce::confirmed_legacy_nonce_retention_survives_reversible_cleanup \
  kernel::tests::security_dispatch::legacy_nonce::legacy_nonce_failure_stays_failed_without_another_store_call \
  kernel::tests::security_dispatch::legacy_nonce::retention_failure_after_security_acceptance_records_failed_dispatch \
  kernel::tests::security_dispatch::nested_security_callbacks_preserve_the_effect_boundary \
  kernel::tests::security_dispatch::rejection_with_warning_logging_does_not_call_hook_name \
  -- cargo test -p chio-kernel --lib kernel::tests::security_dispatch::

run_exact_target --label "durable release output binding" --allow-filtered --expected \
  tool_outcome::security_release::context::tests::context_rejects_other_dispatch_and_evaluation_records \
  tool_outcome::security_release::context::tests::context_rejects_substituted_preimages_and_value_or_stream_payloads \
  -- cargo test -p chio-kernel --lib tool_outcome::security_release::context::tests::

run_exact_target --label "durable security release recovery" --expected \
  checkpoint_faults::checkpoint_write_failure_cannot_reconsume_a_live_owner \
  checkpoint_faults::lost_checkpoint_acknowledgement_recovers_the_exact_committed_release \
  checkpoint_faults::successful_live_release_cannot_renew_a_lease_expired_before_checkpoint \
  checkpoint_faults::unsupported_checkpoint_backend_rejects_before_dispatch \
  crash::crash_after_acknowledgement_requires_the_missing_checkpoint \
  crash::crash_after_checkpoint_recovers_without_a_second_release_or_effect \
  crash::crash_before_release_cannot_publish_resolved_output \
  final_release_failure_cannot_be_bypassed_after_restart \
  final_release_failure_cannot_be_bypassed_by_terminal_retry \
  integrity::a_frozen_no_owner_requirement_does_not_create_release_authority \
  integrity::acknowledgement_time_follows_the_native_release_callback \
  integrity::checkpoint_omission_and_rewritten_bindings_fail_on_reopen \
  integrity::checkpoint_sql_guards_reject_replace_update_and_delete \
  integrity::checkpoint_survives_authorized_payload_compaction_and_owner_rotation \
  integrity::decoded_checkpoint_is_exact_data_not_a_live_owner \
  integrity::removing_hook_configuration_cannot_erase_a_pending_release \
  nested::nested_release_failure_remains_withheld_on_retry \
  nested::nested_release_success_replays_the_same_terminal \
  output::current_output_refusal_withholds_value_and_stream_without_reinvocation \
  output::output_release_callback_panic_cannot_publish_or_reinvoke \
  output::release_owner_receives_redacted_chunks_not_only_their_digests \
  output::release_owner_receives_the_exact_redacted_value \
  serialization::live_release_callback_can_enter_the_original_mutation_sequence \
  serialization::nested_live_release_callback_can_enter_the_original_mutation_sequence \
  successful_release_is_checkpointed_before_completion_and_replayed_after_restart \
  -- cargo test -p chio-store-sqlite --test security_release_recovery

run_exact_target --label "dispatch rejection payment custody" --allow-filtered --expected \
  kernel::tests::dispatch_commit_failure::freeze_rejection_after_payment_does_not_invent_credential_custody \
  kernel::tests::dispatch_commit_failure::freeze_rejection_after_payment_retains_the_authorizing_approval \
  kernel::tests::dispatch_commit_failure::mustprepay::explicit_unsafe_no_charge_mustprepay_records_the_actual_request_reference \
  kernel::tests::dispatch_commit_failure::mustprepay::no_charge_mustprepay_requires_a_durable_payment_participant_before_authorization \
  kernel::tests::dispatch_commit_failure::security_rejection_after_payment_preserves_actual_credential_disposition \
  kernel::tests::dispatch_commit_failure::unconfirmed_dispatch_commit_retains_payment_quota_and_approval \
  kernel::tests::dispatch_commit_failure::unconfirmed_payment_authorization_receipt_names_the_attempted_durable_operation \
  kernel::tests::dispatch_commit_failure::unconfirmed_payment_unwind_receipt_names_the_attempted_durable_operation \
  -- cargo test -p chio-kernel --lib kernel::tests::dispatch_commit_failure::

run_exact_target --label "security runtime composition" --allow-filtered --expected \
  security::tests::active_defense_builder_installs_exact_boundary_order \
  security::tests::active_defense_builder_refuses_unready_runtime \
  -- cargo test -p chio-control-plane --lib security::tests

run_exact_target --label "OpenAPI bridge canonical flow" --allow-filtered --expected \
  tests::registry_bound_mcp_export_preserves_canonical_openapi_flow \
  -- cargo test -p chio-openapi-mcp-bridge --lib registry_bound_mcp_export_preserves_canonical_openapi_flow
run_exact_target --label "MCP flow sidecar" --allow-filtered --expected \
  runtime::discovery::tests::constrained_tool_does_not_expose_internal_flow_sidecar \
  -- cargo test -p chio-mcp-edge --lib constrained_tool_does_not_expose_internal_flow_sidecar
run_exact_target --label "A2A canonical flow" --allow-filtered --expected \
  tests::registry_admitted_flow_survives_a2a_execution_projection_canonically \
  -- cargo test -p chio-a2a-edge --lib registry_admitted_flow_survives_a2a_execution_projection_canonically
run_exact_target --label "A2A rejected flow sidecar" --allow-filtered --expected \
  tests::a2a_execution_boundary_rejects_removed_or_mismatched_flow_sidecar \
  -- cargo test -p chio-a2a-edge --lib a2a_execution_boundary_rejects_removed_or_mismatched_flow_sidecar
run_exact_target --label "ACP canonical flow" --allow-filtered --expected \
  tests::registry_admitted_flow_survives_acp_execution_projection_canonically \
  -- cargo test -p chio-acp-edge --lib registry_admitted_flow_survives_acp_execution_projection_canonically
run_exact_target --label "ACP rejected flow sidecar" --allow-filtered --expected \
  tests::acp_execution_boundary_rejects_removed_or_mismatched_flow_sidecar \
  -- cargo test -p chio-acp-edge --lib acp_execution_boundary_rejects_removed_or_mismatched_flow_sidecar
run_exact_target --label "OpenAI canonical flow" --allow-filtered --expected \
  registry_bound_lift_preserves_exact_flow_sidecar \
  -- cargo test -p chio-openai-adapter --features provider-adapter --test adapter_lift registry_bound_lift_preserves_exact_flow_sidecar
run_exact_target --label "OpenAI rejected flow sidecar" --allow-filtered --expected \
  registry_bound_lift_rejects_tool_without_admitted_sidecar \
  -- cargo test -p chio-openai-adapter --features provider-adapter --test adapter_lift registry_bound_lift_rejects_tool_without_admitted_sidecar
run_exact_target --label "Anthropic canonical round trip" --allow-filtered --expected \
  registry_admitted_flow_survives_anthropic_invocation_round_trip_canonically \
  -- cargo test -p chio-anthropic-tools-adapter --test server_tools registry_admitted_flow_survives_anthropic_invocation_round_trip_canonically
run_exact_target --label "cross-protocol canonical flow" --allow-filtered --expected \
  tests::cross_protocol_routing_preserves_registry_admitted_flow_canonical_bytes \
  -- cargo test -p chio-cross-protocol --lib cross_protocol_routing_preserves_registry_admitted_flow_canonical_bytes
run_exact_target --label "cross-protocol rejects unadmitted sidecar" --allow-filtered --expected \
  tests::execution_boundary_rejects_unadmitted_bridge_security \
  -- cargo test -p chio-cross-protocol --lib execution_boundary_rejects_unadmitted_bridge_security
run_exact_target --label "cross-protocol rejects forged sidecar" --allow-filtered --expected \
  tests::execution_boundary_rejects_forged_digest_flow_and_topology_fields \
  -- cargo test -p chio-cross-protocol --lib execution_boundary_rejects_forged_digest_flow_and_topology_fields
run_exact_target --label "Bedrock canonical flow" --allow-filtered --expected \
  tests::registry_bound_lift_preserves_exact_flow_sidecar \
  -- cargo test -p chio-bedrock-converse-adapter --lib registry_bound_lift_preserves_exact_flow_sidecar
run_exact_target --label "Gemini canonical flow" --allow-filtered --expected \
  adapter::tests::registry_bound_lift_preserves_exact_flow_sidecar \
  -- cargo test -p chio-gemini-tools-adapter --lib registry_bound_lift_preserves_exact_flow_sidecar
run_exact_target --label "Ollama canonical flow" --allow-filtered --expected \
  tests::registry_bound_lift_preserves_exact_flow_sidecar \
  -- cargo test -p chio-ollama-tools-adapter --lib registry_bound_lift_preserves_exact_flow_sidecar
run_exact_target --label "Mistral canonical stream" --allow-filtered --expected \
  registry_bound_stream_preserves_exact_canonical_flow_bytes \
  -- cargo test -p chio-mistral-tools-adapter --test registry_security registry_bound_stream_preserves_exact_canonical_flow_bytes
run_exact_target --label "Groq canonical stream" --allow-filtered --expected \
  registry_bound_stream_preserves_exact_canonical_flow_bytes \
  -- cargo test -p chio-groq-tools-adapter --test registry_security registry_bound_stream_preserves_exact_canonical_flow_bytes
run_exact_target --label "Cohere canonical stream" --allow-filtered --expected \
  registry_bound_stream_preserves_exact_canonical_flow_bytes \
  -- cargo test -p chio-cohere-tools-adapter --test registry_security registry_bound_stream_preserves_exact_canonical_flow_bytes
run_exact_target --label "security schema vectors" --expected \
  every_mapping_entry_resolves_to_existing_files \
  every_vector_domain_has_a_schema_mapping_entry \
  -- cargo test -p chio-conformance --test vectors_schema_pair

run_exact_target --label "native input intent contracts" --allow-filtered --expected \
  admission_operation::native_input_join::tests::decoded_input_intent_rejects_unknown_fields_and_recomputed_binding_mismatch \
  admission_operation::native_input_join::tests::input_resolution_cannot_discard_the_classified_input_label \
  admission_operation::native_input_join::tests::input_resolution_requires_complete_propagation_exact_keys_and_safe_generation \
  admission_operation::native_input_join::tests::input_transition_binds_operation_each_identity_and_classified_label \
  -- cargo test -p chio-kernel --lib admission_operation::native_input_join::tests::

echo "Flow security gate passed"
