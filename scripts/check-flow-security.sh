#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

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
  declassification::tests::all_static_bindings_and_store_failure_deny_before_release \
  declassification::tests::concurrent_consumers_produce_exactly_one_verified_result \
  declassification::tests::exact_grant_consumes_once_and_persists_terminal_dispatch_outcomes \
  declassification::tests::time_purpose_trust_signature_and_label_fail_closed \
  engine::tests::accumulated_knowledge_blocks_unclassified_egress \
  engine::tests::complete_source_joins_payload_floor_and_all_durable_labels \
  engine::tests::every_policy_clearance_must_accept_the_complete_source \
  engine::tests::fence_is_prepared_only_after_taint_persistence \
  engine::tests::many_small_outputs_accumulate_taint_monotonically \
  engine::tests::non_egress_call_retains_taint_without_clearance_or_fence \
  engine::tests::one_shot_downgrade_substitutes_the_exact_signed_target_for_egress \
  engine::tests::payload_only_declassification_binding_cannot_downgrade_accumulated_knowledge \
  engine::tests::post_invocation_joins_classifier_and_declared_floors_before_delivery \
  engine::tests::post_invocation_overflow_transitions_to_top \
  engine::tests::post_invocation_rejects_classification_from_another_representation \
  engine::tests::post_invocation_rejects_classification_from_another_tenant \
  engine::tests::pre_invocation_precheck_persists_full_taint_without_consuming_declassification \
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

echo "Flow security gate passed"
