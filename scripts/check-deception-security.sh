#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_exact_target() {
  ./scripts/run-exact-cargo-test-inventory.sh "$@"
}

run_exact_target --label "decoy coordinator" --expected \
  changed_content_blocks_retirement_and_exact_retry_recovers \
  durable_materializing_intent_recovers_after_file_creation_and_exact_retry_is_stable \
  materialization_failure_is_durable_and_only_the_same_operation_can_retry \
  -- cargo test -p chio-decoy --test coordinator

run_exact_target --label "decoy lifecycle" --expected \
  error_preserves_prior_and_only_exact_retry_or_retire_is_legal \
  lifecycle_accepts_every_linear_edge \
  lifecycle_rejects_every_non_linear_edge \
  retire_requires_a_distinct_armed_successor_for_the_next_version \
  stale_generation_and_wrong_version_fail_closed \
  -- cargo test -p chio-decoy --test lifecycle

run_exact_target --label "decoy matcher" --expected \
  active_direct_presentation_is_high_confidence_and_requires_immediate_deny \
  inactive_marker_is_distinct_from_clear \
  registry_or_lifecycle_errors_never_collapse_to_clear \
  scanner_and_operator_touches_are_signals_but_never_proof_of_malice \
  -- cargo test -p chio-decoy --test matcher

run_exact_target --label "decoy materialization" --expected \
  cleanup_is_idempotent_and_recovers_after_quarantine_rename \
  cleanup_rejects_changed_or_replaced_content_without_removal \
  cleanup_rejects_forged_registry_identity_and_metadata_proof \
  cleanup_rejects_symlink_replacement_and_preserves_target \
  debug_output_redacts_identity_path_content_digest_and_tag \
  foreign_existing_file_is_never_adopted_even_when_content_matches \
  hardlink_invalidates_retry_and_cleanup \
  identity_or_key_rebinding_cannot_adopt_an_existing_file \
  materialize_creates_restrictive_tree_and_exact_retry_is_idempotent \
  materialize_rejects_empty_or_nul_operation_identity \
  materialize_rejects_unsafe_relative_paths_before_mutation \
  ordinary_cleanup_removes_only_the_proven_owned_file \
  ownership_key_debug_never_exposes_secret_bytes \
  ownership_receipt_round_trips_non_utf8_paths_and_remains_authoritative \
  symlink_root_component_and_final_entry_are_rejected \
  -- cargo test -p chio-decoy --test materialize

run_exact_target --label "sealed decoy registry API" --expected \
  concurrent_transition_has_one_winner_and_exact_retry_is_stable \
  duplicate_marker_in_the_same_tenant_and_surface_is_rejected \
  operation_id_is_globally_unique_within_a_tenant \
  privileged_export_derives_tenant_from_the_configured_authorizer \
  rotation_arms_the_distinct_successor_before_retiring_the_old_version \
  rows_contain_only_keyed_tokens_and_authenticated_ciphertext \
  signed_watermark_public_reference_is_generated_and_never_stored_raw \
  tenant_tokens_are_domain_separated_and_ciphertext_transplant_fails \
  -- cargo test -p chio-decoy --test registry

run_exact_target --label "decoy registry key rotation" --expected \
  overlap_opens_legacy_private_public_and_marker_lookups_and_writes_active \
  shared_index_key_continues_to_the_matching_legacy_encryption_version \
  unknown_version_overlap_expiry_and_tenant_boundaries_fail_closed \
  -- cargo test -p chio-decoy --test registry_key_rotation

run_exact_target --label "signed watermark lifecycle" --expected \
  a_verified_active_hit_survives_observation_store_failure_and_cross_tenant_replay \
  active_and_overlap_keys_verify_only_inside_receipt_anchored_windows \
  canonical_payload_signature_and_safe_integer_tampering_are_advisory_not_clear \
  clean_output_is_clear_and_malformed_or_duplicate_candidates_cannot_mask_a_valid_hit \
  detector_dependency_failure_is_never_reported_as_clear \
  issuer_requires_verified_recent_context_an_active_key_and_an_armed_registry_entry \
  observation_deduplication_binds_token_and_first_complete_attribution \
  replay_is_reserved_before_signing_and_exact_operation_retry_is_idempotent \
  retired_and_expired_entries_are_verified_inactive_advisories \
  -- cargo test -p chio-decoy --test watermark

run_exact_target --label "signed watermark vectors" --expected \
  shared_watermark_vector_pins_rust_bytes_and_signature \
  unsafe_integer_rejection_vector_is_fail_closed_in_rust \
  -- cargo test -p chio-decoy --test watermark_vectors

run_exact_target --label "pre-dispatch tripwire adapters" --allow-filtered --expected \
  tripwire_content_digest_separates_identity_and_replays_exactly \
  tripwire_emits_canonical_event_with_existing_observation_receipt_lineage \
  tripwire_event_outage_still_emits_closed_native_observation_receipt \
  tripwire_event_store_outage_preserves_pre_dispatch_deny \
  tripwire_receipt_outage_is_explicit_and_never_allows_dispatch \
  tripwire_signing_failure_is_fail_closed_before_unverified_ingress \
  -- cargo test -p chio-security-kernel --test adapters tripwire

run_exact_target --label "post-response watermark tripwire" --allow-filtered --expected \
  post_output_match_blocks_delivery_after_server_execution \
  -- cargo test -p chio-security-kernel --test adapters post_output_match

run_exact_target --label "sealed private registry store" --expected \
  cas_rejects_immutable_mutation_stale_state_and_generation_skips \
  concurrent_distinct_watermark_observations_never_misreport_duplicates \
  concurrent_expected_generation_writers_have_one_winner \
  concurrent_identical_observations_preserve_one_first_attribution \
  concurrent_identical_sequence_retries_are_exactly_idempotent \
  concurrent_watermark_sequence_writers_have_one_winner \
  durable_open_rejects_constraint_incompatible_preexisting_schema \
  durable_open_rejects_memory_uris_queries_and_fragments \
  every_read_surface_is_tenant_isolated \
  malformed_record_and_transition_rows_fail_closed \
  malformed_watermark_state_fails_closed \
  marker_collision_is_tenant_and_surface_scoped \
  operation_reuse_across_artifacts_and_transition_mutation_conflict \
  public_reference_lookup_is_keyed_unique_and_tenant_scoped \
  public_reference_shape_follows_surface_lifecycle \
  scan_uses_byte_ordered_opaque_cursor_without_duplicates \
  sqlite_fixture_contains_tokens_and_ciphertext_but_no_raw_secrets \
  stable_operation_can_record_distinct_retry_transitions_for_one_artifact \
  transition_replay_rejects_shape_valid_equal_generation_tampering \
  transition_replay_returns_original_snapshot_after_later_update_and_reopen \
  watermark_observation_identity_is_source_tenant_scoped \
  watermark_observation_retry_preserves_first_attribution_and_rejects_mutation \
  watermark_sequence_operation_ids_are_tenant_wide \
  watermark_sequence_reservation_is_durable_monotonic_and_exactly_idempotent \
  -- cargo test -p chio-store-sqlite --test sealed_decoy_registry

run_exact_target --label "native canary and honey-tool pre-dispatch denial" --allow-filtered --expected \
  canary_pre_dispatch_denial \
  honey_tool_pre_dispatch_denial \
  -- cargo test -p chio-conformance --test active_defense pre_dispatch_denial

echo "Deception security gate passed (82 exact tests)"
