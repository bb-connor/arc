#!/usr/bin/env bash
set -euo pipefail

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" == "1" ]]; then
  workspace="${CHIO_SECURITY_WORKSPACE:-}"
  inventory_checker="${CHIO_SECURITY_EXACT_INVENTORY_CHECKER:-}"
  if [[ "$workspace" != "/private/candidate" ]] ||
    [[ "$inventory_checker" != "/opt/chio-security/gates/check-exact-cargo-test-inventory.py" ]]; then
    echo "designated keyring gate paths do not match the trusted contract" >&2
    exit 1
  fi
  if [[ ! -f "$inventory_checker" ]] || [[ -L "$inventory_checker" ]]; then
    echo "designated keyring inventory checker is missing or symbolic" >&2
    exit 1
  fi
else
  if [[ -n "${CHIO_SECURITY_WORKSPACE:-}" ]] ||
    [[ -n "${CHIO_SECURITY_EXACT_INVENTORY_CHECKER:-}" ]]; then
    echo "trusted keyring gate paths leaked into a portable invocation" >&2
    exit 1
  fi
  workspace="$(cd "$(dirname "$0")/.." && pwd)"
  inventory_checker="$workspace/scripts/check-exact-cargo-test-inventory.py"
fi
cd "$workspace"

export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_tests() {
  local label="$1"
  local allow_filtered="$2"
  local inventory="$3"
  shift 3
  local list_output run_output list_status run_status
  local -a expected
  expected=()
  while IFS= read -r test_name; do
    if [[ -n "${test_name}" ]]; then
      expected+=("${test_name}")
    fi
  done <<< "${inventory}"
  if [[ "${#expected[@]}" -eq 0 ]]; then
    echo "${label} has an empty mandated inventory" >&2
    return 1
  fi
  list_output="$(mktemp "${TMPDIR:-/tmp}/chio-keyring-list.XXXXXX")"
  run_output="$(mktemp "${TMPDIR:-/tmp}/chio-keyring-run.XXXXXX")"
  set +e
  "$@" -- --list 2>&1 | tee "${list_output}"
  list_status=${PIPESTATUS[0]}
  set -e
  if [[ "${list_status}" -ne 0 ]]; then
    rm -f "${list_output}" "${run_output}"
    return "${list_status}"
  fi
  set +e
  "$@" 2>&1 | tee "${run_output}"
  run_status=${PIPESTATUS[0]}
  set -e
  if [[ "${run_status}" -ne 0 ]]; then
    rm -f "${list_output}" "${run_output}"
    return "${run_status}"
  fi
  if [[ "${allow_filtered}" == "yes" ]]; then
    python3 -I "$inventory_checker" \
      --label "${label}" \
      --list-output "${list_output}" \
      --run-output "${run_output}" \
      --allow-filtered \
      "${expected[@]}"
  else
    python3 -I "$inventory_checker" \
      --label "${label}" \
      --list-output "${list_output}" \
      --run-output "${run_output}" \
      "${expected[@]}"
  fi
  rm -f "${list_output}" "${run_output}"
}

run_tests "RFC 6962 vectors" yes "$(cat <<'EOF'
merkle::tests::consistency_all_pairs_verify_through_sixteen_leaves
merkle::tests::consistency_deserialization_rejects_overlong_paths_before_growth
merkle::tests::consistency_fixed_paths_match_rfc_6962_example_shape
merkle::tests::consistency_fixed_roots_match_rfc_6962_tree_hashing
merkle::tests::consistency_generation_rejects_zero_and_oversized_old_tree
merkle::tests::consistency_rejects_malformed_proofs_and_roots
merkle::tests::empty_tree_fails
merkle::tests::from_hashes_matches_from_leaves
merkle::tests::inclusion_proof_rejects_wrong_leaf
merkle::tests::inclusion_proofs_roundtrip
merkle::tests::proof_out_of_bounds
merkle::tests::proof_serialization_roundtrip
merkle::tests::root_matches_recursive_reference
merkle::tests::single_leaf_tree
merkle::tests::two_leaf_tree
merkle::tests::verify_hash_works
EOF
)" cargo test -p chio-core-types --lib merkle

run_tests "complete key-log envelopes" no "$(cat <<'EOF'
canonical_body_and_complete_envelope_are_stable_and_non_self_referential
common_validation_rejects_schema_sequence_predecessor_and_time_errors
complete_envelope_hash_and_merkle_leaf_cover_every_signature_byte
genesis_and_rotation_require_exact_authorization_sets
key_id_binds_algorithm_and_complete_self_describing_public_key
recovery_authorizations_are_sorted_and_bounded_before_vector_growth
EOF
)" cargo test -p chio-keyring --test event

run_tests "checkpoint and witness signatures" no "$(cat <<'EOF'
checkpoint_deserialization_rejects_oversized_witness_vectors
checkpoint_operator_signature_and_identity_are_canonical
checkpoint_validation_rejects_root_size_sequence_and_predecessor_mismatch
witness_signatures_bind_checkpoint_hash_and_require_distinct_known_quorum
EOF
)" cargo test -p chio-keyring --test checkpoint

run_tests "two-stage activation and artifact time" no "$(cat <<'EOF'
abort_retire_and_revoke_are_immutable_events
auditor_keys_cannot_overlap_any_fixed_or_lifecycle_authority_role
auditor_policy_requires_exactly_two_unique_identifiers_and_role_keys
complete_history_and_replay_reject_malformed_sequences_and_role_key_overlap
configuration_binding_commits_the_canonical_auditor_roster
genesis_and_pending_rotation_preserve_one_active_signer
recovery_requires_distinct_threshold_authorizers_and_witnessed_activation
trust_policy_bindings_commit_roster_keys_and_recovery_threshold
trusted_artifact_time_evidence_blocks_post_deactivation_and_preactivation_use
witnessed_rotation_uses_signed_commit_time_and_strict_majority
EOF
)" cargo test -p chio-keyring --test state

run_tests "transactional key-log storage" no "$(cat <<'EOF'
activation_rejects_clock_rollback_and_preserves_pending_selector
append_checkpoint_witness_activation_and_reopen_are_transactional
append_retry_returns_existing_checkpoint_and_conflict_does_not_mutate_log
concurrent_rotation_proposals_commit_exactly_one_head
durable_store_rejects_changed_security_configuration
key_log_rejects_ephemeral_sqlite_paths
key_log_storage_identity_is_retained_across_path_replacement
key_log_store_rejects_hard_link_database_aliases
key_log_store_rejects_untrusted_parent_directory_swap_boundary
local_single_writer_is_fenced_across_store_handles_while_observers_remain_available
oversized_sqlite_blob_is_refused_before_blob_materialization
startup_rebuild_rejects_root_corruption_and_multi_worker_topology
write_and_signing_failures_leave_no_partial_event_checkpoint_or_state
EOF
)" cargo test -p chio-keyring --test sqlite

run_tests "signing epoch serialization" no "$(cat <<'EOF'
activation_waits_until_inflight_signature_is_durably_anchored
concurrent_duplicate_signing_returns_one_durable_artifact
enterprise_anchor_insert_failure_rolls_back_the_artifact_signature
enterprise_router_rejects_legacy_artifact_without_trusted_time
enterprise_router_rejects_unguarded_activation_and_standard_runtime
enterprise_router_returns_one_identity_epoch_signature_and_anchor_result
enterprise_time_anchor_keeps_pre_rotation_artifact_verifiable_after_reopen
failed_durable_anchor_never_returns_signature_evidence
remote_verifier_accepts_pre_activation_anchor_and_rejects_post_activation_or_invented_context
router_persists_epoch_evidence_cuts_over_atomically_and_reopens_exact_selector
EOF
)" cargo test -p chio-keyring --test router

run_tests "trusted artifact-time anchors" no "$(cat <<'EOF'
artifact_time_root_cannot_overlap_any_independent_role
configured_trusted_anchor_authenticates_hash_anchor_and_time
untrusted_tampered_and_future_anchor_statements_fail_closed
EOF
)" cargo test -p chio-keyring --test time

run_tests "contiguous synchronization and split views" no "$(cat <<'EOF'
authenticated_unseen_gossip_is_durable_for_witness_and_verifier
contiguous_sync_activation_fresh_verifier_and_monitor_preserve_pins
durable_witness_prevents_restart_double_sign_and_records_gossip_conflict
omitted_envelope_and_stale_consistency_proof_do_not_advance_witness_pin
synchronization_deserialization_rejects_oversized_vectors_before_growth
synchronization_deserialization_rejects_present_but_empty_activation_commits
synchronization_item_limit_cannot_emit_a_decoder_oversized_page
witness_and_audit_storage_identities_survive_database_path_swap
witness_and_verifier_open_require_preprovisioned_durable_files
witness_rejects_checkpoint_beyond_configured_future_skew
witness_restart_accepts_a_signed_multi_checkpoint_range
EOF
)" cargo test -p chio-keyring --test witness_sync

run_tests "complete witnessed history" no "$(cat <<'EOF'
activation_commit_signature_epoch_and_time_are_verified
history_rejects_omission_fork_chain_break_and_insufficient_witnesses
verified_history_accepts_complete_checkpoint_prefix_and_activation_quorum
EOF
)" cargo test -p chio-keyring --test history

run_tests "keyring service policy and seed custody" no "$(cat <<'EOF'
bounded_json_line_rejects_requests_over_one_megabyte
policy_file_loader_is_strict_and_binds_all_configured_roots
witness_seed_loader_rejects_links_and_permissive_modes
EOF
)" cargo test -p chio-keyring --test service

run_tests "atomic exhaustive enterprise receipts" no "$(cat <<'EOF'
enterprise_receipt_is_canonical_secret_free_and_rejects_every_leaf_tamper
production_store_emits_pending_and_active_enterprise_receipts_atomically
EOF
)" cargo test -p chio-keyring --test enterprise_receipt

run_tests "independent witness and audit services" no "$(cat <<'EOF'
canonical_framing_rejects_noncanonical_oversized_and_truncated_messages
three_witness_processes_prove_distinct_durable_identity_and_restart_recovery
two_autonomous_auditors_rebuild_and_retain_the_same_witnessed_view
EOF
)" cargo test -p chio-keyring --test independent_services

echo "Keyring transparency gate passed"
