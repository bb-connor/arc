#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

./scripts/check-enterprise-cross-mechanism.sh

./scripts/run-exact-cargo-test-inventory.sh \
  --label "enterprise migration state" \
  --expected \
    duplicate_generation_is_classified_without_replace \
    independently_anchored_head_rejects_valid_restored_prefix \
    legacy_mutable_row_authority_is_rejected \
    load_rejects_raw_append_with_invalid_signature \
    raw_sql_cannot_skip_update_or_delete \
    runtime_binding_rejects_downgrade_advance_and_posture_rebinding \
    schema_trigger_removal_is_detected_before_load \
    signed_hash_linked_chain_survives_reopen \
    symlink_hardlink_and_live_path_replacement_are_rejected \
    two_connections_race_one_promotion_and_one_conflict \
    valid_signature_from_untrusted_signer_is_rejected \
    volatile_and_relative_paths_are_rejected \
  -- cargo test -p chio-store-sqlite --test enterprise_migration_state

./scripts/run-exact-cargo-test-inventory.sh \
  --label "threat-model schema" \
  --expected \
    schema_accepts_covered_by_tests_alias \
    schema_accepts_pending_with_deferred_to \
    schema_accepts_weak_coverage_state \
    schema_rejects_invalid_boundary_surface \
    schema_rejects_invalid_coverage_state \
    schema_rejects_threat_missing_required_field \
    schema_validates_threat_model_v1 \
  -- cargo test -p chio-spec-codegen --test threat_model_schema_test

./scripts/run-exact-cargo-test-inventory.sh \
  --label "Rust generated security vectors" \
  --expected \
    authoritative_schema_rejects_both_approval_forms_vector \
    generated_active_defense_integer_wrappers_fail_closed \
    generated_active_defense_types_decode_reencode_and_reject \
    generated_detector_health_type_rejects_invalid_serialization \
    generated_detector_health_type_rejects_mutation_corpus \
    generated_protocol_types_preserve_approval_and_aggregate_budget_fields \
    generated_receipt_types_cover_semantic_mutation_corpus \
    legacy_response_transition_canonical_digest_is_unchanged \
    native_receipt_types_reject_unsafe_json_integers \
    protocol_schema_and_generated_types_cover_exact_negative_corpus \
  -- cargo test -p chio-core-types --test security_generated_vectors

./scripts/run-exact-cargo-test-inventory.sh \
  --label "threat-model conformance" \
  --expected \
    agent_velocity_abuse::threat_agent_velocity_abuse_is_covered \
    audience_confusion::threat_audience_confusion_carries_expected_and_found_audiences \
    audience_confusion::threat_audience_confusion_require_audience_rejects_mismatch \
    behavioral_sequence_attack::threat_behavioral_sequence_attack_is_covered \
    capability_token_theft::threat_capability_token_theft_legitimate_token_round_trips \
    capability_token_theft::threat_capability_token_theft_partial_signature_retargeted_issuer_rejected \
    capability_token_theft::threat_capability_token_theft_replayed_after_expiry_rejected \
    capability_token_theft::threat_capability_token_theft_scope_superset_after_sign_rejected \
    cumulative_data_exfiltration::threat_cumulative_data_exfiltration_is_covered \
    delegation_chain_abuse::threat_delegation_chain_abuse_expired_capability_rejected \
    delegation_chain_abuse::threat_delegation_chain_abuse_legitimate_root_capability_round_trips \
    delegation_chain_abuse::threat_delegation_chain_abuse_tampered_signature_rejected \
    delegation_chain_abuse::threat_delegation_chain_abuse_unknown_parent_in_registry_rejected \
    delegation_chain_abuse::threat_delegation_chain_abuse_untrusted_issuer_rejected \
    device_key_extraction::device_key_extraction_is_rejected_by_key_and_device_binding \
    kernel_impersonation::threat_kernel_impersonation_genuine_receipt_round_trips \
    kernel_impersonation::threat_kernel_impersonation_signing_with_mismatched_key_rejected \
    kernel_impersonation::threat_kernel_impersonation_tampered_kernel_key_field_fails_verification \
    mobile_attestation_replay::mobile_attestation_replay_is_rejected_by_bound_challenges \
    native_channel_replay::threat_native_channel_replay_binding_mismatch_rejected \
    native_channel_replay::threat_native_channel_replay_replayed_nonce_rejected \
    native_channel_replay::threat_native_channel_replay_tampered_signature_rejected \
    passkey_credential_theft::threat_passkey_credential_theft_distinct_credentials_are_independent \
    passkey_credential_theft::threat_passkey_credential_theft_replay_attack_rejected \
    passkey_credential_theft::threat_passkey_credential_theft_supplementary_evidence_remains_in_tree \
    pii_phi_exposure::threat_pii_phi_exposure_is_covered \
    play_integrity_token_replay::play_integrity_token_replay_fails_nonce_expiry_and_audience_gates \
    pq_signature_downgrade::threat_pq_signature_downgrade_classical_token_under_allow_classical_round_trips \
    pq_signature_downgrade::threat_pq_signature_downgrade_classical_token_under_pq_required_rejected \
    pq_signature_downgrade::threat_pq_signature_downgrade_floor_wire_identifiers_pinned \
    resource_exhaustion_dos::threat_resource_exhaustion_dos_class_set_is_pinned \
    resource_exhaustion_dos::threat_resource_exhaustion_dos_escape_class_fixtures_remain_in_tree \
    resource_exhaustion_dos::threat_resource_exhaustion_dos_infinite_loop_attack_traps_under_fuel_cap \
    resource_exhaustion_dos::threat_resource_exhaustion_dos_zero_fuel_ceiling_traps_immediately \
    ssrf_via_http_substrate::threat_ssrf_via_http_substrate_is_covered \
    tee_quote_forgery::threat_tee_quote_forgery_cross_tee_misbinding_rejected \
    tee_quote_forgery::threat_tee_quote_forgery_forged_signature_rejected \
    tee_quote_forgery::threat_tee_quote_forgery_genuine_frame_round_trips \
    tee_quote_forgery::threat_tee_quote_forgery_tampered_body_rejected \
    tee_quote_forgery::threat_tee_quote_forgery_validator_evidence_files_remain_in_tree \
    tee_quote_forgery::threat_tee_quote_forgery_wrong_tenant_key_rejected \
    tool_server_escape::threat_tool_server_escape_benign_module_round_trips \
    tool_server_escape::threat_tool_server_escape_fuel_exhaustion_attack_traps \
    tool_server_escape::threat_tool_server_escape_undeclared_host_import_rejected_at_load \
    wasm_guard_resource_exhaustion::threat_wasm_guard_resource_exhaustion_benign_module_round_trips \
    wasm_guard_resource_exhaustion::threat_wasm_guard_resource_exhaustion_escape_harness_pins_remain \
    wasm_guard_resource_exhaustion::threat_wasm_guard_resource_exhaustion_fuel_overrun_traps \
    wasm_guard_resource_exhaustion::threat_wasm_guard_resource_exhaustion_oversize_module_rejected_at_load \
    weights_hash_spoof::threat_weights_hash_spoof_is_covered \
  -- cargo test -p chio-conformance --test threats

go_security_vector_tests=(
  TestBothApprovalFormsVectorTracksAuthoritativeExclusion
  TestDetectorHealthGeneratedEmittersRejectInvalidState
  TestDetectorHealthGeneratedTypeRejectsMutationCorpus
  TestDetectorHealthTaggedKnowledgeRejectsInvalidVariants
  TestGeneratedActiveDefenseTypesDecodeReencodeAndReject
  TestGeneratedProtocolTypesPreserveApprovalAndAggregateBudgetFields
  TestGeneratedReceiptEmittersRejectUnsafePortableIntegers
  TestGeneratedReceiptTypesCoverSemanticMutationCorpus
  TestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus
)
go_security_vector_pattern="$(
  IFS='|'
  printf '^(%s)$' "${go_security_vector_tests[*]}"
)"
expected_go_security_vectors="$(
  printf '%s\n' "${go_security_vector_tests[@]}" | LC_ALL=C sort
)"
actual_go_security_vectors="$(
  cd sdks/go/chio-go-http
  go test ./... -list "${go_security_vector_pattern}" |
    awk '/^Test/ { print $1 }' |
    LC_ALL=C sort
)"
test -n "${actual_go_security_vectors}"
test "${actual_go_security_vectors}" = "${expected_go_security_vectors}"
(
  cd sdks/go/chio-go-http
  go test ./... -run "${go_security_vector_pattern}" -count=1
)

echo "Enterprise exact test inventories passed (88 tests across 6 targets)"
