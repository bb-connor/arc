#!/usr/bin/env bash
set -euo pipefail

if [[ "${CHIO_ENTERPRISE_SECURITY_RUNNER:-0}" == "1" ]]; then
  workspace="${CHIO_SECURITY_WORKSPACE:-}"
  inventory_checker="${CHIO_SECURITY_EXACT_INVENTORY_CHECKER:-}"
  if [[ "$workspace" != "/private/candidate" ]] ||
    [[ "$inventory_checker" != "/opt/chio-security/gates/check-exact-cargo-test-inventory.py" ]]; then
    echo "designated broker gate paths do not match the trusted contract" >&2
    exit 1
  fi
  if [[ ! -f "$inventory_checker" ]] || [[ -L "$inventory_checker" ]]; then
    echo "designated broker inventory checker is missing or symbolic" >&2
    exit 1
  fi
else
  if [[ -n "${CHIO_SECURITY_WORKSPACE:-}" ]] ||
    [[ -n "${CHIO_SECURITY_EXACT_INVENTORY_CHECKER:-}" ]]; then
    echo "trusted broker gate paths leaked into a portable invocation" >&2
    exit 1
  fi
  workspace="$(cd "$(dirname "$0")/.." && pwd)"
  inventory_checker="$workspace/scripts/check-exact-cargo-test-inventory.py"
fi
cd "$workspace"

mode="${1:---release}"
if [[ "$#" -gt 1 ]] || [[ "${mode}" != "--release" && "${mode}" != "--portable" ]]; then
  echo "usage: $0 [--release|--portable]" >&2
  exit 64
fi

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
  list_output="$(mktemp "${TMPDIR:-/tmp}/chio-broker-list.XXXXXX")"
  run_output="$(mktemp "${TMPDIR:-/tmp}/chio-broker-run.XXXXXX")"
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

run_doctest() {
  local output status
  output="$(mktemp "${TMPDIR:-/tmp}/chio-broker-doc.XXXXXX")"
  set +e
  cargo test -p chio-secret-broker --doc 2>&1 | tee "${output}"
  status=${PIPESTATUS[0]}
  set -e
  if [[ "${status}" -ne 0 ]]; then
    rm -f "${output}"
    return "${status}"
  fi
  if ! grep -Eq \
    '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in [0-9]+(\.[0-9]+)?s$' \
    "${output}"; then
    echo "production transport API doctest inventory is not exactly one passing test" >&2
    rm -f "${output}"
    return 1
  fi
  rm -f "${output}"
}

run_tests "broker capability and proof binding" no "$(cat <<'EOF'
canonical_wire_round_trip_and_unknown_field_rejection
capability_and_proof_reject_single_field_tampering
capability_signature_rejects_each_bound_field_tamper
destination_rejects_userinfo_before_valid_normalization
duplicate_reordered_and_unknown_option_inputs_fail_closed
proof_rejects_body_path_header_option_key_stale_and_future_changes
EOF
)" cargo test -p chio-secret-broker --test execution

run_doctest

run_tests "broker execution concurrency and recovery" no \
  "deterministic_attempt_conflict_precedes_exact_retry_and_concurrent_replay" \
  cargo test -p chio-secret-broker --test concurrency

if [[ "$(uname -s)" == "Linux" ]]; then
  run_tests "broker isolation secret boundary" no "$(cat <<'EOF'
brokerd_process_governed_provisioning_keeps_seeded_secret_inside_broker
public_response_and_daemon_diagnostics_do_not_contain_seeded_credential
EOF
)" cargo test -p chio-secret-broker --test no_secret_crossing
else
  run_tests "portable broker isolation secret boundary" no \
    "public_response_and_daemon_diagnostics_do_not_contain_seeded_credential" \
    cargo test -p chio-secret-broker --test no_secret_crossing
fi

run_tests "broker network adversarial cases" no "$(cat <<'EOF'
globally_routable_fixture_is_not_classified_as_restricted
restricted_ipv4_ipv6_decimal_equivalents_and_mapped_forms_are_denied
EOF
)" cargo test -p chio-secret-broker --test network_adversarial

run_tests "governed provisioning and durable receipts" no "$(cat <<'EOF'
durable_completed_response_replays_exact_bytes_after_restart
durable_failure_receipt_binds_truthful_dispatch_state_and_survives_restart
durable_receipt_sink_is_append_only_idempotent_and_restart_safe
enterprise_receipt_binds_every_execution_field_and_excludes_seeded_secret
governed_admin_authorization_is_threshold_bound_and_durably_single_use
governed_admin_control_replays_the_exact_signed_response_after_restart
governed_admin_journal_rejects_self_signed_completion_substitution
governed_admin_operation_recovers_after_expiry_and_persists_signed_completion
governed_admin_replay_detects_hardlinks_and_path_rebinding
governed_admin_replay_rejects_volatile_and_relative_database_names
receipt_store_rejects_success_failure_terminal_conflicts_in_both_orders
EOF
)" cargo test -p chio-secret-broker --test production_surfaces

daemon_runtime_inventory="$(cat <<'EOF'
daemon_config_file_owner_is_bound_to_the_effective_service_uid
daemon_governed_intent_changes_with_operation_tenant_and_payload
daemon_runtime_config_is_closed_and_rejects_partial_authority_or_storage
daemon_runtime_config_rejects_a_self_declared_service_uid
EOF
)"
if [[ "$(uname -s)" == "Linux" ]]; then
  daemon_runtime_inventory="${daemon_runtime_inventory}
startup::broker_first_startup_stays_unpublished_until_authority_is_ready_then_retries
startup::broker_startup_rejects_missing_or_wrong_migration_head_before_socket_publication
"
fi
run_tests "broker daemon authority and fake upstream" no \
  "${daemon_runtime_inventory}" \
  cargo test -p chio-secret-broker --test daemon_runtime

run_tests "daemon payload and sink governance" yes \
  "daemon::tests::daemon_governance_binds_payload_and_fake_upstream_is_the_only_secret_sink" \
  cargo test -p chio-secret-broker --lib \
  daemon::tests::daemon_governance_binds_payload_and_fake_upstream_is_the_only_secret_sink

run_tests "authority IPC signed response binding" yes \
  "authority_ipc::tests::authority_rpc_requires_signed_exact_responses_and_full_capabilities" \
  cargo test -p chio-secret-broker --lib \
  authority_ipc::tests::authority_rpc_requires_signed_exact_responses_and_full_capabilities

run_tests "supplemental verifier and combined capture" yes "$(cat <<'EOF'
security::broker::tests::broker_send_requires_durable_dispatch_commit_and_survives_authority_restart
security::broker::tests::compensated_release_outbox_survives_both_release_crash_windows
security::broker::tests::outcome_unknown_retains_registry_and_capture_query_after_restart
security::broker::tests::production_admission_composition_routes_kernel_revocation_through_combined_authority
security::broker::tests::runtime_construction_has_no_partial_or_mismatched_mode
security::broker::tests::startup_rejects_orphaned_pending_admission_after_partial_restore
security::broker::tests::supplemental_verifier_rejects_noncanonical_and_context_swapped_artifacts
EOF
)" cargo test -p chio-control-plane --lib security::broker::tests

if [[ "$(uname -s)" == "Linux" ]]; then
  run_tests "sealed inherited FD master-key custody" no \
    "secure_inherited_key_file_owns_the_original_descriptor_and_closes_it_on_drop" \
    cargo test -p chio-secret-broker --test inherited_fd_custody
elif [[ "${mode}" == "--release" ]]; then
  echo "release broker evidence requires the Linux inherited-FD custody test" >&2
  exit 1
else
  echo "Broker portable gate passed; no Linux inherited-FD custody evidence was produced"
  exit 0
fi

echo "Secret broker boundary gate passed"
