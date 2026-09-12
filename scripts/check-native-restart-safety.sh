#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 022
ulimit -c 0
export RUST_TEST_THREADS=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

./scripts/run-exact-cargo-test-inventory.sh --label "native process failure and restart" --allow-filtered --expected \
  security::adapters::tests::native_flow::support::process_recovery::baseline_before_participants \
  security::adapters::tests::native_flow::support::process_recovery::baseline_capture_before_connector \
  security::adapters::tests::native_flow::support::process_recovery::baseline_capture_transaction_rollback \
  security::adapters::tests::native_flow::support::process_recovery::baseline_database_commit_before_anchor \
  security::adapters::tests::native_flow::support::process_recovery::baseline_effect_started \
  security::adapters::tests::native_flow::support::process_recovery::baseline_evaluation_started \
  security::adapters::tests::native_flow::support::process_recovery::baseline_output_resolved \
  security::adapters::tests::native_flow::support::process_recovery::baseline_release_acknowledged \
  security::adapters::tests::native_flow::support::process_recovery::baseline_release_checkpointed \
  security::adapters::tests::native_flow::support::process_recovery::baseline_return_persisted \
  security::adapters::tests::native_flow::support::process_recovery::baseline_reversible_reservation \
  security::adapters::tests::native_flow::support::process_recovery::baseline_terminal_projected \
  security::adapters::tests::native_flow::support::process_recovery::combined_capture_transaction_rollback \
  security::adapters::tests::native_flow::support::process_recovery::combined_database_commit_before_anchor \
  security::adapters::tests::native_flow::support::process_recovery::combined_effect_started \
  security::adapters::tests::native_flow::support::process_recovery::combined_release_checkpointed \
  security::adapters::tests::native_flow::support::process_recovery::combined_reversible_reservation \
  security::adapters::tests::native_flow::support::process_recovery::competing_native_recovery_workers_converge_on_original_terminalization \
  security::adapters::tests::native_flow::support::process_recovery::cumulative_capture_transaction_rollback \
  security::adapters::tests::native_flow::support::process_recovery::cumulative_database_commit_before_anchor \
  security::adapters::tests::native_flow::support::process_recovery::cumulative_release_checkpointed \
  security::adapters::tests::native_flow::support::process_recovery::declassification_capture_transaction_rollback \
  security::adapters::tests::native_flow::support::process_recovery::declassification_database_commit_before_anchor \
  security::adapters::tests::native_flow::support::process_recovery::declassification_effect_started \
  security::adapters::tests::native_flow::support::process_recovery::declassification_output_joined \
  security::adapters::tests::native_flow::support::process_recovery::declassification_release_checkpointed \
  security::adapters::tests::native_flow::support::process_recovery::late_caller_report_cannot_replace_native_unknown_outcome \
  security::adapters::tests::native_flow::support::process_recovery::nonce_capture_transaction_rollback \
  security::adapters::tests::native_flow::support::process_recovery::nonce_database_commit_before_anchor \
  security::adapters::tests::native_flow::support::process_recovery::nonce_effect_started \
  security::adapters::tests::native_flow::support::process_recovery::nonce_release_checkpointed \
  security::adapters::tests::native_flow::support::process_recovery::races::duplicate_native_start_cannot_steal_the_live_operation \
  security::adapters::tests::native_flow::support::process_recovery::races::revocation_after_native_capture_fences_connector_handoff \
  security::adapters::tests::native_flow::support::process_recovery::races::revocation_wins_before_native_capture \
  -- cargo test -p chio-control-plane --lib --locked security::adapters::tests::native_flow::support::process_recovery::

./scripts/run-exact-cargo-test-inventory.sh --label "live admission ownership" --allow-filtered --expected \
  admission_operation::sequencer::tests::identical_fences_exclude_duplicate_live_operations_until_drop \
  admission_operation::sequencer::tests::identical_store_fences_share_one_mutation_sequence \
  admission_operation::sequencer::tests::poisoned_live_registry_denies_acquisition_and_drop_does_not_panic \
  admission_operation::sequencer::tests::unrelated_live_operations_do_not_hold_the_mutation_lock \
  admission_operation::sequencer::tests::unwinding_releases_live_ownership_without_poisoning_the_registry \
  -- cargo test -p chio-kernel --lib --locked admission_operation::sequencer::tests::
