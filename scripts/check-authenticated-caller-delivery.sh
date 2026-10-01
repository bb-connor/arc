#!/usr/bin/env bash
# M3 acceptance requires the complete authenticated caller and native custody
# inventories, including real process loss. Missing, filtered or ignored cases
# cannot silently satisfy the named milestone gate.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 022
ulimit -c 0
export RUST_TEST_THREADS=1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

./scripts/run-exact-cargo-test-inventory.sh --label "authenticated caller lifecycle" --expected \
  a_nonce_of_an_unreserved_operation_cannot_reconcile \
  a_report_for_other_arguments_is_refused_and_keeps_the_reservation \
  a_second_reservation_is_bounded_by_the_shared_budget \
  an_expired_caller_reservation_is_compensated_by_startup_recovery \
  authenticated::authenticated_report_finalizes_after_expiry_and_restart_without_readmission \
  authenticated::monetary::monetary_exposure_survives_lost_report_and_settles_original_authenticated_cost \
  authenticated::negative_controls::authenticated_executor_pin_does_not_bypass_native_release_custody \
  authenticated::negative_controls::changed_executor_pin_cannot_adopt_original_start_or_report \
  authenticated::negative_controls::revocation_blocks_historical_output_and_completed_receipt_replay \
  authenticated::negative_controls::unused_expired_reservation_cannot_publish_start_authority \
  authenticated::private_evidence::private_delivery_evidence_rejects_tampering_and_schema_confusion \
  authenticated::process_loss::process_loss_retains_capture_and_never_reexecutes_original_attempt \
  authenticated::start_captures_before_publication_and_retries_original_authorization \
  caller_reservation_holds_the_budget_until_the_report_settles \
  delegated_share::an_expired_caller_share_stays_owned_until_recovery_compensates_it \
  delegated_share::authenticated::lost_authenticated_report_retains_sibling_share_until_original_settlement \
  delegated_share::boundaries::a_caller_share_also_blocks_ordinary_kernel_dispatch_until_settlement \
  delegated_share::boundaries::an_out_of_band_terminal_edit_cannot_hide_a_live_caller_share \
  delegated_share::boundaries::concurrent_siblings_cannot_oversubscribe_and_denied_claims_do_not_leak \
  delegated_share::caller_share_snapshot_is_complete_scoped_and_fenced \
  delegated_share::outcome_unknown::an_unknown_caller_outcome_retains_its_share_and_capture_after_restart_and_expiry \
  delegated_share::pending::a_later_funded_sibling_cannot_displace_an_existing_caller_owner \
  delegated_share::pending::an_interrupted_funded_caller_is_compensated_without_displacing_a_reserved_owner \
  delegated_share::restart_preserves_the_delegated_share_of_a_live_caller_reservation \
  delegated_share::settling_a_durable_caller_reservation_releases_its_delegated_share \
  delegated_share::two_caller_operations_share_one_child_edge_until_both_settle \
  dispatch_context::caller_context_capture_rejects_out_of_band_schema_changes \
  dispatch_context::caller_context_survives_interruption_after_capture_before_report_recording \
  dispatch_context::caller_report_retains_typed_private_context_with_capture_and_exact_restart_replay \
  external_delivery::an_external_effect_with_a_lost_report_cannot_be_refunded_at_nonce_expiry \
  external_delivery::reservation_only_effect_reproduces_the_original_refund_counterexample \
  kernel_dispatch_cannot_resume_a_caller_reservation \
  restart_keeps_a_live_caller_reservation \
  -- cargo test -p chio-store-sqlite --test execution_nonce_caller_execution --locked

./scripts/run-exact-cargo-test-inventory.sh --label "durable authenticated executor" --expected \
  another_attempt_or_kernel_signing_key_cannot_create_a_second_execution \
  claimed_attempt_survives_process_death_without_redispatch \
  completed_delivery_replays_the_exact_report_after_reopen_without_another_effect \
  expired_or_untrusted_authorization_never_claims_or_invokes \
  expired_permission_can_replay_a_retained_report_but_cannot_execute \
  failed_or_panicking_effect_retains_an_unknown_attempt_across_restart \
  full_ledger_and_changed_schema_do_not_reset_retained_claims \
  independent_connections_race_one_operation_without_holding_sqlite_across_effect \
  substituted_key_epoch_or_physical_ledger_fails_closed \
  -- cargo test -p chio-store-sqlite --test caller_execution_ledger --locked

./scripts/run-exact-cargo-test-inventory.sh --label "native authenticated caller custody" --allow-filtered --expected \
  security::adapters::tests::native_flow::support::caller::denial::native_caller_changed_input_cannot_replace_original_reserved_join \
  security::adapters::tests::native_flow::support::caller::denial::native_caller_output_refusal_revocation_and_stop_never_release_raw_delivery \
  security::adapters::tests::native_flow::support::caller::denial::native_caller_preflight_requires_fresh_host_flow_state_before_reservation \
  security::adapters::tests::native_flow::support::caller::native_caller_composes_local_egress_declassification_and_complete_credentials \
  security::adapters::tests::native_flow::support::caller::native_caller_releases_only_the_authenticated_original_guarded_output \
  security::adapters::tests::native_flow::support::caller::restart::native_caller_original_delivery_survives_restart_and_authority_expiry \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_atomic_capture \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_claim_before_effect \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_durable_report \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_effect_without_report \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_output_join \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_raw_report \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_release_acknowledgement \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_release_checkpoint \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_after_terminal_projection \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_abort_before_atomic_capture \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_combined_disclosure_abort_after_release \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_combined_disclosure_abort_after_report \
  security::adapters::tests::native_flow::support::process_recovery::caller::native_caller_output_recovery_rejects_changed_classification \
  -- cargo test -p chio-control-plane --lib --locked native_caller
