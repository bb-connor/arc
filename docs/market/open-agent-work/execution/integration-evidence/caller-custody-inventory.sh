#!/usr/bin/env bash
set -euo pipefail
cd /home/connor/backbay/arc-funded-integration
umask 022
ulimit -c 0
export CARGO_BUILD_JOBS=3 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1
./scripts/run-exact-cargo-test-inventory.sh --label "frozen dispatch participant context" --allow-filtered --expected \
  kernel::admission_coordinator::return_context::caller::tests::selected_custody::caller_snapshot_allows_configured_but_unused_approval_authority \
  kernel::admission_coordinator::return_context::caller::tests::selected_custody::caller_snapshot_allows_configured_but_unused_dpop_authority \
  kernel::admission_coordinator::return_context::caller::tests::selected_custody::caller_snapshot_preserves_genuinely_unselected_and_legacy_custody_absence \
  kernel::admission_coordinator::return_context::caller::tests::selected_custody::caller_snapshot_rejects_missing_required_dpop_custody \
  kernel::admission_coordinator::return_context::caller::tests::selected_custody::caller_snapshot_rejects_missing_selected_runtime_custody \
  kernel::admission_coordinator::return_context::caller::tests::caller_observation_metadata_cannot_be_injected_before_dispatch \
  kernel::admission_coordinator::return_context::caller::tests::custody::caller_return_custody_requires_explicit_absence_and_rejects_unowned_claims \
  kernel::admission_coordinator::return_context::caller::tests::custody::caller_return_v3_remains_readable_but_cannot_acquire_custody_on_reissue \
  kernel::admission_coordinator::return_context::caller::tests::caller_return_codec_keeps_frozen_facts_without_credentials_or_return_observations \
  kernel::admission_coordinator::return_context::caller::tests::caller_return_codec_keeps_legacy_identity_absence_explicit \
  kernel::admission_coordinator::return_context::caller::tests::caller_return_codec_rejects_individually_valid_but_unadmitted_security_context \
  kernel::admission_coordinator::return_context::caller::tests::caller_return_codec_rejects_noncanonical_oversized_and_unbound_frames \
  kernel::admission_coordinator::return_context::caller::tests::caller_return_codec_rejects_private_payload_schema_identity_grant_and_limit_substitution \
  kernel::admission_coordinator::return_context::caller::tests::participants::frozen_participants_preserve_legacy_absence_without_upgrading_custody \
  kernel::admission_coordinator::return_context::caller::tests::participants::frozen_participants_reject_changed_operation_references_in_caller_decode \
  kernel::admission_coordinator::return_context::caller::tests::participants::frozen_participants_reject_changed_operation_references_in_live_context \
  kernel::admission_coordinator::return_context::caller::tests::participants::frozen_participants_require_every_reference_and_reject_substitution \
  kernel::tests::return_context::capture_callback_panics_retain_uncertainty_without_poisoning_recovery \
  kernel::tests::return_context::changed_capture_participant_denies_before_tool_effect_and_retains_accounting \
  kernel::tests::return_context::frozen_return_context_cannot_cross_operations_with_the_same_request_id \
  kernel::tests::return_context::frozen_return_context_keeps_limits_and_metadata_when_kernel_configuration_changes \
  kernel::tests::return_context::frozen_return_context_rejects_substituted_return_request_before_persistence \
  kernel::tests::return_context::invalid_return_context_cannot_commit_dispatch_or_capture_budget \
  kernel::tests::return_context::nested_return_context_preserves_large_request_behavior \
  kernel::tests::return_context::ordinary_return_context_preserves_large_request_behavior \
  kernel::tests::return_context::return_context_rejects_request_or_grant_substitution_before_commit \
  kernel::tests::return_context::signing::callbacks::signer_callback_cannot_extend_the_original_finalization_lease \
  kernel::tests::return_context::signing::callbacks::signer_can_reenter_without_holding_the_mutation_sequencer \
  kernel::tests::return_context::signing::callbacks::signer_identity_substitution_cannot_publish_a_terminal \
  kernel::tests::return_context::signing::callbacks::signer_panic_preserves_finalizing_without_poisoning_the_sequencer \
  kernel::tests::return_context::signing::completed_replay_does_not_weaken_the_current_crypto_floor \
  kernel::tests::return_context::signing::completed_replay_uses_original_signer_without_reinvocation \
  kernel::tests::return_context::signing::nested_completed_replay_uses_original_signer_without_reinvocation \
  kernel::tests::return_context::signing::raw_signing_identity_codec_rejects_omission_downgrade_and_invalid_floor \
  kernel::tests::return_context::signing::unfinished_return_cannot_be_signed_by_a_replacement_authority \
  -- cargo test -p chio-kernel --lib return_context::
