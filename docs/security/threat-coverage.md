# Chio Threat Coverage

**Status: INCOMPLETE.** 0/20 threat-model rows are fully covered (`Covered`); 0/20 are partially covered (`Partial`); 20/20 are pending (`Pending`). Full threat closure requires no `Partial`, `Pending`, or `Weak Coverage` rows.

Generated from `spec/security/chio-threat-model.v1.json` and the `crates/core/chio-adversarial-suite/cases/` corpus.

Two fail-closed scripts enforce this state: `scripts/check-threat-coverage.sh` validates coverage-state, partial-row, and test-body shape, while `scripts/check-threat-coverage-mutants.sh` validates per-row mutation evidence. The current threat model renders 0 covered / 0 partial / 20 pending / 0 weak coverage rows. Pending rows have no mutation evidence file; `deferred_to` states the source-bound cargo-mutants condition required for promotion.

In-tree conformance tests and adversarial corpus cases are not mutation evidence. `Covered` and `Partial` require promoted, source-bound, caught-only cargo-mutants outcomes.

Coverage states:
- `Covered` - the threat ID has a populated test body at `crates/tooling/chio-conformance/tests/threats/<id>.rs` AND a mutation-testing evidence file at `audits/evidence/threats/<id>.json` recording at least one caught mutant.
- `Partial` - a backing test exists and the defended sub-vector has source-bound evidence with `caught >= 1` and zero survivors, but the row defends only part of the attack surface.
- `Pending` - the row has no release mutation evidence. The gate accepts it only when `deferred_to` states a technical closure condition.
- `Weak Coverage` - a backing test file exists but mutation-testing evidence is missing, invalid, or shows zero kills. This state fails the threat-model coverage gate.

# Pending (20)

## Threat: capability_token_theft

- **Name:** Capability token theft
- **State:** Pending
- **Surfaces:** trust_control, hosted_mcp, native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/capability_token_theft.rs`
- **Corpus cases:**
  - `broker-revocation-race-001` (class `broker_revocation_race`, reason `broker_revocation_race_detected`, path `cases/broker_revocation_race/broker-revocation-race-001.json`)
  - `clock-rewound-001` (class `clock_rewound`, reason `clock_rewound_capability_window`, path `cases/clock_rewound/clock-rewound-001.json`)
  - `clock-rewound-002` (class `clock_rewound`, reason `clock_rewound_capability_window`, path `cases/clock_rewound/clock-rewound-002.json`)
  - `clock-rewound-005` (class `clock_rewound`, reason `clock_rewound_grant_activation`, path `cases/clock_rewound/clock-rewound-005.json`)
  - `future-dated-002` (class `future_dated`, reason `future_dated_capability_issued_at`, path `cases/future_dated/future-dated-002.json`)
  - `partial-signature-005` (class `partial_signature`, reason `partial_signature_missing_expiry_claim`, path `cases/partial_signature/partial-signature-005.json`)
  - `scope-superset-003` (class `scope_superset`, reason `scope_superset_resource`, path `cases/scope_superset/scope-superset-003.json`)
  - `scope-superset-005` (class `scope_superset`, reason `scope_superset_admin`, path `cases/scope_superset/scope-superset-005.json`)

## Threat: kernel_impersonation

- **Name:** Kernel impersonation
- **State:** Pending
- **Surfaces:** hosted_mcp, native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/kernel_impersonation.rs`
- **Corpus cases:**
  - `anchor-grafted-002` (class `anchor_grafted`, reason `anchor_grafted_checkpoint_signature`, path `cases/anchor_grafted/anchor-grafted-002.json`)
  - `anchor-grafted-005` (class `anchor_grafted`, reason `anchor_grafted_tenant_boundary`, path `cases/anchor_grafted/anchor-grafted-005.json`)
  - `clock-rewound-004` (class `clock_rewound`, reason `clock_rewound_authority_epoch`, path `cases/clock_rewound/clock-rewound-004.json`)
  - `future-dated-005` (class `future_dated`, reason `future_dated_authority_signature`, path `cases/future_dated/future-dated-005.json`)
  - `key-log-inconsistent-growth-001` (class `key_log_inconsistent_growth`, reason `key_log_inconsistent_growth_detected`, path `cases/key_log_inconsistent_growth/key-log-inconsistent-growth-001.json`)
  - `key-log-omission-001` (class `key_log_omission`, reason `key_log_omission_detected`, path `cases/key_log_omission/key-log-omission-001.json`)
  - `key-log-split-view-001` (class `key_log_split_view`, reason `key_log_split_view_detected`, path `cases/key_log_split_view/key-log-split-view-001.json`)
  - `old-key-backdating-001` (class `old_key_backdating`, reason `old_key_backdating_detected`, path `cases/old_key_backdating/old-key-backdating-001.json`)
  - `partial-signature-001` (class `partial_signature`, reason `partial_signature_envelope`, path `cases/partial_signature/partial-signature-001.json`)
  - `partial-signature-002` (class `partial_signature`, reason `partial_signature_missing_scope_claim`, path `cases/partial_signature/partial-signature-002.json`)
  - `rotation-partial-commit-001` (class `rotation_partial_commit`, reason `rotation_partial_commit_detected`, path `cases/rotation_partial_commit/rotation-partial-commit-001.json`)
  - `rotation-unwitnessed-signing-001` (class `rotation_unwitnessed_signing`, reason `rotation_unwitnessed_signing_detected`, path `cases/rotation_unwitnessed_signing/rotation-unwitnessed-signing-001.json`)
  - `sandbox-helper-substitution-001` (class `sandbox_helper_substitution`, reason `sandbox_helper_substitution_detected`, path `cases/sandbox_helper_substitution/sandbox-helper-substitution-001.json`)
  - `sigstore-bundle-payload-mismatch-001` (class `sigstore_bundle_payload_mismatch`, reason `sigstore_bundle_payload_mismatch`, path `cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-001.json`)
  - `sigstore-bundle-payload-mismatch-002` (class `sigstore_bundle_payload_mismatch`, reason `sigstore_bundle_payload_mismatch`, path `cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-002.json`)
  - `sigstore-bundle-payload-mismatch-003` (class `sigstore_bundle_payload_mismatch`, reason `sigstore_bundle_payload_mismatch`, path `cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-003.json`)
  - `sigstore-bundle-payload-mismatch-005` (class `sigstore_bundle_payload_mismatch`, reason `sigstore_bundle_payload_mismatch`, path `cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-005.json`)
  - `threshold-proposal-mutations-001` (class `authority_binding_mutation`, reason `threshold_proposal_binding_mutated`, path `cases/authority_binding_mutation/threshold-proposal-mutations-001.json`)

## Threat: tool_server_escape

- **Name:** Tool server escape
- **State:** Pending
- **Surfaces:** kernel_to_tool
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/tool_server_escape.rs`
- **Escape harness:** `crates/guards/chio-wasm-guards/tests/escape/`
- **Corpus cases:**
  - `broker-plaintext-custody-001` (class `broker_plaintext_custody`, reason `broker_plaintext_custody_detected`, path `cases/broker_plaintext_custody/broker-plaintext-custody-001.json`)
  - `broker-secret-boundary-crossing-001` (class `broker_secret_boundary_crossing`, reason `broker_secret_boundary_crossing_detected`, path `cases/broker_secret_boundary_crossing/broker-secret-boundary-crossing-001.json`)
  - `sandbox-false-exec-success-001` (class `sandbox_false_exec_success`, reason `sandbox_false_exec_success_detected`, path `cases/sandbox_false_exec_success/sandbox-false-exec-success-001.json`)
  - `sandbox-fd-or-env-leak-001` (class `sandbox_fd_or_env_leak`, reason `sandbox_fd_or_env_leak_detected`, path `cases/sandbox_fd_or_env_leak/sandbox-fd-or-env-leak-001.json`)
  - `sandbox-partial-enforcement-001` (class `sandbox_partial_enforcement`, reason `sandbox_partial_enforcement_detected`, path `cases/sandbox_partial_enforcement/sandbox-partial-enforcement-001.json`)
  - `sandbox-path-swap-001` (class `sandbox_path_swap`, reason `sandbox_path_swap_detected`, path `cases/sandbox_path_swap/sandbox-path-swap-001.json`)
  - `sandbox-symlink-escape-001` (class `sandbox_symlink_escape`, reason `sandbox_symlink_escape_detected`, path `cases/sandbox_symlink_escape/sandbox-symlink-escape-001.json`)
  - `sandbox-syscall-escape-001` (class `sandbox_syscall_escape`, reason `sandbox_syscall_escape_detected`, path `cases/sandbox_syscall_escape/sandbox-syscall-escape-001.json`)
  - `sandbox-unsigned-manifest-001` (class `sandbox_unsigned_manifest`, reason `sandbox_unsigned_manifest_detected`, path `cases/sandbox_unsigned_manifest/sandbox-unsigned-manifest-001.json`)
  - `sigstore-bundle-payload-mismatch-004` (class `sigstore_bundle_payload_mismatch`, reason `sigstore_bundle_payload_mismatch`, path `cases/sigstore_bundle_payload_mismatch/sigstore-bundle-payload-mismatch-004.json`)

## Threat: native_channel_replay

- **Name:** Replay attacks on the native channel
- **State:** Pending
- **Surfaces:** native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/native_channel_replay.rs`
- **Corpus cases:**
  - `anchor-grafted-001` (class `anchor_grafted`, reason `anchor_grafted_receipt_root`, path `cases/anchor_grafted/anchor-grafted-001.json`)
  - `anchor-grafted-003` (class `anchor_grafted`, reason `anchor_grafted_tree_size`, path `cases/anchor_grafted/anchor-grafted-003.json`)
  - `anchor-grafted-004` (class `anchor_grafted`, reason `anchor_grafted_proof_path`, path `cases/anchor_grafted/anchor-grafted-004.json`)
  - `broker-proof-replay-001` (class `broker_proof_replay`, reason `broker_proof_replay_detected`, path `cases/broker_proof_replay/broker-proof-replay-001.json`)
  - `clock-rewound-003` (class `clock_rewound`, reason `clock_rewound_receipt_sequence`, path `cases/clock_rewound/clock-rewound-003.json`)
  - `future-dated-001` (class `future_dated`, reason `future_dated_receipt_window`, path `cases/future_dated/future-dated-001.json`)
  - `future-dated-003` (class `future_dated`, reason `future_dated_checkpoint`, path `cases/future_dated/future-dated-003.json`)
  - `key-log-noncontiguous-sync-001` (class `key_log_noncontiguous_sync`, reason `key_log_noncontiguous_sync_detected`, path `cases/key_log_noncontiguous_sync/key-log-noncontiguous-sync-001.json`)
  - `partial-signature-003` (class `partial_signature`, reason `partial_signature_missing_nonce_claim`, path `cases/partial_signature/partial-signature-003.json`)
  - `replayed-nonce-001` (class `replayed_nonce`, reason `nonce_replayed`, path `cases/replayed_nonce/replayed-nonce-001.json`)
  - `replayed-nonce-002` (class `replayed_nonce`, reason `nonce_replayed`, path `cases/replayed_nonce/replayed-nonce-002.json`)
  - `replayed-nonce-003` (class `replayed_nonce`, reason `nonce_replayed_across_sessions`, path `cases/replayed_nonce/replayed-nonce-003.json`)
  - `revocation-rollback-003` (class `revocation_rollback`, reason `revocation_timestamp_rollback`, path `cases/revocation_rollback/revocation-rollback-003.json`)

## Threat: resource_exhaustion_dos

- **Name:** Resource exhaustion denial of service
- **State:** Pending
- **Surfaces:** native_chio, hosted_mcp, trust_control, kernel_to_tool
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/resource_exhaustion_dos.rs`
- **Escape harness:** `crates/guards/chio-wasm-guards/tests/escape/`
- **Corpus cases:**
  - `broker-execution-overspend-001` (class `broker_execution_overspend`, reason `broker_execution_overspend_detected`, path `cases/broker_execution_overspend/broker-execution-overspend-001.json`)
  - `broker-orphan-hold-001` (class `broker_orphan_hold`, reason `broker_orphan_hold_detected`, path `cases/broker_orphan_hold/broker-orphan-hold-001.json`)
  - `broker-parent-double-charge-001` (class `broker_parent_double_charge`, reason `broker_parent_double_charge_detected`, path `cases/broker_parent_double_charge/broker-parent-double-charge-001.json`)
  - `containment-rollback-001` (class `containment_rollback`, reason `containment_rollback_detected`, path `cases/containment_rollback/containment-rollback-001.json`)

## Threat: delegation_chain_abuse

- **Name:** Delegation chain abuse
- **State:** Pending
- **Surfaces:** trust_control, native_chio, hosted_mcp
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/delegation_chain_abuse.rs`
- **Corpus cases:**
  - `aggregate-root-binding-mutations-001` (class `authority_binding_mutation`, reason `aggregate_root_binding_mutated`, path `cases/authority_binding_mutation/aggregate-root-binding-mutations-001.json`)
  - `future-dated-004` (class `future_dated`, reason `future_dated_delegation_chain`, path `cases/future_dated/future-dated-004.json`)
  - `partial-signature-004` (class `partial_signature`, reason `partial_signature_missing_parent_link`, path `cases/partial_signature/partial-signature-004.json`)
  - `replayed-nonce-004` (class `replayed_nonce`, reason `nonce_replayed_with_scope_change`, path `cases/replayed_nonce/replayed-nonce-004.json`)
  - `replayed-nonce-005` (class `replayed_nonce`, reason `nonce_replayed_after_revocation`, path `cases/replayed_nonce/replayed-nonce-005.json`)
  - `revocation-rollback-001` (class `revocation_rollback`, reason `revocation_epoch_rollback`, path `cases/revocation_rollback/revocation-rollback-001.json`)
  - `revocation-rollback-002` (class `revocation_rollback`, reason `revocation_root_rollback`, path `cases/revocation_rollback/revocation-rollback-002.json`)
  - `revocation-rollback-004` (class `revocation_rollback`, reason `revocation_proof_rollback`, path `cases/revocation_rollback/revocation-rollback-004.json`)
  - `revocation-rollback-005` (class `revocation_rollback`, reason `revocation_chain_rollback`, path `cases/revocation_rollback/revocation-rollback-005.json`)
  - `scope-superset-001` (class `scope_superset`, reason `scope_superset`, path `cases/scope_superset/scope-superset-001.json`)
  - `scope-superset-002` (class `scope_superset`, reason `scope_superset_wildcard`, path `cases/scope_superset/scope-superset-002.json`)
  - `scope-superset-004` (class `scope_superset`, reason `scope_superset_cross_protocol`, path `cases/scope_superset/scope-superset-004.json`)

## Threat: ssrf_via_http_substrate

- **Name:** SSRF via HTTP substrate
- **State:** Pending
- **Surfaces:** hosted_mcp, kernel_to_tool
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/ssrf_via_http_substrate.rs`
- **Corpus cases:**
  - `broker-destination-rebinding-001` (class `broker_destination_rebinding`, reason `broker_destination_rebinding_detected`, path `cases/broker_destination_rebinding/broker-destination-rebinding-001.json`)
  - `broker-unbound-headers-001` (class `broker_unbound_headers`, reason `broker_unbound_headers_detected`, path `cases/broker_unbound_headers/broker-unbound-headers-001.json`)

## Threat: pii_phi_exposure

- **Name:** PII or PHI exposure in responses
- **State:** Pending
- **Surfaces:** tool_response_pipeline
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/pii_phi_exposure.rs`
- **Corpus cases:**
  - `label-downgrade-001` (class `label_downgrade`, reason `label_downgrade_detected`, path `cases/label_downgrade/label-downgrade-001.json`)

## Threat: agent_velocity_abuse

- **Name:** Agent velocity abuse
- **State:** Pending
- **Surfaces:** native_chio, hosted_mcp, trust_control, kernel_to_tool
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/agent_velocity_abuse.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: cumulative_data_exfiltration

- **Name:** Cumulative data exfiltration
- **State:** Pending
- **Surfaces:** session_data_flow
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/cumulative_data_exfiltration.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: behavioral_sequence_attack

- **Name:** Behavioral sequence attack
- **State:** Pending
- **Surfaces:** session_tool_sequence
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/behavioral_sequence_attack.rs`
- **Corpus cases:**
  - `canary-evasion-001` (class `canary_evasion`, reason `canary_evasion_detected`, path `cases/canary_evasion/canary-evasion-001.json`)
  - `temporal-evasion-001` (class `temporal_evasion`, reason `temporal_evasion_detected`, path `cases/temporal_evasion/temporal-evasion-001.json`)

## Threat: wasm_guard_resource_exhaustion

- **Name:** WASM guard resource exhaustion
- **State:** Pending
- **Surfaces:** wasm_guard_runtime
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/wasm_guard_resource_exhaustion.rs`
- **Escape harness:** `crates/guards/chio-wasm-guards/tests/escape/`
- **Corpus cases:** (none cite this threat ID)

## Threat: pq_signature_downgrade

- **Name:** Post-quantum signature downgrade
- **State:** Pending
- **Surfaces:** trust_control, hosted_mcp, native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/pq_signature_downgrade.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: tee_quote_forgery

- **Name:** TEE quote forgery or misbinding
- **State:** Pending
- **Surfaces:** hosted_mcp, native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/tee_quote_forgery.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: passkey_credential_theft

- **Name:** Passkey credential theft
- **State:** Pending
- **Surfaces:** trust_control, native_chio, hosted_mcp
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/passkey_credential_theft.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: audience_confusion

- **Name:** Audience confusion
- **State:** Pending
- **Surfaces:** trust_control, native_chio, hosted_mcp
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/audience_confusion.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: weights_hash_spoof

- **Name:** Weights hash spoof
- **State:** Pending
- **Surfaces:** kernel_to_tool, native_chio
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/weights_hash_spoof.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: mobile_attestation_replay

- **Name:** Mobile attestation replay
- **State:** Pending
- **Surfaces:** mobile_ios, mobile_android, capability_issuance
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/mobile_attestation_replay.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: device_key_extraction

- **Name:** Device key extraction
- **State:** Pending
- **Surfaces:** mobile_ios, mobile_android, capability_issuance
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/device_key_extraction.rs`
- **Corpus cases:** (none cite this threat ID)

## Threat: play_integrity_token_replay

- **Name:** Play Integrity token replay
- **State:** Pending
- **Surfaces:** mobile_android, capability_issuance
- **Conformance test:** `crates/tooling/chio-conformance/tests/threats/play_integrity_token_replay.rs`
- **Corpus cases:** (none cite this threat ID)
