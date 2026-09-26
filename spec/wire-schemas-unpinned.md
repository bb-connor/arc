# Wire-schema identifiers without a pin

Identifier constants in the security crates whose value appears in no
test-scope literal, fixture or `spec/` file. Each needs a canonical-byte
shape fixture and an old-reader test that names the value independently
of the constant, so that a bump is caught by a test and not only by the
lock. Written by `scripts/check-wire-schemas.py --update`; the gate fails
when an unpinned constant is missing from this list, and an entry that has
since been pinned is removed by the next `--update`.

169 of 507 identifier constants in the security crates are unpinned.

## crates/core/chio-core-types (26)

- `crates/core/chio-core-types/src/capability/caveat.rs:10` `CAPABILITY_SECURITY_BINDING_SCHEMA` = `chio.capability-security-binding.v1`
- `crates/core/chio-core-types/src/declassification.rs:12` `DECLASSIFICATION_GRANT_SIGNATURE_DOMAIN` = `chio:declassification-grant:v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:27` `RESOURCE_HEAD_DIGEST_DOMAIN` = `chio.economy.resource-head.digest.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:28` `EFFECT_SLOT_ID_DOMAIN` = `chio.economy.effect-slot.id.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:29` `EFFECT_SLOT_DIGEST_DOMAIN` = `chio.economy.effect-slot.digest.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:30` `EXPECTED_HEADS_ROOT_DOMAIN` = `chio.economy.expected-heads-root.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:31` `NEXT_HEADS_ROOT_DOMAIN` = `chio.economy.next-heads-root.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:32` `BATCH_ID_DOMAIN` = `chio.economy.state-batch.id.v1`
- `crates/core/chio-core-types/src/economic_continuity.rs:34` `CHECKPOINT_DIGEST_DOMAIN` = `chio.economy.state-batch.checkpoint.v1`
- `crates/core/chio-core-types/src/economic_continuity/anchor.rs:12` `VIEW_HEADS_ROOT_DOMAIN` = `chio.economy.anchor-view.heads-root.v1`
- `crates/core/chio-core-types/src/economic_continuity/anchor.rs:13` `VIEW_REPLAYS_ROOT_DOMAIN` = `chio.economy.anchor-view.replays-root.v1`
- `crates/core/chio-core-types/src/economic_continuity/anchor.rs:15` `DISPATCH_COMMIT_ID_DOMAIN` = `chio.economy.effect-dispatch-commit.id.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:17` `PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA` = `chio.provider-attempt-checkpoint.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:18` `PROVIDER_INVOCATION_BLOB_SCHEMA` = `chio.provider-invocation-blob.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:19` `PROVIDER_ACCEPTANCE_SCHEMA` = `chio.provider-acceptance.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:20` `PROVIDER_CANCELLATION_SCHEMA` = `chio.provider-cancellation.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:21` `PROVIDER_EXECUTION_LEASE_SCHEMA` = `chio.provider-execution-lease.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:22` `PROVIDER_COMPLETION_SCHEMA` = `chio.provider-completion.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:33` `CHECKPOINT_DIGEST_DOMAIN` = `chio.provider-attempt-checkpoint.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:34` `INVOCATION_BLOB_DIGEST_DOMAIN` = `chio.provider-invocation-blob.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:35` `ACCEPTANCE_DIGEST_DOMAIN` = `chio.provider-acceptance.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:36` `CANCELLATION_DIGEST_DOMAIN` = `chio.provider-cancellation.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:37` `EXECUTION_LEASE_DIGEST_DOMAIN` = `chio.provider-execution-lease.v1`
- `crates/core/chio-core-types/src/provider_attempt.rs:38` `COMPLETION_DIGEST_DOMAIN` = `chio.provider-completion.v1`
- `crates/core/chio-core-types/src/receipt/economics.rs:8` `CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA` = `chio.channel.receipt-metadata.v1`
- `crates/core/chio-core-types/src/receipt/metadata.rs:483` `FINDING_RECOVERY_SCHEMA` = `chio.finding.recovery.v1`

## crates/kernel/chio-kernel (49)

- `crates/kernel/chio-kernel/src/admission_operation.part1.inc:9` `ADMISSION_OPERATION_SCHEMA` = `chio.security-admission-operation.v1`
- `crates/kernel/chio-kernel/src/admission_operation.rs:83` `ADMISSION_REQUEST_NAMESPACE_SCHEMA` = `chio.admission-request-namespace.v1`
- `crates/kernel/chio-kernel/src/admission_operation/caller_dispatch_context.rs:9` `SCHEMA` = `chio.admission-caller-dispatch-context.v1`
- `crates/kernel/chio-kernel/src/admission_operation/governed_approval_replay.rs:12` `SCHEMA` = `chio.governed-approval-replay-source-seal.v1`
- `crates/kernel/chio-kernel/src/admission_operation/native_security_binding.rs:6` `SCHEMA` = `chio.native-security-authority-binding.v1`
- `crates/kernel/chio-kernel/src/checkpoint.rs:44` `CHECKPOINT_PUBLICATION_SCHEMA` = `chio.checkpoint_publication.v1`
- `crates/kernel/chio-kernel/src/checkpoint.rs:45` `CHECKPOINT_WITNESS_SCHEMA` = `chio.checkpoint_witness.v1`
- `crates/kernel/chio-kernel/src/checkpoint.rs:47` `CHECKPOINT_CONSISTENCY_PROOF_SCHEMA_V1` = `chio.checkpoint_consistency_proof.v1`
- `crates/kernel/chio-kernel/src/checkpoint.rs:52` `CHECKPOINT_EQUIVOCATION_SCHEMA` = `chio.checkpoint_equivocation.v1`
- `crates/kernel/chio-kernel/src/dpop/replay_source/snapshot.rs:24` `SCHEMA` = `chio.dpop-replay-source-seal.v1`
- `crates/kernel/chio-kernel/src/evidence_export.rs:13` `EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA` = `chio.evidence_transparency_claims.v1`
- `crates/kernel/chio-kernel/src/finding_pool.rs:25` `FINDING_POOL_MUTATION_SCHEMA_V1` = `chio.finding.pool-mutation.v1`
- `crates/kernel/chio-kernel/src/finding_pool.rs:26` `FINDING_POOL_DEBIT_AUTHORIZATION_SCHEMA_V1` = `chio.finding.pool-debit-authorization.v1`
- `crates/kernel/chio-kernel/src/finding_purchase.rs:50` `FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA` = `chio.finding.purchase-replay-snapshot.v1`
- `crates/kernel/chio-kernel/src/finding_recovery.rs:49` `FINDING_RECOVERY_REPLAY_SNAPSHOT_SCHEMA` = `chio.finding.recovery-replay-snapshot.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_admission.rs:20` `ACTIVE_RESPONSE_SUBMISSION_SCHEMA` = `chio.active-response-submission.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_artifact.rs:16` `ACTIVE_RESPONSE_ARTIFACT_AUTHORITY_ATTESTATION_SCHEMA` = `chio.active-response-artifact-authority-attestation.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_artifact.rs:18` `ACTIVE_RESPONSE_ADMISSION_ARTIFACT_PAYLOAD_SCHEMA` = `chio.attested-finding-admission-artifact-payload.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_executor.rs:12` `ACTIVE_RESPONSE_EXECUTOR_AUTHORITY_SCHEMA` = `chio.active-response-executor-authority.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_executor.rs:16` `ACTIVE_RESPONSE_DISPATCH_SCHEMA` = `chio.active-response-dispatch.v1`
- `crates/kernel/chio-kernel/src/kernel/active_response_policy.rs:22` `ACTIVE_RESPONSE_POLICY_DECISION_SCHEMA` = `chio.active-response-policy-decision.v1`
- `crates/kernel/chio-kernel/src/kernel/admission_cleanup.rs:17` `APPROVAL_CLEANUP_SCHEMA` = `chio.admission-cleanup.approval.v2`
- `crates/kernel/chio-kernel/src/kernel/admission_cleanup.rs:18` `ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA` = `chio.admission-cleanup.active-response-approval.v2`
- `crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs:11` `LEGACY_SCHEMA` = `chio.kernel-caller-return-context.v1`
- `crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs:12` `SIGNING_SCHEMA` = `chio.kernel-caller-return-context.v2`
- `crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs:13` `PARTICIPANT_SCHEMA` = `chio.kernel-caller-return-context.v3`
- `crates/kernel/chio-kernel/src/kernel/admission_terminal_receipt.rs:11` `TERMINAL_RECEIPT_OUTBOX_SCHEMA` = `chio.admission-terminal-receipt.v1`
- `crates/kernel/chio-kernel/src/kernel/mod.rs:137` `MANIFEST_SECURITY_METADATA_KEY` = `chio_manifest_security_v1`
- `crates/kernel/chio-kernel/src/kernel/recovery_gate.rs:34` `FINDING_RECOVERY_REQUEST_BINDING_SCHEMA` = `chio.finding.recovery-request-binding.v1`
- `crates/kernel/chio-kernel/src/memory_provenance.rs:46` `MEMORY_PROVENANCE_ENTRY_SCHEMA` = `chio.memory_provenance_entry.v1`
- `crates/kernel/chio-kernel/src/operator_report/constants.rs:23` `ECONOMIC_COMPLETION_FLOW_SCHEMA` = `chio.economic-completion-flow.v1`
- `crates/kernel/chio-kernel/src/operator_report/constants.rs:43` `CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS` = `chio_mtls_thumbprint_v1`
- `crates/kernel/chio-kernel/src/operator_report/constants.rs:45` `CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION` = `chio_attestation_binding_v1`
- `crates/kernel/chio-kernel/src/payment.rs:535` `ACP_SETTLEMENT_STATE_REQUEST_SCHEMA` = `chio.payment.acp-settlement-state-request.v1`
- `crates/kernel/chio-kernel/src/payment.rs:536` `ACP_SETTLEMENT_STATE_RESPONSE_SCHEMA` = `chio.payment.acp-settlement-state-response.v1`
- `crates/kernel/chio-kernel/src/receipt_store.rs:1051` `ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND` = `chio.admission.terminal-projection.v1`
- `crates/kernel/chio-kernel/src/supplemental_quota.rs:27` `SUPPLEMENTAL_REQUEST_BINDING_DOMAIN` = `chio.supplemental-quota-request-binding.v1`
- `crates/kernel/chio-kernel/src/supplemental_quota.rs:28` `ADMISSION_REVOCATION_SET_DOMAIN` = `chio.admission-revocation-set.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:24` `RAW_INVOCATION_OUTCOME_SCHEMA` = `chio.raw-invocation-outcome.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:25` `RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA` = `chio.raw-invocation-outcome-with-request.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:27` `RAW_INVOCATION_OUTCOME_WITH_SECURITY_CONTEXT_SCHEMA` = `chio.raw-invocation-outcome-with-security-context.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:29` `RAW_INVOCATION_OUTCOME_WITH_FEDERATION_CONTEXT_SCHEMA` = `chio.raw-invocation-outcome-with-federation-context.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:31` `RAW_INVOCATION_OUTCOME_WITH_SECURITY_RELEASE_SCHEMA` = `chio.raw-invocation-outcome-with-security-release.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:35` `RAW_INVOCATION_OUTCOME_WITH_CALLER_DELIVERY_SCHEMA` = `chio.raw-invocation-outcome-with-caller-delivery.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:41` `TOOL_OUTCOME_SCHEMA` = `chio.tool-outcome.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:42` `POST_RETURN_EVALUATION_SCHEMA` = `chio.post-return-evaluation.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:43` `POST_RETURN_EXACT_INPUTS_SCHEMA` = `chio.post-return-exact-inputs.v1`
- `crates/kernel/chio-kernel/src/tool_outcome.rs:86` `MONETARY_RELEASE_EVIDENCE_SCHEMA` = `chio.monetary-release-evidence.v1`
- `crates/kernel/chio-kernel/src/tool_outcome/security_release.rs:34` `SCHEMA` = `chio.security-release-checkpoint.v1`

## crates/kernel/chio-kernel-core (1)

- `crates/kernel/chio-kernel-core/src/passport_verify.rs:46` `PORTABLE_PASSPORT_SCHEMA` = `chio.portable-agent-passport.v1`

## crates/platform/chio-control-plane (44)

- `crates/platform/chio-control-plane/src/certify/schema.rs:7` `CERTIFICATION_PUBLIC_SEARCH_SCHEMA` = `chio.certify.search.v1`
- `crates/platform/chio-control-plane/src/certify/schema.rs:8` `CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA` = `chio.certify.transparency.v1`
- `crates/platform/chio-control-plane/src/certify/schema.rs:9` `CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1` = `chio.certify.consume.v1`
- `crates/platform/chio-control-plane/src/federation_policy.rs:15` `FEDERATION_ADMISSION_POLICY_RECORD_SCHEMA` = `chio.permissionless-federation-policy.v1`
- `crates/platform/chio-control-plane/src/federation_policy.rs:17` `FEDERATION_ADMISSION_POLICY_REGISTRY_VERSION` = `chio.permissionless-federation-policy-registry.v1`
- `crates/platform/chio-control-plane/src/keyring_runtime.rs:1202` `AUTHORITY_SEED_HANDOFF_SCHEMA` = `chio.authority-seed-handoff.v1`
- `crates/platform/chio-control-plane/src/passport_verifier.rs:25` `VERIFIER_POLICY_REGISTRY_VERSION` = `chio.passport-verifier-policies.v1`
- `crates/platform/chio-control-plane/src/passport_verifier.rs:26` `PASSPORT_STATUS_REGISTRY_VERSION` = `chio.passport-status-registry.v1`
- `crates/platform/chio-control-plane/src/passport_verifier.rs:27` `PASSPORT_ISSUANCE_REGISTRY_VERSION` = `chio.passport-issuance-offers.v1`
- `crates/platform/chio-control-plane/src/scim_lifecycle.rs:13` `SCIM_LIFECYCLE_REGISTRY_VERSION` = `chio.scim-lifecycle-registry.v1`
- `crates/platform/chio-control-plane/src/scim_lifecycle.rs:14` `SCIM_LIFECYCLE_RECORD_SCHEMA` = `chio.scim-lifecycle-record.v1`
- `crates/platform/chio-control-plane/src/security/adapters/native_flow/policy.rs:11` `DECLASSIFIED_SCHEMA` = `chio.native-flow-dispatch-policy.v2`
- `crates/platform/chio-control-plane/src/security/event_consumer_parts/part_01.inc:79` `SECURITY_EVENT_RECEIPT_PROJECTION_VERSION` = `chio.security-event-receipt-projection.v1`
- `crates/platform/chio-control-plane/src/security/event_consumer_parts/part_03.inc:19` `ATTESTED_FINDING_ADMISSION_ARTIFACT_BUNDLE_SCHEMA` = `chio.attested-finding-admission-artifacts.v1`
- `crates/platform/chio-control-plane/src/security/migration_evidence.rs:11` `ENTERPRISE_MIGRATION_CANARY_EVIDENCE_SCHEMA` = `chio.enterprise-migration-canary-evidence.v1`
- `crates/platform/chio-control-plane/src/security/migration_evidence.rs:13` `ENTERPRISE_MIGRATION_CUTOVER_ATTESTATION_SCHEMA` = `chio.enterprise-migration-cutover-attestation.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:146` `DEFECT_DOMAIN` = `chio.finding.defect.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:158` `EFFECT_FEE_DOMAIN` = `chio.finding.effect.fee.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:161` `EFFECT_ROOT_INTENT_DOMAIN` = `chio.finding.effect.root-intent.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:164` `EFFECT_RETRACTION_DOMAIN` = `chio.finding.effect.retraction.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:167` `EFFECT_ANCHOR_EVIDENCE_DOMAIN` = `chio.finding.effect.anchor-evidence.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:174` `EVIDENCE_BUNDLE_DOMAIN` = `chio.finding.challenge-evidence-bundle.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:177` `TRIGGER_DOMAIN` = `chio.finding.challenge-trigger.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:180` `PURCHASE_SNAPSHOT_DOMAIN` = `chio.finding.claim-snapshot.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs:188` `ENFORCEMENT_ROOT_DOMAIN` = `chio.finding.enforcement-root.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs:101` `FINDING_CHALLENGE_STATUS_SCHEMA` = `chio.finding.challenge-status.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_hosted_profile.rs:33` `FINDING_HOSTED_PROFILE_SCHEMA` = `chio.finding.hosted-operator-profile.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_hosted_profile.rs:338` `FINDING_HOSTED_CANARY_OBSERVATION_SCHEMA` = `chio.finding.hosted-canary-observation.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_profile.rs:15` `FINDING_OPERATOR_PROFILE_SCHEMA` = `chio.finding.operator-profile.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_profile.rs:16` `FINDING_OPERATOR_CLIENT_PROFILE_SCHEMA` = `chio.finding.operator-client-profile.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_profile.rs:17` `FINDING_OPERATOR_BUYER_CLIENT_SCHEMA` = `chio.finding.buyer-client.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_profile.rs:18` `FINDING_OPERATOR_SELLER_CLIENT_SCHEMA` = `chio.finding.seller-client.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_operator_seller_routes.rs:19` `FINDING_VOLUNTARY_RETRACTION_REQUEST_SCHEMA` = `chio.finding.voluntary-retraction-request.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_purchase_coordinator.rs:71` `RESERVATION_DOMAIN` = `chio.finding.reservation.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes.rs:50` `FINDING_PURCHASE_REQUEST_SCHEMA` = `chio.finding.purchase-request.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes.rs:54` `FINDING_PURCHASE_ERROR_SCHEMA` = `chio.finding.purchase-error.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_status_handlers.rs:25` `FINDING_STATUS_INTENT_SCHEMA` = `chio.finding.status-intent-submission.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_status_handlers.rs:26` `FINDING_STATUS_INTENT_ID_DOMAIN` = `chio.finding.status-intent-id.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_status_handlers.rs:27` `FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA` = `chio.finding.voluntary-retraction-receipt.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs:70` `VERIFIED_FIX_DRAFT_SCHEMA` = `chio.finding.verified-fix-draft.v1`
- `crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs:72` `VERIFIED_FIX_PAYLOAD_SCHEMA` = `chio.finding.verified-fix-payload.v1`
- `crates/platform/chio-control-plane/src/trust_control/service_types/admission_authority.rs:19` `ADMISSION_AUTHORITY_REQUEST_SCHEMA` = `chio.admission-authority-request.v1`
- `crates/platform/chio-control-plane/src/trust_control/service_types/admission_authority.rs:20` `ADMISSION_AUTHORITY_RESPONSE_SCHEMA` = `chio.admission-authority-response.v1`
- `crates/platform/chio-control-plane/src/trust_control/service_types/structured_budget.rs:4` `STRUCTURED_BUDGET_RESPONSE_SCHEMA` = `chio.structured-budget-response.v1`

## crates/platform/chio-store-sqlite (18)

- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs:7` `DECLASSIFIED_POLICY_SCHEMA` = `chio.native-flow-dispatch-policy.v2`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/record.rs:5` `FORMAT` = `chio.native-security-egress.v1`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/record.rs:6` `DECLASSIFIED_FORMAT` = `chio.native-security-egress.v2`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/record.rs:7` `FORMAT` = `chio.native-security-nonce-preflight-join.v1`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/record.rs:7` `FORMAT` = `chio.native-security-output-join.v1`
- `crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/record.rs:8` `DECLASSIFIED_FORMAT` = `chio.native-security-output-join.v2`
- `crates/platform/chio-store-sqlite/src/channel_release_publisher_store.rs:50` `CHANNEL_ROOT_PUBLICATION_RESULT_SCHEMA` = `chio.channel.root-publication-result.v1`
- `crates/platform/chio-store-sqlite/src/economic_state_cache.rs:48` `ADMISSION_TERMINAL_EFFECT_RESULT_SCHEMA` = `chio.admission.terminal-effect-result.v1`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:140` `DISPUTE_BOND_FUNDING_DOMAIN` = `chio.finding.dispute-bond-funding.v1`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:141` `DISPUTE_BOND_RETURN_DOMAIN` = `chio.finding.dispute-bond-return.v1`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:142` `EFFECT_FEE_DOMAIN` = `chio.finding.effect.fee.v1`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:143` `DISPUTE_FEE_OPERATION_DOMAIN` = `chio.finding.dispute-fee-operation.v1`
- `crates/platform/chio-store-sqlite/src/finding_challenge_store.rs:144` `DISPUTE_FEE_RETURN_OPERATION_DOMAIN` = `chio.finding.dispute-fee-return-operation.v1`
- `crates/platform/chio-store-sqlite/src/frost_store/ceremony.rs:26` `CUSTODY_AAD_FORMAT` = `chio.frost.ceremony-custody-aad.v1`
- `crates/platform/chio-store-sqlite/src/frost_store/signer.rs:34` `SIGNER_AAD_FORMAT` = `chio.frost.signer-nonce-aad.v1`
- `crates/platform/chio-store-sqlite/src/security_state/participant_source/evidence.rs:10` `SCHEMA` = `chio.security-participant-source-fingerprint.v1`
- `crates/platform/chio-store-sqlite/src/serving_owner/path_identity.rs:21` `FORMAT` = `chio.sqlite-local-path-identity.v1`
- `crates/platform/chio-store-sqlite/src/serving_owner/relocation.rs:34` `RELOCATION_SEAL_FORMAT` = `chio.sqlite-authority-relocation-seal.v1`

## crates/security/chio-active-response-authority (4)

- `crates/security/chio-active-response-authority/src/config.rs:16` `AUTHORITY_RUNTIME_CONFIG_SCHEMA` = `chio.active-response-authority.runtime-config.v1`
- `crates/security/chio-active-response-authority/src/config.rs:18` `ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA` = `chio.active-defense.deployment-config.v1`
- `crates/security/chio-active-response-authority/src/store.rs:31` `AUTHORITY_STORE_BUNDLE_SCHEMA` = `chio.active-response-authority.bundle.v1`
- `crates/security/chio-active-response-authority/src/store.rs:32` `AUTHORITY_STORE_MANIFEST_SCHEMA` = `chio.active-response-authority.store-manifest.v1`

## crates/security/chio-cage (3)

- `crates/security/chio-cage/src/launch/linux_parts/part_01_sections/bootstrap.inc:31` `LAUNCH_ENVELOPE_SCHEMA` = `chio.cage.launch-envelope.v1`
- `crates/security/chio-cage/src/launch/linux_parts/part_01_sections/bootstrap.inc:32` `STATUS_RECORD_SCHEMA` = `chio.cage.status-record.v1`
- `crates/security/chio-cage/src/lib_parts/part_01.rs:35` `COMPILED_SANDBOX_PROFILE_SCHEMA` = `chio.cage.compiled-sandbox-profile.v2`

## crates/security/chio-decoy (1)

- `crates/security/chio-decoy/src/registry.rs:35` `PRIVATE_ENVELOPE_SCHEMA` = `chio.decoy-private-envelope.v2`

## crates/security/chio-keyring (12)

- `crates/security/chio-keyring/src/checkpoint.rs:17` `WITNESS_STATEMENT_SCHEMA` = `chio.key-log.witness-statement.v1`
- `crates/security/chio-keyring/src/event.rs:15` `KEY_ID_SCHEMA` = `chio.key-log.key-id.v1`
- `crates/security/chio-keyring/src/ipc.rs:20` `KEY_LOG_WITNESS_IPC_REQUEST_SCHEMA` = `chio.key-log.witness-ipc-request.v1`
- `crates/security/chio-keyring/src/ipc.rs:21` `KEY_LOG_WITNESS_IPC_RESPONSE_SCHEMA` = `chio.key-log.witness-ipc-response.v1`
- `crates/security/chio-keyring/src/ipc.rs:23` `KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA` = `chio.key-log.audit-ipc-request.v1`
- `crates/security/chio-keyring/src/ipc.rs:24` `KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA` = `chio.key-log.audit-ipc-response.v1`
- `crates/security/chio-keyring/src/service.rs:15` `KEY_LOG_POLICY_DOCUMENT_SCHEMA` = `chio.key-log.policy.v1`
- `crates/security/chio-keyring/src/service.rs:16` `KEY_LOG_WITNESS_REQUEST_SCHEMA` = `chio.key-log.witness-request.v1`
- `crates/security/chio-keyring/src/service.rs:17` `KEY_LOG_WITNESS_RESPONSE_SCHEMA` = `chio.key-log.witness-response.v1`
- `crates/security/chio-keyring/src/service.rs:18` `KEY_LOG_AUDIT_COMMAND_SCHEMA` = `chio.key-log.audit-command.v1`
- `crates/security/chio-keyring/src/service.rs:19` `KEY_LOG_AUDIT_RESPONSE_SCHEMA` = `chio.key-log.audit-response.v1`
- `crates/security/chio-keyring/src/witness.rs:15` `CHECKPOINT_EQUIVOCATION_SCHEMA` = `chio.key-log.equivocation.v1`

## crates/security/chio-secret-broker (9)

- `crates/security/chio-secret-broker/src/audit.rs:39` `BROKER_AUDIT_GOVERNED_INTENT_SCHEMA` = `chio.broker-audit-intent.v1`
- `crates/security/chio-secret-broker/src/daemon.rs:34` `DAEMON_ADMIN_INTENT_SCHEMA` = `chio.broker-daemon-admin-intent.v1`
- `crates/security/chio-secret-broker/src/daemon.rs:35` `ISSUE_CAPABILITY_SCHEMA` = `chio.broker-issue-capability.v1`
- `crates/security/chio-secret-broker/src/daemon_runtime.rs:62` `BROKER_DAEMON_CONFIG_SCHEMA` = `chio.secret-brokerd.runtime-config.v5`
- `crates/security/chio-secret-broker/src/kernel_admission.rs:26` `VERIFIER_ID` = `chio.secret-broker.kernel-quota-verifier.v1`
- `crates/security/chio-secret-broker/src/kernel_admission/registration.rs:23` `PARTICIPANT_ID` = `chio.secret-broker.kernel-registration.v1`
- `crates/security/chio-secret-broker/src/migration.rs:18` `BROKER_MIGRATION_POSTURE_SCHEMA` = `chio.broker-migration-posture.v1`
- `crates/security/chio-secret-broker/src/provision.rs:19` `GOVERNED_ADMIN_AUTHORIZATION_SCHEMA` = `chio.broker-admin-authorization.v1`
- `crates/security/chio-secret-broker/src/provision.rs:22` `GOVERNED_ADMIN_INTENT_SCHEMA` = `chio.broker-admin-intent.v1`

## crates/security/chio-security-types (2)

- `crates/security/chio-security-types/src/migration.rs:9` `ENTERPRISE_MIGRATION_TRANSITION_SIGNATURE_DOMAIN` = `chio.enterprise-migration-transition.v1`
- `crates/security/chio-security-types/src/migration.rs:13` `CAGE_MIGRATION_POSTURE_SCHEMA` = `chio.cage-migration-posture.v2`
