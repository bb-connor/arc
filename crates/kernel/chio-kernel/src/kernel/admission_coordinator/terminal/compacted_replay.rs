//! Read-only replay of a sealed value. Erased raw bytes are never reconstructed.

use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedPostReturnContext {
    schema: String,
    request_binding_hash: String,
    matched_grant_index: usize,
    elapsed_millis: u64,
    max_stream_total_bytes: u64,
    max_stream_chunks: u64,
    max_stream_duration_secs: u64,
}

impl ChioKernel {
    pub(super) fn completed_compacted_value_response(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        outcome: &ToolOutcomeRecordV1,
        digest: AdmissionDigest,
        size_bytes: u64,
    ) -> Result<ToolCallResponse, KernelError> {
        let operation = &admission.operation;
        if operation.state() != AdmissionOperationState::Completed
            || admission
                .original_native_security_authority_binding()
                .is_some()
            || request.federated_origin_kernel_id.is_some()
        {
            return Err(durable_outcome_store_error(
                ToolOutcomeStoreError::Compacted {
                    raw_output_digest: digest,
                    raw_output_size_bytes: size_bytes,
                },
            ));
        }
        outcome
            .validate_against(operation)
            .map_err(tool_outcome_error)?;
        let runtime = self.durable_runtime()?;
        let evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("terminal evaluation disappeared".into())
            })?;
        evaluation
            .validate_against(operation, outcome)
            .map_err(tool_outcome_error)?;
        if !matches!(
            evaluation.state(),
            PostReturnEvaluationStateV1::Resolved { .. }
        ) {
            return Err(KernelError::DurableAdmission(
                "compacted admission retains a nonterminal evaluation".into(),
            ));
        }
        let normalized = evaluation.retained_normalized_request_context();
        let context: RetainedPostReturnContext =
            serde_json::from_value(normalized.normalized_value().clone())
                .map_err(chio_core::canonical::UntrustedJsonError::Decode)?;
        if context.schema != "chio.kernel-post-return-context.v1"
            || context.request_binding_hash != operation.binding().request_binding_hash().as_str()
            || context.max_stream_duration_secs == 0
            || context.max_stream_chunks == 0
            || context.max_stream_total_bytes == 0
        {
            return Err(KernelError::DurableAdmission(
                "retained replay context conflicts with its admission".into(),
            ));
        }
        let plan = self.durable_post_return_plan()?;
        evaluation
            .validate_replay_contract(&plan.frozen_steps, normalized)
            .map_err(tool_outcome_error)?;
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        let security_binding = admission
            .original_retained_request()
            .and_then(|original| original.security_binding());
        // A context-bearing original without retained context material is held
        // by maintenance. This path never invents that original context.
        let request_hash = immutable_tool_admission_request_hash(
            request,
            &matching,
            &plan,
            security_binding,
            admission
                .original_retained_request()
                .map(|original| original.authority_profile()),
        )?;
        if &request_hash != operation.binding().immutable_request_hash() {
            return Err(KernelError::DurableAdmission(
                "compacted replay request or frozen profile changed".into(),
            ));
        }
        let selected = matching
            .iter()
            .find(|grant| {
                grant.index == context.matched_grant_index
                    && admission.permits_matching_grant(grant)
            })
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "compacted replay has no captured matching grant".into(),
                )
            })?;
        if let Some(reason) =
            crate::kernel::evaluation::evaluation_helpers::delivery_marked_selection_denial(
                &matching,
                context.matched_grant_index,
            )
        {
            return Err(KernelError::DurableAdmission(format!(
                "compacted replay selection is invalid: {reason}"
            )));
        }
        let receipt_id = match operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "completed admission has no signed receipt reference".into(),
                ))
            }
        };
        let receipt = runtime
            .store
            .load_chio_receipt(receipt_id.as_str())?
            .ok_or_else(|| KernelError::DurableAdmission("projected receipt disappeared".into()))?;
        // Maintenance permits only the explicit original classical selection
        // equal to this immutable capability issuer. The receipt cannot select
        // its own trusted key, and a later installed signer does not replace it.
        if request.capability.issuer.algorithm() != chio_core::crypto::SigningAlgorithm::Ed25519
            || receipt.kernel_key != request.capability.issuer
        {
            return Err(KernelError::DurableAdmission(
                "compacted replay receipt does not match the independently selected signer".into(),
            ));
        }
        for floor in [
            chio_core::receipt::crypto_floor::ReceiptCryptoFloor::AllowClassical,
            self.receipt_signing_crypto_floor(),
        ] {
            if !receipt
                .verify_signature_with_floor(floor)
                .map_err(KernelError::ReceiptVerificationFailed)?
            {
                return Err(KernelError::ReceiptVerificationFailed(
                    chio_core::receipt::crypto_floor::ReceiptFloorVerifyError::Crypto(
                        chio_core::Error::SignatureVerificationFailed,
                    ),
                ));
            }
        }
        let metadata: AdmissionReceiptMetadataV1 = serde_json::from_value(
            receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.get(ADMISSION_RECEIPT_METADATA_KEY))
                .cloned()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "compacted replay receipt has no admission metadata".into(),
                    )
                })?,
        )
        .map_err(chio_core::canonical::UntrustedJsonError::Decode)?;
        let binding = operation.binding().to_persisted();
        let expected_tenant = (binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
            .then_some(binding.authenticated_tenant_id.as_str());
        let action = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?;
        let dispatch = operation.dispatch_commit().ok_or_else(|| {
            KernelError::DurableAdmission("compacted replay lost its dispatch commit".into())
        })?;
        if receipt.id != receipt_id.as_str()
            || receipt.capability_id != request.capability.id
            || receipt.tool_server != request.server_id
            || receipt.tool_name != request.tool_name
            || receipt.action.parameters != action.parameters
            || receipt.action.parameter_hash != action.parameter_hash
            || receipt.policy_hash != operation.binding().policy_hash().as_str()
            || receipt.tenant_id.as_deref() != expected_tenant
            || metadata.schema != AdmissionReceiptSchema::V1
            || metadata.operation_id != *operation.binding().operation_id()
            || metadata.request_id != *operation.binding().request_id()
            || metadata.request_namespace_digest != *operation.binding().request_namespace_digest()
            || metadata.request_binding_hash != *operation.binding().request_binding_hash()
            || metadata.projected_operation_version != operation.version()
            || metadata.projected_state != AdmissionOperationState::Completed
            || metadata.projected_dispatch_state != AdmissionDispatchState::Terminal
            || metadata.coordinator_lease_epoch != operation.coordinator_lease_epoch()
            || metadata.retained_dispatch_commit.as_ref() != Some(dispatch)
            || metadata.compensation_status != AdmissionCompensationStatus::NotCompensated
            || metadata.tool_outcome_id.as_ref() != Some(outcome.outcome_id())
            || metadata.tool_outcome_version != Some(outcome.version())
            || metadata.trusted_time_unix_ms == 0
            || receipt.timestamp != metadata.trusted_time_unix_ms / 1_000
            || metadata.store_fence.store_uuid != dispatch.store_fence.store_uuid
            || metadata.store_fence.store_uuid != runtime.fence.store_uuid
            || metadata.store_fence.owner_epoch < dispatch.store_fence.owner_epoch
            || metadata.store_fence.owner_epoch > runtime.fence.owner_epoch
        {
            return Err(KernelError::DurableAdmission(
                "compacted replay receipt conflicts with its sealed admission".into(),
            ));
        }
        if receipt.metadata.as_ref().is_some_and(|metadata| {
            metadata.get("stream").is_some()
                || metadata.get("caller_delivery").is_some()
                || metadata
                    .get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
                    .is_some()
                || metadata
                    .get(crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY)
                    .is_some()
        }) {
            return Err(durable_outcome_store_error(
                ToolOutcomeStoreError::Compacted {
                    raw_output_digest: digest,
                    raw_output_size_bytes: size_bytes,
                },
            ));
        }
        self.validate_retained_financial_receipt(operation, request, &receipt)?;
        if receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata.get(chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
            })
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(KernelError::DurableAdmission(
                "compacted replay receipt has no signing nonce".into(),
            ));
        }
        let blob = runtime
            .outcome_store
            .load_resolved_output_by_operation(operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("resolved value preimage disappeared".into())
            })?;
        let Some((expected, expected_size)) = outcome.resolved_output_ref() else {
            return Err(KernelError::DurableAdmission(
                "compacted admission retains an unresolved outcome".into(),
            ));
        };
        if blob.blob_ref() != expected
            || u64::try_from(blob.bytes().len()).ok() != Some(expected_size)
            || sha256_hex(blob.bytes()) != receipt.content_hash
        {
            return Err(KernelError::DurableAdmission(
                "compacted replay value conflicts with its signed output commitment".into(),
            ));
        }
        let maximum = usize::try_from(expected_size).map_err(|_| {
            KernelError::DurableAdmission("retained output size exceeds address space".into())
        })?;
        let value: serde_json::Value =
            chio_core::canonical::UntrustedJsonText::from_wire(blob.bytes(), maximum)
                .and_then(|input| input.decode_canonical())?;
        let server_output = ToolServerOutput::Value(value);
        self.validate_guarded_output(request, selected.index, &server_output, true)?;
        let (output, _) = Self::terminal_tool_call_output(server_output);
        let (verdict, reason, terminal_state, output) = match receipt.decision.as_ref() {
            Some(Decision::Allow) => (
                Verdict::Allow,
                None,
                OperationTerminalState::Completed,
                Some(output),
            ),
            Some(Decision::Incomplete { reason }) => (
                Verdict::Deny,
                Some(reason.clone()),
                OperationTerminalState::Incomplete {
                    reason: reason.clone(),
                },
                Some(output),
            ),
            _ => {
                return Err(KernelError::DurableAdmission(
                    "compacted completed receipt has an incompatible decision".into(),
                ))
            }
        };
        // No invocation, signing, settlement, nonce consumption, hook rerun or
        // receipt mirroring occurs on this historical read.
        let _recorded_elapsed = context.elapsed_millis;
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict,
            output,
            reason,
            terminal_state,
            receipt,
            execution_nonce: None,
        })
    }
}
