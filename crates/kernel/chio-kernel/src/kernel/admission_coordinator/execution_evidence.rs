//! Export retained native execution without mutating financial authority.
use super::*;
use crate::tool_outcome::{
    execution_metadata, validate_execution_evidence_request, validate_execution_provenance,
    QualifiedExecutionEvidenceV1,
};
use chio_core::receipt::execution_evidence::PRE_SETTLEMENT_EXECUTION_PROFILE;
use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::receipt::signing::ReceiptSigningHandle;

impl ChioKernel {
    /// Return one immutable receipt for the original retained native execution.
    /// This creates neither dispatch nor settlement authority. Unsupported
    /// provenance and missing original signing identity fail closed.
    pub fn export_durable_execution_evidence(
        &self,
        request: &ToolCallRequest,
    ) -> Result<ChioReceipt, KernelError> {
        let runtime = self.durable_runtime()?;
        let guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        let selector = AdmissionIdentifier::try_new("request_id", request.request_id.clone())?;
        let (operation, retained) = runtime
            .store
            .load_unambiguous_retained_tool_request(&selector, &runtime.fence, now)
            .map_err(durable_store_error)?
            .ok_or_else(|| execution_error("original retained request is unavailable"))?;
        retained
            .validate_binding(operation.binding())
            .map_err(durable_store_error)?;
        retained
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        let tenant = self
            .receipt_tenant_id_for_request(Some(&request.request_id))
            .or_else(current_scoped_receipt_tenant_id)
            .unwrap_or_else(|| LOCAL_SYSTEM_TENANT_ID.to_owned());
        if operation.binding().coordinator_authority_id().as_str() != runtime.fence.store_uuid
            || operation
                .binding()
                .to_persisted()
                .authenticated_tenant_id
                .as_str()
                != tenant
        {
            return Err(execution_error(
                "request authority or tenant differs from original admission",
            ));
        }
        let _owner = runtime
            .mutation_sequencer
            .try_own_operation(operation.binding().operation_id())?
            .ok_or_else(|| {
                execution_error("original operation is owned by another live evaluation")
            })?;
        let id = operation.binding().operation_id();
        let raw = runtime
            .outcome_store
            .load_raw_invocation_by_operation(id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| execution_error("original native return is unavailable"))?;
        let original_request = raw
            .recovery_request()
            .map_err(tool_outcome_error)?
            .ok_or_else(|| execution_error("original native request is unavailable"))?;
        if canonical_json_bytes(&original_request).map_err(execution_error)?
            != canonical_json_bytes(request).map_err(execution_error)?
        {
            return Err(execution_error(
                "request differs from the original native invocation",
            ));
        }
        let outcome = runtime
            .outcome_store
            .lookup_by_operation(id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| execution_error("original outcome is unavailable"))?;
        let evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| execution_error("original evaluation is unavailable"))?;
        let resolved = runtime
            .outcome_store
            .load_resolved_output_by_operation(id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| execution_error("original resolved output is unavailable"))?;
        validate_execution_provenance(&operation, &raw).map_err(tool_outcome_error)?;
        let journal = runtime
            .store
            .load_payment_journal(id.as_str(), &runtime.fence)
            .map_err(execution_error)?
            .ok_or_else(|| execution_error("original payment identity is unavailable"))?;
        validate_execution_evidence_request(&operation, &retained, &raw, &evaluation)
            .map_err(tool_outcome_error)?;
        let metadata = execution_metadata(
            &operation,
            &raw,
            &outcome,
            &evaluation,
            &journal,
            resolved.bytes(),
        )
        .map_err(tool_outcome_error)?;
        if let Some(record) = runtime
            .outcome_store
            .lookup_execution_evidence(id)
            .map_err(durable_outcome_store_error)?
        {
            record
                .validate_against(
                    &operation,
                    &raw,
                    &outcome,
                    &evaluation,
                    &journal,
                    resolved.bytes(),
                )
                .map_err(tool_outcome_error)?;
            let receipt = record.receipt().map_err(tool_outcome_error)?;
            if !receipt
                .verify_signature_with_floor(self.receipt_signing_crypto_floor())
                .map_err(execution_error)?
            {
                return Err(execution_error(
                    "stored execution does not satisfy current crypto floor",
                ));
            }
            drop(guard);
            self.materialize_execution_evidence(&receipt)?;
            return Ok(receipt);
        }
        if operation.state() != AdmissionOperationState::Finalizing {
            return Err(execution_error(
                "first execution export requires a finalizing operation",
            ));
        }
        let identity = raw
            .receipt_signing_identity()
            .ok_or_else(|| execution_error("original signing identity was not retained"))?;
        let lease = self.claim_admission_recovery(&operation, now)?;
        let signing_nonce = format!(
            "execution:{}",
            sha256_hex(&canonical_json_bytes(&metadata).map_err(execution_error)?)
        );
        let body = chio_core::receipt::body::ChioReceiptBody {
            id: signing_nonce,
            timestamp: evaluation.trusted_time_unix_ms() / 1000,
            capability_id: original_request.capability.id.clone(),
            tool_server: original_request.server_id.clone(),
            tool_name: original_request.tool_name.clone(),
            action: ToolCallAction::from_parameters(original_request.arguments.clone())
                .map_err(execution_error)?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: metadata.resolved_output_sha256.clone(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "receipt_semantics": {"profile": PRE_SETTLEMENT_EXECUTION_PROFILE},
                "execution_evidence": metadata,
                "receipt_context": {"request_id": original_request.request_id},
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: (tenant != LOCAL_SYSTEM_TENANT_ID).then_some(tenant),
            kernel_key: identity.public_key().clone(),
            bbs_projection_version: None,
        };
        drop(guard);
        self.require_original_receipt_signer(identity)?;
        // This uses the same identity-bound core primitive as ordinary receipts.
        // The body id is a stable signing nonce; core derives the normal receipt id.
        let receipt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            chio_kernel_core::sign_receipt_with_handle(
                body,
                self.signing_authority.backend.as_ref(),
                ReceiptSigningHandle::from_content_preimage(resolved.bytes().to_vec()),
            )
        }))
        .map_err(|_| KernelError::ReceiptSigningFailed("execution signer panicked".into()))?
        .map_err(|e| KernelError::ReceiptSigningFailed(format!("{e:?}")))?;
        let guard = runtime.lock_mutations()?;
        let fresh = runtime.refresh_trusted_time(current_unix_timestamp_ms());
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.store.revalidate_recovery_claim(
                &operation,
                lease.untrusted_claim(),
                fresh,
                &runtime.fence,
            )
        }))
        .map_err(|_| execution_error("execution lease revalidation panicked"))?
        .map_err(durable_store_error)?;
        let (current, current_request) = runtime
            .store
            .load_retained_tool_request(id, &runtime.fence, fresh)
            .map_err(durable_store_error)?
            .ok_or_else(|| execution_error("original request disappeared during signing"))?;
        if current != operation || current_request.canonical_bytes() != retained.canonical_bytes() {
            return Err(execution_error("original operation changed during signing"));
        }
        let qualified = QualifiedExecutionEvidenceV1::qualify(
            &operation,
            &retained,
            &raw,
            &outcome,
            &evaluation,
            &journal,
            resolved.bytes(),
            &receipt,
            fresh,
            runtime.fence.clone(),
        )
        .map_err(tool_outcome_error)?;
        // Store validation rereads all source records and the same original lease
        // in its anchored transaction. No authority is renewed after signing.
        let record = runtime
            .outcome_store
            .record_execution_evidence(&qualified, &lease)
            .map_err(durable_outcome_store_error)?;
        if record != *qualified.record() {
            return Err(execution_error(
                "execution store returned a conflicting projection",
            ));
        }
        let receipt = record.receipt().map_err(tool_outcome_error)?;
        drop(guard);
        self.materialize_execution_evidence(&receipt)?;
        Ok(receipt)
    }

    fn materialize_execution_evidence(&self, receipt: &ChioReceipt) -> Result<(), KernelError> {
        let _write = self
            .receipt_store_write_lock
            .lock()
            .map_err(|_| execution_error("receipt store write lock poisoned"))?;
        self.with_receipt_store(|store| {
            match store.load_chio_receipt(&receipt.id)? {
                Some(existing) => {
                    if canonical_json_bytes(&existing).map_err(execution_error)?
                        != canonical_json_bytes(receipt).map_err(execution_error)?
                    {
                        return Err(execution_error(
                            "receipt log conflicts with execution projection",
                        ));
                    }
                }
                None => {
                    store.append_chio_receipt_with_timeout(
                        receipt,
                        self.config.deadlines.receipt_append_budget(),
                    )?;
                }
            }
            Ok(())
        })?;
        // Execution evidence creates no settlement-observer work item.
        self.mirror_durable_admission_receipt(receipt)
    }
}

fn execution_error(reason: impl std::fmt::Display) -> KernelError {
    KernelError::DurableAdmission(format!("execution evidence: {reason}"))
}
