//! Admission facts are fixed before dispatch; return observations remain separate.

use super::*;
use crate::admission_operation::RetainedToolAdmissionRequestV1;
use crate::kernel::delivery_contract;

#[path = "return_context/caller.rs"]
mod caller;

#[path = "return_context/participants.rs"]
mod participants;
use participants::FrozenDispatchParticipants;

/// A local freeze rejection proves that no dispatch commit was attempted.
/// Errors from the store path do not provide that evidence and retain custody.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DurableDispatchCommitError {
    #[error(transparent)]
    RejectedBeforeCommit(KernelError),
    #[error(transparent)]
    CommitUnconfirmed(KernelError),
}

/// Kernel-owned frozen return material. This is one component of the complete
/// caller snapshot, not an execution permit or a durable custody certificate.
/// Its request-material digest deliberately excludes transient credentials.
pub(crate) struct DurableToolReturnContext {
    operation_id: crate::admission_operation::AdmissionOperationId,
    request_binding_hash: AdmissionDigest,
    request_id: String,
    request_material_digest: AdmissionDigest,
    pub(super) matched_grant_index: usize,
    pub(super) stream_limits: InvocationStreamLimitsV1,
    admitted_metadata: Option<serde_json::Value>,
    purchase_replay_metadata: Option<serde_json::Value>,
    recovery_replay_metadata: Option<serde_json::Value>,
    pub(super) pre_invocation_guard_evidence: Vec<chio_core::receipt::metadata::GuardEvidence>,
    pub(super) security_invocation_context: Option<SecurityInvocationContext>,
    pub(super) security_release_required: bool,
    pub(super) federation_context: Option<FrozenFederationContext>,
    pub(super) receipt_signing_identity:
        Option<crate::tool_outcome::FrozenReceiptSigningIdentityV1>,
    // Legacy caller frames stay explicitly unbound. New live contexts always
    // retain the original selection, including absent participants.
    participants: Option<Box<FrozenDispatchParticipants>>,
    // None on native dispatch and on older caller formats. Historical frames
    // cannot acquire missing custody by reading a newer current projection.
    caller_participant_custody: Option<caller::CallerParticipantCustody>,
}

pub(crate) struct DurableToolReturnContextInput<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) matched_grant_index: usize,
    pub(crate) extra_receipt_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(crate) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
    pub(crate) verified_purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    pub(crate) verified_recovery: Option<&'a delivery_contract::VerifiedFindingRecoveryAdmission>,
    pub(crate) trusted_now_unix_ms: u64,
    pub(crate) security_invocation_context: Option<&'a SecurityInvocationContext>,
    pub(crate) security_release_required: bool,
}

impl DurableToolReturnContext {
    pub(super) fn metadata_with_return_observation(
        &self,
        memory_read_metadata: Option<serde_json::Value>,
    ) -> Option<serde_json::Value> {
        merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(self.admitted_metadata.clone(), memory_read_metadata),
                    self.purchase_replay_metadata.clone(),
                ),
                self.recovery_replay_metadata.clone(),
            ),
            Some(serde_json::json!({"receipt_context": {
                "request_id": self.request_id
            }})),
        )
    }

    pub(super) fn validate_binding(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        if &self.operation_id != admission.operation.binding().operation_id()
            || &self.request_binding_hash != admission.operation.binding().request_binding_hash()
        {
            return Err(KernelError::DurableAdmission(
                "frozen return context belongs to another operation".into(),
            ));
        }
        if self.request_material_digest
            != RetainedToolAdmissionRequestV1::request_material_digest(request)
                .map_err(durable_store_error)?
        {
            return Err(KernelError::DurableAdmission(
                "request differs from its frozen admission material".into(),
            ));
        }
        if !admission.permits_grant(self.matched_grant_index) {
            return Err(KernelError::DurableAdmission(
                "frozen return context lost its selected grant".into(),
            ));
        }
        if let Some(participants) = self.participants.as_ref() {
            participants.validate(&admission.operation)?;
        }
        Ok(())
    }

    pub(super) fn bind_native_dispatch(
        &mut self,
        digest: &AdmissionDigest,
    ) -> Result<(), KernelError> {
        if !self.security_release_required {
            return Err(KernelError::DurableAdmission(
                "native dispatch binding requires the original security release context".into(),
            ));
        }
        self.participants
            .as_mut()
            .ok_or_else(|| {
                KernelError::DurableAdmission("native dispatch lost frozen participants".into())
            })?
            .bind_native_dispatch(digest)
    }
}

impl ChioKernel {
    pub(crate) fn freeze_and_commit_durable_dispatch(
        &self,
        admission: &mut DurableToolAdmission,
        capability: &CapabilityToken,
        budget_mutation: &mut PreExecutionBudgetMutation,
        mut input: DurableToolReturnContextInput<'_>,
    ) -> Result<DurableToolReturnContext, DurableDispatchCommitError> {
        input.trusted_now_unix_ms = current_unix_timestamp_ms().max(input.trusted_now_unix_ms);
        let now = input.trusted_now_unix_ms;
        let request = input.request;
        let context = self
            .freeze_durable_tool_return_context(admission, input)
            .map_err(DurableDispatchCommitError::RejectedBeforeCommit)?;
        let caller_context = self
            .frame_caller_return_context(admission, &context, now)
            .map_err(DurableDispatchCommitError::RejectedBeforeCommit)?;
        if caller_context.is_some() && budget_mutation.durable_hold_result().is_none() {
            return Err(DurableDispatchCommitError::RejectedBeforeCommit(
                KernelError::DurableAdmission(
                    "caller context requires atomic invocation capture".into(),
                ),
            ));
        }
        if budget_mutation.durable_hold_result().is_some() {
            self.capture_and_commit_durable_dispatch(
                admission,
                capability,
                budget_mutation,
                caller_context.as_ref(),
                now,
            )
            .map_err(DurableDispatchCommitError::CommitUnconfirmed)?;
        } else {
            self.commit_durable_dispatch(admission, now)
                .map_err(DurableDispatchCommitError::CommitUnconfirmed)?;
        }
        context
            .validate_binding(admission, request)
            .map_err(DurableDispatchCommitError::CommitUnconfirmed)?;
        if let Some(expected) = caller_context.as_ref() {
            self.restore_caller_return_context(admission, expected, now)
                .map_err(DurableDispatchCommitError::CommitUnconfirmed)
        } else {
            Ok(context)
        }
    }

    pub(crate) fn freeze_durable_tool_return_context(
        &self,
        admission: &DurableToolAdmission,
        input: DurableToolReturnContextInput<'_>,
    ) -> Result<DurableToolReturnContext, KernelError> {
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(
                "return context must be frozen before dispatch commitment".into(),
            ));
        }
        self.validate_return_context_admission(
            admission,
            input.request,
            input.matched_grant_index,
            input.security_invocation_context,
        )?;
        if input.security_release_required {
            self.durable_runtime()?
                .outcome_store
                .require_security_release_checkpoint_support()
                .map_err(durable_outcome_store_error)?;
        }
        let DurableToolReturnContextInput {
            request,
            matched_grant_index,
            extra_receipt_metadata,
            pre_invocation_guard_evidence,
            verified_payee_binding,
            verified_purchase,
            verified_recovery,
            trusted_now_unix_ms,
            security_invocation_context,
            security_release_required,
        } = input;
        let purchase_replay_metadata =
            self.capture_purchase_replay_metadata(request, matched_grant_index, verified_purchase)?;
        let recovery_replay_metadata =
            self.capture_recovery_replay_metadata(request, matched_grant_index, verified_recovery)?;
        let request_metadata = request_receipt_metadata_with_payee_binding(
            request,
            self.attestation_trust_policy.as_ref(),
            trusted_now_unix_ms / 1_000,
            extra_receipt_metadata.as_ref(),
            verified_payee_binding,
        )?;
        let admitted_metadata = merge_metadata_objects(
            merge_metadata_objects(request_metadata, extra_receipt_metadata),
            receipt_attribution_metadata(&request.capability, Some(matched_grant_index)),
        );
        let context = DurableToolReturnContext {
            operation_id: admission.operation.binding().operation_id().clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            request_id: request.request_id.clone(),
            request_material_digest: RetainedToolAdmissionRequestV1::request_material_digest(
                request,
            )
            .map_err(durable_store_error)?,
            matched_grant_index,
            stream_limits: self.durable_stream_limits()?,
            admitted_metadata,
            purchase_replay_metadata,
            recovery_replay_metadata,
            pre_invocation_guard_evidence: pre_invocation_guard_evidence.to_vec(),
            security_invocation_context: security_invocation_context.cloned(),
            security_release_required,
            federation_context: self.freeze_federation_return_context(
                admission,
                request,
                trusted_now_unix_ms,
            )?,
            receipt_signing_identity: Some(self.freeze_receipt_signing_identity()?),
            participants: Some(Box::new(FrozenDispatchParticipants::from_operation(
                &admission.operation,
            )?)),
            caller_participant_custody: if admission
                .operation
                .provider_attempt()
                .is_some_and(is_caller_report_attempt)
            {
                Some(self.read_caller_participant_custody(
                    admission,
                    matched_grant_index,
                    trusted_now_unix_ms,
                )?)
            } else {
                None
            },
        };
        context.validate_binding(admission, request)?;
        Ok(context)
    }

    fn validate_return_context_admission(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<(), KernelError> {
        self.validate_security_invocation_context_binding(request, security_context, None)?;
        let security_binding = self.admission_security_binding(security_context)?;
        if let Some(original) = admission.retained_request.as_ref() {
            self.validate_original_authority_profile(original)?;
            original
                .validate_security_binding(security_binding.as_ref())
                .map_err(durable_store_error)?;
            original
                .validate_binding(admission.operation.binding())
                .map_err(durable_store_error)?;
            original
                .validate_request_material(request)
                .map_err(durable_store_error)?;
            if original
                .retained_matching_grant(matched_grant_index)
                .is_some()
            {
                return Ok(());
            }
        } else {
            // Do not reconstruct missing caller provenance from a live request.
            if admission.requires_execution_nonce()
                || admission
                    .operation
                    .provider_attempt()
                    .is_some_and(is_caller_report_attempt)
            {
                return Err(KernelError::DurableAdmission(
                    "return context lost its original admission request".into(),
                ));
            }
            // Ordinary calls retain no original-request artifact. Bind the live
            // material to the admitted operation before the effect, without
            // creating an artifact or imposing the caller retention size cap.
            let matching = resolve_required_matching_grants(
                &request.capability,
                &request.tool_name,
                &request.server_id,
                &request.arguments,
                request.model_metadata.as_ref(),
            )
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
            RetainedToolAdmissionRequestV1::validate_request_binding(
                admission.operation.binding(),
                request,
                &matching,
                &self.durable_post_return_plan()?.frozen_steps,
                security_binding.as_ref(),
                None,
            )
            .map_err(durable_store_error)?;
            if matching
                .iter()
                .any(|grant| grant.index == matched_grant_index)
            {
                return Ok(());
            }
        }
        Err(KernelError::DurableAdmission(
            "return context request or selected grant differs from admission".into(),
        ))
    }
}
