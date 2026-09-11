//! Live evidence borrows the actual reservation, never reconstructed history.
use super::*;
use crate::admission_operation::{
    dpop_claim::DpopReplayClaimReferenceV1,
    governed_approval_claim::GovernedApprovalClaimReferenceV1,
    runtime_participant::{RuntimeDispatchValidity, RuntimeParticipantClaimHistoryV1},
    AdmissionOperationState, AdmissionOperationStoreError, AdmissionOperationV1,
    RetainedToolAdmissionRequestV1,
};

/// A non-serializable borrow of the original kernel reservation and immutable
/// live request. Stores must still validate the exact physical claims, current
/// authority and time in their capture transaction. This is not a tool permit.
#[must_use]
pub struct VerifiedNativeDispatchCredentials<'a> {
    reservation: &'a DispatchCredentialReservation<'a>,
    request: &'a ToolCallRequest,
    operation: &'a AdmissionOperationV1,
    original: &'a RetainedToolAdmissionRequestV1,
    grant_index: usize,
    runtime: Option<(RuntimeParticipantClaimHistoryV1, RuntimeDispatchValidity)>,
}

impl VerifiedNativeDispatchCredentials<'_> {
    /// Check the complete command identity, including transient credentials.
    /// A matching digest or deserialized claim cannot manufacture this borrow.
    pub fn validate_binding(
        &self,
        operation: &AdmissionOperationV1,
        original: &RetainedToolAdmissionRequestV1,
        request: &ToolCallRequest,
        grant_index: usize,
    ) -> Result<(), AdmissionOperationStoreError> {
        if operation != self.operation
            || original.canonical_bytes() != self.original.canonical_bytes()
            || !std::ptr::eq(request, self.request)
            || grant_index != self.grant_index
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "native capture credentials differ from original live custody".into(),
            ));
        }
        Ok(())
    }

    pub fn runtime(&self) -> Option<&RuntimeParticipantClaimHistoryV1> {
        self.runtime.as_ref().map(|(history, _)| history)
    }

    pub fn runtime_validity(&self) -> Option<&RuntimeDispatchValidity> {
        self.runtime.as_ref().map(|(_, validity)| validity)
    }

    pub fn approval(&self) -> Option<&GovernedApprovalClaimReferenceV1> {
        self.reservation.owned_approval.as_ref()
    }

    pub fn dpop(&self) -> Option<&DpopReplayClaimReferenceV1> {
        self.reservation.owned_dpop.as_ref()
    }
}

impl DispatchCredentialReservation<'_> {
    pub(crate) fn verify_native_dispatch<'a>(
        &'a self,
        admission: &'a DurableToolAdmission,
        request: &'a ToolCallRequest,
        grant_index: usize,
        metadata: Option<&serde_json::Value>,
    ) -> Result<VerifiedNativeDispatchCredentials<'a>, KernelError> {
        let original = admission.original_retained_request().ok_or_else(|| {
            invalid("native capture credentials require the original authority profile")
        })?;
        self.kernel.validate_original_authority_profile(original)?;
        let profile = original.authority_profile().ok_or_else(|| {
            invalid("native capture credentials cannot upgrade a legacy authority profile")
        })?;
        let selection = profile.selection();
        if original.native_security_authority_binding().is_none()
            || admission.operation().state() != AdmissionOperationState::CapturePending
            || admission.requires_execution_nonce()
            || request.execution_nonce.is_some()
            || request.declassification_grant.is_some()
            || self.execution_nonce_present
            || self.dpop_key.is_some()
            || self.approval_key.is_some()
            || (selection.runtime_hook_installed && selection.runtime.is_none())
            || (selection.swarm_admission_required && !selection.runtime_enforces_swarm_authority)
            || original.retained_matching_grant(grant_index).is_none()
        {
            return Err(invalid(
                "native capture requires complete operation-owned custody",
            ));
        }
        let dpop_required = original.matching_grants_require_dpop();
        if self.kernel.is_emergency_stopped() {
            return Err(invalid("native capture denied by emergency stop"));
        }
        self.kernel
            .verify_capability_full_pre_admit(
                &request.capability,
                request.federated_origin_kernel_id.as_deref(),
                current_unix_timestamp(),
            )
            .map_err(|error| invalid(&error))?;
        self.kernel.check_revocation(&request.capability)?;
        self.kernel
            .validate_delegation_admission(&request.capability)?;
        if (dpop_required && profile.dpop().is_none())
            || (request.approval_token.is_some() && profile.approval().is_none())
        {
            return Err(invalid(
                "native capture cannot use legacy credential custody",
            ));
        }
        let prepared = self
            .kernel
            .prepare_dispatch_credentials(
                request,
                &request.capability,
                dpop_required,
                current_unix_timestamp(),
                false,
            )?
            .refresh()?;
        prepared.validate_origin(self.kernel, original)?;
        let dpop = prepared
            .dpop_credential()
            .map(|credential| {
                self.kernel
                    .verify_owned_dpop(admission, &prepared, credential, grant_index)
            })
            .transpose()?;
        let approval = prepared
            .approval_credential()?
            .as_ref()
            .map(|credential| {
                self.kernel.verify_owned_governed_approval(
                    admission,
                    &prepared,
                    credential,
                    grant_index,
                )
            })
            .transpose()?;
        if dpop != self.owned_dpop
            || approval != self.owned_approval
            || dpop.is_some() != dpop_required
            || approval.is_some() != request.approval_token.is_some()
        {
            return Err(invalid(
                "native capture differs from the actual credential reservation",
            ));
        }
        let runtime = self.kernel.verify_owned_runtime_for_native_capture(
            admission,
            request,
            grant_index,
            metadata,
        )?;
        Ok(VerifiedNativeDispatchCredentials {
            reservation: self,
            request,
            operation: admission.operation(),
            original,
            grant_index,
            runtime,
        })
    }
}

fn invalid(message: &str) -> KernelError {
    KernelError::DurableAdmission(message.into())
}
