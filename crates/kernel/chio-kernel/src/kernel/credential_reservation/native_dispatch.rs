//! Live evidence borrows the actual reservation, never reconstructed history.
use super::*;
use crate::admission_operation::{
    dpop_claim::DpopReplayClaimReferenceV1,
    governed_approval_claim::GovernedApprovalClaimReferenceV1,
    runtime_participant::{RuntimeDispatchValidity, RuntimeParticipantClaimHistoryV1},
    AdmissionDigest, AdmissionExecutionNonceReservationV1, AdmissionOperationState,
    AdmissionOperationStoreError, AdmissionOperationV1, RetainedToolAdmissionRequestV1,
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
    execution_nonce: Option<&'a AdmissionExecutionNonceReservationV1>,
    nonce_binding: Option<VerifiedBoundExecutionNonceTime>,
    valid_until_unix_ms: u64,
}

impl VerifiedNativeDispatchCredentials<'_> {
    pub(crate) fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
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

    /// Exact issuance borrowed from this admission, not a replay-store marker.
    /// The physical capture must independently verify its owned reservation.
    pub fn execution_nonce(&self) -> Option<&AdmissionExecutionNonceReservationV1> {
        self.execution_nonce
    }

    /// Historical approval binding of the exact physically reserved nonce.
    /// The store must independently validate this time against its proposal.
    pub fn execution_nonce_binding_time_unix_ms(&self) -> Option<u64> {
        self.nonce_binding
            .as_ref()
            .map(|binding| binding.bound_at_unix_ms)
    }
}

/// Created only from the original proposal and physical nonce reservation.
/// This is read-only verification evidence, never renewed dispatch authority.
pub(crate) struct VerifiedBoundExecutionNonceTime {
    nonce: crate::execution_nonce::SignedExecutionNonce,
    bound_at_unix_ms: u64,
    approval_valid_until_unix_ms: u64,
}

impl VerifiedBoundExecutionNonceTime {
    pub(super) fn matches_nonce(
        &self,
        nonce: &crate::execution_nonce::SignedExecutionNonce,
    ) -> bool {
        &self.nonce == nonce
    }
    pub(super) fn approval_valid_until_unix_ms(&self) -> u64 {
        self.approval_valid_until_unix_ms
    }
}

impl ChioKernel {
    pub(crate) fn verified_bound_execution_nonce_time(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        now: u64,
    ) -> Result<Option<VerifiedBoundExecutionNonceTime>, KernelError> {
        if !admission.requires_execution_nonce() {
            return Ok(None);
        }
        let operation = admission.operation();
        let Some(proposal) = operation.threshold_proposal() else {
            return Ok(None);
        };
        let issued = admission
            .issued_execution_nonce()
            .ok_or_else(|| invalid("bound nonce lost original issuance"))?;
        if operation.state() != AdmissionOperationState::CapturePending
            || !operation.binding().participant_requirements().approval
            || proposal.body.proposal_id != operation.binding().operation_id().as_str()
            || request.threshold_approval_proposal.as_ref() != Some(proposal)
            || request.execution_nonce.as_ref() != Some(issued.signed_nonce())
            || operation.execution_nonce_id() != Some(issued.nonce_id())
            || operation
                .threshold_proposal_hash()
                .map(AdmissionDigest::as_str)
                != Some(
                    proposal
                        .artifact_digest()
                        .map_err(|error| invalid(&error.to_string()))?
                        .as_str(),
                )
        {
            return Err(invalid(
                "bound nonce differs from its original approval operation",
            ));
        }
        self.validate_cumulative_threshold_proposal(
            request,
            proposal,
            &self.threshold_approval_requirement(request, now / 1000)?,
            now / 1000,
        )?;
        let bound_at = proposal
            .body
            .proposal_created_at
            .checked_mul(1000)
            .ok_or_else(|| invalid("nonce binding time overflows"))?;
        self.verify_bound_execution_nonce_reservation(admission, request, bound_at, now)?;
        let until = proposal
            .body
            .proposal_deadline
            .checked_mul(1000)
            .ok_or_else(|| invalid("approval deadline overflows"))?;
        if bound_at > now || now >= until {
            return Err(invalid("original nonce approval window is not live"));
        }
        Ok(Some(VerifiedBoundExecutionNonceTime {
            nonce: issued.signed_nonce().clone(),
            bound_at_unix_ms: bound_at,
            approval_valid_until_unix_ms: until,
        }))
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
        let profile = original.authority_profile();
        let selection = profile.selection();
        if original.native_security_authority_binding().is_none()
            || admission.operation().state() != AdmissionOperationState::CapturePending
            || self.execution_nonce_id.is_some()
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
        let nonce_binding = self.kernel.verified_bound_execution_nonce_time(
            admission,
            request,
            self.kernel.read_authority_time()?.get(),
        )?;
        let execution_nonce = self.verify_native_execution_nonce(
            admission,
            request,
            original,
            nonce_binding.as_ref(),
        )?;
        let dpop_required = original.matching_grants_require_dpop();
        if self.kernel.is_emergency_stopped() {
            return Err(invalid("native capture denied by emergency stop"));
        }
        self.kernel
            .verify_capability_full_pre_admit(
                &request.capability,
                request.federated_origin_kernel_id.as_deref(),
                self.kernel.read_authority_time()?.as_secs(),
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
                self.kernel.read_authority_time()?.as_secs(),
                admission.requires_execution_nonce(),
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
        let approval_credential = prepared.approval_credential()?;
        let approval = approval_credential
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
        // Carry the already verified artifacts' exclusive horizon across the
        // capture callback. Never refresh or extend them after commitment.
        let mut valid_until = prepared.valid_until_unix_ms(nonce_binding.as_ref())?;
        if let Some((_, validity)) = &runtime {
            valid_until = valid_until.min(validity.valid_until_unix_ms());
        }
        Ok(VerifiedNativeDispatchCredentials {
            reservation: self,
            request,
            operation: admission.operation(),
            original,
            grant_index,
            runtime,
            execution_nonce,
            nonce_binding,
            valid_until_unix_ms: valid_until,
        })
    }

    fn verify_native_execution_nonce<'a>(
        &self,
        admission: &'a DurableToolAdmission,
        request: &ToolCallRequest,
        original: &RetainedToolAdmissionRequestV1,
        binding: Option<&VerifiedBoundExecutionNonceTime>,
    ) -> Result<Option<&'a AdmissionExecutionNonceReservationV1>, KernelError> {
        let required = admission.requires_execution_nonce();
        let issued = admission.issued_execution_nonce();
        if self.execution_nonce_present != required
            || request.execution_nonce.is_some() != required
            || issued.is_some() != required
        {
            return Err(invalid(
                "native execution nonce lacks its original reservation",
            ));
        }
        let Some(issued) = issued else {
            return Ok(None);
        };
        if Some(issued.signed_nonce()) != request.execution_nonce.as_ref()
            || admission.operation().execution_nonce_id() != Some(issued.nonce_id())
            || admission
                .operation()
                .execution_nonce_issuance_digest()
                .is_none()
        {
            return Err(invalid(
                "native execution nonce differs from original issuance",
            ));
        }
        issued
            .require_operation_bound_profile()
            .map_err(|error| invalid(&error.to_string()))?;
        // Only a checked original approval binding supplies historical time.
        // Unapproved nonces still require a currently live issuance window.
        AdmissionExecutionNonceReservationV1::from_canonical_bytes(
            issued.canonical_bytes(),
            admission.operation(),
            original,
            &self.kernel.config.keypair.public_key(),
            match binding {
                Some(binding) => binding.bound_at_unix_ms,
                None => self.kernel.read_authority_time()?.get(),
            },
        )
        .map_err(|error| invalid(&error.to_string()))?;
        Ok(Some(issued))
    }
}

fn invalid(message: &str) -> KernelError {
    KernelError::DurableAdmission(message.into())
}
