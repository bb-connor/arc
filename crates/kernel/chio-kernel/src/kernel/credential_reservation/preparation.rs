//! Read-only credential validation before any replay reservation is attempted.
//! A prepared value borrows its kernel and immutable request. It is not
//! serializable, durable custody, or an external execution authorization.

use super::*;
use crate::admission_operation::dpop_claim::DpopReplayCredentialV1;

pub(super) struct CredentialPreparationInput<'request> {
    pub(super) request: &'request ToolCallRequest,
    pub(super) cap: &'request CapabilityToken,
    pub(super) dpop_required: bool,
    pub(super) now: u64,
    pub(super) execution_nonce_credential: ExecutionNonceCredential,
    pub(super) require_governed_approval: bool,
}

/// Validated inputs for one consuming reservation attempt. Dropping this value
/// cannot release or consume a credential because preparation owns no marker.
pub(crate) struct PreparedDispatchCredentials<'kernel, 'request> {
    pub(super) kernel: &'kernel ChioKernel,
    pub(super) input: CredentialPreparationInput<'request>,
    pub(super) dpop_proof: Option<&'request crate::dpop::DpopProof>,
    pub(super) dpop_credential: Option<DpopReplayCredentialV1>,
    pub(super) execution_nonce: Option<crate::execution_nonce::ValidatedExecutionNonce<'request>>,
    pub(super) execution_nonce_reservable: bool,
    pub(super) durable_nonce_presented: bool,
    pub(super) approval_intent_hash: Option<String>,
}

impl<'kernel> PreparedDispatchCredentials<'kernel, '_> {
    /// Recheck the same immutable artifacts before the first mutation. The
    /// reservation remains on the originating kernel; no replacement request,
    /// capability, store, or authority can be supplied by the consumer.
    #[cfg(test)]
    pub(crate) fn reserve(self) -> Result<DispatchCredentialReservation<'kernel>, KernelError> {
        let refreshed = self.refresh()?;
        if (refreshed.approval_intent_hash.is_some()
            && refreshed.kernel.governed_approval_authority.is_some())
            || refreshed.dpop_credential.is_some()
        {
            return Err(KernelError::DurableAdmission(
                "operation-owned credentials require their exact admission episode".into(),
            ));
        }
        refreshed.reserve_checked(None, None)
    }

    pub(crate) fn refresh(self) -> Result<Self, KernelError> {
        let execution_nonce_reservable = self.execution_nonce_reservable;
        let refreshed = self
            .kernel
            .prepare_credentials(CredentialPreparationInput {
                now: current_unix_timestamp().max(self.input.now),
                ..self.input
            })?;
        if refreshed.execution_nonce_reservable != execution_nonce_reservable {
            return Err(KernelError::Internal(
                "execution nonce reservation capability changed after preparation".into(),
            ));
        }
        Ok(refreshed)
    }

    pub(crate) fn validate_origin(
        &self,
        kernel: &ChioKernel,
        retained: &crate::admission_operation::RetainedToolAdmissionRequestV1,
    ) -> Result<(), KernelError> {
        if !std::ptr::eq(self.kernel, kernel) {
            return Err(KernelError::DurableAdmission(
                "prepared credentials belong to a different kernel".into(),
            ));
        }
        kernel.validate_original_authority_profile(retained)?;
        retained
            .validate_request_material(self.input.request)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }

    pub(crate) fn approval_credential(
        &self,
    ) -> Result<
        Option<crate::admission_operation::governed_approval_claim::GovernedApprovalCredentialV1>,
        KernelError,
    > {
        if self.approval_intent_hash.is_none() {
            return Ok(None);
        }
        self.input.request.approval_token.as_ref().map(
            crate::admission_operation::governed_approval_claim::GovernedApprovalCredentialV1::from_token,
        ).transpose().map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }

    pub(crate) fn dpop_credential(&self) -> Option<&DpopReplayCredentialV1> {
        self.dpop_credential.as_ref()
    }
}

impl ChioKernel {
    pub(crate) fn prepare_dispatch_credentials<'kernel, 'request>(
        &'kernel self,
        request: &'request ToolCallRequest,
        cap: &'request CapabilityToken,
        dpop_required: bool,
        now: u64,
        durable_execution_nonce: bool,
    ) -> Result<PreparedDispatchCredentials<'kernel, 'request>, KernelError> {
        self.prepare_credentials(CredentialPreparationInput {
            request,
            cap,
            dpop_required,
            now,
            execution_nonce_credential: ExecutionNonceCredential::for_dispatch(
                durable_execution_nonce,
            ),
            require_governed_approval: false,
        })
    }

    pub(super) fn prepare_credentials<'kernel, 'request>(
        &'kernel self,
        input: CredentialPreparationInput<'request>,
    ) -> Result<PreparedDispatchCredentials<'kernel, 'request>, KernelError> {
        let CredentialPreparationInput {
            request,
            cap,
            dpop_required,
            now,
            execution_nonce_credential,
            require_governed_approval,
        } = input;
        let mut dpop_credential = None;
        let dpop_proof = if dpop_required {
            let proof = request.dpop_proof.as_ref().ok_or_else(|| {
                KernelError::DpopVerificationFailed(
                    "grant requires DPoP proof but none was provided".to_string(),
                )
            })?;
            if self.dpop_authority.is_some() {
                dpop_credential = Some(DpopReplayCredentialV1::from_verified(
                    self.verify_operation_owned_dpop(
                        proof,
                        cap,
                        &request.server_id,
                        &request.tool_name,
                        &request.arguments,
                    )?,
                ));
                None
            } else {
                self.verify_dpop_for_permission_preview(
                    proof,
                    cap,
                    &request.server_id,
                    &request.tool_name,
                    &request.arguments,
                )?;
                Some(proof)
            }
        } else {
            None
        };

        let execution_nonce = match execution_nonce_credential {
            ExecutionNonceCredential::LegacyReplayStore => {
                self.validate_execution_nonce_non_consuming(request, cap, now)?
            }
            ExecutionNonceCredential::DurableParticipant
            | ExecutionNonceCredential::NotPresented => None,
        };
        let durable_nonce_presented = execution_nonce_credential
            == ExecutionNonceCredential::DurableParticipant
            && request.execution_nonce.is_some();
        let approval_intent_hash =
            self.validate_governed_approval_for_dispatch_non_consuming(request, cap, now)?;
        if require_governed_approval && approval_intent_hash.is_none() {
            return Err(KernelError::GovernedTransactionDenied(
                "strict reserve-for-caller payment authorization requires a governed approval token"
                    .to_string(),
            ));
        }
        if approval_intent_hash.is_some() && self.governed_approval_authority.is_some() {
            self.verify_configured_governed_approval_source()?;
        } else if approval_intent_hash.is_some() && self.approval_replay_store.is_none() {
            return Err(KernelError::GovernedTransactionDenied(
                "approval replay store not configured; denying as fail-closed".to_string(),
            ));
        }

        // This capability query is read-only but remains a host callback. It
        // must not unwind after an earlier credential has been reserved.
        let execution_nonce_reservable = if execution_nonce.is_some() {
            let store = self.execution_nonce_store.as_deref().ok_or_else(|| {
                KernelError::Internal("execution nonce store is not installed".into())
            })?;
            run_credential_store_operation(
                "unreserved",
                "execution nonce reservation capability",
                || Ok(store.supports_dispatch_reservations()),
            )?
        } else {
            false
        };
        Ok(PreparedDispatchCredentials {
            kernel: self,
            input,
            dpop_proof,
            dpop_credential,
            execution_nonce,
            execution_nonce_reservable,
            durable_nonce_presented,
            approval_intent_hash,
        })
    }
}
