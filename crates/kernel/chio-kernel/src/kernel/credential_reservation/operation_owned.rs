//! Connect selected-grant admission to origin-bound DPoP and approval custody.
//! Terminal treaty replay deliberately does not use this acquisition path.

use super::*;

impl ChioKernel {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_pre_budget_admission(
        &self,
        request: &ToolCallRequest,
        security_context: Option<&SecurityInvocationContext>,
        metadata: Option<&serde_json::Value>,
        now: u64,
        now_unix_ms: u64,
        grant_index: usize,
        dpop_required: bool,
        mut admission: Option<&mut DurableToolAdmission>,
    ) -> RuntimeAdmissionDecision {
        if let Err(error) = self.validate_live_admission_authority_profile(admission.as_deref()) {
            return RuntimeAdmissionDecision::deny(error.to_string(), None);
        }
        let prepared = if (self.governed_approval_authority.is_some()
            && request.approval_token.is_some())
            || (self.dpop_authority.is_some() && dpop_required)
        {
            let Some(operation) = admission.as_deref() else {
                return RuntimeAdmissionDecision::deny(
                    "operation-owned credentials require durable admission",
                    None,
                );
            };
            // Prepare all one-shot credentials before either the runtime hook
            // or approval participant can acquire this grant's replay markers.
            match self.prepare_dispatch_credentials(
                request,
                &request.capability,
                dpop_required,
                now,
                operation.requires_execution_nonce(),
            ) {
                Ok(prepared) => Some(prepared),
                Err(error) => return RuntimeAdmissionDecision::deny(error.to_string(), None),
            }
        } else {
            None
        };
        let native_preparation = if admission.as_deref().is_some_and(|operation| {
            operation.requires_execution_nonce()
                && operation.operation.state()
                    == crate::admission_operation::AdmissionOperationState::Prepared
        }) {
            self.run_native_nonce_preflight_preparation(
                request,
                security_context,
                admission.as_deref(),
                now_unix_ms,
            )
        } else {
            self.run_native_admission_preparation(
                request,
                security_context,
                admission.as_deref(),
                now_unix_ms,
            )
        };
        if let Err(error) = native_preparation {
            return RuntimeAdmissionDecision::deny(error.to_string(), None);
        }
        let decision = self.run_runtime_admission_hook(
            request,
            metadata,
            now,
            now_unix_ms,
            Some(grant_index),
            admission.as_deref_mut(),
        );
        if !decision.allowed {
            return decision;
        }
        if let Some(prepared) = prepared {
            let result = admission
                .ok_or_else(|| {
                    KernelError::DurableAdmission("credential admission disappeared".into())
                })
                .and_then(|admission| {
                    prepared.claim_for_admission(admission, grant_index, now_unix_ms)
                });
            if let Err(error) = result {
                return RuntimeAdmissionDecision::deny(error.to_string(), decision.metadata);
            }
        }
        decision
    }

    pub(crate) fn reserve_admitted_dispatch_credentials(
        &self,
        request: &ToolCallRequest,
        dpop_required: bool,
        now: u64,
        admission: Option<&DurableToolAdmission>,
        grant_index: usize,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.prepare_dispatch_credentials(
            request,
            &request.capability,
            dpop_required,
            now,
            admission.is_some_and(DurableToolAdmission::requires_execution_nonce),
        )?
        .reserve_for_admission(admission, grant_index)
    }

    pub(crate) fn reserve_admitted_caller_credentials(
        &self,
        request: &ToolCallRequest,
        dpop_required: bool,
        now: u64,
        admission: Option<&DurableToolAdmission>,
        grant_index: usize,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.prepare_credentials(CredentialPreparationInput {
            request,
            cap: &request.capability,
            dpop_required,
            now,
            execution_nonce_credential: ExecutionNonceCredential::NotPresented,
            require_governed_approval: Self::is_governed_mustprepay_request(request),
        })?
        .reserve_for_admission(admission, grant_index)
    }
}

impl<'kernel> PreparedDispatchCredentials<'kernel, '_> {
    /// Consume the request-bound preparation once for this selected-grant
    /// episode. A second participant sees the updated operation version and
    /// obtains its own exact-version lease; failure leaves cleanup to the saga.
    fn claim_for_admission(
        self,
        admission: &mut DurableToolAdmission,
        grant_index: usize,
        now: u64,
    ) -> Result<(), KernelError> {
        let prepared = if self.dpop_credential.is_some() {
            self.refresh()?
        } else {
            self
        };
        if prepared.dpop_credential.is_some() {
            prepared
                .kernel
                .claim_prepared_dpop(&prepared, admission, grant_index, now)?;
        }
        if prepared.kernel.governed_approval_authority.is_some()
            && prepared.approval_intent_hash.is_some()
        {
            prepared.kernel.claim_prepared_governed_approval(
                prepared,
                admission,
                grant_index,
                now,
            )?;
        }
        Ok(())
    }

    fn reserve_for_admission(
        self,
        admission: Option<&DurableToolAdmission>,
        grant_index: usize,
    ) -> Result<DispatchCredentialReservation<'kernel>, KernelError> {
        let prepared = self.refresh()?;
        let owned = if prepared.kernel.governed_approval_authority.is_some() {
            prepared
                .approval_credential()?
                .map(|credential| {
                    let admission =
                        admission.ok_or_else(|| {
                            KernelError::DurableAdmission(
                    "operation-owned approval cannot fall back to the legacy replay store".into())
                        })?;
                    prepared.kernel.verify_owned_governed_approval(
                        admission,
                        &prepared,
                        &credential,
                        grant_index,
                    )
                })
                .transpose()?
        } else {
            None
        };
        let owned_dpop = prepared
            .dpop_credential()
            .map(|credential| {
                let admission = admission.ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "operation-owned DPoP cannot fall back to the legacy replay store".into(),
                    )
                })?;
                prepared
                    .kernel
                    .verify_owned_dpop(admission, &prepared, credential, grant_index)
            })
            .transpose()?;
        prepared.reserve_checked(owned, owned_dpop)
    }
}
