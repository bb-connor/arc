use super::*;
use chio_log_redact::redacted;

#[path = "credential_reservation/acquisition.rs"]
mod acquisition;
#[path = "credential_reservation/legacy_nonce.rs"]
mod legacy_nonce;
mod native_dispatch;
#[path = "credential_reservation/operation_owned.rs"]
mod operation_owned;
#[path = "credential_reservation/preparation.rs"]
mod preparation;

pub use native_dispatch::VerifiedNativeDispatchCredentials;

use legacy_nonce::LegacyExecutionNonce;
use preparation::CredentialPreparationInput;
pub(crate) use preparation::PreparedDispatchCredentials;

fn run_credential_store_operation<T>(
    reservation_id: &str,
    operation_name: &'static str,
    operation: impl FnOnce() -> Result<T, KernelError>,
) -> Result<T, KernelError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)) {
        Ok(result) => result,
        Err(_) => {
            tracing::warn!(
                reservation_id,
                operation = operation_name,
                "dispatch credential store operation panicked; denying fail-closed"
            );
            Err(KernelError::Internal(format!(
                "dispatch credential {operation_name} panicked; denying fail-closed"
            )))
        }
    }
}

/// How a presented execution nonce participates in dispatch credentials.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecutionNonceCredential {
    /// Validate and reserve the nonce in the legacy replay store.
    LegacyReplayStore,
    /// The durable admission operation owns the nonce; the store already
    /// verified it and reserves it atomically with the operation.
    DurableParticipant,
    /// A reserve-for-caller preflight mints a nonce and presents none.
    NotPresented,
}

impl ExecutionNonceCredential {
    fn for_dispatch(durable_execution_nonce: bool) -> Self {
        if durable_execution_nonce {
            Self::DurableParticipant
        } else {
            Self::LegacyReplayStore
        }
    }
}

pub(crate) struct DispatchCredentialReservation<'a> {
    kernel: &'a ChioKernel,
    reservation_id: String,
    dpop_key: Option<(String, String)>,
    owned_dpop: Option<crate::admission_operation::dpop_claim::DpopReplayClaimReferenceV1>,
    execution_nonce_id: Option<String>,
    legacy_execution_nonce: LegacyExecutionNonce,
    execution_nonce_present: bool,
    approval_key: Option<(String, String, String)>,
    owned_approval: Option<
        crate::admission_operation::governed_approval_claim::GovernedApprovalClaimReferenceV1,
    >,
    credentials_present: bool,
    rollback_on_drop: bool,
    retain_on_drop: bool,
}

impl DispatchCredentialReservation<'_> {
    /// Retain replay markers once entering the durable dispatch commitment or
    /// tool effect boundary. A dropped evaluation cannot then prove nonexecution.
    pub(crate) fn retain_if_dropped(
        &mut self,
    ) -> Result<PaymentCredentialDisposition, KernelError> {
        // Keep owned reservations reversible until dispatch starts. Once the
        // server is polled, neither a dropped future nor a server-controlled
        // URL-elicitation result can prove that no side effect occurred. Drop
        // therefore promotes the governed approval marker and leaves owned
        // nonce reservations in their fail-closed state.
        self.rollback_on_drop = false;
        self.retain_on_drop = true;
        // A legacy execution nonce store has no owned reservation state. Its
        // marker must be consumed before entering the effect boundary and
        // cannot participate in pre-effect rollback.
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        Ok(self.retention_disposition())
    }

    /// Retain replay markers after an external authorization has already been
    /// acknowledged. At this point retrying could duplicate a payment hold or
    /// minted authority, so the governed approval marker must be promoted
    /// before the evaluation can continue.
    pub(crate) fn retain_after_external_authorization(
        &mut self,
    ) -> Result<PaymentCredentialDisposition, KernelError> {
        self.rollback_on_drop = false;
        self.retain_on_drop = true;
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        self.commit_approval_marker()?;
        Ok(self.retention_disposition())
    }

    pub(crate) fn requires_post_reservation_revalidation(&self) -> bool {
        self.credentials_present
    }

    pub(crate) fn has_payment_authorization_credential(&self) -> bool {
        self.execution_nonce_present || self.approval_key.is_some() || self.owned_approval.is_some()
    }

    pub(crate) fn commit(&mut self) -> Result<PaymentCredentialDisposition, KernelError> {
        // Clear rollback before the first fallible retention operation. On an
        // uncertain failure, keeping every owned marker is the safe direction.
        self.rollback_on_drop = false;
        self.retain_on_drop = false;
        self.reserve_legacy_execution_nonce_at_effect_boundary()?;
        self.commit_approval_marker()?;
        Ok(self.retention_disposition())
    }

    /// Report which credentials an established retention boundary owns.
    /// This does not perform retention or infer custody from a payment alone.
    pub(crate) fn retention_disposition(&self) -> PaymentCredentialDisposition {
        if self.credentials_present {
            PaymentCredentialDisposition::RetainedAfterAuthorization
        } else {
            PaymentCredentialDisposition::NonePresent
        }
    }

    fn commit_approval_marker(&mut self) -> Result<(), KernelError> {
        let Some((subject_id, request_id, intent_hash)) = self.approval_key.as_ref() else {
            return Ok(());
        };
        let result = match self.kernel.approval_replay_store.as_deref() {
            Some(store) => run_credential_store_operation(
                &self.reservation_id,
                "governed approval reservation commit",
                || {
                    store.commit_dispatch_reservation(
                        subject_id,
                        request_id,
                        intent_hash,
                        &self.reservation_id,
                    )
                },
            ),
            None => Err(KernelError::GovernedTransactionDenied(
                "approval replay store disappeared during dispatch commit; marker retained fail-closed"
                    .to_string(),
            )),
        };
        match result {
            Ok(true) => {
                self.approval_key = None;
                Ok(())
            }
            Ok(false) => Err(KernelError::GovernedTransactionDenied(
                "governed approval reservation ownership was not confirmed during commit; marker retention outcome unknown"
                    .to_string(),
            )),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn rollback_before_dispatch(self) -> Result<(), KernelError> {
        match self.rollback_before_dispatch_with_disposition()? {
            PaymentCredentialDisposition::NonePresent => Ok(()),
            _ => Err(KernelError::Internal(
                "irreversible legacy nonce retention remains after credential rollback".into(),
            )),
        }
    }

    pub(crate) fn rollback_before_dispatch_with_disposition(
        mut self,
    ) -> Result<PaymentCredentialDisposition, KernelError> {
        self.rollback_on_drop = false;
        self.retain_on_drop = false;
        self.rollback_entries()?;
        Ok(self.legacy_execution_nonce.disposition())
    }

    fn rollback_entries(&mut self) -> Result<(), KernelError> {
        let mut failures = Vec::new();

        // Only a pending legacy nonce is discardable. Confirmed consumption or
        // a lost acknowledgement remains explicit: this API has no owned undo.
        self.legacy_execution_nonce.discard_unconsumed();

        if let Some(reference) = self.owned_approval.take() {
            if let Err(error) = self
                .kernel
                .release_exact_governed_approval_reservation(&reference)
            {
                failures.push(error.to_string());
            }
        }

        if let Some(reference) = self.owned_dpop.take() {
            if let Err(error) = self.kernel.release_exact_dpop_reservation(&reference) {
                failures.push(error.to_string());
            }
        }

        if let Some((subject_id, request_id, intent_hash)) = self.approval_key.take() {
            let result = match self.kernel.approval_replay_store.as_deref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "governed approval reservation rollback",
                    || {
                        store.rollback_dispatch_reservation(
                            &subject_id,
                            &request_id,
                            &intent_hash,
                            &self.reservation_id,
                        )
                    },
                ),
                None => Err(KernelError::GovernedTransactionDenied(
                    "approval replay store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures.push(
                    "governed approval dispatch reservation was not owned during rollback"
                        .to_string(),
                ),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if let Some(nonce_id) = self.execution_nonce_id.take() {
            let result = match self.kernel.execution_nonce_store.as_deref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "execution nonce reservation rollback",
                    || store.rollback_dispatch_reservation(&nonce_id, &self.reservation_id),
                ),
                None => Err(KernelError::Internal(
                    "execution nonce store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures.push(
                    "execution nonce dispatch reservation was not owned during rollback"
                        .to_string(),
                ),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if let Some((nonce, capability_id)) = self.dpop_key.take() {
            let result = match self.kernel.dpop_nonce_store.as_ref() {
                Some(store) => run_credential_store_operation(
                    &self.reservation_id,
                    "DPoP nonce reservation rollback",
                    || {
                        store.rollback_dispatch_reservation(
                            &nonce,
                            &capability_id,
                            &self.reservation_id,
                        )
                    },
                ),
                None => Err(KernelError::DpopVerificationFailed(
                    "DPoP nonce store disappeared during dispatch rollback".to_string(),
                )),
            };
            match result {
                Ok(true) => {}
                Ok(false) => failures
                    .push("DPoP dispatch reservation was not owned during rollback".to_string()),
                Err(error) => failures.push(error.to_string()),
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(KernelError::Internal(format!(
                "dispatch credential rollback failed: {}",
                failures.join("; ")
            )))
        }
    }
}

impl Drop for DispatchCredentialReservation<'_> {
    fn drop(&mut self) {
        if self.retain_on_drop {
            if let Err(error) = self.reserve_legacy_execution_nonce_at_effect_boundary() {
                tracing::warn!(
                    reason = %redacted!(&error),
                    "legacy dispatch credential retention failed while dropping an evaluation"
                );
            }
            if let Err(error) = self.commit_approval_marker() {
                tracing::warn!(
                    reason = %redacted!(&error),
                    "governed dispatch credential retention failed while dropping an evaluation"
                );
            }
            return;
        }
        if !self.rollback_on_drop {
            return;
        }
        if let Err(error) = self.rollback_entries() {
            tracing::warn!(
                reason = %redacted!(&error),
                "dispatch credential rollback failed while dropping an evaluation"
            );
        }
    }
}

impl ChioKernel {
    /// `durable_execution_nonce` marks a request whose nonce is owned by the
    /// durable admission operation. The store verified it before any mutation
    /// and reserves it atomically with `ReadyToDispatch`, so the legacy replay
    /// store must not consume or roll back that nonce.
    #[cfg(test)]
    pub(crate) fn reserve_dispatch_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
        durable_execution_nonce: bool,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.prepare_dispatch_credentials(
            request,
            cap,
            dpop_required,
            now,
            durable_execution_nonce,
        )?
        .reserve()
    }

    /// Reserve the credentials presented to a reserve-for-caller authorization.
    ///
    /// No execution nonce exists yet on this preflight. DPoP and governed
    /// approval credentials are nevertheless authorizing this request to mint
    /// one, so they use the same owned commit/rollback lifecycle as normal
    /// dispatch credentials. This prevents concurrent authorization replays
    /// without burning a credential when later admission revalidation denies.
    #[cfg(test)]
    pub(crate) fn reserve_caller_authorization_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
        require_governed_approval: bool,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.reserve_credentials(
            request,
            cap,
            dpop_required,
            now,
            ExecutionNonceCredential::NotPresented,
            require_governed_approval,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn reserve_credentials(
        &self,
        request: &ToolCallRequest,
        cap: &CapabilityToken,
        dpop_required: bool,
        now: u64,
        execution_nonce_credential: ExecutionNonceCredential,
        require_governed_approval: bool,
    ) -> Result<DispatchCredentialReservation<'_>, KernelError> {
        self.prepare_credentials(CredentialPreparationInput {
            request,
            cap,
            dpop_required,
            now,
            execution_nonce_credential,
            require_governed_approval,
        })?
        .reserve()
    }
}
