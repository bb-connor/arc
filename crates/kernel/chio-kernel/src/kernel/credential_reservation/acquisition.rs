//! Consume a validated credential plan through the existing owned replay
//! reservation lifecycle. Partial failures roll back only this attempt's
//! reversible markers; retention behavior remains in the parent module.

use super::*;

impl<'kernel> PreparedDispatchCredentials<'kernel, '_> {
    pub(super) fn reserve_checked(
        self,
        owned_approval: Option<
            crate::admission_operation::governed_approval_claim::GovernedApprovalClaimReferenceV1,
        >,
        owned_dpop: Option<crate::admission_operation::dpop_claim::DpopReplayClaimReferenceV1>,
    ) -> Result<DispatchCredentialReservation<'kernel>, KernelError> {
        if self.dpop_credential.is_some() != owned_dpop.is_some() {
            return Err(KernelError::DurableAdmission(
                "prepared DPoP requires its exact operation-owned claim".into(),
            ));
        }
        let Self {
            kernel,
            input,
            dpop_proof,
            dpop_credential,
            execution_nonce,
            execution_nonce_reservable,
            durable_nonce_presented,
            approval_intent_hash,
        } = self;
        let request = input.request;
        let mut reservation = DispatchCredentialReservation {
            kernel,
            reservation_id: uuid::Uuid::now_v7().as_hyphenated().to_string(),
            dpop_key: None,
            execution_nonce_id: None,
            legacy_execution_nonce: LegacyExecutionNonce::NotPresented,
            execution_nonce_present: execution_nonce.is_some() || durable_nonce_presented,
            approval_key: None,
            owned_approval,
            owned_dpop,
            credentials_present: dpop_proof.is_some()
                || dpop_credential.is_some()
                || execution_nonce.is_some()
                || durable_nonce_presented
                || approval_intent_hash.is_some(),
            rollback_on_drop: true,
            retain_on_drop: false,
        };

        let result = (|| {
            if let Some(proof) = dpop_proof {
                let store = kernel.dpop_nonce_store.as_ref().ok_or_else(|| {
                    KernelError::DpopVerificationFailed(
                        "kernel DPoP nonce store not configured".to_string(),
                    )
                })?;
                let config = kernel.dpop_config.as_ref().ok_or_else(|| {
                    KernelError::DpopVerificationFailed(
                        "kernel DPoP configuration not installed".to_string(),
                    )
                })?;
                reservation.dpop_key =
                    Some((proof.body.nonce.clone(), proof.body.capability_id.clone()));
                let valid_through = proof.body.issued_at.saturating_add(config.proof_ttl_secs);
                match run_credential_store_operation(
                    &reservation.reservation_id,
                    "DPoP nonce reservation",
                    || {
                        store.reserve_for_dispatch_through(
                            &proof.body.nonce,
                            &proof.body.capability_id,
                            valid_through,
                            &reservation.reservation_id,
                        )
                    },
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        reservation.dpop_key = None;
                        return Err(KernelError::DpopVerificationFailed(
                            "nonce replayed: this nonce has already been used during the proof validity window"
                                .to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }

            if let Some(validated) = execution_nonce {
                let presented = validated.signed();
                let store = kernel.execution_nonce_store.as_deref().ok_or_else(|| {
                    KernelError::Internal("execution nonce store is not installed".to_string())
                })?;
                if execution_nonce_reservable {
                    reservation.execution_nonce_id = Some(presented.nonce.nonce_id.clone());
                    match run_credential_store_operation(
                        &reservation.reservation_id,
                        "execution nonce reservation",
                        || {
                            store.reserve_for_dispatch(
                                &presented.nonce.nonce_id,
                                presented.nonce.expires_at,
                                &reservation.reservation_id,
                            )
                        },
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            reservation.execution_nonce_id = None;
                            return Err(KernelError::Internal(
                                "execution nonce has already been consumed".to_string(),
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    reservation.legacy_execution_nonce = LegacyExecutionNonce::Pending {
                        nonce_id: presented.nonce.nonce_id.clone(),
                        expires_at: presented.nonce.expires_at,
                    };
                }
            }

            if let (Some(approval_token), Some(intent_hash)) = (
                request.approval_token.as_ref(),
                approval_intent_hash.as_ref(),
            ) {
                if reservation.owned_approval.is_some() {
                    return Ok(());
                }
                let store = kernel.approval_replay_store.as_deref().ok_or_else(|| {
                    KernelError::GovernedTransactionDenied(
                        "approval replay store not configured; denying as fail-closed".to_string(),
                    )
                })?;
                reservation.approval_key = Some((
                    approval_token.subject.to_hex(),
                    approval_token.request_id.clone(),
                    intent_hash.to_string(),
                ));
                match run_credential_store_operation(
                    &reservation.reservation_id,
                    "governed approval reservation",
                    || {
                        store.reserve_for_dispatch(
                            &approval_token.subject.to_hex(),
                            &approval_token.request_id,
                            intent_hash,
                            approval_token.expires_at,
                            &reservation.reservation_id,
                        )
                    },
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        reservation.approval_key = None;
                        return Err(KernelError::GovernedTransactionDenied(
                            "approval token has already been consumed (replay detected)"
                                .to_string(),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => Ok(reservation),
            Err(error) => match reservation.rollback_before_dispatch() {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(KernelError::Internal(format!(
                    "dispatch credential reservation failed: {error}; {rollback_error}"
                ))),
            },
        }
    }
}
