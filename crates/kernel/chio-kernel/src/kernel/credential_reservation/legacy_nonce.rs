//! Non-reservable replay stores cross an irreversible boundary exactly once.

use super::*;

pub(super) enum LegacyExecutionNonce {
    NotPresented,
    Pending { nonce_id: String, expires_at: i64 },
    Retained,
    Rejected,
    OutcomeUnknown,
}

impl LegacyExecutionNonce {
    pub(super) fn discard_unconsumed(&mut self) {
        if matches!(self, Self::Pending { .. }) {
            *self = Self::NotPresented;
        }
    }

    pub(super) fn disposition(&self) -> PaymentCredentialDisposition {
        match self {
            Self::NotPresented | Self::Pending { .. } => PaymentCredentialDisposition::NonePresent,
            Self::Retained => PaymentCredentialDisposition::RetainedAfterAuthorization,
            // Rejection does not prove this attempt owns the existing marker.
            Self::Rejected | Self::OutcomeUnknown => {
                PaymentCredentialDisposition::RetentionOutcomeUnknown
            }
        }
    }
}

impl DispatchCredentialReservation<'_> {
    /// A failed callback stays failed, even if a legacy store consumed its
    /// marker before returning an error. Neither retry nor Drop resends it.
    pub(crate) fn reserve_legacy_execution_nonce_at_effect_boundary(
        &mut self,
    ) -> Result<(), KernelError> {
        let pending = std::mem::replace(
            &mut self.legacy_execution_nonce,
            LegacyExecutionNonce::OutcomeUnknown,
        );
        let (nonce_id, expires_at) = match pending {
            LegacyExecutionNonce::Pending {
                nonce_id,
                expires_at,
            } => (nonce_id, expires_at),
            state @ (LegacyExecutionNonce::NotPresented | LegacyExecutionNonce::Retained) => {
                self.legacy_execution_nonce = state;
                return Ok(());
            }
            LegacyExecutionNonce::Rejected => {
                self.legacy_execution_nonce = LegacyExecutionNonce::Rejected;
                return Err(rejected());
            }
            LegacyExecutionNonce::OutcomeUnknown => {
                return Err(KernelError::Internal(
                    "legacy execution nonce consumption outcome remains unknown".into(),
                ));
            }
        };
        let store = self
            .kernel
            .execution_nonce_store
            .as_deref()
            .ok_or_else(|| {
                KernelError::Internal("execution nonce store disappeared before dispatch".into())
            })?;
        match run_credential_store_operation(
            &self.reservation_id,
            "legacy execution nonce reservation",
            || store.reserve_until(&nonce_id, expires_at),
        ) {
            Ok(true) => {
                self.legacy_execution_nonce = LegacyExecutionNonce::Retained;
                Ok(())
            }
            Ok(false) => {
                self.legacy_execution_nonce = LegacyExecutionNonce::Rejected;
                Err(rejected())
            }
            Err(error) => Err(KernelError::Internal(format!(
                "legacy execution nonce reservation failed; consumption outcome unknown: {error}"
            ))),
        }
    }
}

fn rejected() -> KernelError {
    KernelError::Internal("execution nonce has already been consumed".into())
}
