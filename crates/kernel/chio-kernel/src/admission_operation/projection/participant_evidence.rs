use chio_core::capability::scope::MonetaryAmount;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct VerifiedTerminalParticipantSourceV1 {
    binding: AdmissionExactProjectionBindingV1,
    source_authority_digest: AdmissionDigest,
    source_record_id: AdmissionIdentifier,
    source_record_digest: AdmissionDigest,
    source_recorded_at_unix_ms: u64,
    consumer_receipt_id: AdmissionIdentifier,
    consumer_receipt_digest: AdmissionDigest,
    outcome_id: AdmissionDigest,
    outcome_version: u64,
}

impl VerifiedTerminalParticipantSourceV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_source_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        source_authority_digest: AdmissionDigest,
        source_record_id: AdmissionIdentifier,
        source_record_digest: AdmissionDigest,
        source_recorded_at_unix_ms: u64,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        let receipt = receipt.receipt();
        validate_positive_ijson("source_recorded_at_unix_ms", source_recorded_at_unix_ms)?;
        validate_positive_ijson("participant_outcome_version", outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(&outcome_id)?;
        if source_recorded_at_unix_ms > context.trusted_time_unix_ms {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(Self {
            binding: AdmissionExactProjectionBindingV1::from_verified(
                operation,
                context,
                AdmissionOperationState::Completed,
            )?,
            source_authority_digest,
            source_record_id,
            source_record_digest,
            source_recorded_at_unix_ms,
            consumer_receipt_id: AdmissionIdentifier::try_new(
                "consumer_receipt_id",
                receipt.id.clone(),
            )?,
            consumer_receipt_digest: receipt_digest(receipt)?,
            outcome_id,
            outcome_version,
        })
    }

    fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: &AdmissionDigest,
        outcome_version: u64,
    ) -> Result<(), AdmissionOperationError> {
        let receipt = receipt.receipt();
        self.binding
            .validate_against(operation, context, AdmissionOperationState::Completed)?;
        validate_positive_ijson(
            "source_recorded_at_unix_ms",
            self.source_recorded_at_unix_ms,
        )?;
        validate_positive_ijson("participant_outcome_version", self.outcome_version)?;
        operation.validate_completed_tool_outcome_attachment(outcome_id)?;
        if self.source_recorded_at_unix_ms > context.trusted_time_unix_ms
            || self.consumer_receipt_id.as_str() != receipt.id
            || self.consumer_receipt_digest != receipt_digest(receipt)?
            || self.outcome_id != *outcome_id
            || self.outcome_version != outcome_version
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        Ok(())
    }
}

macro_rules! attached_terminal_participant {
    ($name:ident, $field:ident, $ty:ty, $kind:ident, $variant:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        pub struct $name {
            source: VerifiedTerminalParticipantSourceV1,
            $field: $ty,
        }

        impl $name {
            #[allow(clippy::too_many_arguments, dead_code)]
            pub(crate) fn from_source_verified(
                operation: &AdmissionOperationV1,
                context: &AdmissionProjectionContext,
                receipt: &VerifiedAdmissionReceipt,
                $field: $ty,
                source_authority_digest: AdmissionDigest,
                source_record_id: AdmissionIdentifier,
                source_record_digest: AdmissionDigest,
                source_recorded_at_unix_ms: u64,
                outcome_id: AdmissionDigest,
                outcome_version: u64,
            ) -> Result<Self, AdmissionOperationError> {
                if !matches!(
                    operation.attachment(AdmissionAttachmentKind::$kind),
                    Some(AdmissionAttachment::$variant(expected)) if expected == &$field
                ) {
                    return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                }
                Ok(Self {
                    source: VerifiedTerminalParticipantSourceV1::from_source_verified(
                        operation,
                        context,
                        receipt,
                        source_authority_digest,
                        source_record_id,
                        source_record_digest,
                        source_recorded_at_unix_ms,
                        outcome_id,
                        outcome_version,
                    )?,
                    $field,
                })
            }

            pub(in crate::admission_operation) fn validate_against(
                &self,
                operation: &AdmissionOperationV1,
                context: &AdmissionProjectionContext,
                receipt: &VerifiedAdmissionReceipt,
                outcome_id: &AdmissionDigest,
                outcome_version: u64,
            ) -> Result<(), AdmissionOperationError> {
                if !matches!(
                    operation.attachment(AdmissionAttachmentKind::$kind),
                    Some(AdmissionAttachment::$variant(expected)) if expected == &self.$field
                ) {
                    return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
                }
                self.source.validate_against(
                    operation,
                    context,
                    receipt,
                    outcome_id,
                    outcome_version,
                )
            }
        }
    };
}

attached_terminal_participant!(
    PaymentTerminalEvidence,
    payment_participant_id,
    AdmissionIdentifier,
    PaymentParticipant,
    PaymentParticipantId
);
attached_terminal_participant!(
    OutcomeEligibilityFinalization,
    outcome_eligibility_digest,
    AdmissionDigest,
    OutcomeEligibility,
    OutcomeEligibilityDigest
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationDispositionV1 {
    PerCall,
    Assigned,
    Channelized,
    ClearingReserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObligationProjection {
    source: VerifiedTerminalParticipantSourceV1,
    debtor_id: AdmissionIdentifier,
    original_creditor_id: AdmissionIdentifier,
    amount: MonetaryAmount,
    due_at_unix_ms: u64,
    disposition: ObligationDispositionV1,
}

impl ObligationProjection {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn from_source_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        obligation_id: AdmissionIdentifier,
        obligation_atom_digest: AdmissionDigest,
        debtor_id: AdmissionIdentifier,
        original_creditor_id: AdmissionIdentifier,
        amount: MonetaryAmount,
        due_at_unix_ms: u64,
        disposition: ObligationDispositionV1,
        source_authority_digest: AdmissionDigest,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        validate_obligation_terms(&amount, due_at_unix_ms, context.trusted_time_unix_ms)?;
        Ok(Self {
            source: VerifiedTerminalParticipantSourceV1::from_source_verified(
                operation,
                context,
                receipt,
                source_authority_digest,
                obligation_id,
                obligation_atom_digest,
                context.trusted_time_unix_ms,
                outcome_id,
                outcome_version,
            )?,
            debtor_id,
            original_creditor_id,
            amount,
            due_at_unix_ms,
            disposition,
        })
    }

    pub(in crate::admission_operation) fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        outcome_id: &AdmissionDigest,
        outcome_version: u64,
    ) -> Result<(), AdmissionOperationError> {
        validate_obligation_terms(
            &self.amount,
            self.due_at_unix_ms,
            self.source.source_recorded_at_unix_ms,
        )?;
        if self.source.source_recorded_at_unix_ms != context.trusted_time_unix_ms {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        self.source
            .validate_against(operation, context, receipt, outcome_id, outcome_version)
    }
}

fn validate_obligation_terms(
    amount: &MonetaryAmount,
    due_at_unix_ms: u64,
    created_at_unix_ms: u64,
) -> Result<(), AdmissionOperationError> {
    validate_positive_ijson("obligation_amount_units", amount.units)?;
    validate_positive_ijson("obligation_due_at_unix_ms", due_at_unix_ms)?;
    if amount.currency.len() != 3
        || !amount
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
        || due_at_unix_ms <= created_at_unix_ms
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
    }
    Ok(())
}
