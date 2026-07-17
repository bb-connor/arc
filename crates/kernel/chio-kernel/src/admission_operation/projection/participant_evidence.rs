use chio_core::capability::scope::MonetaryAmount;
pub use chio_credit::obligation::ObligationDispositionV1;
#[cfg(test)]
use chio_credit::obligation::{ObligationAtomInputV1, ObligationCreditElectionV1};
use chio_credit::obligation::{
    ObligationAtomV1, ObligationDispositionRecordV1, ObligationDispositionTransitionV1,
};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObligationProjection {
    source: VerifiedTerminalParticipantSourceV1,
    atom: ObligationAtomV1,
    disposition_record: ObligationDispositionRecordV1,
}

impl ObligationProjection {
    pub(crate) fn from_verified_channel_advance(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        tool_outcome: &ToolOutcomeTerminalEvidenceV1,
        advance: &VerifiedChannelTerminalAdvanceV1,
    ) -> Result<Option<Self>, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        let Some(atom) = advance.obligation_atom() else {
            if advance.actual_charge().units != 0
                || advance.obligation_atom_id().is_some()
                || advance.obligation_atom_digest().is_some()
            {
                return Err(mismatch());
            }
            return Ok(None);
        };
        atom.validate().map_err(|_| mismatch())?;
        let atom_digest = AdmissionDigest::try_new(
            "channel_obligation_atom_digest",
            atom.digest().map_err(|_| mismatch())?,
        )?;
        let obligation_id = AdmissionIdentifier::try_new(
            "channel_obligation_atom_id",
            atom.obligation_id().to_owned(),
        )?;
        if advance.actual_charge().units == 0
            || advance.obligation_atom_id() != Some(obligation_id.as_str())
            || advance.obligation_atom_digest() != Some(atom_digest.as_str())
            || atom.amount() != advance.actual_charge()
            || atom.source_receipt_id() != receipt.receipt().id
            || atom.source_receipt_digest() != receipt_digest(receipt.receipt())?.as_str()
            || atom.pre_action_authority_digest() != advance.reservation_digest()
        {
            return Err(mismatch());
        }
        validate_obligation_terms(
            atom.amount(),
            atom.due_at_unix_ms(),
            atom.created_at_unix_ms(),
        )?;
        let disposition_record = ObligationDispositionRecordV1::produced(atom)
            .and_then(|produced| {
                produced.advance(
                    atom,
                    ObligationDispositionTransitionV1::ReserveChannel {
                        channel_id: advance.channel_id().to_owned(),
                        reservation_id: advance.reservation_id().to_owned(),
                        authority_digest: advance.reservation_digest().to_owned(),
                    },
                )
            })
            .map_err(|_| mismatch())?;
        let projection = Self {
            source: VerifiedTerminalParticipantSourceV1::from_source_verified(
                operation,
                context,
                receipt,
                AdmissionDigest::try_new(
                    "channel_obligation_source_authority_digest",
                    atom.pre_action_authority_digest().to_owned(),
                )?,
                obligation_id,
                atom_digest,
                atom.created_at_unix_ms(),
                tool_outcome.outcome_id().clone(),
                tool_outcome.outcome_version(),
            )?,
            atom: atom.clone(),
            disposition_record,
        };
        projection.validate_against(
            operation,
            context,
            receipt,
            tool_outcome.outcome_id(),
            tool_outcome.outcome_version(),
        )?;
        Ok(Some(projection))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_source_verified(
        operation: &AdmissionOperationV1,
        context: &AdmissionProjectionContext,
        receipt: &VerifiedAdmissionReceipt,
        debtor_id: AdmissionIdentifier,
        original_creditor_id: AdmissionIdentifier,
        amount: MonetaryAmount,
        due_at_unix_ms: u64,
        disposition: ObligationDispositionV1,
        source_authority_digest: AdmissionDigest,
        outcome_id: AdmissionDigest,
        outcome_version: u64,
    ) -> Result<Self, AdmissionOperationError> {
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        let receipt_digest = receipt_digest(receipt.receipt())?;
        let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
            economic_intent_digest: operation
                .binding()
                .request_binding_hash()
                .as_str()
                .to_owned(),
            source_receipt_id: receipt.receipt().id.clone(),
            source_receipt_digest: receipt_digest.as_str().to_owned(),
            debtor_id: debtor_id.as_str().to_owned(),
            original_creditor_id: original_creditor_id.as_str().to_owned(),
            original_settlement_destination_ref: format!(
                "settlement:{}",
                original_creditor_id.as_str()
            ),
            payee_binding_digest: source_authority_digest.as_str().to_owned(),
            amount,
            credit_election: ObligationCreditElectionV1::NotCredit,
            pre_action_authority_digest: source_authority_digest.as_str().to_owned(),
            created_at_unix_ms: context.trusted_time_unix_ms,
            due_at_unix_ms,
        })
        .map_err(|_| mismatch())?;
        let disposition_record =
            ObligationDispositionRecordV1::produced(&atom).map_err(|_| mismatch())?;
        if disposition_record.disposition() != &disposition {
            return Err(mismatch());
        }
        validate_obligation_terms(
            atom.amount(),
            atom.due_at_unix_ms(),
            atom.created_at_unix_ms(),
        )?;
        let obligation_id =
            AdmissionIdentifier::try_new("obligation_id", atom.obligation_id().to_owned())?;
        let obligation_atom_digest = AdmissionDigest::try_new(
            "obligation_atom_digest",
            atom.digest()
                .map_err(|_| AdmissionOperationError::TerminalProjectionBindingMismatch)?,
        )?;
        Ok(Self {
            source: VerifiedTerminalParticipantSourceV1::from_source_verified(
                operation,
                context,
                receipt,
                source_authority_digest,
                obligation_id,
                obligation_atom_digest,
                atom.created_at_unix_ms(),
                outcome_id,
                outcome_version,
            )?,
            atom,
            disposition_record,
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
        let mismatch = || AdmissionOperationError::TerminalProjectionBindingMismatch;
        self.atom.validate().map_err(|_| mismatch())?;
        self.disposition_record
            .validate_against(&self.atom)
            .map_err(|_| mismatch())?;
        validate_obligation_terms(
            self.atom.amount(),
            self.atom.due_at_unix_ms(),
            self.atom.created_at_unix_ms(),
        )?;
        if self.source.source_recorded_at_unix_ms > context.trusted_time_unix_ms
            || self.source.source_record_id.as_str() != self.atom.obligation_id()
            || self.source.source_record_digest.as_str()
                != self.atom.digest().map_err(|_| mismatch())?
            || self.source.source_authority_digest.as_str()
                != self.atom.pre_action_authority_digest()
            || self.disposition_record.obligation_id() != self.atom.obligation_id()
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch);
        }
        self.source
            .validate_against(operation, context, receipt, outcome_id, outcome_version)
    }

    pub(in crate::admission_operation) fn obligation_id(&self) -> &AdmissionIdentifier {
        &self.source.source_record_id
    }

    pub(in crate::admission_operation) fn atom_digest(&self) -> &AdmissionDigest {
        &self.source.source_record_digest
    }

    #[cfg(test)]
    pub(crate) const fn atom(&self) -> &ObligationAtomV1 {
        &self.atom
    }

    #[cfg(test)]
    pub(crate) const fn disposition_record(&self) -> &ObligationDispositionRecordV1 {
        &self.disposition_record
    }

    pub(in crate::admission_operation) const fn amount(&self) -> &MonetaryAmount {
        self.atom.amount()
    }

    pub(in crate::admission_operation) const fn disposition(&self) -> &ObligationDispositionV1 {
        self.disposition_record.disposition()
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
