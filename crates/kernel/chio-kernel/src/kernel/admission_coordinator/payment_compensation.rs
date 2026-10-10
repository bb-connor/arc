//! Resume the original no-effect release or refund before budget compensation.

use super::recovery::failure::{item_failure, payment_error, payment_record_error};
use super::*;
use crate::admission_operation::AdmissionRecoveryFailureKind as FailureKind;
use crate::payment::{
    PaymentJournalRecord, PaymentJournalState, PaymentJournalTransition, PaymentRailMode,
    PaymentReleaseAuthorityKind, PaymentSettleAction, PreDispatchPaymentUnwindStatus,
    RailSettlementStatus,
};

#[path = "payment_compensation/authorization.rs"]
mod authorization;

pub(super) struct DurablePaymentCompensationInput<'a> {
    pub(super) operation: &'a AdmissionOperationV1,
    pub(super) runtime: &'a DurableAdmissionRuntime,
    pub(super) lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    pub(super) context: &'a AdmissionProjectionContext,
    pub(super) verifier_policy: &'a serde_json::Value,
    pub(super) confirmed_unwind: Option<&'a PreDispatchPaymentUnwindEvidence>,
    pub(super) trusted_now_unix_ms: u64,
}

impl ChioKernel {
    pub(super) fn compensate_retained_payment(
        &self,
        input: DurablePaymentCompensationInput<'_>,
    ) -> Result<(), KernelError> {
        let operation = input.operation;
        if operation
            .attachment(crate::admission_operation::AdmissionAttachmentKind::PaymentParticipant)
            .is_none()
        {
            return Ok(());
        }
        let mut journal = input
            .runtime
            .store
            .load_payment_journal(
                operation.binding().operation_id().as_str(),
                &input.runtime.fence,
            )
            .map_err(super::recovery::failure::payment_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("pre-dispatch payment journal disappeared".into())
            })?;
        journal.validate().map_err(payment_record_error)?;
        if journal.operation_id != operation.binding().operation_id().as_str()
            || journal.capability_id != operation.binding().capability_id().as_str()
            || journal.request_id != operation.binding().request_id().as_str()
            || journal.request_namespace_digest
                != operation.binding().request_namespace_digest().as_str()
            || journal.hold_id.as_deref() != operation.budget_hold_id().map(|id| id.as_str())
        {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch payment changed its original operation binding".into(),
            ));
        }
        let mut recovered_unwind = None;
        if journal.state == PaymentJournalState::HoldPlaced {
            let (recovered, unwind) =
                self.recover_pre_dispatch_payment_authorization(&input, journal)?;
            journal = recovered;
            recovered_unwind = unwind;
        }
        let confirmed = input.confirmed_unwind.or(recovered_unwind.as_ref());
        let compensated = journal.is_compensated_before_dispatch();
        if journal.rail_mode == PaymentRailMode::PrepaidFinal
            && journal.authorized_amount_units.is_none()
            && (!compensated || journal.authorization_id.is_some())
        {
            return Err(item_failure(
                FailureKind::LegacyPaymentAmountAbsent,
                "legacy prepayment has no exact debit or whole-debit unwind evidence",
            ));
        }
        if compensated {
            return Ok(());
        }
        if let Some(unwind) = confirmed {
            validate_confirmed_unwind(&journal, unwind)?;
        }
        let transition = match (journal.rail_mode, journal.state) {
            (PaymentRailMode::ReversibleHold, PaymentJournalState::Authorized)
            | (PaymentRailMode::PrepaidFinal, PaymentJournalState::Settled) => {
                let proof = crate::tool_outcome::VerifiedPreDispatchNoEffect::from_qualified_released_operation_snapshot(
                    operation, input.context, input.verifier_policy.clone(),
                ).map_err(tool_outcome_error)?;
                let evidence = crate::tool_outcome::MonetaryReleaseAuthority::NoEffect(
                    crate::tool_outcome::VerifiedNoEffectProof::BeforeDispatch(proof),
                )
                .evidence_bundle()
                .map_err(tool_outcome_error)?;
                let persisted = evidence.to_persisted();
                let authority = crate::payment::PaymentReleaseAuthorityBinding {
                    kind: PaymentReleaseAuthorityKind::PreDispatchNoEffect,
                    operation_id: persisted.operation_id.as_str().to_owned(),
                    operation_version: persisted.operation_version,
                    evidence_id: persisted.evidence_id.as_str().to_owned(),
                    evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                };
                let transition = match journal.rail_mode {
                    PaymentRailMode::ReversibleHold => {
                        PaymentJournalTransition::BeginRelease { authority }
                    }
                    PaymentRailMode::PrepaidFinal => {
                        PaymentJournalTransition::BeginPrepaymentRefund { authority }
                    }
                };
                journal = self.advance_compensation_payment(
                    &input,
                    &journal,
                    &transition,
                    Some(&evidence),
                )?;
                true
            }
            (_, PaymentJournalState::Settling | PaymentJournalState::ReconcileFailed) => true,
            _ => false,
        };
        if !transition || !pre_dispatch_unwind_intent(&journal) {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch payment has no replayable no-effect unwind intent".into(),
            ));
        }
        let authorization_id = journal.authorization_id.as_deref().ok_or_else(|| {
            KernelError::DurableAdmission("pre-dispatch payment omitted authorization_id".into())
        })?;
        let transaction_id = if let Some(unwind) = confirmed {
            unwind.transaction_id.clone()
        } else {
            let adapter = self.compensation_payment_adapter(&journal)?;
            let result =
                run_payment_adapter_operation("pre-dispatch unwind", || match journal.rail_mode {
                    PaymentRailMode::ReversibleHold => {
                        adapter.release(authorization_id, &journal.operation_id)
                    }
                    PaymentRailMode::PrepaidFinal => adapter.refund(
                        authorization_id,
                        journal.authorized_amount_units.ok_or_else(|| {
                            PaymentError::RailError("original prepayment debit is absent".into())
                        })?,
                        &journal.currency,
                        &journal.operation_id,
                    ),
                })
                .map_err(payment_error)?;
            let expected_status = match journal.rail_mode {
                PaymentRailMode::ReversibleHold => RailSettlementStatus::Released,
                PaymentRailMode::PrepaidFinal => RailSettlementStatus::Refunded,
            };
            if result.settlement_status != expected_status {
                return Err(item_failure(
                    if result.settlement_status == RailSettlementStatus::Pending {
                        FailureKind::PaymentPending
                    } else {
                        FailureKind::ContractChanged
                    },
                    "pre-dispatch rail unwind was not confirmed",
                ));
            }
            result.transaction_id
        };
        validate_payment_adapter_identifier(&transaction_id, "pre-dispatch unwind transaction_id")
            .map_err(payment_error)?;
        let transition = match journal.rail_mode {
            PaymentRailMode::ReversibleHold => {
                PaymentJournalTransition::SettlementCompleted { transaction_id }
            }
            PaymentRailMode::PrepaidFinal => {
                PaymentJournalTransition::PrepaymentRefunded { transaction_id }
            }
        };
        journal = self.advance_compensation_payment(&input, &journal, &transition, None)?;
        if !journal.is_compensated_before_dispatch() {
            return Err(KernelError::DurableAdmission(
                "pre-dispatch payment unwind is not durable".into(),
            ));
        }
        Ok(())
    }

    fn advance_compensation_payment(
        &self,
        input: &DurablePaymentCompensationInput<'_>,
        journal: &PaymentJournalRecord,
        transition: &PaymentJournalTransition,
        release_evidence: Option<&crate::tool_outcome::MonetaryReleaseEvidenceV1>,
    ) -> Result<PaymentJournalRecord, KernelError> {
        input
            .runtime
            .store
            .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                operation: input.operation,
                recovery_lease: input.lease,
                expected: journal,
                transition,
                release_evidence,
                active_fence: &input.runtime.fence,
                trusted_now_unix_ms: input.trusted_now_unix_ms,
            })
            .map_err(super::recovery::failure::payment_store_error)
    }

    fn compensation_payment_adapter(
        &self,
        journal: &PaymentJournalRecord,
    ) -> Result<&dyn crate::payment::PaymentAdapter, KernelError> {
        let adapter = self.payment_adapter.as_deref().ok_or_else(|| {
            item_failure(
                FailureKind::ParticipantUnavailable,
                "pre-dispatch payment adapter is unavailable",
            )
        })?;
        if adapter.rail_id() != journal.rail || adapter.rail_mode() != Some(journal.rail_mode) {
            return Err(item_failure(
                FailureKind::ContractChanged,
                "pre-dispatch payment adapter changed its original rail profile",
            ));
        }
        Ok(adapter)
    }
}

fn pre_dispatch_unwind_intent(journal: &PaymentJournalRecord) -> bool {
    journal
        .release_authority
        .as_ref()
        .is_some_and(|authority| authority.kind == PaymentReleaseAuthorityKind::PreDispatchNoEffect)
        && match journal.rail_mode {
            PaymentRailMode::ReversibleHold => {
                journal.settle_action == Some(PaymentSettleAction::Release)
            }
            PaymentRailMode::PrepaidFinal => journal.settle_action.is_none(),
        }
}

fn validate_confirmed_unwind(
    journal: &PaymentJournalRecord,
    unwind: &PreDispatchPaymentUnwindEvidence,
) -> Result<(), KernelError> {
    let status = match journal.rail_mode {
        PaymentRailMode::ReversibleHold => PreDispatchPaymentUnwindStatus::Released,
        PaymentRailMode::PrepaidFinal => PreDispatchPaymentUnwindStatus::Refunded,
    };
    if journal.authorization_id.as_deref() != Some(unwind.authorization_id.as_str())
        || unwind.settlement_status != status
    {
        return Err(KernelError::DurableAdmission(
            "confirmed pre-dispatch unwind conflicts with the original payment".into(),
        ));
    }
    validate_payment_adapter_identifier(&unwind.transaction_id, "confirmed unwind transaction_id")
        .map_err(payment_error)
}
