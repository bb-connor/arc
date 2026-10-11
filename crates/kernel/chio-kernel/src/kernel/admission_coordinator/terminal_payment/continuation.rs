//! Retry the exact committed settlement intent against the original rail.
use super::*;

impl ChioKernel {
    pub(super) fn continue_durable_payment_settlement(
        &self,
        operation: &AdmissionOperationV1,
        runtime: &DurableAdmissionRuntime,
        lease: &crate::admission_operation::AdmissionRecoveryLease,
        mut journal: crate::payment::PaymentJournalRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, KernelError> {
        journal.validate().map_err(payment_record_error)?;
        if journal.operation_id != operation.binding().operation_id().as_str() {
            return Err(KernelError::DurableAdmission(
                "payment settlement changed operation identity".to_owned(),
            ));
        }
        if journal.state == crate::payment::PaymentJournalState::Settled {
            return Ok(Some(journal));
        }
        // A journal sealed as reconcile_failed still carries its settle action and
        // authorization, so the same intent is re-driven against the rail rather
        // than leaving the operation non-terminal with its hold already reconciled.
        if journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
            || !matches!(
                journal.state,
                crate::payment::PaymentJournalState::Settling
                    | crate::payment::PaymentJournalState::ReconcileFailed
            )
        {
            return Err(KernelError::DurableAdmission(
                "payment journal has no replayable settlement intent".to_owned(),
            ));
        }
        let settle_action = journal.settle_action.ok_or_else(|| {
            KernelError::DurableAdmission("settling payment journal omitted its action".to_owned())
        })?;
        let authorization_id = journal.authorization_id.as_deref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "settling payment journal omitted authorization_id".to_owned(),
            )
        })?;
        let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
            item_failure(
                FailureKind::ParticipantUnavailable,
                "durable payment adapter disappeared during settlement",
            )
        })?;
        if adapter.rail_id() != journal.rail || adapter.rail_mode() != Some(journal.rail_mode) {
            return Err(item_failure(
                FailureKind::ContractChanged,
                "durable payment adapter changed before settlement",
            ));
        }
        let result = run_payment_adapter_operation("retained settlement", || match settle_action {
            crate::payment::PaymentSettleAction::Capture => adapter.capture(
                authorization_id,
                journal.settle_amount_units.ok_or_else(|| {
                    PaymentError::RailError(
                        "capture journal omitted its settlement amount".to_owned(),
                    )
                })?,
                &journal.currency,
                &journal.operation_id,
            ),
            crate::payment::PaymentSettleAction::Release => {
                adapter.release(authorization_id, &journal.operation_id)
            }
        })
        .map_err(payment_error)?;
        let compatible = matches!(
            (settle_action, result.settlement_status),
            (
                crate::payment::PaymentSettleAction::Capture,
                crate::payment::RailSettlementStatus::Captured
                    | crate::payment::RailSettlementStatus::Settled
            ) | (
                crate::payment::PaymentSettleAction::Release,
                crate::payment::RailSettlementStatus::Released
            )
        );
        if compatible {
            validate_payment_adapter_identifier(
                &result.transaction_id,
                "retained settlement transaction_id",
            )
            .map_err(payment_error)?;
            let transition = crate::payment::PaymentJournalTransition::SettlementCompleted {
                transaction_id: result.transaction_id,
            };
            journal = runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(payment_store_error)?;
            return Ok(Some(journal));
        }
        if result.settlement_status == crate::payment::RailSettlementStatus::Pending {
            return Ok(None);
        }
        if journal.state != crate::payment::PaymentJournalState::ReconcileFailed {
            let transition = crate::payment::PaymentJournalTransition::ReconcileFailed;
            runtime
                .store
                .advance_payment_journal(crate::receipt_store::AdmissionPaymentJournalAdvance {
                    operation,
                    recovery_lease: lease,
                    expected: &journal,
                    transition: &transition,
                    release_evidence: None,
                    active_fence: &runtime.fence,
                    trusted_now_unix_ms,
                })
                .map_err(payment_store_error)?;
        }
        Err(item_failure(
            FailureKind::ContractChanged,
            "payment rail returned an incompatible settlement status",
        ))
    }
}
