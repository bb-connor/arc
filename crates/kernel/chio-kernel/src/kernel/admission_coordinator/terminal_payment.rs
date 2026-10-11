//! Payment settlement of a durable tool return: the journal disposition,
//! the rail settlement and its continuation after an interrupted attempt.

use super::*;
#[path = "terminal_payment/continuation.rs"]
mod continuation;
use super::super::recovery::failure::{
    item_failure, payment_error, payment_record_error, payment_store_error,
};
use crate::admission_operation::AdmissionRecoveryFailureKind as FailureKind;

pub(super) struct DurablePaymentTerminal {
    pub(super) journal: crate::payment::PaymentJournalRecord,
    pub(super) reconcile: BudgetReconcileHoldDecision,
    pub(super) amount_units: u64,
}

pub(super) struct DurablePaymentSettlementInput<'a> {
    pub(super) admission: &'a DurableToolAdmission,
    pub(super) runtime: &'a DurableAdmissionRuntime,
    pub(super) lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    pub(super) journal: crate::payment::PaymentJournalRecord,
    pub(super) disposition: &'a SettlementDispositionV1,
    pub(super) context: &'a AdmissionProjectionContext,
    pub(super) purchase: Option<&'a crate::finding_purchase::VerifiedFindingPurchase>,
    pub(super) trusted_now_unix_ms: u64,
}

fn payment_journal_matches_settlement(
    journal: &crate::payment::PaymentJournalRecord,
    action: crate::payment::PaymentSettleAction,
    amount_units: u64,
) -> bool {
    if journal.rail_mode == crate::payment::PaymentRailMode::PrepaidFinal {
        return journal.state == crate::payment::PaymentJournalState::Settled
            && journal.authorization_id.is_some()
            && journal.transaction_id.is_none()
            && journal.settle_action.is_none()
            && journal.settle_amount_units.is_none()
            && journal.release_authority.is_none()
            && action == crate::payment::PaymentSettleAction::Capture
            && journal.authorized_amount_units == Some(amount_units);
    }
    journal.settle_action == Some(action)
        && match action {
            crate::payment::PaymentSettleAction::Capture => {
                journal.settle_amount_units == Some(amount_units)
                    && journal.release_authority.is_none()
            }
            crate::payment::PaymentSettleAction::Release => {
                journal.settle_amount_units.is_none()
                    && journal.release_authority.as_ref().is_some_and(|authority| {
                        authority.kind
                            == crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge
                    })
            }
        }
}

impl ChioKernel {
    pub(super) fn settle_durable_payment(
        &self,
        input: DurablePaymentSettlementInput<'_>,
    ) -> Result<DurablePaymentTerminal, KernelError> {
        let DurablePaymentSettlementInput {
            admission,
            runtime,
            lease,
            mut journal,
            disposition,
            context,
            purchase,
            trusted_now_unix_ms,
        } = input;
        let authorized_amount = journal.authorized_amount_units;
        let (amount_units, settle_action) = match disposition {
            SettlementDispositionV1::Capture { amount } => {
                let authorized_amount = authorized_amount.ok_or_else(|| item_failure(
                    FailureKind::LegacyPaymentAmountAbsent, "legacy payment has no exact debit; new capture cannot be inferred from exposure"))?;
                if amount.currency != journal.currency
                    || amount.units == 0
                    || amount.units > authorized_amount
                {
                    return Err(KernelError::DurableAdmission(
                        "durable capture disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (amount.units, crate::payment::PaymentSettleAction::Capture)
            }
            SettlementDispositionV1::ContractualZeroCharge { currency } => {
                if currency != &journal.currency
                    || journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold
                {
                    return Err(KernelError::DurableAdmission(
                        "zero-charge disposition conflicts with the payment journal".to_owned(),
                    ));
                }
                (0, crate::payment::PaymentSettleAction::Release)
            }
            SettlementDispositionV1::NotApplicable => {
                return Err(KernelError::DurableAdmission(
                    "payment participant cannot use a not-applicable settlement".to_owned(),
                ));
            }
        };
        let hold_id = journal.hold_id.clone().ok_or_else(|| {
            KernelError::DurableAdmission("payment journal omitted its budget hold".to_owned())
        })?;
        let (transition, release_evidence) = match (journal.rail_mode, journal.state) {
            (
                crate::payment::PaymentRailMode::PrepaidFinal,
                crate::payment::PaymentJournalState::Settled,
            ) if journal.authorization_id.is_some() && Some(amount_units) == authorized_amount => {
                (None, None)
            }
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Authorized,
            ) => match settle_action {
                crate::payment::PaymentSettleAction::Capture => (
                    Some(crate::payment::PaymentJournalTransition::BeginCapture { amount_units }),
                    None,
                ),
                crate::payment::PaymentSettleAction::Release => {
                    let proof = runtime
                        .verify_contractual_zero_charge(&admission.operation, context)
                        .map_err(tool_outcome_error)?;
                    let evidence =
                        crate::tool_outcome::MonetaryReleaseAuthority::ContractualZeroCharge(
                            Box::new(proof),
                        )
                        .evidence_bundle()
                        .map_err(tool_outcome_error)?;
                    let persisted = evidence.to_persisted();
                    let authority = crate::payment::PaymentReleaseAuthorityBinding {
                        kind: crate::payment::PaymentReleaseAuthorityKind::ContractualZeroCharge,
                        operation_id: persisted.operation_id.as_str().to_owned(),
                        operation_version: persisted.operation_version,
                        evidence_id: persisted.evidence_id.as_str().to_owned(),
                        evidence_digest: persisted.bundle_digest.as_str().to_owned(),
                    };
                    (
                        Some(crate::payment::PaymentJournalTransition::BeginRelease { authority }),
                        Some(evidence),
                    )
                }
            },
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                crate::payment::PaymentJournalState::Settling
                | crate::payment::PaymentJournalState::ReconcileFailed
                | crate::payment::PaymentJournalState::Settled,
            ) if payment_journal_matches_settlement(&journal, settle_action, amount_units) => {
                (None, None)
            }
            (crate::payment::PaymentRailMode::PrepaidFinal, _) => {
                return Err(KernelError::DurableAdmission(
                    "final prepayment journal is not terminal and fixed-price".to_owned(),
                ));
            }
            (crate::payment::PaymentRailMode::ReversibleHold, _) => {
                return Err(KernelError::DurableAdmission(
                    "payment journal has no replayable settlement intent".to_owned(),
                ));
            }
        };
        let settlement = runtime
            .store
            .begin_payment_settlement(crate::receipt_store::AdmissionPaymentSettlementBegin {
                operation: &admission.operation,
                recovery_lease: lease,
                expected: &journal,
                transition: transition.as_ref(),
                release_evidence: release_evidence.as_ref(),
                budget_reconcile: BudgetReconcileHoldRequest {
                    capability_id: journal.capability_id.clone(),
                    grant_index: usize::try_from(journal.grant_index).map_err(|_| {
                        KernelError::DurableAdmission(
                            "payment journal grant index overflowed".to_owned(),
                        )
                    })?,
                    exposed_cost_units: journal.amount_units,
                    realized_spend_units: amount_units,
                    hold_id: Some(hold_id.clone()),
                    event_id: Some(format!("{hold_id}:reconcile")),
                    authority: Some(runtime.authority()),
                },
                active_fence: &runtime.fence,
                trusted_now_unix_ms,
            })
            .map_err(payment_store_error)?;
        journal = settlement.journal;
        let reconcile = settlement.budget;
        if !payment_journal_matches_settlement(&journal, settle_action, amount_units) {
            return Err(KernelError::DurableAdmission(
                "payment journal conflicts with the pricing disposition".to_owned(),
            ));
        }
        if settle_action == crate::payment::PaymentSettleAction::Capture {
            if let Some(purchase) = purchase {
                let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "purchase capture lost its configured verifier".to_owned(),
                    )
                })?;
                verifier
                    .mark_capture_pending(purchase, trusted_now_unix_ms / 1_000)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "purchase capture fence failed: {error}"
                        ))
                    })?;
            }
        }
        journal = self
            .continue_durable_payment_settlement(
                &admission.operation,
                runtime,
                lease,
                journal,
                trusted_now_unix_ms,
            )?
            .ok_or_else(|| {
                super::super::recovery::failure::item_failure(
                    crate::admission_operation::AdmissionRecoveryFailureKind::PaymentPending,
                    "payment settlement remains pending",
                )
            })?;
        if journal.state != crate::payment::PaymentJournalState::Settled {
            return Err(KernelError::DurableAdmission(
                "payment journal did not reach a terminal settlement".to_owned(),
            ));
        }
        Ok(DurablePaymentTerminal {
            journal,
            reconcile,
            amount_units,
        })
    }
}
