//! Recover an acknowledgement lost before the authorization reached the journal.

use super::*;
use crate::payment::{PaymentCredentialDisposition, RailSettlementState};

impl ChioKernel {
    pub(super) fn recover_pre_dispatch_payment_authorization(
        &self,
        input: &DurablePaymentCompensationInput<'_>,
        journal: PaymentJournalRecord,
    ) -> Result<
        (
            PaymentJournalRecord,
            Option<PreDispatchPaymentUnwindEvidence>,
        ),
        KernelError,
    > {
        if journal.authorization_attempt
            == Some(crate::payment::PaymentAuthorizationAttempt::NotStarted)
        {
            if input.confirmed_unwind.is_some() {
                return Err(KernelError::DurableAdmission(
                    "unattempted payment conflicts with a rail unwind result".into(),
                ));
            }
            let cancelled = self.advance_compensation_payment(
                input,
                &journal,
                &PaymentJournalTransition::CancelBeforeAuthorization,
                None,
            )?;
            return Ok((cancelled, None));
        }
        let (authorization_id, unwind) = if let Some(unwind) = input.confirmed_unwind {
            (unwind.authorization_id.clone(), Some(unwind.clone()))
        } else {
            let adapter = self.compensation_payment_adapter(&journal)?;
            let state = run_payment_adapter_operation("recover authorization", || {
                adapter.settlement_state(&journal.operation_id, None)
            })
            .map_err(payment_error)?;
            match state {
                RailSettlementState::NoAuthorization => {
                    let cancelled = self.advance_compensation_payment(
                        input,
                        &journal,
                        &PaymentJournalTransition::CancelBeforeAuthorization,
                        None,
                    )?;
                    return Ok((cancelled, None));
                }
                RailSettlementState::Held { authorization_id }
                    if journal.rail_mode == PaymentRailMode::ReversibleHold =>
                {
                    (authorization_id, None)
                }
                RailSettlementState::Settled {
                    authorization_id,
                    result,
                } => {
                    let status = match (journal.rail_mode, result.settlement_status) {
                        (PaymentRailMode::ReversibleHold, RailSettlementStatus::Released) => {
                            Some(PreDispatchPaymentUnwindStatus::Released)
                        }
                        (PaymentRailMode::PrepaidFinal, RailSettlementStatus::Refunded) => {
                            return Err(item_failure(
                                FailureKind::ContractChanged,
                                "status-only refund query cannot prove the whole original prepayment was unwound",
                            ))
                        }
                        (PaymentRailMode::PrepaidFinal, RailSettlementStatus::Settled)
                            if result.transaction_id == authorization_id =>
                        {
                            None
                        }
                        _ => {
                            return Err(item_failure(
                                FailureKind::ContractChanged,
                                "recovered authorization has an incompatible rail state",
                            ))
                        }
                    };
                    let unwind = status.map(|settlement_status| PreDispatchPaymentUnwindEvidence {
                        authorization_id: authorization_id.clone(),
                        transaction_id: result.transaction_id,
                        settlement_status,
                        credential_disposition: PaymentCredentialDisposition::NonePresent,
                    });
                    (authorization_id, unwind)
                }
                _ => {
                    return Err(item_failure(
                        FailureKind::ContractChanged,
                        "recovered authorization conflicts with the original rail mode",
                    ))
                }
            }
        };
        validate_payment_adapter_identifier(&authorization_id, "recovered authorization_id")
            .map_err(payment_error)?;
        let transition = match journal.rail_mode {
            PaymentRailMode::ReversibleHold => {
                PaymentJournalTransition::AuthorizationHeld { authorization_id }
            }
            PaymentRailMode::PrepaidFinal => {
                PaymentJournalTransition::PrepaymentSettled { authorization_id }
            }
        };
        let recovered = self.advance_compensation_payment(input, &journal, &transition, None)?;
        Ok((recovered, unwind))
    }
}
