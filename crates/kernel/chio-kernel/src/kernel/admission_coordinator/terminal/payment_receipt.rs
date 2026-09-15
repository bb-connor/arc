//! Replay validation binds paid cost, consumed budget and the entire resolution authority.
use super::*;

pub(super) fn verify_replayed_financial(
    runtime: &DurableAdmissionRuntime,
    operation: &AdmissionOperationV1,
    request: &ToolCallRequest,
    receipt: &ChioReceipt,
) -> Result<(), KernelError> {
    let financial = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|metadata| metadata.get("financial"))
        .cloned()
        .map(serde_json::from_value::<FinancialReceiptMetadata>)
        .transpose()
        .map_err(|_| {
            KernelError::DurableAdmission(
                "projected receipt financial metadata is invalid".to_owned(),
            )
        })?;
    if operation.binding().participant_requirements().payment {
        let journal = runtime
            .store
            .load_payment_journal(operation.binding().operation_id().as_str(), &runtime.fence)
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission("completed payment journal disappeared".to_owned())
            })?;
        let resolved = journal.state == crate::payment::PaymentJournalState::Resolved;
        let expected_cost = match (journal.rail_mode, journal.settle_action) {
            (crate::payment::PaymentRailMode::PrepaidFinal, _) => journal.amount_units,
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                Some(crate::payment::PaymentSettleAction::Capture),
            ) => journal.settle_amount_units.ok_or_else(|| {
                KernelError::DurableAdmission(
                    "completed capture journal omitted its amount".to_owned(),
                )
            })?,
            (
                crate::payment::PaymentRailMode::ReversibleHold,
                Some(crate::payment::PaymentSettleAction::Release),
            ) => 0,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "completed payment journal omitted its settlement action".to_owned(),
                ));
            }
        };
        let financial = financial.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "completed payment receipt omitted financial metadata".to_owned(),
            )
        })?;
        let payment_reference = journal
            .transaction_id
            .as_ref()
            .or(journal.authorization_id.as_ref());
        if resolved
            && (financial
                .cost_breakdown
                .as_ref()
                .and_then(|b| b.pointer("/payment/recorded_units"))
                .and_then(|v| v.as_u64())
                != Some(expected_cost)
                || financial
                    .cost_breakdown
                    .as_ref()
                    .and_then(|b| b.pointer("/payment/contractual_resolution"))
                    != Some(
                        &serde_json::to_value(&journal.release_authority)
                            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
                    ))
        {
            return Err(KernelError::DurableAdmission(
                "waived payment receipt lost positive budget or resolution authority".into(),
            ));
        }
        if !matches!(
            journal.state,
            crate::payment::PaymentJournalState::Settled
                | crate::payment::PaymentJournalState::Resolved
        ) || financial.grant_index != journal.grant_index
            || financial.cost_charged != if resolved { 0 } else { expected_cost }
            || financial.currency != journal.currency
            || financial.payment_reference.as_ref() != payment_reference
            || financial.settlement_status
                != if resolved {
                    SettlementStatus::Failed
                } else {
                    SettlementStatus::Settled
                }
            || financial.delegation_depth
                != u32::try_from(request.capability.delegation_chain.len()).unwrap_or(u32::MAX)
            || financial.root_budget_holder != request.capability.issuer.to_hex()
            || financial.budget_remaining > financial.budget_total
            || financial.attempted_cost.is_some()
        {
            return Err(KernelError::DurableAdmission(
                "projected receipt financial metadata conflicts with the payment journal"
                    .to_owned(),
            ));
        }
    } else if financial.is_some() {
        return Err(KernelError::DurableAdmission(
            "nonpayment admission projected financial metadata".to_owned(),
        ));
    }
    Ok(())
}
