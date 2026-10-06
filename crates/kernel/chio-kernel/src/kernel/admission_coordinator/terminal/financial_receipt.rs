//! Validate financial receipt facts against the retained journal and resolution.

use super::*;
use chio_core::canonical::UntrustedJsonError;

impl ChioKernel {
    pub(super) fn validate_retained_financial_receipt(
        &self,
        operation: &AdmissionOperationV1,
        request: &ToolCallRequest,
        receipt: &ChioReceipt,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let financial = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| metadata.get("financial"))
            .cloned()
            .map(serde_json::from_value::<FinancialReceiptMetadata>)
            .transpose()
            .map_err(UntrustedJsonError::Decode)?;
        if operation.binding().participant_requirements().payment {
            let journal = runtime
                .store
                .load_payment_journal(operation.binding().operation_id().as_str(), &runtime.fence)
                .map_err(super::super::recovery::failure::payment_store_error)?
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "completed payment journal disappeared".to_owned(),
                    )
                })?;
            let expected_cost = match (journal.rail_mode, journal.settle_action) {
                // Historical completed receipts keep their original legacy facts.
                // This validation issues no new payment operation.
                (crate::payment::PaymentRailMode::PrepaidFinal, _) => journal
                    .authorized_amount_units
                    .unwrap_or(journal.amount_units),
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
            let outcome = runtime
                .outcome_store
                .lookup_by_operation(operation.binding().operation_id())
                .map_err(durable_outcome_store_error)?
                .ok_or_else(|| {
                    KernelError::DurableAdmission("completed financial outcome disappeared".into())
                })?;
            let evaluation = runtime
                .outcome_store
                .lookup_post_return_evaluation(operation.binding().operation_id())
                .map_err(durable_outcome_store_error)?
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "completed financial evaluation disappeared".into(),
                    )
                })?;
            evaluation
                .validate_against(operation, &outcome)
                .map_err(tool_outcome_error)?;
            let snapshot = DurableTerminalSnapshot::from_evaluation(&evaluation)?;
            let pricing = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.pricing.as_ref());
            let expected_status = pricing.map_or(
                SettlementStatus::Settled,
                DurablePaymentPricing::settlement_status,
            );
            let expected_oracle =
                serde_json::to_value(pricing.and_then(|pricing| pricing.oracle_evidence.as_ref()))
                    .map_err(|error| UntrustedJsonError::Canonicalization(error.into()))?;
            let recorded_oracle = serde_json::to_value(&financial.oracle_evidence)
                .map_err(|error| UntrustedJsonError::Canonicalization(error.into()))?;
            let payment_reference = journal
                .transaction_id
                .as_ref()
                .or(journal.authorization_id.as_ref());
            let grant = request
                .capability
                .scope
                .grants
                .get(usize::try_from(journal.grant_index).map_err(|_| {
                    KernelError::DurableAdmission(
                        "payment grant index exceeds address space".into(),
                    )
                })?)
                .ok_or_else(|| {
                    KernelError::DurableAdmission("payment journal names a missing grant".into())
                })?;
            let expected_ceiling = grant.max_total_cost.as_ref().map(|amount| amount.units);
            if journal.state != crate::payment::PaymentJournalState::Settled
                || financial.grant_index != journal.grant_index
                || financial.cost_charged != expected_cost
                || financial.currency != journal.currency
                || financial.payment_reference.as_ref() != payment_reference
                || financial.settlement_status != expected_status
                || recorded_oracle != expected_oracle
                || financial.cost_breakdown.as_ref()
                    != Some(&payment_pricing::payment_cost_breakdown(
                        &journal,
                        expected_cost,
                        pricing,
                    ))
                || financial.delegation_depth
                    != u32::try_from(request.capability.delegation_chain.len()).unwrap_or(u32::MAX)
                || financial.root_budget_holder != request.capability.issuer.to_hex()
                || financial.budget_total != expected_ceiling
                || financial.budget_remaining.is_some() != financial.budget_total.is_some()
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
}
