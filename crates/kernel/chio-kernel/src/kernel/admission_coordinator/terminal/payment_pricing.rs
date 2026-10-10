//! Pricing after dispatch closes at the original exposure when reporting fails.

use super::super::recovery::failure::{item_failure, payment_record_error, payment_store_error};
use super::*;
use crate::admission_operation::AdmissionRecoveryFailureKind as FailureKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DurablePricingFailure {
    AuthorizationExceeded,
    ConversionUnavailable,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurablePaymentPricing {
    pub(super) reported_cost: Option<chio_core::capability::scope::MonetaryAmount>,
    pub(super) oracle_evidence: Option<chio_core::web3::anchors::OracleConversionEvidence>,
    pub(super) failure: Option<DurablePricingFailure>,
}

pub(super) struct DurablePaymentPlan {
    pub(super) journal: crate::payment::PaymentJournalRecord,
    pub(super) disposition: SettlementDispositionV1,
    pub(super) pricing: Option<DurablePaymentPricing>,
}

pub(super) struct DurablePaymentDispositionInput<'a> {
    pub(super) admission: &'a DurableToolAdmission,
    pub(super) runtime: &'a DurableAdmissionRuntime,
    pub(super) raw: &'a RawInvocationOutcomeV1,
    pub(super) trusted_now_unix_ms: u64,
    pub(super) delivery_denied: bool,
    pub(super) retained: Option<(
        &'a SettlementDispositionV1,
        Option<&'a DurablePaymentPricing>,
    )>,
}

impl ChioKernel {
    pub(super) fn durable_payment_disposition(
        &self,
        input: DurablePaymentDispositionInput<'_>,
    ) -> Result<Option<DurablePaymentPlan>, KernelError> {
        let DurablePaymentDispositionInput {
            admission,
            runtime,
            raw,
            trusted_now_unix_ms,
            delivery_denied,
            retained,
        } = input;
        if !admission.requires_payment() {
            if retained.is_some_and(|(disposition, pricing)| {
                !matches!(disposition, SettlementDispositionV1::NotApplicable) || pricing.is_some()
            }) {
                return Err(KernelError::DurableAdmission(
                    "nonpayment replay retains a financial disposition".into(),
                ));
            }
            return Ok(None);
        }
        // Finalization already owns the mutation guard. Loading through the
        // separately locked authorization helper would reacquire that mutex.
        let journal = runtime
            .store
            .load_payment_journal(admission.operation_id(), &runtime.fence)
            .map_err(payment_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable payment participant disappeared during finalization".into(),
                )
            })?;
        journal.validate().map_err(payment_record_error)?;
        if journal.operation_id != admission.operation_id() {
            return Err(KernelError::DurableAdmission(
                "finalization payment changed operation identity".into(),
            ));
        }
        if journal.capability_id != admission.operation.binding().capability_id().as_str()
            || usize::try_from(journal.grant_index).ok()
                != Some(raw.matched_grant_index().map_err(tool_outcome_error)?)
        {
            return Err(KernelError::DurableAdmission(
                "payment journal does not match the recorded tool outcome".into(),
            ));
        }
        if let Some((disposition, pricing)) = retained {
            if matches!(disposition, SettlementDispositionV1::Capture { .. })
                && journal.authorized_amount_units.is_none()
            {
                return Err(item_failure(FailureKind::LegacyPaymentAmountAbsent,
                    "legacy capture lacks its exact original debit; budget exposure cannot replace it"));
            }
            if let Some(pricing) = pricing {
                if pricing.reported_cost.as_ref() != raw.reported_cost() {
                    return Err(KernelError::DurableAdmission(
                        "retained pricing changed the reported tool cost".into(),
                    ));
                }
            }
            return Ok(Some(DurablePaymentPlan {
                journal,
                disposition: disposition.clone(),
                pricing: pricing.cloned(),
            }));
        }
        let authorized_amount = journal.authorized_amount_units.ok_or_else(|| {
            item_failure(
                FailureKind::LegacyPaymentAmountAbsent,
                "legacy payment lacks its exact original debit for pricing",
            )
        })?;
        let mut pricing = DurablePaymentPricing {
            reported_cost: raw.reported_cost().cloned(),
            ..Default::default()
        };
        let amount_units = if delivery_denied {
            if journal.rail_mode != crate::payment::PaymentRailMode::ReversibleHold {
                return Err(KernelError::DurableAdmission(
                    "delivery denial requires a reversible-hold rail".into(),
                ));
            }
            0
        } else {
            match journal.rail_mode {
                crate::payment::PaymentRailMode::PrepaidFinal => authorized_amount,
                crate::payment::PaymentRailMode::ReversibleHold => {
                    let reported = match raw.reported_cost() {
                        Some(cost) if cost.units == 0 => 0,
                        Some(cost) if cost.currency != journal.currency => {
                            let cost = ToolInvocationCost {
                                units: cost.units,
                                currency: cost.currency.clone(),
                                breakdown: None,
                            };
                            match self.resolve_cross_currency_cost(
                                &cost,
                                &journal.currency,
                                trusted_now_unix_ms / 1_000,
                            ) {
                                Ok((units, evidence)) => {
                                    pricing.oracle_evidence = Some(evidence);
                                    units
                                }
                                Err(error @ KernelError::Clock(_)) => return Err(error),
                                Err(error) => {
                                    warn!(operation_id = %journal.operation_id, reason = %redacted!(&error), "post-dispatch conversion unavailable; capture remains within original exposure");
                                    pricing.failure =
                                        Some(DurablePricingFailure::ConversionUnavailable);
                                    authorized_amount
                                }
                            }
                        }
                        Some(cost) => cost.units,
                        None => authorized_amount,
                    };
                    if reported > authorized_amount {
                        pricing.failure = Some(DurablePricingFailure::AuthorizationExceeded);
                    }
                    reported.min(authorized_amount)
                }
            }
        };
        let disposition = if amount_units == 0 {
            SettlementDispositionV1::ContractualZeroCharge {
                currency: journal.currency.clone(),
            }
        } else {
            SettlementDispositionV1::Capture {
                amount: chio_core::capability::scope::MonetaryAmount {
                    units: amount_units,
                    currency: journal.currency.clone(),
                },
            }
        };
        Ok(Some(DurablePaymentPlan {
            journal,
            disposition,
            pricing: Some(pricing),
        }))
    }
}

impl DurablePaymentPricing {
    pub(super) fn settlement_status(&self) -> SettlementStatus {
        if self.failure.is_some() {
            SettlementStatus::Failed
        } else {
            SettlementStatus::Settled
        }
    }
}

pub(super) fn payment_cost_breakdown(
    journal: &crate::payment::PaymentJournalRecord,
    amount_units: u64,
    pricing: Option<&DurablePaymentPricing>,
) -> serde_json::Value {
    let mut payment = serde_json::Map::from_iter([
        ("rail".into(), serde_json::json!(journal.rail)),
        ("rail_mode".into(), serde_json::json!(journal.rail_mode)),
        (
            "authorization_id".into(),
            serde_json::json!(journal.authorization_id),
        ),
        (
            "transaction_id".into(),
            serde_json::json!(journal.transaction_id),
        ),
        (
            "preauthorized_units".into(),
            serde_json::json!(journal
                .authorized_amount_units
                .unwrap_or(journal.amount_units)),
        ),
        ("recorded_units".into(), serde_json::json!(amount_units)),
    ]);
    if journal.authorized_amount_units.is_some() {
        payment.insert(
            "budget_exposure_units".into(),
            serde_json::json!(journal.amount_units),
        );
    }
    if let Some(pricing) = pricing {
        payment.insert("pricing_failure".into(), serde_json::json!(pricing.failure));
        payment.insert(
            "reported_cost".into(),
            serde_json::json!(pricing.reported_cost),
        );
    }
    serde_json::json!({"payment": payment})
}
