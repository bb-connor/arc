//! Mutable terminal decisions are committed once, before any settlement callback.

use super::*;
use crate::finding_denial::FindingDenialCode;
use serde::{Deserialize, Serialize};

const SCHEMA: &str = "chio.kernel-terminal-snapshot.v1";

#[derive(Serialize, Deserialize)]
#[serde(remote = "FindingDenialCode", rename_all = "snake_case")]
enum FindingDenialCodeSnapshot {
    CarrierInvalid,
    AuthorityInvalid,
    BindingMismatch,
    StaleOrSuperseded,
    StatusDenied,
    QuotaExhausted,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingDenialSnapshot {
    #[serde(with = "FindingDenialCodeSnapshot")]
    code: FindingDenialCode,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableTerminalSnapshot {
    schema: String,
    pub(super) delivery_status_denied: bool,
    finding_denial: Option<FindingDenialSnapshot>,
    pub(super) pricing: Option<DurablePaymentPricing>,
}

impl DurableTerminalSnapshot {
    pub(super) fn prepare(
        delivery: &delivery_contract::DeliveryEvaluation,
        denial: Option<&FindingDenial>,
        pricing: Option<DurablePaymentPricing>,
    ) -> Self {
        Self {
            schema: SCHEMA.into(),
            delivery_status_denied: delivery.denial.as_ref().is_some_and(|denial| {
                denial.reason
                    == crate::admission_operation::DeliveryDenialReason::FindingStatusChanged
            }),
            finding_denial: denial.map(|denial| FindingDenialSnapshot {
                code: denial.code(),
            }),
            pricing,
        }
    }

    pub(super) fn from_evaluation(
        evaluation: &PostReturnEvaluationRecordV1,
    ) -> Result<Option<Self>, KernelError> {
        evaluation
            .retained_terminal_snapshot()
            .map(|value| {
                let snapshot: Self = serde_json::from_value(value.clone())
                    .map_err(chio_core::canonical::UntrustedJsonError::Decode)?;
                if snapshot.schema != SCHEMA
                    || (snapshot.finding_denial.is_some() && !snapshot.delivery_status_denied)
                {
                    return Err(KernelError::DurableAdmission(
                        "retained terminal snapshot conflicts with its schema or status decision"
                            .into(),
                    ));
                }
                Ok(snapshot)
            })
            .transpose()
    }

    pub(super) fn restore_delivery(
        &self,
        delivery: &mut delivery_contract::DeliveryEvaluation,
    ) -> Option<FindingDenial> {
        if self.delivery_status_denied && delivery.denial.is_none() {
            delivery.denial = Some(delivery_contract::finding_status_delivery_denial());
        }
        self.finding_denial.as_ref().map(|denial| {
            FindingDenial::new(denial.code, "retained terminal finding status denial")
        })
    }

    pub(super) fn canonical_value(&self) -> Result<serde_json::Value, KernelError> {
        serde_json::to_value(self).map_err(|error| KernelError::DurableAdmission(error.to_string()))
    }
}
