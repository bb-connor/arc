//! Fenced, read-only recovery projection of a durable budget hold.

use super::structured_budget::StructuredBudgetEventAuthorityView;
use chio_kernel::budget_store::{BudgetHoldDispositionView, BudgetHoldSnapshot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedBudgetHoldRequest {
    pub(crate) hold_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedBudgetHoldWire {
    hold_id: String,
    capability_id: String,
    grant_index: u32,
    authorized_exposure_units: u64,
    remaining_exposure_units: u64,
    disposition: String,
    reserved_until: Option<i64>,
    reserved_currency: Option<String>,
    reserved_payment_reference: Option<String>,
    reserved_budget_total: Option<u64>,
    reserved_delegation_depth: Option<u32>,
    reserved_root_budget_holder: Option<String>,
    authority: Option<StructuredBudgetEventAuthorityView>,
}

impl RetainedBudgetHoldWire {
    pub(crate) fn from_core(hold: BudgetHoldSnapshot) -> Result<Self, String> {
        Ok(Self {
            hold_id: hold.hold_id,
            capability_id: hold.capability_id,
            grant_index: u32::try_from(hold.grant_index)
                .map_err(|_| "hold grant index overflow")?,
            authorized_exposure_units: hold.authorized_exposure_units,
            remaining_exposure_units: hold.remaining_exposure_units,
            disposition: hold.disposition.as_str().to_owned(),
            reserved_until: hold.reserved_until,
            reserved_currency: hold.reserved_currency,
            reserved_payment_reference: hold.reserved_payment_reference,
            reserved_budget_total: hold.reserved_budget_total,
            reserved_delegation_depth: hold.reserved_delegation_depth,
            reserved_root_budget_holder: hold.reserved_root_budget_holder,
            authority: hold.authority.map(Into::into),
        })
    }

    pub(crate) fn into_core(self, expected_hold: &str) -> Result<BudgetHoldSnapshot, String> {
        if self.hold_id != expected_hold
            || self.capability_id.is_empty()
            || self.remaining_exposure_units > self.authorized_exposure_units
        {
            return Err("retained budget hold changed identity or exposure bounds".to_owned());
        }
        let disposition = match self.disposition.as_str() {
            "open" => BudgetHoldDispositionView::Open,
            "released" => BudgetHoldDispositionView::Released,
            "reversed" => BudgetHoldDispositionView::Reversed,
            "reconciled" => BudgetHoldDispositionView::Reconciled,
            "expired" => BudgetHoldDispositionView::Expired,
            _ => return Err("retained budget hold disposition is invalid".to_owned()),
        };
        Ok(BudgetHoldSnapshot {
            hold_id: self.hold_id,
            capability_id: self.capability_id,
            grant_index: usize::try_from(self.grant_index)
                .map_err(|_| "hold grant index overflow")?,
            authorized_exposure_units: self.authorized_exposure_units,
            remaining_exposure_units: self.remaining_exposure_units,
            disposition,
            reserved_until: self.reserved_until,
            reserved_currency: self.reserved_currency,
            reserved_payment_reference: self.reserved_payment_reference,
            reserved_budget_total: self.reserved_budget_total,
            reserved_delegation_depth: self.reserved_delegation_depth,
            reserved_root_budget_holder: self.reserved_root_budget_holder,
            authority: self.authority.map(Into::into),
        })
    }
}
