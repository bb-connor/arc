//! Recovery reads come from the fenced authority, never the advisory usage cache.

use super::*;

impl RemoteBudgetStore {
    pub(super) fn load_retained_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<chio_kernel::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        let fence = self.recovery_fence.as_ref().ok_or_else(|| {
            structured_budget_error("remote hold recovery requires a pinned joint authority")
        })?;
        chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "hold_id",
            hold_id.to_owned(),
        )
        .map_err(|error| structured_budget_error(error.to_string()))?;
        let request = AdmissionAuthorityRequest::new(
            Some(fence.clone()),
            AdmissionAuthorityAction::LoadBudgetHold,
            &RetainedBudgetHoldRequest {
                hold_id: hold_id.to_owned(),
            },
        )
        .map_err(|error| structured_budget_error(error.to_string()))?;
        let response: AdmissionAuthorityResponse = self
            .client
            .post_json_capped(INTERNAL_ADMISSION_AUTHORITY_PATH, &request, 64 * 1024)
            .map_err(into_budget_store_error)?;
        if !response.schema_is_valid() {
            return Err(structured_budget_error(
                "retained hold response schema is invalid",
            ));
        }
        match (response.result, response.error) {
            (Some(result), None) => {
                let hold: Option<RetainedBudgetHoldWire> = serde_json::from_value(result.value)
                    .map_err(|error| structured_budget_error(error.to_string()))?;
                hold.map(|hold| hold.into_core(hold_id).map_err(structured_budget_error))
                    .transpose()
            }
            (None, Some(error)) => Err(structured_budget_error(format!(
                "retained hold authority {:?}: {}",
                error.code, error.message,
            ))),
            _ => Err(structured_budget_error(
                "retained hold response must have exactly one outcome",
            )),
        }
    }
}
